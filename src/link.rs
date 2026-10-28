//! The only place where netnode talks to the Linux kernel directly.
//!
//! It wraps a raw `AF_PACKET` socket (send and receive whole Ethernet frames)
//! plus a few interface queries and one thread setting. This is the only
//! module allowed to use `unsafe`: every `unsafe` block carries a `SAFETY:`
//! comment explaining why it is sound, and the rest of the crate only sees
//! the safe functions defined here.

#![allow(unsafe_code)]
#![deny(clippy::undocumented_unsafe_blocks)]

use std::ffi::CString;
use std::io;
use std::mem::size_of;
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::time::Duration;

use crate::hosts::MacAddr;

/// How long `recv` blocks before returning `Ok(None)`, so that the RX thread
/// can notice a shutdown request.
pub const RECV_TIMEOUT: Duration = Duration::from_millis(100);

/// Kernel receive buffer. Large enough to absorb short bursts.
const RECV_BUFFER_BYTES: libc::c_int = 4 * 1024 * 1024;

/// Facts about the interface, read once when the link is opened.
#[derive(Debug, Clone)]
pub struct InterfaceInfo {
    pub name: String,
    pub index: u32,
    pub mac: MacAddr,
    pub mtu: u32,
}

/// What the kernel tells us about one received frame.
#[derive(Debug, Clone, Copy)]
pub struct Received {
    /// Number of bytes written into the caller's buffer.
    pub len: usize,
    /// True when the frame was sent by this machine (we only want incoming ones).
    pub outgoing: bool,
}

/// A raw Ethernet socket bound to one interface in promiscuous mode.
///
/// `Link` is `Send + Sync`: the RX thread receives and the TX/CLI threads send
/// on the same socket concurrently, which the kernel supports.
pub struct Link {
    fd: OwnedFd,
    info: InterfaceInfo,
}

impl Link {
    /// Opens a raw socket on `name`, enables promiscuous mode and low-latency
    /// socket options. Needs `CAP_NET_RAW` and `CAP_NET_ADMIN`.
    pub fn open(name: &str) -> io::Result<Self> {
        if name.is_empty() || name.len() >= libc::IFNAMSIZ {
            return Err(invalid_input(format!("invalid interface name {name:?}")));
        }
        let c_name =
            CString::new(name).map_err(|_| invalid_input("interface name contains a NUL byte".into()))?;

        // SAFETY: `c_name` is a valid NUL-terminated string that outlives the call.
        let index = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
        if index == 0 {
            return Err(io::Error::new(io::ErrorKind::NotFound, format!("interface {name} not found")));
        }

        let all_protocols = (libc::ETH_P_ALL as u16).to_be();
        // SAFETY: a plain syscall with constant arguments; the result is checked below.
        let raw = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::c_int::from(all_protocols),
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `raw` is a freshly created, valid descriptor that nothing else owns,
        // so `OwnedFd` may take ownership and close it on drop.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };

        // Bind to the interface so the socket only sees eth1's frames.
        let addr = libc::sockaddr_ll {
            sll_family: libc::AF_PACKET as u16,
            sll_protocol: all_protocols,
            sll_ifindex: index as libc::c_int,
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: 0,
            sll_addr: [0; 8],
        };
        // SAFETY: `addr` is a fully initialised `sockaddr_ll` and we pass its exact size.
        let rc = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                (&raw const addr).cast(),
                size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        check(rc)?;

        // Promiscuous mode through a socket membership: the kernel removes it
        // automatically when the socket closes, even if netnode crashes.
        let promisc = libc::packet_mreq {
            mr_ifindex: index as libc::c_int,
            mr_type: libc::PACKET_MR_PROMISC as u16,
            mr_alen: 0,
            mr_address: [0; 8],
        };
        set_option(&fd, libc::SOL_PACKET, libc::PACKET_ADD_MEMBERSHIP, &promisc)?;

        // Best effort: older kernels lack some of these, and netnode works without them.
        let on: libc::c_int = 1;
        let _ = set_option(&fd, libc::SOL_PACKET, libc::PACKET_IGNORE_OUTGOING, &on); // 4.20+
        let _ = set_option(&fd, libc::SOL_PACKET, libc::PACKET_QDISC_BYPASS, &on); // 3.14+
        let _ = set_option(&fd, libc::SOL_SOCKET, libc::SO_RCVBUF, &RECV_BUFFER_BYTES);

        let timeout = libc::timeval { tv_sec: 0, tv_usec: RECV_TIMEOUT.as_micros() as libc::suseconds_t };
        set_option(&fd, libc::SOL_SOCKET, libc::SO_RCVTIMEO, &timeout)?;

        let mac = read_mac(&fd, name)?;
        let mtu = read_mtu(&fd, name)?;
        Ok(Self { fd, info: InterfaceInfo { name: name.to_owned(), index, mac, mtu } })
    }

    pub fn info(&self) -> &InterfaceInfo {
        &self.info
    }

    /// Receives one frame into `buf`. Returns `Ok(None)` when nothing arrived
    /// within [`RECV_TIMEOUT`].
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<Option<Received>> {
        let mut from = libc::sockaddr_ll {
            sll_family: 0,
            sll_protocol: 0,
            sll_ifindex: 0,
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: 0,
            sll_addr: [0; 8],
        };
        let mut from_len = size_of::<libc::sockaddr_ll>() as libc::socklen_t;
        // SAFETY: `buf` is valid for writes of `buf.len()` bytes; `from` and
        // `from_len` are valid out-parameters whose size we pass correctly.
        let n = unsafe {
            libc::recvfrom(
                self.fd.as_raw_fd(),
                buf.as_mut_ptr().cast(),
                buf.len(),
                0,
                (&raw mut from).cast(),
                &mut from_len,
            )
        };
        if n < 0 {
            let err = io::Error::last_os_error();
            return match err.kind() {
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted => Ok(None),
                _ => Err(err),
            };
        }
        Ok(Some(Received { len: n as usize, outgoing: from.sll_pkttype == libc::PACKET_OUTGOING }))
    }

    /// Sends one complete Ethernet frame (destination MAC first).
    pub fn send(&self, frame: &[u8]) -> io::Result<()> {
        // SAFETY: `frame` is valid for reads of `frame.len()` bytes for the whole call.
        let n = unsafe { libc::send(self.fd.as_raw_fd(), frame.as_ptr().cast(), frame.len(), 0) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        if n as usize != frame.len() {
            return Err(io::Error::new(io::ErrorKind::WriteZero, "short write on raw socket"));
        }
        Ok(())
    }

    /// The interface's primary IPv4 address and prefix length, read live.
    /// `None` when the interface has no IPv4 address (which is fine for netnode).
    pub fn ipv4(&self) -> Option<(Ipv4Addr, u8)> {
        let addr = ioctl_ifreq(&self.fd, libc::SIOCGIFADDR as _, &self.info.name).ok()?;
        let mask = ioctl_ifreq(&self.fd, libc::SIOCGIFNETMASK as _, &self.info.name).ok()?;
        // SAFETY: SIOCGIFADDR / SIOCGIFNETMASK fill the `ifru_addr` / `ifru_netmask` member.
        let (addr, mask) = unsafe { (addr.ifr_ifru.ifru_addr, mask.ifr_ifru.ifru_netmask) };
        let ip = ipv4_from_sockaddr(&addr);
        let prefix = u32::from(ipv4_from_sockaddr(&mask)).count_ones() as u8;
        Some((ip, prefix))
    }
}

/// Removes the default 50 µs timer slack from the calling thread, so timed
/// sleeps wake up as close to their deadline as the kernel allows.
pub fn minimise_timer_slack() -> io::Result<()> {
    // SAFETY: PR_SET_TIMERSLACK takes a plain integer and only affects the calling thread.
    let rc = unsafe { libc::prctl(libc::PR_SET_TIMERSLACK, 1 as libc::c_ulong, 0, 0, 0) };
    check(rc)
}

fn set_option<T>(fd: &OwnedFd, level: libc::c_int, name: libc::c_int, value: &T) -> io::Result<()> {
    // SAFETY: `value` points to a valid, initialised `T` for the whole call, and
    // we pass exactly `size_of::<T>()` as its length.
    let rc = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            level,
            name,
            (value as *const T).cast(),
            size_of::<T>() as libc::socklen_t,
        )
    };
    check(rc)
}

/// Runs an interface ioctl that fills an `ifreq` and returns the filled struct.
fn ioctl_ifreq(fd: &OwnedFd, request: libc::Ioctl, name: &str) -> io::Result<libc::ifreq> {
    // SAFETY: `ifreq` contains only integers, byte arrays and a raw pointer,
    // for all of which the all-zero bit pattern is a valid value.
    let mut req: libc::ifreq = unsafe { std::mem::zeroed() };
    for (dst, src) in req.ifr_name.iter_mut().zip(name.bytes()) {
        *dst = src as libc::c_char; // `name` is shorter than IFNAMSIZ, so the last byte stays NUL
    }
    // SAFETY: `req` is a valid, initialised `ifreq` that the kernel reads and
    // writes in place; it lives on our stack for the whole call.
    let rc = unsafe { libc::ioctl(fd.as_raw_fd(), request, &raw mut req) };
    check(rc)?;
    Ok(req)
}

fn read_mac(fd: &OwnedFd, name: &str) -> io::Result<MacAddr> {
    let req = ioctl_ifreq(fd, libc::SIOCGIFHWADDR as _, name)?;
    // SAFETY: SIOCGIFHWADDR fills the `ifru_hwaddr` member of the union.
    let data = unsafe { req.ifr_ifru.ifru_hwaddr.sa_data };
    let mut mac = [0u8; 6];
    for (dst, src) in mac.iter_mut().zip(data) {
        *dst = src as u8;
    }
    Ok(MacAddr(mac))
}

fn read_mtu(fd: &OwnedFd, name: &str) -> io::Result<u32> {
    let req = ioctl_ifreq(fd, libc::SIOCGIFMTU as _, name)?;
    // SAFETY: SIOCGIFMTU fills the `ifru_mtu` member of the union.
    let mtu = unsafe { req.ifr_ifru.ifru_mtu };
    Ok(mtu.max(0) as u32)
}

/// A `sockaddr` holding an IPv4 address stores it in `sa_data[2..6]`
/// (bytes 0 and 1 are the port).
fn ipv4_from_sockaddr(addr: &libc::sockaddr) -> Ipv4Addr {
    let d = addr.sa_data;
    Ipv4Addr::new(d[2] as u8, d[3] as u8, d[4] as u8, d[5] as u8)
}

fn check(rc: libc::c_int) -> io::Result<()> {
    if rc < 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
}

fn invalid_input(msg: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg)
}
