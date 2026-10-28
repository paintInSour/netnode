//! The RX thread: receive every frame on the interface, decide whether a
//! virtual host must answer, and either send the reply at once or hand it to
//! the TX thread with a deadline.

#![forbid(unsafe_code)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use crossbeam_channel::Sender;
use etherparse::{Ethernet2HeaderSlice, Ipv4HeaderSlice};

use crate::hosts::{HostTable, MacAddr, SharedHosts, VirtualHost};
use crate::link::Link;
use crate::proto::arp::{self, Arp, OP_REQUEST};
use crate::proto::icmp::{self, Endpoint};
use crate::proto::{ETH_HEADER_LEN, ETHERTYPE_ARP, ETHERTYPE_IPV4, IP_PROTO_ICMP, checksum};
use crate::sniff::Sniffer;
use crate::stats::Stats;
use crate::tx::{self, Scheduled};

/// Receive buffer size. Larger than any MTU because GRO can deliver
/// coalesced frames above the MTU to packet sockets.
const RX_BUFFER_LEN: usize = 64 * 1024;

/// A reply produced for one received frame.
#[derive(Debug)]
pub struct Reply {
    pub host: Arc<VirtualHost>,
    pub frame: Vec<u8>,
}

pub struct RxThread {
    pub link: Arc<Link>,
    pub hosts: SharedHosts,
    pub stats: Arc<Stats>,
    pub sniffer: Arc<Sniffer>,
    pub to_tx: Sender<Scheduled>,
    pub stop: Arc<AtomicBool>,
}

impl RxThread {
    pub fn run(self) {
        let mut buf = vec![0u8; RX_BUFFER_LEN]; // reused for every frame: no allocation per receive
        while !self.stop.load(Ordering::Relaxed) {
            let received = match self.link.recv(&mut buf) {
                Ok(Some(received)) => received,
                Ok(None) => continue, // timeout: loop to check `stop`
                Err(err) => {
                    self.stats.rx_errors.inc();
                    tracing::warn!(%err, "receive failed");
                    thread::sleep(Duration::from_millis(10));
                    continue;
                }
            };
            if received.outgoing {
                continue; // our own transmissions, on kernels without PACKET_IGNORE_OUTGOING
            }
            let rx_at = Instant::now();
            let frame = &buf[..received.len];
            self.stats.rx_frames.inc();
            self.sniffer.rx(frame, &self.stats);

            let hosts = self.hosts.load(); // one atomic load; never blocks
            if let Some(reply) = handle_frame(frame, &hosts, &self.stats) {
                self.dispatch(reply, rx_at);
            }
        }
    }

    fn dispatch(&self, reply: Reply, rx_at: Instant) {
        match reply.host.reply_deadline(rx_at) {
            // Fast path: no delay configured, send straight from this thread.
            None => tx::transmit(&self.link, &reply.frame, None, &self.stats, &self.sniffer),
            Some(deadline) => {
                let item = Scheduled { deadline, rx_at: Some(rx_at), frame: reply.frame };
                if self.to_tx.try_send(item).is_err() {
                    self.stats.tx_queue_full.inc();
                }
            }
        }
    }
}

/// Decides what to do with one received frame.
///
/// Apart from bumping counters it has no side effects, so it is tested
/// without a socket.
pub fn handle_frame(frame: &[u8], hosts: &HostTable, stats: &Stats) -> Option<Reply> {
    let Ok(eth) = Ethernet2HeaderSlice::from_slice(frame) else {
        stats.rx_malformed.inc();
        return None;
    };
    let payload = &frame[ETH_HEADER_LEN..];
    match eth.ether_type().0 {
        ETHERTYPE_ARP => {
            stats.rx_arp.inc();
            handle_arp(payload, hosts, stats)
        }
        ETHERTYPE_IPV4 => {
            stats.rx_ipv4.inc();
            let link = (MacAddr(eth.destination()), MacAddr(eth.source()));
            handle_ipv4(link, payload, hosts, stats)
        }
        _ => {
            stats.rx_other.inc(); // IPv6, VLAN-tagged, LLDP, ...
            None
        }
    }
}

fn handle_arp(payload: &[u8], hosts: &HostTable, stats: &Stats) -> Option<Reply> {
    let Some(arp) = Arp::parse(payload) else {
        stats.rx_malformed.inc();
        return None;
    };
    // Another machine using one of our IPs is worth knowing about.
    if let Some(owner) = hosts.by_ip(arp.sender_ip)
        && owner.mac != arp.sender_mac
    {
        stats.ip_conflicts.inc();
    }

    let host = hosts.by_ip(arp.target_ip)?;
    stats.rx_for_hosts.inc();
    host.stats.count_rx();
    if arp.op != OP_REQUEST || arp.is_announcement() {
        return None;
    }
    host.stats.count_reply();
    Some(Reply { host: host.clone(), frame: arp::build_reply(host.mac, host.ip(), &arp) })
}

fn handle_ipv4(
    (dst_mac, src_mac): (MacAddr, MacAddr),
    packet: &[u8],
    hosts: &HostTable,
    stats: &Stats,
) -> Option<Reply> {
    let Ok(ip) = Ipv4HeaderSlice::from_slice(packet) else {
        stats.rx_malformed.inc();
        return None;
    };
    let host = hosts.by_ip(ip.destination_addr())?;
    if dst_mac != host.mac {
        return None; // broadcast, or a frame really meant for another machine
    }
    stats.rx_for_hosts.inc();
    host.stats.count_rx();

    if !checksum::is_valid(ip.slice()) {
        stats.rx_bad_checksum.inc();
        return None;
    }
    if ip.is_fragmenting_payload() {
        stats.rx_fragments.inc();
        return None;
    }
    // The IP total length excludes Ethernet padding; `get` also rejects a
    // total length shorter than the header or longer than the frame.
    let Some(body) = packet.get(ip.slice().len()..usize::from(ip.total_len())) else {
        stats.rx_malformed.inc();
        return None;
    };
    if ip.protocol().0 != IP_PROTO_ICMP {
        stats.rx_unhandled.inc();
        host.stats.count_unhandled();
        return None;
    }
    if !icmp::is_echo_request(body) {
        if body.first() == Some(&icmp::TYPE_ECHO_REQUEST) {
            stats.rx_bad_checksum.inc();
        } else {
            stats.rx_unhandled.inc();
            host.stats.count_unhandled();
        }
        return None;
    }

    host.stats.count_reply();
    let tos = packet[1];
    let me = Endpoint { mac: host.mac, ip: host.ip() };
    let peer = Endpoint { mac: src_mac, ip: ip.source_addr() };
    Some(Reply { host: host.clone(), frame: icmp::build_echo_reply(me, peer, tos, body) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hosts::HostSpec;
    use crate::proto::{ethernet_frame, push_ipv4_header};
    use std::net::Ipv4Addr;

    const PEER_MAC: MacAddr = MacAddr([0x5a, 0x11, 0x22, 0x33, 0x44, 0x55]);
    const PEER_IP: Ipv4Addr = Ipv4Addr::new(10, 77, 0, 10);

    fn table() -> (HostTable, Arc<VirtualHost>) {
        let spec = HostSpec {
            name: "alpha".into(),
            addr: "10.77.0.50/24".parse().unwrap(),
            mac: Some("02:4e:4e:00:00:01".parse().unwrap()),
            delay: Duration::ZERO,
            jitter: Duration::ZERO,
        };
        HostTable::default().with_added(spec).unwrap()
    }

    /// "Who has `target`? Tell 10.77.0.10", broadcast by the peer.
    fn arp_request(target: Ipv4Addr) -> Vec<u8> {
        let mut f = ethernet_frame(MacAddr::BROADCAST, PEER_MAC, ETHERTYPE_ARP, 60);
        f.extend_from_slice(&[0, 1, 8, 0, 6, 4, 0, 1]); // Ethernet, IPv4, 6, 4, op=request
        f.extend_from_slice(&PEER_MAC.0);
        f.extend_from_slice(&PEER_IP.octets());
        f.extend_from_slice(&MacAddr::ZERO.0);
        f.extend_from_slice(&target.octets());
        f.resize(60, 0);
        f
    }

    fn echo_request(dst_mac: MacAddr, dst_ip: Ipv4Addr) -> Vec<u8> {
        let mut icmp_bytes = vec![8, 0, 0, 0, 0, 9, 0, 3, b'p', b'i', b'n', b'g'];
        let sum = checksum::internet_checksum(&icmp_bytes);
        icmp_bytes[2..4].copy_from_slice(&sum.to_be_bytes());
        let mut f = ethernet_frame(dst_mac, PEER_MAC, ETHERTYPE_IPV4, 64);
        push_ipv4_header(&mut f, PEER_IP, dst_ip, IP_PROTO_ICMP, 0, icmp_bytes.len());
        f.extend_from_slice(&icmp_bytes);
        f.resize(60, 0); // Ethernet padding after the IP packet must be ignored
        f
    }

    #[test]
    fn answers_arp_for_own_ip_only() {
        let (hosts, alpha) = table();
        let stats = Stats::default();
        let reply = handle_frame(&arp_request(alpha.ip()), &hosts, &stats).unwrap();
        assert_eq!(
            reply.frame,
            arp::build_reply(alpha.mac, alpha.ip(), &Arp::parse(&arp_request(alpha.ip())[14..]).unwrap())
        );
        assert!(handle_frame(&arp_request(Ipv4Addr::new(10, 77, 0, 99)), &hosts, &stats).is_none());
        assert_eq!(stats.rx_arp.get(), 2);
        assert_eq!(stats.rx_for_hosts.get(), 1);
    }

    #[test]
    fn answers_ping_with_echo_reply() {
        let (hosts, alpha) = table();
        let stats = Stats::default();
        let reply = handle_frame(&echo_request(alpha.mac, alpha.ip()), &hosts, &stats).unwrap();
        let ip = Ipv4HeaderSlice::from_slice(&reply.frame[14..]).unwrap();
        assert_eq!((ip.source_addr(), ip.destination_addr()), (alpha.ip(), PEER_IP));
        let body = &reply.frame[34..34 + 12];
        assert_eq!(body[0], icmp::TYPE_ECHO_REPLY);
        assert_eq!(&body[8..], b"ping");
        assert!(checksum::is_valid(body));
        assert_eq!(alpha.stats.replies.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn ignores_ping_sent_to_another_mac() {
        let (hosts, alpha) = table();
        let stats = Stats::default();
        assert!(handle_frame(&echo_request(PEER_MAC, alpha.ip()), &hosts, &stats).is_none());
    }

    #[test]
    fn drops_corrupted_ping_and_counts_it() {
        let (hosts, alpha) = table();
        let stats = Stats::default();
        let mut frame = echo_request(alpha.mac, alpha.ip());
        frame[40] ^= 0xff; // flip a byte inside the ICMP message
        assert!(handle_frame(&frame, &hosts, &stats).is_none());
        assert_eq!(stats.rx_bad_checksum.get(), 1);
    }

    #[test]
    fn counts_conflicting_announcement() {
        let (hosts, alpha) = table();
        let stats = Stats::default();
        // The peer claims alpha's IP with its own MAC.
        let mut f = ethernet_frame(MacAddr::BROADCAST, PEER_MAC, ETHERTYPE_ARP, 60);
        f.extend_from_slice(&[0, 1, 8, 0, 6, 4, 0, 1]);
        f.extend_from_slice(&PEER_MAC.0);
        f.extend_from_slice(&alpha.ip().octets());
        f.extend_from_slice(&[0; 6]);
        f.extend_from_slice(&alpha.ip().octets());
        assert!(handle_frame(&f, &hosts, &stats).is_none());
        assert_eq!(stats.ip_conflicts.get(), 1);
    }

    #[test]
    fn non_ip_traffic_is_counted_and_ignored() {
        let (hosts, _) = table();
        let stats = Stats::default();
        let mut f = ethernet_frame(MacAddr::BROADCAST, PEER_MAC, 0x86dd, 60);
        f.resize(60, 0);
        assert!(handle_frame(&f, &hosts, &stats).is_none());
        assert!(handle_frame(&[0u8; 5], &hosts, &stats).is_none());
        assert_eq!((stats.rx_other.get(), stats.rx_malformed.get()), (1, 1));
    }
}
