//! ARP for IPv4 over Ethernet (RFC 826): parsing requests, building replies
//! and gratuitous announcements.
//!
//! Packet layout (28 bytes after the Ethernet header):
//!
//! ```text
//! 0  hardware type = 1 (Ethernet)   2  protocol type = 0x0800 (IPv4)
//! 4  hw addr len = 6   5  proto addr len = 4   6  operation (1 request, 2 reply)
//! 8  sender MAC (6)   14 sender IP (4)   18 target MAC (6)   24 target IP (4)
//! ```

#![forbid(unsafe_code)]

use std::net::Ipv4Addr;

use super::{ETH_HEADER_LEN, ETHERTYPE_ARP, ETHERTYPE_IPV4, ethernet_frame, pad_to_minimum};
use crate::hosts::MacAddr;

pub const OP_REQUEST: u16 = 1;
pub const OP_REPLY: u16 = 2;
const ARP_LEN: usize = 28;

/// A parsed IPv4-over-Ethernet ARP packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Arp {
    pub op: u16,
    pub sender_mac: MacAddr,
    pub sender_ip: Ipv4Addr,
    pub target_mac: MacAddr,
    pub target_ip: Ipv4Addr,
}

impl Arp {
    /// Parses the ARP payload that follows the Ethernet header.
    /// Returns `None` for anything that is not IPv4-over-Ethernet ARP.
    pub fn parse(payload: &[u8]) -> Option<Arp> {
        let p = payload.get(..ARP_LEN)?;
        let is_ipv4_over_ethernet =
            p[0..2] == [0, 1] && p[2..4] == ETHERTYPE_IPV4.to_be_bytes() && p[4] == 6 && p[5] == 4;
        if !is_ipv4_over_ethernet {
            return None;
        }
        Some(Arp {
            op: u16::from_be_bytes([p[6], p[7]]),
            sender_mac: mac_at(p, 8),
            sender_ip: ip_at(p, 14),
            target_mac: mac_at(p, 18),
            target_ip: ip_at(p, 24),
        })
    }

    /// A host announcing its own address (sender IP == target IP).
    pub fn is_announcement(&self) -> bool {
        self.sender_ip == self.target_ip
    }
}

/// Builds the reply a virtual host sends to an ARP request for its IP.
pub fn build_reply(host_mac: MacAddr, host_ip: Ipv4Addr, request: &Arp) -> Vec<u8> {
    build(
        request.sender_mac,
        host_mac,
        OP_REPLY,
        (host_mac, host_ip),
        (request.sender_mac, request.sender_ip),
    )
}

/// Builds a gratuitous ARP that tells the segment "`ip` is at `mac`".
/// It is a broadcast request whose sender and target IP are both `ip`.
pub fn build_announcement(mac: MacAddr, ip: Ipv4Addr) -> Vec<u8> {
    build(MacAddr::BROADCAST, mac, OP_REQUEST, (mac, ip), (MacAddr::ZERO, ip))
}

fn build(
    eth_dst: MacAddr,
    eth_src: MacAddr,
    op: u16,
    (sender_mac, sender_ip): (MacAddr, Ipv4Addr),
    (target_mac, target_ip): (MacAddr, Ipv4Addr),
) -> Vec<u8> {
    let mut frame = ethernet_frame(eth_dst, eth_src, ETHERTYPE_ARP, ETH_HEADER_LEN + ARP_LEN);
    frame.extend_from_slice(&[0, 1]); // hardware type: Ethernet
    frame.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
    frame.extend_from_slice(&[6, 4]);
    frame.extend_from_slice(&op.to_be_bytes());
    frame.extend_from_slice(&sender_mac.0);
    frame.extend_from_slice(&sender_ip.octets());
    frame.extend_from_slice(&target_mac.0);
    frame.extend_from_slice(&target_ip.octets());
    pad_to_minimum(&mut frame);
    frame
}

fn mac_at(p: &[u8], at: usize) -> MacAddr {
    let mut mac = [0u8; 6];
    mac.copy_from_slice(&p[at..at + 6]);
    MacAddr(mac)
}

fn ip_at(p: &[u8], at: usize) -> Ipv4Addr {
    Ipv4Addr::new(p[at], p[at + 1], p[at + 2], p[at + 3])
}

#[cfg(test)]
mod tests {
    use super::*;

    const PEER_MAC: MacAddr = MacAddr([0x5a, 0x11, 0x22, 0x33, 0x44, 0x55]);
    const HOST_MAC: MacAddr = MacAddr([0x02, 0x4e, 0x4e, 0x00, 0x00, 0x01]);

    /// "Who has 10.77.0.50? Tell 10.77.0.10", as captured from the peer (padded to 60 bytes).
    fn request_frame() -> Vec<u8> {
        let mut f = vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x5a, 0x11, 0x22, 0x33, 0x44, 0x55, 0x08, 0x06, // eth
            0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01, // htype ptype hlen plen op=1
            0x5a, 0x11, 0x22, 0x33, 0x44, 0x55, 10, 77, 0, 10, // sender
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 10, 77, 0, 50, // target
        ];
        f.resize(60, 0);
        f
    }

    #[test]
    fn parses_request() {
        let arp = Arp::parse(&request_frame()[ETH_HEADER_LEN..]).unwrap();
        assert_eq!(arp.op, OP_REQUEST);
        assert_eq!(arp.sender_mac, PEER_MAC);
        assert_eq!(arp.sender_ip, Ipv4Addr::new(10, 77, 0, 10));
        assert_eq!(arp.target_ip, Ipv4Addr::new(10, 77, 0, 50));
        assert!(!arp.is_announcement());
        assert!(Arp::parse(&[0u8; 10]).is_none());
    }

    #[test]
    fn reply_is_byte_exact() {
        let request = Arp::parse(&request_frame()[ETH_HEADER_LEN..]).unwrap();
        let reply = build_reply(HOST_MAC, Ipv4Addr::new(10, 77, 0, 50), &request);
        let mut expected = vec![
            0x5a, 0x11, 0x22, 0x33, 0x44, 0x55, 0x02, 0x4e, 0x4e, 0x00, 0x00, 0x01, 0x08, 0x06, // eth
            0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x02, // op=2
            0x02, 0x4e, 0x4e, 0x00, 0x00, 0x01, 10, 77, 0, 50, // sender = virtual host
            0x5a, 0x11, 0x22, 0x33, 0x44, 0x55, 10, 77, 0, 10, // target = requester
        ];
        expected.resize(60, 0);
        assert_eq!(reply, expected);
    }

    #[test]
    fn announcement_is_broadcast_with_same_ips() {
        let ip = Ipv4Addr::new(10, 77, 0, 51);
        let frame = build_announcement(HOST_MAC, ip);
        assert_eq!(frame.len(), 60);
        assert_eq!(&frame[0..6], &[0xff; 6]);
        let arp = Arp::parse(&frame[ETH_HEADER_LEN..]).unwrap();
        assert_eq!(arp.op, OP_REQUEST);
        assert!(arp.is_announcement());
        assert_eq!((arp.sender_mac, arp.sender_ip), (HOST_MAC, ip));
    }
}
