//! ICMP echo (ping) for IPv4.
//!
//! An echo message starts with `type, code, checksum (2), identifier (2),
//! sequence (2)` followed by the payload. A reply copies everything after the
//! checksum, changes the type from 8 to 0 and recomputes the checksum.

#![forbid(unsafe_code)]

use std::net::Ipv4Addr;

use super::{ETH_HEADER_LEN, ETHERTYPE_IPV4, IP_PROTO_ICMP, IPV4_HEADER_LEN, checksum};
use super::{ethernet_frame, pad_to_minimum, push_ipv4_header};
use crate::hosts::MacAddr;

pub const TYPE_ECHO_REPLY: u8 = 0;
pub const TYPE_ECHO_REQUEST: u8 = 8;
const ECHO_HEADER_LEN: usize = 8;

/// True when `icmp` (the IP payload) is a well-formed echo request.
pub fn is_echo_request(icmp: &[u8]) -> bool {
    icmp.len() >= ECHO_HEADER_LEN && icmp[0] == TYPE_ECHO_REQUEST && icmp[1] == 0 && checksum::is_valid(icmp)
}

/// Identifier and sequence number of an echo message, for log lines.
pub fn echo_id_seq(icmp: &[u8]) -> Option<(u16, u16)> {
    let h = icmp.get(..ECHO_HEADER_LEN)?;
    Some((u16::from_be_bytes([h[4], h[5]]), u16::from_be_bytes([h[6], h[7]])))
}

/// The addressing of one side of a conversation.
#[derive(Debug, Clone, Copy)]
pub struct Endpoint {
    pub mac: MacAddr,
    pub ip: Ipv4Addr,
}

/// Builds the full Ethernet frame of an echo reply from `host` to `peer`.
/// `request` must have passed [`is_echo_request`].
pub fn build_echo_reply(host: Endpoint, peer: Endpoint, tos: u8, request: &[u8]) -> Vec<u8> {
    let capacity = ETH_HEADER_LEN + IPV4_HEADER_LEN + request.len();
    let mut frame = ethernet_frame(peer.mac, host.mac, ETHERTYPE_IPV4, capacity);
    push_ipv4_header(&mut frame, host.ip, peer.ip, IP_PROTO_ICMP, tos, request.len());

    let icmp_start = frame.len();
    frame.extend_from_slice(&[TYPE_ECHO_REPLY, 0, 0, 0]); // type, code, checksum placeholder
    frame.extend_from_slice(&request[4..]); // identifier, sequence and payload unchanged
    let sum = checksum::internet_checksum(&frame[icmp_start..]);
    frame[icmp_start + 2..icmp_start + 4].copy_from_slice(&sum.to_be_bytes());

    pad_to_minimum(&mut frame);
    frame
}

#[cfg(test)]
mod tests {
    use super::*;
    use etherparse::{Ethernet2HeaderSlice, Ipv4HeaderSlice};

    fn echo_request(payload: &[u8]) -> Vec<u8> {
        let mut icmp = vec![TYPE_ECHO_REQUEST, 0, 0, 0, 0x00, 0x07, 0x00, 0x01];
        icmp.extend_from_slice(payload);
        let sum = checksum::internet_checksum(&icmp);
        icmp[2..4].copy_from_slice(&sum.to_be_bytes());
        icmp
    }

    #[test]
    fn recognises_echo_request() {
        let req = echo_request(b"hello");
        assert!(is_echo_request(&req));
        assert_eq!(echo_id_seq(&req), Some((7, 1)));
        let mut corrupted = req.clone();
        corrupted[9] ^= 0xff;
        assert!(!is_echo_request(&corrupted));
        assert!(!is_echo_request(&req[..4]));
    }

    #[test]
    fn reply_has_valid_headers_and_same_payload() {
        // Odd-length payload exercises the checksum's trailing-byte rule.
        let req = echo_request(b"abcdefghijklmnopqrstuvwxyz0123456789!");
        let host = Endpoint { mac: MacAddr([2, 0x4e, 0x4e, 0, 0, 2]), ip: Ipv4Addr::new(10, 77, 0, 51) };
        let peer =
            Endpoint { mac: MacAddr([0x5a, 0x11, 0x22, 0x33, 0x44, 0x55]), ip: Ipv4Addr::new(10, 77, 0, 10) };
        let frame = build_echo_reply(host, peer, 0, &req);

        let eth = Ethernet2HeaderSlice::from_slice(&frame).unwrap();
        assert_eq!((eth.destination(), eth.source()), (peer.mac.0, host.mac.0));

        let ip = Ipv4HeaderSlice::from_slice(&frame[ETH_HEADER_LEN..]).unwrap();
        assert!(checksum::is_valid(ip.slice()), "IP header checksum");
        assert_eq!((ip.source_addr(), ip.destination_addr()), (host.ip, peer.ip));
        assert_eq!(ip.ttl(), 64);
        assert_eq!(usize::from(ip.total_len()), IPV4_HEADER_LEN + req.len());

        let icmp = &frame[ETH_HEADER_LEN + IPV4_HEADER_LEN..][..req.len()];
        assert!(checksum::is_valid(icmp), "ICMP checksum");
        assert_eq!(icmp[0], TYPE_ECHO_REPLY);
        assert_eq!(&icmp[4..], &req[4..], "identifier, sequence and payload copied");
    }

    #[test]
    fn small_reply_is_padded() {
        let req = echo_request(b"");
        let host = Endpoint { mac: MacAddr([2, 0, 0, 0, 0, 1]), ip: Ipv4Addr::new(10, 0, 0, 1) };
        let peer = Endpoint { mac: MacAddr([2, 0, 0, 0, 0, 2]), ip: Ipv4Addr::new(10, 0, 0, 2) };
        assert_eq!(build_echo_reply(host, peer, 0, &req).len(), 60);
    }
}
