//! Wire formats: building and checking the frames netnode sends.
//!
//! Parsing of incoming Ethernet and IPv4 headers uses `etherparse` (in `rx.rs`);
//! the reply builders here are written by hand at fixed byte offsets, which
//! keeps them short, allocation-light and easy to compare with a packet capture.

#![forbid(unsafe_code)]

pub mod arp;
pub mod checksum;
pub mod icmp;

use std::net::Ipv4Addr;

use crate::hosts::MacAddr;

pub const ETH_HEADER_LEN: usize = 14;
pub const IPV4_HEADER_LEN: usize = 20;
pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_ARP: u16 = 0x0806;
pub const IP_PROTO_ICMP: u8 = 1;

/// Smallest Ethernet frame without the 4-byte FCS the NIC appends.
pub const MIN_FRAME_LEN: usize = 60;

/// TTL used for every IP packet a virtual host sends (the Linux default).
pub const DEFAULT_TTL: u8 = 64;

/// Starts a frame with the 14-byte Ethernet header.
pub fn ethernet_frame(dst: MacAddr, src: MacAddr, ethertype: u16, capacity: usize) -> Vec<u8> {
    let mut frame = Vec::with_capacity(capacity.max(MIN_FRAME_LEN));
    frame.extend_from_slice(&dst.0);
    frame.extend_from_slice(&src.0);
    frame.extend_from_slice(&ethertype.to_be_bytes());
    frame
}

/// Pads a frame with zeros up to the Ethernet minimum.
pub fn pad_to_minimum(frame: &mut Vec<u8>) {
    if frame.len() < MIN_FRAME_LEN {
        frame.resize(MIN_FRAME_LEN, 0);
    }
}

/// Appends a 20-byte IPv4 header (no options) with a correct checksum.
pub fn push_ipv4_header(
    frame: &mut Vec<u8>,
    src: Ipv4Addr,
    dst: Ipv4Addr,
    protocol: u8,
    tos: u8,
    payload_len: usize,
) {
    let total_len = (IPV4_HEADER_LEN + payload_len) as u16;
    let identification: u16 = rand::random();
    let start = frame.len();
    frame.extend_from_slice(&[0x45, tos]); // version 4, header length 5 words; DSCP/ECN
    frame.extend_from_slice(&total_len.to_be_bytes());
    frame.extend_from_slice(&identification.to_be_bytes());
    frame.extend_from_slice(&[0x00, 0x00]); // flags and fragment offset: not fragmented
    frame.extend_from_slice(&[DEFAULT_TTL, protocol]);
    frame.extend_from_slice(&[0x00, 0x00]); // checksum placeholder
    frame.extend_from_slice(&src.octets());
    frame.extend_from_slice(&dst.octets());
    let sum = checksum::internet_checksum(&frame[start..]);
    frame[start + 10..start + 12].copy_from_slice(&sum.to_be_bytes());
}
