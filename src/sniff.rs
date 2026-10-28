//! The live packet log behind `sniff on` / `sniff off`.
//!
//! The RX and TX threads format one line per matching frame and hand it to
//! the CLI thread through a bounded channel. If the terminal cannot keep up,
//! lines are dropped and counted, so logging never slows down packet handling.

#![forbid(unsafe_code)]

use std::fmt::Write;
use std::net::Ipv4Addr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwapOption;
use crossbeam_channel::Sender;
use etherparse::{Ethernet2HeaderSlice, Ipv4HeaderSlice};

use crate::hosts::MacAddr;
use crate::proto::arp::{Arp, OP_REPLY, OP_REQUEST};
use crate::proto::{ETH_HEADER_LEN, ETHERTYPE_ARP, ETHERTYPE_IPV4, IP_PROTO_ICMP, icmp};
use crate::stats::Stats;

/// Which protocols `sniff on --proto` shows.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum ProtoFilter {
    All,
    Arp,
    Icmp,
    /// Any IPv4 packet.
    Ip,
}

/// What the packet log currently shows.
#[derive(Clone, Debug)]
pub struct SniffFilter {
    pub proto: ProtoFilter,
    /// Only frames to or from this host's IP, when set.
    pub host_ip: Option<Ipv4Addr>,
}

impl SniffFilter {
    fn matches(&self, s: &Summary) -> bool {
        let proto_ok = match self.proto {
            ProtoFilter::All => true,
            ProtoFilter::Arp => s.kind == Kind::Arp,
            ProtoFilter::Icmp => s.kind == Kind::Icmp,
            ProtoFilter::Ip => matches!(s.kind, Kind::Icmp | Kind::OtherIp),
        };
        let host_ok = self.host_ip.is_none_or(|ip| s.ips.contains(&Some(ip)));
        proto_ok && host_ok
    }
}

pub struct Sniffer {
    filter: ArcSwapOption<SniffFilter>,
    out: Sender<String>,
}

impl Sniffer {
    pub fn new(out: Sender<String>) -> Self {
        Self { filter: ArcSwapOption::empty(), out }
    }

    /// `Some` turns the log on with that filter, `None` turns it off.
    pub fn set(&self, filter: Option<SniffFilter>) {
        self.filter.store(filter.map(Into::into));
    }

    /// Logs a received frame.
    pub fn rx(&self, frame: &[u8], stats: &Stats) {
        self.log("rx", frame, None, stats);
    }

    /// Logs a sent frame; `added` is the delay it was held for, if any.
    pub fn tx(&self, frame: &[u8], added: Option<Duration>, stats: &Stats) {
        self.log("tx", frame, added, stats);
    }

    fn log(&self, direction: &str, frame: &[u8], added: Option<Duration>, stats: &Stats) {
        let filter = self.filter.load();
        let Some(filter) = filter.as_ref() else { return }; // log is off: one atomic load
        let Some(summary) = summarize(frame) else { return };
        if !filter.matches(&summary) {
            return;
        }
        let mut line = format!("{} {direction}  {}", utc_clock(), summary.text);
        if let Some(added) = added {
            let _ = write!(line, " (+{:.1}ms)", added.as_secs_f64() * 1000.0);
        }
        if self.out.try_send(line).is_err() {
            stats.sniff_dropped.inc();
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Kind {
    Arp,
    Icmp,
    OtherIp,
    NonIp,
}

/// A one-line description of a frame plus what the filter needs.
struct Summary {
    kind: Kind,
    ips: [Option<Ipv4Addr>; 2],
    text: String,
}

fn summarize(frame: &[u8]) -> Option<Summary> {
    let eth = Ethernet2HeaderSlice::from_slice(frame).ok()?;
    let payload = &frame[ETH_HEADER_LEN..];
    let summary = match eth.ether_type().0 {
        ETHERTYPE_ARP => {
            let arp = Arp::parse(payload)?;
            let text = match arp.op {
                OP_REQUEST if arp.is_announcement() => {
                    format!("arp announce {} is-at {}", arp.sender_ip, arp.sender_mac)
                }
                OP_REQUEST => format!("arp who-has {} tell {}", arp.target_ip, arp.sender_ip),
                OP_REPLY => format!("arp reply {} is-at {}", arp.sender_ip, arp.sender_mac),
                op => format!("arp op={op}"),
            };
            Summary { kind: Kind::Arp, ips: [Some(arp.sender_ip), Some(arp.target_ip)], text }
        }
        ETHERTYPE_IPV4 => {
            let ip = Ipv4HeaderSlice::from_slice(payload).ok()?;
            let (src, dst) = (ip.source_addr(), ip.destination_addr());
            let body = payload.get(ip.slice().len()..).unwrap_or_default();
            let (kind, what) = match ip.protocol().0 {
                IP_PROTO_ICMP => (Kind::Icmp, describe_icmp(body)),
                6 => (Kind::OtherIp, "tcp".to_owned()),
                17 => (Kind::OtherIp, "udp".to_owned()),
                p => (Kind::OtherIp, format!("ip proto {p}")),
            };
            Summary { kind, ips: [Some(src), Some(dst)], text: format!("{src} > {dst} {what}") }
        }
        ethertype => Summary {
            kind: Kind::NonIp,
            ips: [None, None],
            text: format!(
                "ethertype 0x{ethertype:04x} {} > {}",
                MacAddr(eth.source()),
                MacAddr(eth.destination())
            ),
        },
    };
    Some(summary)
}

fn describe_icmp(icmp_bytes: &[u8]) -> String {
    let id_seq = icmp::echo_id_seq(icmp_bytes);
    match (icmp_bytes.first(), id_seq) {
        (Some(&icmp::TYPE_ECHO_REQUEST), Some((id, seq))) => format!("icmp echo id={id} seq={seq}"),
        (Some(&icmp::TYPE_ECHO_REPLY), Some((id, seq))) => format!("icmp reply id={id} seq={seq}"),
        (Some(t), _) => format!("icmp type={t}"),
        (None, _) => "icmp (truncated)".to_owned(),
    }
}

/// Wall-clock time of day in UTC, `HH:MM:SS.mmm`.
fn utc_clock() -> String {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = now.as_secs() % 86_400;
    format!("{:02}:{:02}:{:02}.{:03}", secs / 3600, secs / 60 % 60, secs % 60, now.subsec_millis())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::arp;

    #[test]
    fn summarises_and_filters_arp() {
        let frame = arp::build_announcement(MacAddr([2, 0, 0, 0, 0, 1]), Ipv4Addr::new(10, 0, 0, 5));
        let s = summarize(&frame).unwrap();
        assert_eq!(s.text, "arp announce 10.0.0.5 is-at 02:00:00:00:00:01");
        let arp_only = SniffFilter { proto: ProtoFilter::Arp, host_ip: None };
        let icmp_only = SniffFilter { proto: ProtoFilter::Icmp, host_ip: None };
        let other_host = SniffFilter { proto: ProtoFilter::All, host_ip: Some(Ipv4Addr::new(10, 0, 0, 6)) };
        assert!(arp_only.matches(&s));
        assert!(!icmp_only.matches(&s));
        assert!(!other_host.matches(&s));
    }

    #[test]
    fn full_log_drops_and_counts() {
        let (tx, rx) = crossbeam_channel::bounded(1);
        let sniffer = Sniffer::new(tx);
        let stats = Stats::default();
        let frame = arp::build_announcement(MacAddr([2, 0, 0, 0, 0, 1]), Ipv4Addr::new(10, 0, 0, 5));

        sniffer.rx(&frame, &stats); // off: nothing logged
        assert!(rx.is_empty());

        sniffer.set(Some(SniffFilter { proto: ProtoFilter::All, host_ip: None }));
        sniffer.rx(&frame, &stats);
        sniffer.rx(&frame, &stats); // channel full
        assert_eq!(rx.len(), 1);
        assert_eq!(stats.sniff_dropped.get(), 1);
    }
}
