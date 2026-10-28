//! Global counters. Each is a relaxed atomic: one uncontended add per event.

#![forbid(unsafe_code)]

use std::fmt::Write;
use std::sync::atomic::{AtomicU64, Ordering};

/// A monotonically increasing event counter.
#[derive(Default, Debug)]
pub struct Counter(AtomicU64);

impl Counter {
    pub fn inc(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
    fn reset(&self) {
        self.0.store(0, Ordering::Relaxed);
    }
}

/// A value that goes up and down (the TX queue depth).
#[derive(Default, Debug)]
pub struct Gauge(AtomicU64);

impl Gauge {
    pub fn set(&self, value: u64) {
        self.0.store(value, Ordering::Relaxed);
    }
    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

#[derive(Default, Debug)]
pub struct Stats {
    // receive side
    pub rx_frames: Counter,
    pub rx_arp: Counter,
    pub rx_ipv4: Counter,
    pub rx_other: Counter,
    pub rx_for_hosts: Counter,
    pub rx_malformed: Counter,
    pub rx_bad_checksum: Counter,
    pub rx_fragments: Counter,
    pub rx_unhandled: Counter,
    pub rx_errors: Counter,
    pub ip_conflicts: Counter,
    // send side
    pub tx_frames: Counter,
    pub tx_errors: Counter,
    pub tx_queue_full: Counter,
    pub tx_late: Counter,
    pub tx_queued: Gauge,
    // packet log
    pub sniff_dropped: Counter,
}

impl Stats {
    pub fn reset(&self) {
        for counter in self.counters() {
            counter.1.reset();
        }
    }

    /// The `stats` command output.
    pub fn report(&self) -> String {
        let mut out = String::new();
        for (label, counter) in self.counters() {
            let _ = writeln!(out, "  {label:<24} {}", counter.get());
        }
        let _ = writeln!(out, "  {:<24} {}", "tx queue depth", self.tx_queued.get());
        out
    }

    /// Every counter with its label, in display order.
    fn counters(&self) -> [(&'static str, &Counter); 16] {
        [
            ("rx frames", &self.rx_frames),
            ("  arp", &self.rx_arp),
            ("  ipv4", &self.rx_ipv4),
            ("  other ethertype", &self.rx_other),
            ("  for virtual hosts", &self.rx_for_hosts),
            ("rx malformed", &self.rx_malformed),
            ("rx bad checksum", &self.rx_bad_checksum),
            ("rx fragments dropped", &self.rx_fragments),
            ("rx unhandled protocol", &self.rx_unhandled),
            ("rx socket errors", &self.rx_errors),
            ("ip conflicts seen", &self.ip_conflicts),
            ("tx frames", &self.tx_frames),
            ("tx errors", &self.tx_errors),
            ("tx queue full (dropped)", &self.tx_queue_full),
            ("tx late (>1ms)", &self.tx_late),
            ("sniff lines dropped", &self.sniff_dropped),
        ]
    }
}
