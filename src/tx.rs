//! The TX thread: holds delayed replies and sends each one at its deadline.
//!
//! Replies wait in a min-heap ordered by deadline. The thread sleeps until
//! shortly before the earliest deadline (or until a new reply arrives), then
//! spins for the last stretch so the frame leaves within microseconds of its
//! deadline instead of whenever the scheduler wakes us.

#![forbid(unsafe_code)]

use std::cmp::Ordering as CmpOrdering;
use std::collections::BinaryHeap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crossbeam_channel::{Receiver, RecvTimeoutError};

use crate::link::{self, Link};
use crate::sniff::Sniffer;
use crate::stats::Stats;

/// Sleep until this long before a deadline, then spin.
const SPIN_WINDOW: Duration = Duration::from_micros(100);
/// Upper bound on any single sleep, so the thread notices shutdown.
const MAX_SLEEP: Duration = link::RECV_TIMEOUT;
/// A frame sent later than this past its deadline counts as late.
const LATE_THRESHOLD: Duration = Duration::from_millis(1);

/// A frame waiting to be sent.
#[derive(Debug)]
pub struct Scheduled {
    pub deadline: Instant,
    /// When the frame that caused this reply arrived; used for the log's `(+40.2ms)`.
    pub rx_at: Option<Instant>,
    pub frame: Vec<u8>,
}

/// Pending frames, earliest deadline first. Frames with equal deadlines
/// leave in the order they were queued.
#[derive(Default)]
pub struct DelayQueue {
    heap: BinaryHeap<Pending>,
    next_seq: u64,
}

struct Pending {
    seq: u64,
    item: Scheduled,
}

impl Pending {
    fn key(&self) -> (Instant, u64) {
        (self.item.deadline, self.seq)
    }
}

// `BinaryHeap` pops the largest element, so the comparison is reversed:
// the earliest deadline is the "largest".
impl Ord for Pending {
    fn cmp(&self, other: &Self) -> CmpOrdering {
        other.key().cmp(&self.key())
    }
}
impl PartialOrd for Pending {
    fn partial_cmp(&self, other: &Self) -> Option<CmpOrdering> {
        Some(self.cmp(other))
    }
}
impl PartialEq for Pending {
    fn eq(&self, other: &Self) -> bool {
        self.key() == other.key()
    }
}
impl Eq for Pending {}

impl DelayQueue {
    pub fn push(&mut self, item: Scheduled) {
        self.heap.push(Pending { seq: self.next_seq, item });
        self.next_seq += 1;
    }

    /// Removes and returns the earliest frame if its deadline has passed.
    pub fn pop_due(&mut self, now: Instant) -> Option<Scheduled> {
        if self.heap.peek()?.item.deadline <= now { self.heap.pop().map(|p| p.item) } else { None }
    }

    pub fn next_deadline(&self) -> Option<Instant> {
        self.heap.peek().map(|p| p.item.deadline)
    }

    pub fn len(&self) -> usize {
        self.heap.len()
    }
}

pub struct TxThread {
    pub link: Arc<Link>,
    pub stats: Arc<Stats>,
    pub sniffer: Arc<Sniffer>,
    pub from_rx: Receiver<Scheduled>,
    pub stop: Arc<AtomicBool>,
}

impl TxThread {
    pub fn run(self) {
        if let Err(err) = link::minimise_timer_slack() {
            tracing::warn!(%err, "could not reduce timer slack; delays may be ~50µs late");
        }
        let mut queue = DelayQueue::default();
        while !self.stop.load(Ordering::Relaxed) {
            while let Some(item) = queue.pop_due(Instant::now()) {
                self.send(item);
            }
            self.stats.tx_queued.set(queue.len() as u64);

            match queue.next_deadline() {
                Some(deadline) => self.wait_until(deadline, &mut queue),
                None => match self.from_rx.recv_timeout(MAX_SLEEP) {
                    Ok(item) => queue.push(item),
                    Err(RecvTimeoutError::Timeout) => {}
                    Err(RecvTimeoutError::Disconnected) => break,
                },
            }
        }
    }

    /// Waits until `deadline` or until a new frame arrives, whichever is first.
    fn wait_until(&self, deadline: Instant, queue: &mut DelayQueue) {
        let now = Instant::now();
        let spin_from = deadline.checked_sub(SPIN_WINDOW).unwrap_or(deadline);
        if now < spin_from {
            // Sleep, but wake for new frames and at least every MAX_SLEEP.
            let wake = spin_from.min(now + MAX_SLEEP);
            if let Ok(item) = self.from_rx.recv_deadline(wake) {
                queue.push(item);
            }
            return; // the caller re-plans: a new frame may have an earlier deadline
        }
        // Final approach: spin, still accepting new frames.
        while Instant::now() < deadline {
            if let Ok(item) = self.from_rx.try_recv() {
                queue.push(item);
                return;
            }
            std::hint::spin_loop();
        }
    }

    fn send(&self, item: Scheduled) {
        let now = Instant::now();
        if now.saturating_duration_since(item.deadline) > LATE_THRESHOLD {
            self.stats.tx_late.inc();
        }
        let added = item.rx_at.map(|rx_at| now.saturating_duration_since(rx_at));
        transmit(&self.link, &item.frame, added, &self.stats, &self.sniffer);
    }
}

/// Sends one frame and records the outcome. Used by the TX thread, the RX
/// fast path and the CLI (gratuitous ARP).
pub fn transmit(link: &Link, frame: &[u8], added: Option<Duration>, stats: &Stats, sniffer: &Sniffer) {
    match link.send(frame) {
        Ok(()) => {
            stats.tx_frames.inc();
            sniffer.tx(frame, added, stats);
        }
        Err(err) => {
            stats.tx_errors.inc();
            tracing::debug!(%err, "send failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(deadline: Instant, tag: u8) -> Scheduled {
        Scheduled { deadline, rx_at: None, frame: vec![tag] }
    }

    #[test]
    fn pops_in_deadline_order_then_fifo() {
        let t0 = Instant::now();
        let mut q = DelayQueue::default();
        q.push(item(t0 + Duration::from_millis(30), 3));
        q.push(item(t0 + Duration::from_millis(10), 1));
        q.push(item(t0 + Duration::from_millis(20), 2));
        q.push(item(t0 + Duration::from_millis(20), 22)); // same deadline, queued later
        assert_eq!(q.next_deadline(), Some(t0 + Duration::from_millis(10)));

        assert!(q.pop_due(t0).is_none(), "nothing is due yet");
        let later = t0 + Duration::from_millis(25);
        let popped: Vec<u8> = std::iter::from_fn(|| q.pop_due(later)).map(|s| s.frame[0]).collect();
        assert_eq!(popped, vec![1, 2, 22]);
        assert_eq!(q.len(), 1);
    }
}
