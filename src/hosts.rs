//! Virtual hosts and the shared table that the RX thread reads on every frame.
//!
//! The table is immutable once built. The CLI thread changes it by building a
//! new table and swapping it in through `ArcSwap`, so the RX thread never
//! waits on a lock. There is exactly one writer (the CLI thread).

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use thiserror::Error;

/// The longest delay a host may have.
pub const MAX_DELAY: Duration = Duration::from_secs(10);

/// The host table shared between the CLI (writer) and RX thread (reader).
pub type SharedHosts = Arc<ArcSwap<HostTable>>;

// ---------------------------------------------------------------------------
// MAC address
// ---------------------------------------------------------------------------

/// A 48-bit Ethernet MAC address.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    pub const BROADCAST: MacAddr = MacAddr([0xff; 6]);
    pub const ZERO: MacAddr = MacAddr([0; 6]);

    /// A random unicast, locally administered address (first byte `x2`, `x6`,
    /// `xA` or `xE`). These never collide with vendor-assigned hardware MACs.
    pub fn random_local() -> Self {
        let mut bytes = [0u8; 6];
        rand::fill(&mut bytes);
        bytes[0] = (bytes[0] & 0b1111_1100) | 0b0000_0010;
        MacAddr(bytes)
    }

    /// Unicast addresses have the lowest bit of the first byte cleared.
    pub fn is_unicast(&self) -> bool {
        self.0[0] & 1 == 0
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = self.0;
        write!(f, "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", b[0], b[1], b[2], b[3], b[4], b[5])
    }
}

impl FromStr for MacAddr {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split([':', '-']).collect();
        if parts.len() != 6 {
            return Err(format!("invalid MAC address {s:?} (expected aa:bb:cc:dd:ee:ff)"));
        }
        let mut bytes = [0u8; 6];
        for (byte, part) in bytes.iter_mut().zip(parts) {
            *byte = u8::from_str_radix(part, 16).map_err(|_| format!("invalid MAC address {s:?}"))?;
        }
        Ok(MacAddr(bytes))
    }
}

// ---------------------------------------------------------------------------
// IPv4 address with prefix
// ---------------------------------------------------------------------------

/// An IPv4 address with its prefix length, written `192.168.1.50/24`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Ipv4Cidr {
    pub ip: Ipv4Addr,
    pub prefix: u8,
}

impl Ipv4Cidr {
    /// True when `other` is in the same subnet as this address.
    pub fn contains(&self, other: Ipv4Addr) -> bool {
        let mask = if self.prefix == 0 { 0 } else { u32::MAX << (32 - u32::from(self.prefix)) };
        u32::from(self.ip) & mask == u32::from(other) & mask
    }
}

impl fmt::Display for Ipv4Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.ip, self.prefix)
    }
}

impl FromStr for Ipv4Cidr {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (ip, prefix) = s.split_once('/').unwrap_or((s, "24"));
        let ip: Ipv4Addr = ip.parse().map_err(|_| format!("invalid IPv4 address {ip:?}"))?;
        let prefix: u8 = prefix
            .parse()
            .ok()
            .filter(|p| *p <= 32)
            .ok_or_else(|| format!("invalid prefix length {prefix:?} (0-32)"))?;
        Ok(Ipv4Cidr { ip, prefix })
    }
}

// ---------------------------------------------------------------------------
// Virtual host
// ---------------------------------------------------------------------------

/// Per-host counters. Shared across `host set`, so counts survive a delay change.
#[derive(Default, Debug)]
pub struct HostStats {
    /// Frames addressed to this host (ARP requests for its IP, IP packets to it).
    pub rx_frames: AtomicU64,
    /// Replies this host produced (ARP and ICMP).
    pub replies: AtomicU64,
    /// IP packets to this host that the MVP does not handle (TCP, UDP, ...).
    pub unhandled: AtomicU64,
}

impl HostStats {
    pub fn count_rx(&self) {
        self.rx_frames.fetch_add(1, Ordering::Relaxed);
    }
    pub fn count_reply(&self) {
        self.replies.fetch_add(1, Ordering::Relaxed);
    }
    pub fn count_unhandled(&self) {
        self.unhandled.fetch_add(1, Ordering::Relaxed);
    }
}

/// Everything needed to create a host, as typed on the CLI or read from TOML.
#[derive(Clone, Debug)]
pub struct HostSpec {
    pub name: String,
    pub addr: Ipv4Cidr,
    pub mac: Option<MacAddr>,
    pub delay: Duration,
    pub jitter: Duration,
}

/// One impersonated machine: its own IP, its own MAC and its own delay.
#[derive(Debug)]
pub struct VirtualHost {
    pub name: String,
    pub addr: Ipv4Cidr,
    pub mac: MacAddr,
    pub delay: Duration,
    pub jitter: Duration,
    pub stats: Arc<HostStats>,
}

impl VirtualHost {
    pub fn ip(&self) -> Ipv4Addr {
        self.addr.ip
    }

    /// When a reply to a frame received at `rx_at` should leave.
    /// `None` means "send immediately" (no delay and no jitter configured).
    pub fn reply_deadline(&self, rx_at: Instant) -> Option<Instant> {
        if self.delay.is_zero() && self.jitter.is_zero() {
            return None;
        }
        Some(rx_at + sample_delay(self.delay, self.jitter))
    }
}

/// `delay` plus a uniform random offset in `[-jitter, +jitter]`, never negative.
pub fn sample_delay(delay: Duration, jitter: Duration) -> Duration {
    if jitter.is_zero() {
        return delay;
    }
    let jitter_ns = jitter.as_nanos() as i128;
    let offset_ns = rand::random_range(-jitter_ns..=jitter_ns);
    let total_ns = (delay.as_nanos() as i128 + offset_ns).max(0);
    Duration::from_nanos(total_ns as u64)
}

// ---------------------------------------------------------------------------
// Host table
// ---------------------------------------------------------------------------

#[derive(Debug, Error, PartialEq, Eq)]
pub enum HostError {
    #[error("host name must be 1-32 characters of letters, digits, '-' or '_'")]
    BadName,
    #[error("a host named {0:?} already exists")]
    NameTaken(String),
    #[error("IP {0} is already used by host {1:?}")]
    IpTaken(Ipv4Addr, String),
    #[error("MAC {0} is already used by host {1:?}")]
    MacTaken(MacAddr, String),
    #[error("MAC {0} is not a unicast address")]
    MacNotUnicast(MacAddr),
    #[error("{0} cannot be used as a host address")]
    BadIp(Ipv4Addr),
    #[error("no host named {0:?}")]
    NotFound(String),
    #[error("delay must be at most {}", humantime::format_duration(MAX_DELAY))]
    DelayTooLong,
    #[error("jitter ({}) cannot exceed delay ({})", humantime::format_duration(*.jitter), humantime::format_duration(*.delay))]
    JitterTooLarge { delay: Duration, jitter: Duration },
}

/// Delay and jitter rules shared by `host add`, `host set` and `load`.
pub fn validate_timing(delay: Duration, jitter: Duration) -> Result<(), HostError> {
    if delay > MAX_DELAY {
        return Err(HostError::DelayTooLong);
    }
    if jitter > delay {
        return Err(HostError::JitterTooLarge { delay, jitter });
    }
    Ok(())
}

/// All virtual hosts, indexed for the hot path (by IP) and the CLI (by name).
#[derive(Default, Clone, Debug)]
pub struct HostTable {
    by_ip: HashMap<Ipv4Addr, Arc<VirtualHost>>,
    by_name: BTreeMap<String, Arc<VirtualHost>>,
}

impl HostTable {
    /// Hot-path lookup used for every received frame.
    pub fn by_ip(&self, ip: Ipv4Addr) -> Option<&Arc<VirtualHost>> {
        self.by_ip.get(&ip)
    }

    pub fn by_name(&self, name: &str) -> Option<&Arc<VirtualHost>> {
        self.by_name.get(name)
    }

    /// Hosts sorted by name.
    pub fn iter(&self) -> impl Iterator<Item = &Arc<VirtualHost>> {
        self.by_name.values()
    }

    pub fn len(&self) -> usize {
        self.by_name.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_name.is_empty()
    }

    /// Returns a new table with `spec` added, after checking every uniqueness rule.
    pub fn with_added(&self, spec: HostSpec) -> Result<(HostTable, Arc<VirtualHost>), HostError> {
        validate_name(&spec.name)?;
        validate_timing(spec.delay, spec.jitter)?;
        let ip = spec.addr.ip;
        if ip.is_unspecified() || ip.is_broadcast() || ip.is_multicast() || ip.is_loopback() {
            return Err(HostError::BadIp(ip));
        }
        if self.by_name.contains_key(&spec.name) {
            return Err(HostError::NameTaken(spec.name));
        }
        if let Some(other) = self.by_ip.get(&ip) {
            return Err(HostError::IpTaken(ip, other.name.clone()));
        }
        let mac = match spec.mac {
            Some(mac) => {
                if !mac.is_unicast() || mac == MacAddr::ZERO {
                    return Err(HostError::MacNotUnicast(mac));
                }
                if let Some(other) = self.iter().find(|h| h.mac == mac) {
                    return Err(HostError::MacTaken(mac, other.name.clone()));
                }
                mac
            }
            None => self.unused_random_mac(),
        };

        let host = Arc::new(VirtualHost {
            name: spec.name,
            addr: spec.addr,
            mac,
            delay: spec.delay,
            jitter: spec.jitter,
            stats: Arc::default(),
        });
        let mut table = self.clone();
        table.insert(host.clone());
        Ok((table, host))
    }

    /// Returns a new table with the named host's delay and/or jitter changed.
    pub fn with_timing(
        &self,
        name: &str,
        delay: Option<Duration>,
        jitter: Option<Duration>,
    ) -> Result<(HostTable, Arc<VirtualHost>), HostError> {
        let old = self.by_name(name).ok_or_else(|| HostError::NotFound(name.to_owned()))?;
        let delay = delay.unwrap_or(old.delay);
        let jitter = jitter.unwrap_or(old.jitter);
        validate_timing(delay, jitter)?;

        let host = Arc::new(VirtualHost {
            name: old.name.clone(),
            addr: old.addr,
            mac: old.mac,
            delay,
            jitter,
            stats: old.stats.clone(), // counters carry over
        });
        let mut table = self.clone();
        table.insert(host.clone());
        Ok((table, host))
    }

    /// Returns a new table without the named host.
    pub fn with_removed(&self, name: &str) -> Result<(HostTable, Arc<VirtualHost>), HostError> {
        let host = self.by_name(name).ok_or_else(|| HostError::NotFound(name.to_owned()))?.clone();
        let mut table = self.clone();
        table.by_name.remove(name);
        table.by_ip.remove(&host.ip());
        Ok((table, host))
    }

    fn insert(&mut self, host: Arc<VirtualHost>) {
        self.by_ip.insert(host.ip(), host.clone());
        self.by_name.insert(host.name.clone(), host);
    }

    fn unused_random_mac(&self) -> MacAddr {
        loop {
            let mac = MacAddr::random_local();
            if self.iter().all(|h| h.mac != mac) {
                return mac;
            }
        }
    }
}

fn validate_name(name: &str) -> Result<(), HostError> {
    let ok = (1..=32).contains(&name.len())
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if ok { Ok(()) } else { Err(HostError::BadName) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(name: &str, ip: &str) -> HostSpec {
        HostSpec {
            name: name.into(),
            addr: ip.parse().unwrap(),
            mac: None,
            delay: Duration::ZERO,
            jitter: Duration::ZERO,
        }
    }

    #[test]
    fn mac_round_trip_and_random_is_local_unicast() {
        let mac: MacAddr = "02:4E:4e:00:00:01".parse().unwrap();
        assert_eq!(mac.to_string(), "02:4e:4e:00:00:01");
        assert!("02:4e:4e:00:00".parse::<MacAddr>().is_err());
        for _ in 0..100 {
            let m = MacAddr::random_local();
            assert!(m.is_unicast());
            assert_eq!(m.0[0] & 0b10, 0b10, "locally administered bit set");
        }
    }

    #[test]
    fn cidr_parsing_and_subnet() {
        let c: Ipv4Cidr = "10.77.0.50/24".parse().unwrap();
        assert!(c.contains("10.77.0.1".parse().unwrap()));
        assert!(!c.contains("10.78.0.1".parse().unwrap()));
        assert_eq!("10.0.0.1".parse::<Ipv4Cidr>().unwrap().prefix, 24);
        assert!("10.0.0.1/33".parse::<Ipv4Cidr>().is_err());
    }

    #[test]
    fn add_rejects_duplicates() {
        let (t, a) = HostTable::default().with_added(spec("alpha", "10.0.0.50/24")).unwrap();
        assert_eq!(
            t.with_added(spec("alpha", "10.0.0.51/24")).unwrap_err(),
            HostError::NameTaken("alpha".into())
        );
        assert!(matches!(t.with_added(spec("beta", "10.0.0.50/24")), Err(HostError::IpTaken(..))));
        let mut same_mac = spec("beta", "10.0.0.51/24");
        same_mac.mac = Some(a.mac);
        assert!(matches!(t.with_added(same_mac), Err(HostError::MacTaken(..))));
    }

    #[test]
    fn add_rejects_bad_input() {
        let t = HostTable::default();
        assert_eq!(t.with_added(spec("bad name", "10.0.0.5/24")).unwrap_err(), HostError::BadName);
        assert!(matches!(t.with_added(spec("x", "255.255.255.255/24")), Err(HostError::BadIp(_))));
        let mut multicast = spec("x", "10.0.0.5/24");
        multicast.mac = Some("01:00:5e:00:00:01".parse().unwrap());
        assert!(matches!(t.with_added(multicast), Err(HostError::MacNotUnicast(_))));
        let mut slow = spec("x", "10.0.0.5/24");
        slow.delay = Duration::from_secs(11);
        assert_eq!(t.with_added(slow).unwrap_err(), HostError::DelayTooLong);
    }

    #[test]
    fn timing_rules() {
        assert!(validate_timing(Duration::from_millis(40), Duration::from_millis(5)).is_ok());
        assert!(validate_timing(Duration::from_millis(4), Duration::from_millis(5)).is_err());
    }

    #[test]
    fn set_keeps_identity_and_counters() {
        let (t, a) = HostTable::default().with_added(spec("alpha", "10.0.0.50/24")).unwrap();
        a.stats.count_rx();
        let (t, a2) = t.with_timing("alpha", Some(Duration::from_millis(40)), None).unwrap();
        assert_eq!(a2.mac, a.mac);
        assert_eq!(a2.delay, Duration::from_millis(40));
        assert_eq!(a2.stats.rx_frames.load(Ordering::Relaxed), 1);
        assert!(Arc::ptr_eq(t.by_ip(a.ip()).unwrap(), &a2));
    }

    #[test]
    fn remove_clears_both_indexes() {
        let (t, a) = HostTable::default().with_added(spec("alpha", "10.0.0.50/24")).unwrap();
        let (t, _) = t.with_removed("alpha").unwrap();
        assert!(t.by_ip(a.ip()).is_none() && t.by_name("alpha").is_none() && t.is_empty());
    }

    #[test]
    fn jitter_stays_in_bounds() {
        let (d, j) = (Duration::from_millis(40), Duration::from_millis(5));
        for _ in 0..1000 {
            let s = sample_delay(d, j);
            assert!(s >= d - j && s <= d + j);
        }
        assert_eq!(sample_delay(d, Duration::ZERO), d);
    }
}
