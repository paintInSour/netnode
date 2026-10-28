//! Saving and loading the host table as TOML.
//!
//! ```toml
//! [[hosts]]
//! name = "beta"
//! ip = "192.168.1.51/24"
//! mac = "02:4e:4e:00:00:02"   # optional; generated when missing
//! delay = "40ms"              # optional, default 0
//! jitter = "5ms"              # optional, default 0
//! ```

#![forbid(unsafe_code)]

use std::fs;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::hosts::{HostSpec, HostTable};

#[derive(Serialize, Deserialize, Default)]
struct ConfigFile {
    #[serde(default)]
    hosts: Vec<HostEntry>,
}

#[derive(Serialize, Deserialize)]
struct HostEntry {
    name: String,
    ip: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mac: Option<String>,
    #[serde(default = "zero")]
    delay: String,
    #[serde(default = "zero")]
    jitter: String,
}

fn zero() -> String {
    "0s".to_owned()
}

/// Reads host definitions from `path`. Validation happens when they are added.
pub fn load(path: &Path) -> Result<Vec<HostSpec>> {
    let text = fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))?;
    let file: ConfigFile =
        toml::from_str(&text).with_context(|| format!("invalid TOML in {}", path.display()))?;
    file.hosts
        .into_iter()
        .map(|entry| {
            let name = entry.name.clone();
            to_spec(entry).with_context(|| format!("host {name:?} in {}", path.display()))
        })
        .collect()
}

/// Writes every host in `table` to `path`, including its MAC so it stays stable.
pub fn save(path: &Path, table: &HostTable) -> Result<()> {
    let file = ConfigFile {
        hosts: table
            .iter()
            .map(|h| HostEntry {
                name: h.name.clone(),
                ip: h.addr.to_string(),
                mac: Some(h.mac.to_string()),
                delay: humantime::format_duration(h.delay).to_string(),
                jitter: humantime::format_duration(h.jitter).to_string(),
            })
            .collect(),
    };
    let text = toml::to_string_pretty(&file)?;
    fs::write(path, text).with_context(|| format!("cannot write {}", path.display()))
}

fn to_spec(entry: HostEntry) -> Result<HostSpec> {
    Ok(HostSpec {
        addr: entry.ip.parse().map_err(anyhow::Error::msg)?,
        mac: entry.mac.as_deref().map(str::parse).transpose().map_err(anyhow::Error::msg)?,
        delay: parse_duration(&entry.delay)?,
        jitter: parse_duration(&entry.jitter)?,
        name: entry.name,
    })
}

/// Parses `0`, `500us`, `20ms`, `1s`, `1s 500ms`.
pub fn parse_duration(s: &str) -> Result<Duration> {
    if s.trim() == "0" {
        return Ok(Duration::ZERO);
    }
    humantime::parse_duration(s)
        .with_context(|| format!("invalid duration {s:?} (examples: 0, 500us, 20ms, 1s)"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn save_then_load_round_trip() {
        let spec = HostSpec {
            name: "beta".into(),
            addr: "10.77.0.51/24".parse().unwrap(),
            mac: Some("02:4e:4e:00:00:02".parse().unwrap()),
            delay: Duration::from_millis(40),
            jitter: Duration::from_millis(5),
        };
        let (table, _) = HostTable::default().with_added(spec).unwrap();
        let path = std::env::temp_dir().join(format!("netnode-test-{}.toml", std::process::id()));
        save(&path, &table).unwrap();
        let loaded = load(&path).unwrap();
        fs::remove_file(&path).ok();

        assert_eq!(loaded.len(), 1);
        let h = &loaded[0];
        assert_eq!(h.name, "beta");
        assert_eq!(h.addr.to_string(), "10.77.0.51/24");
        assert_eq!(h.mac.unwrap().to_string(), "02:4e:4e:00:00:02");
        assert_eq!((h.delay, h.jitter), (Duration::from_millis(40), Duration::from_millis(5)));
    }

    #[test]
    fn minimal_entry_uses_defaults() {
        let file: ConfigFile = toml::from_str("[[hosts]]\nname = \"a\"\nip = \"10.0.0.5\"\n").unwrap();
        let spec = to_spec(file.hosts.into_iter().next().unwrap()).unwrap();
        assert_eq!(spec.addr.prefix, 24);
        assert!(spec.mac.is_none() && spec.delay.is_zero() && spec.jitter.is_zero());
    }

    #[test]
    fn durations() {
        assert_eq!(parse_duration("0").unwrap(), Duration::ZERO);
        assert_eq!(parse_duration("500us").unwrap(), Duration::from_micros(500));
        assert_eq!(parse_duration("40ms").unwrap(), Duration::from_millis(40));
        assert!(parse_duration("fast").is_err());
    }
}
