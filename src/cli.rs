//! Commands: parsing a line, running it, and the local prompt.
//!
//! Commands come from three places: the interactive prompt (when stdin is a
//! terminal), stdin lines (when it is a pipe), and `netnode ctl` sessions over
//! the control socket (`control.rs`). All of them call [`Context::run_line`],
//! which runs one command at a time and returns the text to show.
//!
//! The packet path never waits for commands: a command builds a new host table
//! and swaps it in, and the RX thread picks it up on the next frame.

#![forbid(unsafe_code)]

use std::fmt::Write as _;
use std::io::{self, BufRead};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
use crossbeam_channel::{Receiver, Sender};
use rustyline::error::ReadlineError;
use rustyline::{DefaultEditor, ExternalPrinter};

use crate::config::{self, parse_duration};
use crate::hosts::{HostSpec, Ipv4Cidr, MacAddr, SharedHosts, VirtualHost};
use crate::link::Link;
use crate::proto::arp;
use crate::sniff::{ProtoFilter, SniffFilter, Sniffer};
use crate::stats::Stats;
use crate::tx::{self, Scheduled};

/// The second gratuitous ARP follows the first after this long.
const REANNOUNCE_AFTER: Duration = Duration::from_secs(1);

// ---------------------------------------------------------------------------
// Command definitions (clap parses each line into these)
// ---------------------------------------------------------------------------

#[derive(Parser, Debug)]
#[command(
    name = "netnode",
    no_binary_name = true,
    disable_version_flag = true,
    override_usage = "<command> [arguments]   (try: help host add)"
)]
struct Line {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Add, change, remove or list virtual hosts
    #[command(subcommand)]
    Host(HostCommand),
    /// Show counters (`stats reset` zeroes them)
    Stats {
        #[arg(value_enum)]
        action: Option<StatsAction>,
    },
    /// Turn the live packet log on or off (printed by the netnode process)
    #[command(subcommand)]
    Sniff(SniffCommand),
    /// Save all hosts to a TOML file
    Save { path: PathBuf },
    /// Add the hosts defined in a TOML file
    Load { path: PathBuf },
    /// Show the interface name, MAC, MTU and IPv4 address
    Iface,
    /// Leave this prompt (at netnode's own prompt this also stops netnode)
    #[command(alias = "exit")]
    Quit,
    /// Stop netnode, from any prompt or `netnode ctl`
    Shutdown,
}

#[derive(Subcommand, Debug)]
pub enum HostCommand {
    /// Create a virtual host and announce it with a gratuitous ARP
    Add {
        name: String,
        /// Address with prefix, e.g. 192.168.1.50/24 (prefix defaults to 24)
        #[arg(long)]
        ip: Ipv4Cidr,
        /// MAC address; a random locally administered one if omitted
        #[arg(long)]
        mac: Option<MacAddr>,
        /// Added to every frame this host sends, e.g. 40ms
        #[arg(long, default_value = "0", value_parser = parse_duration)]
        delay: Duration,
        /// Random variation of the delay, ± this much
        #[arg(long, default_value = "0", value_parser = parse_duration)]
        jitter: Duration,
    },
    /// Change a host's delay or jitter
    Set {
        name: String,
        #[arg(long, value_parser = parse_duration)]
        delay: Option<Duration>,
        #[arg(long, value_parser = parse_duration)]
        jitter: Option<Duration>,
    },
    /// Remove a host
    #[command(alias = "rm")]
    Del { name: String },
    /// List hosts with their counters
    #[command(alias = "ls")]
    List,
}

#[derive(Subcommand, Debug)]
pub enum SniffCommand {
    /// Print one line per matching frame
    On {
        #[arg(long, value_enum, default_value_t = ProtoFilter::All)]
        proto: ProtoFilter,
        /// Only frames to or from this virtual host
        #[arg(long)]
        host: Option<String>,
    },
    /// Stop the packet log
    Off,
}

#[derive(ValueEnum, Clone, Copy, Debug)]
pub enum StatsAction {
    Reset,
}

/// Parses one line. `Err` holds text to show the user (an error or help).
fn parse(line: &str) -> Result<Command, String> {
    let words = shlex::split(line).ok_or_else(|| "error: unbalanced quotes".to_owned())?;
    Line::try_parse_from(words).map(|l| l.command).map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// Running commands
// ---------------------------------------------------------------------------

/// What should happen after a command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    /// Keep reading commands.
    Continue,
    /// `quit`: end this prompt or `ctl` session.
    EndSession,
    /// `shutdown`: stop netnode.
    Shutdown,
}

/// Everything commands need. Shared by the local prompt and control sessions.
pub struct Context {
    pub link: Arc<Link>,
    pub hosts: SharedHosts,
    pub stats: Arc<Stats>,
    pub sniffer: Arc<Sniffer>,
    pub to_tx: Sender<Scheduled>,
    /// Set to stop netnode; `main` waits on it.
    pub stop: Arc<AtomicBool>,
    /// Commands run one at a time, so each one sees and replaces the newest
    /// host table. The packet path never takes this lock.
    pub command_lock: Mutex<()>,
}

impl Context {
    /// Parses and runs one line, returning the text to show and what to do next.
    pub fn run_line(&self, line: &str) -> (String, Flow) {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            return (String::new(), Flow::Continue);
        }
        let command = match parse(line) {
            Ok(command) => command,
            Err(message) => return (ensure_newline(message), Flow::Continue),
        };
        let _one_at_a_time = self.command_lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut out = String::new();
        let flow = match self.execute(command, &mut out) {
            Ok(flow) => flow,
            Err(err) => {
                let _ = writeln!(out, "error: {err:#}");
                Flow::Continue
            }
        };
        if flow == Flow::Shutdown {
            self.stop.store(true, Ordering::Relaxed);
        }
        (out, flow)
    }

    fn execute(&self, command: Command, out: &mut String) -> Result<Flow> {
        match command {
            Command::Host(HostCommand::Add { name, ip, mac, delay, jitter }) => {
                self.add_host(HostSpec { name, addr: ip, mac, delay, jitter }, out)?;
            }
            Command::Host(HostCommand::Set { name, delay, jitter }) => {
                self.set_host(&name, delay, jitter, out)?
            }
            Command::Host(HostCommand::Del { name }) => self.delete_host(&name, out)?,
            Command::Host(HostCommand::List) => out.push_str(&self.host_list()),
            Command::Stats { action: Some(StatsAction::Reset) } => {
                self.stats.reset();
                out.push_str("counters reset\n");
            }
            Command::Stats { action: None } => out.push_str(&self.stats.report()),
            Command::Sniff(SniffCommand::On { proto, host }) => self.sniff_on(proto, host, out)?,
            Command::Sniff(SniffCommand::Off) => {
                self.sniffer.set(None);
                out.push_str("packet log off\n");
            }
            Command::Save { path } => {
                config::save(&path, &self.hosts.load())?;
                let _ = writeln!(out, "saved {} hosts to {}", self.hosts.load().len(), path.display());
            }
            Command::Load { path } => self.load_file(&path, out)?,
            Command::Iface => out.push_str(&self.iface_report()),
            Command::Quit => return Ok(Flow::EndSession),
            Command::Shutdown => {
                out.push_str("netnode is shutting down\n");
                return Ok(Flow::Shutdown);
            }
        }
        Ok(Flow::Continue)
    }

    fn add_host(&self, spec: HostSpec, out: &mut String) -> Result<Arc<VirtualHost>> {
        self.check_against_interface(spec.addr, out)?;
        let (table, host) = self.hosts.load().with_added(spec)?;
        self.hosts.store(Arc::new(table));
        self.announce(&host);
        let _ = writeln!(out, "added {} {} {} delay={}", host.name, host.addr, host.mac, timing(&host));
        Ok(host)
    }

    fn set_host(
        &self,
        name: &str,
        delay: Option<Duration>,
        jitter: Option<Duration>,
        out: &mut String,
    ) -> Result<()> {
        if delay.is_none() && jitter.is_none() {
            bail!("nothing to change: give --delay and/or --jitter");
        }
        let (table, host) = self.hosts.load().with_timing(name, delay, jitter)?;
        self.hosts.store(Arc::new(table));
        let _ = writeln!(out, "updated {} delay={}", host.name, timing(&host));
        Ok(())
    }

    fn delete_host(&self, name: &str, out: &mut String) -> Result<()> {
        let (table, host) = self.hosts.load().with_removed(name)?;
        self.hosts.store(Arc::new(table));
        let _ = writeln!(out, "removed {} ({})", host.name, host.addr.ip);
        Ok(())
    }

    /// Adds every host in a TOML file, reporting each failure and carrying on.
    pub fn load_file(&self, path: &Path, out: &mut String) -> Result<()> {
        let specs = config::load(path)?;
        let total = specs.len();
        let mut added = 0;
        for spec in specs {
            let name = spec.name.clone();
            match self.add_host(spec, out) {
                Ok(_) => added += 1,
                Err(err) => {
                    let _ = writeln!(out, "skipped {name}: {err:#}");
                }
            }
        }
        let _ = writeln!(out, "loaded {added} of {total} hosts from {}", path.display());
        Ok(())
    }

    fn sniff_on(&self, proto: ProtoFilter, host: Option<String>, out: &mut String) -> Result<()> {
        let host_ip = match &host {
            Some(name) => match self.hosts.load().by_name(name) {
                Some(h) => Some(h.addr.ip),
                None => bail!("no host named {name:?}"),
            },
            None => None,
        };
        self.sniffer.set(Some(SniffFilter { proto, host_ip }));
        let scope = host.map(|h| format!(" for {h}")).unwrap_or_default();
        let _ = writeln!(out, "packet log on ({proto:?}{scope}); `sniff off` to stop");
        Ok(())
    }

    /// Rejects the interface's own IP and warns about addresses outside its subnet.
    fn check_against_interface(&self, addr: Ipv4Cidr, out: &mut String) -> Result<()> {
        let Some((own_ip, prefix)) = self.link.ipv4() else { return Ok(()) };
        let iface = &self.link.info().name;
        if own_ip == addr.ip {
            bail!("{own_ip} is {iface}'s own address");
        }
        let subnet = Ipv4Cidr { ip: own_ip, prefix };
        if !subnet.contains(addr.ip) {
            let _ = writeln!(
                out,
                "warning: {} is outside {iface}'s subnet {subnet}; neighbours may not reach it",
                addr.ip
            );
        }
        Ok(())
    }

    /// Sends a gratuitous ARP now and again shortly after, so switches and
    /// neighbours learn the new MAC immediately.
    fn announce(&self, host: &VirtualHost) {
        let frame = arp::build_announcement(host.mac, host.ip());
        tx::transmit(&self.link, &frame, None, &self.stats, &self.sniffer);
        let again = Scheduled { deadline: Instant::now() + REANNOUNCE_AFTER, rx_at: None, frame };
        let _ = self.to_tx.try_send(again);
    }

    fn host_list(&self) -> String {
        let hosts = self.hosts.load();
        if hosts.is_empty() {
            return "no hosts; add one with `host add <name> --ip <addr/prefix>`\n".to_owned();
        }
        let mut out = format!(
            "{:<12} {:<18} {:<17} {:<14} {:>8} {:>8} {:>9}\n",
            "NAME", "ADDRESS", "MAC", "DELAY", "RX", "REPLIES", "UNHANDLED"
        );
        let load = |c: &AtomicU64| c.load(Ordering::Relaxed);
        for h in hosts.iter() {
            let _ = writeln!(
                out,
                "{:<12} {:<18} {:<17} {:<14} {:>8} {:>8} {:>9}",
                h.name,
                h.addr.to_string(),
                h.mac.to_string(),
                timing(h),
                load(&h.stats.rx_frames),
                load(&h.stats.replies),
                load(&h.stats.unhandled)
            );
        }
        out
    }

    fn iface_report(&self) -> String {
        let info = self.link.info();
        let ipv4 = match self.link.ipv4() {
            Some((ip, prefix)) => format!("{ip}/{prefix}"),
            None => "none".to_owned(),
        };
        format!(
            "  interface   {} (index {})\n  mac         {}\n  mtu         {}\n  ipv4        {ipv4}\n  promiscuous on (held by this process)\n  hosts       {}\n",
            info.name,
            info.index,
            info.mac,
            info.mtu,
            self.hosts.load().len()
        )
    }
}

/// `40ms±5ms`, `40ms` or `0s`.
fn timing(host: &VirtualHost) -> String {
    let delay = humantime::format_duration(host.delay);
    if host.jitter.is_zero() {
        delay.to_string()
    } else {
        format!("{delay}±{}", humantime::format_duration(host.jitter))
    }
}

pub fn ensure_newline(mut s: String) -> String {
    if !s.is_empty() && !s.ends_with('\n') {
        s.push('\n');
    }
    s
}

// ---------------------------------------------------------------------------
// Local input: an interactive prompt on a terminal, or plain lines from a pipe
// ---------------------------------------------------------------------------

/// Interactive prompt on a terminal. `quit`, `shutdown` and Ctrl-D stop netnode.
/// Packet-log lines are printed above the prompt without disturbing typing.
pub fn spawn_terminal_prompt(ctx: Arc<Context>, log_lines: Receiver<String>) -> Result<()> {
    let mut editor = DefaultEditor::new()?;
    match editor.create_external_printer() {
        Ok(mut printer) => {
            thread::Builder::new().name("log-printer".into()).spawn(move || {
                for line in log_lines {
                    if printer.print(ensure_newline(line)).is_err() {
                        break;
                    }
                }
            })?;
        }
        Err(_) => spawn_plain_log_printer(log_lines)?,
    }

    let prompt = format!("netnode({})> ", ctx.link.info().name);
    thread::Builder::new().name("prompt".into()).spawn(move || {
        loop {
            match editor.readline(&prompt) {
                Ok(line) => {
                    let _ = editor.add_history_entry(line.trim());
                    let (out, flow) = ctx.run_line(&line);
                    print!("{out}");
                    if flow != Flow::Continue {
                        break;
                    }
                }
                Err(ReadlineError::Interrupted) => println!("(type `quit` or press Ctrl-D to exit)"),
                Err(_) => break, // Ctrl-D or a terminal error
            }
        }
        ctx.stop.store(true, Ordering::Relaxed);
    })?;
    Ok(())
}

/// Reads commands from a non-terminal stdin (a pipe or `/dev/null`).
///
/// `quit` and `shutdown` stop netnode. End of input does **not**: netnode keeps
/// running headless and is controlled with `netnode ctl`. This is what makes
/// it work in containers started without `-it`, such as containerlab nodes.
pub fn spawn_stdin_reader(ctx: Arc<Context>, control_hint: String) -> Result<()> {
    thread::Builder::new().name("stdin".into()).spawn(move || {
        for line in io::stdin().lock().lines() {
            let Ok(line) = line else { break };
            let (out, flow) = ctx.run_line(&line);
            print!("{out}");
            if flow != Flow::Continue {
                ctx.stop.store(true, Ordering::Relaxed);
                return;
            }
        }
        println!("no terminal on stdin; running headless. Control it with: {control_hint}");
    })?;
    Ok(())
}

/// Prints packet-log lines as they come (used when there is no terminal).
pub fn spawn_plain_log_printer(log_lines: Receiver<String>) -> Result<()> {
    thread::Builder::new().name("log-printer".into()).spawn(move || {
        for line in log_lines {
            println!("{line}");
        }
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_host_add_with_defaults() {
        let Command::Host(HostCommand::Add { name, ip, mac, delay, jitter }) =
            parse("host add beta --ip 10.77.0.51/24 --delay 40ms --jitter 5ms").unwrap()
        else {
            panic!("wrong command")
        };
        assert_eq!((name.as_str(), ip.to_string()), ("beta", "10.77.0.51/24".to_owned()));
        assert!(mac.is_none());
        assert_eq!((delay, jitter), (Duration::from_millis(40), Duration::from_millis(5)));

        let Command::Host(HostCommand::Add { delay, .. }) = parse("host add a --ip 10.0.0.1").unwrap() else {
            panic!("wrong command")
        };
        assert!(delay.is_zero());
    }

    #[test]
    fn parses_other_commands_and_aliases() {
        assert!(matches!(parse("host ls"), Ok(Command::Host(HostCommand::List))));
        assert!(matches!(parse("exit"), Ok(Command::Quit)));
        assert!(matches!(parse("shutdown"), Ok(Command::Shutdown)));
        assert!(matches!(parse("stats reset"), Ok(Command::Stats { action: Some(StatsAction::Reset) })));
        assert!(matches!(
            parse("sniff on --proto icmp --host beta"),
            Ok(Command::Sniff(SniffCommand::On { proto: ProtoFilter::Icmp, host: Some(_) }))
        ));
    }

    #[test]
    fn reports_bad_input() {
        assert!(parse("host add x --ip 300.1.1.1").unwrap_err().contains("invalid IPv4"));
        assert!(parse("host add x --ip 10.0.0.1 --delay soon").unwrap_err().contains("invalid duration"));
        assert!(parse("frobnicate").is_err());
        assert!(parse("host add 'x").unwrap_err().contains("unbalanced"));
    }
}
