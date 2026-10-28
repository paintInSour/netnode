//! netnode: impersonate several hosts, each with its own IP, MAC and delay,
//! on one Ethernet interface, controlled from a live prompt.
//!
//! Threads:
//! - RX  (`rx.rs`)  receives every frame and builds replies for virtual hosts
//! - TX  (`tx.rs`)  sends delayed replies at their deadline
//! - CLI (`cli.rs`) runs the prompt and swaps in new host tables
//!
//! Only `link.rs` may contain `unsafe` code; the lint below rejects it anywhere else.

#![deny(unsafe_code)]

mod cli;
mod config;
mod hosts;
mod link;
mod proto;
mod rx;
mod sniff;
mod stats;
mod tx;

use std::io;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

use anyhow::Result;
use arc_swap::ArcSwap;
use clap::Parser;
use tracing_subscriber::EnvFilter;

use crate::hosts::{HostTable, SharedHosts};
use crate::link::Link;
use crate::rx::RxThread;
use crate::sniff::Sniffer;
use crate::stats::Stats;
use crate::tx::TxThread;

/// Replies waiting for their delay. When full, new replies are dropped and counted.
const TX_QUEUE_CAPACITY: usize = 65_536;
/// Packet-log lines waiting to be printed. When full, lines are dropped and counted.
const LOG_QUEUE_CAPACITY: usize = 1_024;

/// Host several virtual IP/MAC endpoints with configurable delays on one Ethernet port.
#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// Interface to take over
    #[arg(long, default_value = "eth1")]
    iface: String,
    /// TOML file of hosts to load at startup
    #[arg(long)]
    config: Option<PathBuf>,
    /// error, warn, info, debug or trace
    #[arg(long, default_value = "info")]
    log_level: String,
}

fn main() -> ExitCode {
    let args = Args::parse();
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_new(&args.log_level).unwrap_or_else(|_| EnvFilter::new("info")))
        .with_writer(io::stderr)
        .without_time()
        .init();

    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("netnode: {err:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: &Args) -> Result<()> {
    let link = Arc::new(Link::open(&args.iface).map_err(|err| open_error(&args.iface, err))?);
    let hosts: SharedHosts = Arc::new(ArcSwap::from_pointee(HostTable::default()));
    let stats = Arc::new(Stats::default());
    let stop = Arc::new(AtomicBool::new(false));
    let (log_sender, log_lines) = crossbeam_channel::bounded(LOG_QUEUE_CAPACITY);
    let sniffer = Arc::new(Sniffer::new(log_sender));
    let (to_tx, from_rx) = crossbeam_channel::bounded(TX_QUEUE_CAPACITY);

    let rx = RxThread {
        link: link.clone(),
        hosts: hosts.clone(),
        stats: stats.clone(),
        sniffer: sniffer.clone(),
        to_tx: to_tx.clone(),
        stop: stop.clone(),
    };
    let tx = TxThread {
        link: link.clone(),
        stats: stats.clone(),
        sniffer: sniffer.clone(),
        from_rx,
        stop: stop.clone(),
    };
    let rx_handle = thread::Builder::new().name("rx".into()).spawn(move || rx.run())?;
    let tx_handle = thread::Builder::new().name("tx".into()).spawn(move || tx.run())?;

    let ctx = cli::Context { link, hosts, stats, sniffer, to_tx };
    if let Some(path) = &args.config {
        ctx.load_file(path)?;
    }
    let result = cli::run(&ctx, log_lines);

    // Both threads wake at least every 100 ms and see the flag.
    stop.store(true, Ordering::Relaxed);
    let _ = rx_handle.join();
    let _ = tx_handle.join();
    result
}

/// Turns the most common startup failures into an actionable message.
fn open_error(iface: &str, err: io::Error) -> anyhow::Error {
    let hint = match err.kind() {
        io::ErrorKind::PermissionDenied => {
            "run as root, or once: sudo setcap cap_net_raw,cap_net_admin=eip ./netnode"
        }
        io::ErrorKind::NotFound => "list interfaces with `ip link` and pass one with --iface",
        _ => "check that the interface exists and is up",
    };
    anyhow::Error::new(err).context(format!("cannot open {iface} ({hint})"))
}
