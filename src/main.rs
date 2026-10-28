//! netnode: impersonate several hosts, each with its own IP, MAC and delay,
//! on one Ethernet interface, controlled from a live prompt.
//!
//! Threads:
//! - RX  (`rx.rs`)  receives every frame and builds replies for virtual hosts
//! - TX  (`tx.rs`)  sends delayed replies at their deadline
//! - prompt or stdin reader (`cli.rs`) and control sessions (`control.rs`) run commands
//! - main waits for the stop flag, then shuts everything down
//!
//! Only `link.rs` may contain `unsafe` code; the lint below rejects it anywhere else.

#![deny(unsafe_code)]

mod cli;
mod config;
mod control;
mod hosts;
mod link;
mod proto;
mod rx;
mod sniff;
mod stats;
mod tx;

use std::io::{self, IsTerminal};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::Result;
use arc_swap::ArcSwap;
use clap::{Args, Parser, Subcommand};
use signal_hook::consts::{SIGINT, SIGTERM};
use tracing_subscriber::EnvFilter;

use crate::config::parse_duration;
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
/// How often the main thread checks the stop flag.
const STOP_POLL: Duration = Duration::from_millis(50);

/// Host several virtual IP/MAC endpoints with configurable delays on one Ethernet port.
#[derive(Parser, Debug)]
#[command(version, about, args_conflicts_with_subcommands = true)]
struct Cli {
    #[command(subcommand)]
    mode: Option<Mode>,
    #[command(flatten)]
    run: RunArgs,
}

#[derive(Subcommand, Debug)]
enum Mode {
    /// Send commands to a running netnode (e.g. `netnode ctl host list`); no command opens a prompt
    Ctl(CtlArgs),
}

#[derive(Args, Debug)]
struct RunArgs {
    /// Interface to take over
    #[arg(long, default_value = "eth1")]
    iface: String,
    /// TOML file of hosts to load at startup
    #[arg(long)]
    config: Option<PathBuf>,
    /// How long to wait for the interface to appear (containers often add it after start); 0 = fail at once
    #[arg(long, default_value = "60s", value_parser = parse_duration)]
    wait: Duration,
    /// Control socket path [default: /tmp/netnode-<iface>.sock]
    #[arg(long)]
    control: Option<PathBuf>,
    /// error, warn, info, debug or trace
    #[arg(long, default_value = "info")]
    log_level: String,
}

#[derive(Args, Debug)]
struct CtlArgs {
    /// Interface of the netnode to talk to (selects the default socket path)
    #[arg(long, default_value = "eth1")]
    iface: String,
    /// Control socket path [default: /tmp/netnode-<iface>.sock]
    #[arg(long)]
    control: Option<PathBuf>,
    /// How long to wait for netnode to start listening
    #[arg(long, default_value = "10s", value_parser = parse_duration)]
    wait: Duration,
    /// The command to run, e.g. `host add beta --ip 10.0.0.51/24 --delay 40ms`
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    command: Vec<String>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.mode {
        Some(Mode::Ctl(args)) => {
            let path = args.control.unwrap_or_else(|| control::default_socket_path(&args.iface));
            control::client(&path, args.wait, &args.command)
        }
        None => {
            init_logging(&cli.run.log_level);
            run(&cli.run).map(|()| ExitCode::SUCCESS)
        }
    };
    result.unwrap_or_else(|err| {
        eprintln!("netnode: {err:#}");
        ExitCode::FAILURE
    })
}

fn init_logging(level: &str) {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_new(level).unwrap_or_else(|_| EnvFilter::new("info")))
        .with_writer(io::stderr)
        .without_time()
        .init();
}

fn run(args: &RunArgs) -> Result<()> {
    // SIGTERM (docker stop, containerlab destroy) and SIGINT stop netnode cleanly.
    let stop = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(SIGTERM, stop.clone())?;
    signal_hook::flag::register(SIGINT, stop.clone())?;

    let Some(link) = wait_for_link(&args.iface, args.wait, &stop)? else {
        return Ok(()); // stopped while waiting
    };
    let link = Arc::new(link);
    let hosts: SharedHosts = Arc::new(ArcSwap::from_pointee(HostTable::default()));
    let stats = Arc::new(Stats::default());
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

    let ctx = Arc::new(cli::Context {
        link: link.clone(),
        hosts,
        stats,
        sniffer,
        to_tx,
        stop: stop.clone(),
        command_lock: Mutex::new(()),
    });

    let socket = args.control.clone().unwrap_or_else(|| control::default_socket_path(&args.iface));
    let _control = control::start(&socket, ctx.clone())?; // removes the socket file when dropped

    let info = link.info();
    println!(
        "netnode on {} ({}, mtu {}); control socket {}",
        info.name,
        info.mac,
        info.mtu,
        socket.display()
    );
    if let Some(path) = &args.config {
        let mut out = String::new();
        ctx.load_file(path, &mut out)?;
        print!("{out}");
    }

    if io::stdin().is_terminal() {
        println!("Type `help` for commands.");
        cli::spawn_terminal_prompt(ctx.clone(), log_lines)?;
    } else {
        let hint = match &args.control {
            Some(path) => format!("netnode ctl --control {}", path.display()),
            None => format!("netnode ctl --iface {}", args.iface),
        };
        cli::spawn_plain_log_printer(log_lines)?;
        cli::spawn_stdin_reader(ctx.clone(), hint)?;
    }

    while !stop.load(Ordering::Relaxed) {
        thread::sleep(STOP_POLL);
    }
    println!("netnode stopping");
    // RX and TX wake at least every 100 ms and see the flag.
    let _ = rx_handle.join();
    let _ = tx_handle.join();
    Ok(())
}

/// Opens the interface, waiting up to `wait` for it to appear.
///
/// Container tools such as containerlab start the container first and add
/// its data interfaces (eth1, eth2, ...) a moment later.
/// Returns `Ok(None)` if netnode was asked to stop while waiting.
fn wait_for_link(iface: &str, wait: Duration, stop: &AtomicBool) -> Result<Option<Link>> {
    let deadline = Instant::now() + wait;
    let mut told_user = false;
    loop {
        match Link::open(iface) {
            Ok(link) => return Ok(Some(link)),
            Err(err) if err.kind() == io::ErrorKind::NotFound && Instant::now() < deadline => {
                if !told_user {
                    println!(
                        "waiting up to {} for interface {iface} to appear",
                        humantime::format_duration(wait)
                    );
                    told_user = true;
                }
                if stop.load(Ordering::Relaxed) {
                    return Ok(None);
                }
                thread::sleep(Duration::from_millis(200));
            }
            Err(err) => return Err(open_error(iface, wait, err)),
        }
    }
}

/// Turns the most common startup failures into an actionable message.
fn open_error(iface: &str, wait: Duration, err: io::Error) -> anyhow::Error {
    let hint = match err.kind() {
        io::ErrorKind::PermissionDenied => {
            "run as root, or once: sudo setcap cap_net_raw,cap_net_admin=eip ./netnode; \
             in Docker add --cap-add NET_RAW --cap-add NET_ADMIN"
                .to_owned()
        }
        io::ErrorKind::NotFound if !wait.is_zero() => format!(
            "it did not appear within {}; list interfaces with `ip link` and pass one with --iface",
            humantime::format_duration(wait)
        ),
        io::ErrorKind::NotFound => "list interfaces with `ip link` and pass one with --iface".to_owned(),
        _ => "check that the interface exists".to_owned(),
    };
    anyhow::Error::new(err).context(format!("cannot open {iface} ({hint})"))
}
