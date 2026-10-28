# AGENTS.md

Guide for coding agents and contributors working on netnode: what exists, the
rules the design depends on, how to verify a change, and what comes next.
User-facing build and run instructions are in [README.md](README.md).

## Project in one paragraph

netnode is a single Rust binary that opens a raw `AF_PACKET` socket on one
interface in promiscuous mode and impersonates any number of **virtual hosts**,
each with its own IPv4 address, MAC address, delay and jitter. Virtual hosts
answer ARP and ICMP echo. Everything is controlled from an interactive prompt.
Each node runs its own independent instance ("decentralized": no controller).

## Architecture

```text
            frames in                       lookup (ArcSwap load)
  eth1 ───────────────► RX thread ◄──────────────────── Host table ◄── edit + swap ── CLI thread
  (link.rs)  ◄───────── (rx.rs)                                                       (cli.rs)
      ▲    reply, no delay  │ reply + deadline (bounded channel)                          ▲
      │                     ▼                                                             │
      └──────────────── TX thread (tx.rs): min-heap by deadline,       sniff lines ───────┘
          delayed reply  sleep then spin                               (bounded channel)
```

| File | Responsibility |
| --- | --- |
| `src/main.rs` | Flags, opening the link, spawning threads, shutdown |
| `src/link.rs` | Raw socket, promiscuous mode, interface queries, timer slack. **The only `unsafe` code.** |
| `src/hosts.rs` | `MacAddr`, `Ipv4Cidr`, `VirtualHost`, immutable `HostTable` with all validation |
| `src/rx.rs` | Receive loop and `handle_frame` (pure decision logic, unit-tested) |
| `src/tx.rs` | `DelayQueue` and the TX loop; `transmit` used by every sender |
| `src/proto/` | Hand-written ARP and ICMP builders, internet checksum |
| `src/sniff.rs` | Packet-log formatting and filtering |
| `src/stats.rs` | Relaxed atomic counters |
| `src/config.rs` | TOML save/load, duration parsing |
| `src/cli.rs` | Command definitions (clap), command execution, prompt loop |
| `scripts/testbed.sh` | Network-namespace lab for manual and integration testing |

## Rules the design depends on

Keep these true in every change.

1. **`unsafe` lives only in `link.rs`.** The crate root has `#![deny(unsafe_code)]`,
   every other module has `#![forbid(unsafe_code)]`, and `link.rs` requires a
   `// SAFETY:` comment on each block (`clippy::undocumented_unsafe_blocks`).
   New OS calls go into `link.rs` behind a safe function.
2. **The hot path never blocks.** RX and TX take no locks, never wait on the
   CLI and never print. They talk to the rest of the program only through
   `ArcSwap` loads, bounded channels with `try_send`, and relaxed atomics.
   Anything that cannot keep up is dropped and counted, never waited for.
3. **No allocation per received frame.** The RX buffer is reused. Replies
   allocate one `Vec` each; a buffer pool is planned, see below.
4. **The CLI thread is the only writer of the host table.** It builds a new
   `HostTable` (`with_added`, `with_timing`, `with_removed`) and stores it.
   `HostTable` methods never mutate in place.
5. **Validation lives in `hosts.rs`.** CLI, config loading and future APIs all
   go through `HostTable::with_*`, so the rules are enforced once.
6. **Decision logic stays testable without a socket.** `handle_frame` and the
   `proto` builders are pure apart from counters; add tests there first.
7. **Replies are built from the request.** netnode never initiates
   conversations, so it needs no ARP cache. Revisit this rule when TCP arrives.

## How to verify a change

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

Changes to `link.rs`, `rx.rs`, `tx.rs` or `proto/` also need the lab (root required):

```bash
sudo scripts/testbed.sh up
sudo ./target/release/netnode --iface vn0      # add hosts at the prompt
sudo ip netns exec nn-peer ping -c 20 10.77.0.50
sudo scripts/testbed.sh down
```

To drive the prompt from a script, pipe commands into stdin, for example
`printf 'host add a --ip 10.77.0.50\nhost list\nquit\n' | sudo netnode --iface vn0`.
When stdin is not a terminal, packet-log lines go straight to stdout.

## What was done (MVP, 2026-10-28)

All seven milestones from the plan are implemented.

| Milestone | Status | Notes |
| --- | --- | --- |
| M0 toolchain and lab | Done | `scripts/testbed.sh up/down` |
| M1 link and sniffing | Done | `AF_PACKET`, promiscuous via socket membership, `PACKET_IGNORE_OUTGOING` and `PACKET_QDISC_BYPASS` best effort |
| M2 host table and prompt | Done | clap-parsed commands, rustyline prompt with history, `ArcSwap` table |
| M3 ARP responder | Done | Replies, probe defence, two gratuitous ARPs on add, conflict counter |
| M4 ICMP echo | Done | Header and checksum validation, fragments dropped, padding handled |
| M5 delay scheduler | Done | Min-heap, sleep-until-100µs-then-spin, 1 ns timer slack, late counter |
| M6 polish and release | Done | `sniff` filters, `stats`, `save`/`load`, static build, scratch Docker image |

**Verification results** (Ubuntu 24.04, kernel 6.18, 2 vCPU sandbox, veth lab):

- 31 unit tests pass. clippy with `-D warnings` and `rustfmt --check` are clean.
- Two hosts, alpha (no delay) and beta (40 ms): 0% loss, distinct MACs in `ip neigh`.
  alpha RTT 0.13 ms; beta minimum 40.19 ms.
- `host set beta --delay 100ms` during a running ping: RTT changed from 40 ms to 100 ms
  on the next reply with no loss. With `--jitter 10ms`, RTTs spread across 91 to 110 ms.
- Flood test with `sniff on`: 20,000 pings to alpha plus 5,000 to beta (2 ms delay)
  at once: 0% loss, alpha average 0.023 ms, beta average 2.07 ms, and the prompt
  stayed responsive. 8 of 5,000 delayed replies left more than 1 ms late (CPU contention).
- `quit` exits within 100 ms and `promiscuity` returns to 0.
- `save`, restart with `--config`: same names, IPs and MACs restored.
- The scratch-based image ran in the lab with `--network host` and the two capabilities.
  The image was assembled from a locally built static binary because the sandbox could not
  pull `rust:1-alpine`; the Dockerfile's build stage itself has not been run yet.

**Differences from the original spec**

- Generated MACs are random locally administered addresses rather than sequential
  ones, so several netnode instances on one segment do not collide.
- Minimum Rust version is 1.88, not 1.85: a dependency and the `let` chains used in the code need it.
- Promiscuous mode is checked with `ip -d link show <iface>` (`promiscuity N`), not the
  `PROMISC` flag: a socket membership does not set that flag.
- A second gratuitous ARP is sent 1 s after the first.

## Known limitations

- Only ARP and ICMP echo are answered. TCP and UDP to a virtual host are counted as
  `unhandled` and dropped silently, so port scans see every port filtered.
- netnode receives copies of frames; it cannot block or rewrite traffic meant for the
  node's own kernel.
- One syscall per frame. That is fine for control traffic on 1 GbE, not line rate at 10 GbE.
- IPv4 only; 802.1Q-tagged frames are counted as `other ethertype` and ignored.
- Only the interface's primary IPv4 address is checked for conflicts with virtual hosts.
- The prompt must stay attached to a terminal; there is no daemon mode yet.

## What is planned next

In priority order. Each item lists what "done" means.

1. **Run the Docker build stage in CI.** Build the image from the Dockerfile on x86_64
   and arm64 (buildx). Done when both images build and pass the lab test.
2. **Full traffic control with XDP.** An XDP program written with `aya` that drops,
   passes or redirects any frame on the interface, with rules managed from the prompt
   (`rule add drop proto udp port 53`, `rule list`, `rule del`). Done when a rule
   blocks traffic to the node's own kernel stack in the lab.
3. **Realistic hosts.** One `smoltcp` interface per virtual host: TCP resets on closed
   ports, configurable listening ports (`host port add beta tcp/22`), UDP echo; plus
   receive delay, packet loss percentage and bandwidth limits per host.
   This replaces rule 7 above with a real ARP cache.
4. **Throughput.** TPACKET_V3 memory-mapped ring or AF_XDP instead of one `recv` per frame;
   CPU pinning flags for RX and TX; a reply-buffer pool. Done when 1 Mpps of pings is
   answered without loss in a benchmark and `tx late` stays at 0 on pinned cores.
5. **More protocols.** IPv6 with Neighbor Discovery, VLAN-tagged hosts (`--vlan`), DHCP
   for host addresses, and an ARP probe before `host add` to detect conflicts up front.
6. **Decentralized coordination.** A daemon mode with a local control socket
   (`netnode ctl host list`), then discovery between netnode instances on a segment,
   sharing host inventories so no two nodes claim the same IP.
7. **Operations.** Prometheus metrics endpoint, systemd unit, a `--json` output mode
   for commands, persistent prompt history.

## Conventions

- Rust edition 2024, MSRV 1.88. Format with the repository's `rustfmt.toml` (110 columns).
- Errors: `thiserror` enums in modules (`HostError`), `anyhow` with context in `cli.rs`
  and `main.rs`. User-facing messages are one line and say what to do.
- Counters: add a field to `Stats` and a row in `Stats::counters` together.
- New commands: add a variant in `cli.rs`, a doc comment (it becomes the help text),
  a parse test, and a row in the README command table.
- Comments explain why, not what. Every module starts with a `//!` summary.
