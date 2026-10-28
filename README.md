# netnode

netnode makes one Linux machine look like several machines on its Ethernet
segment. It takes over an interface (default `eth1`) and lets you create
**virtual hosts** from a live prompt. Each virtual host has its own IPv4 address,
its own MAC address and its own response delay, so neighbours see separate
machines at different "distances".

```text
netnode> host add alpha --ip 192.168.1.50/24
added alpha 192.168.1.50/24 6a:b9:67:7d:f2:b2 delay=0s
netnode> host add beta --ip 192.168.1.51/24 --delay 40ms --jitter 5ms
added beta 192.168.1.51/24 16:69:f6:4d:8c:56 delay=40ms±5ms
```

From any neighbour, `ping 192.168.1.50` answers in microseconds and
`ping 192.168.1.51` in about 40 ms, and `ip neigh` shows two different MACs.

**What the MVP does:** receives every frame on the interface (promiscuous mode),
answers ARP and ping for its virtual hosts, applies per-host delay and jitter,
and shows live counters and an optional packet log. **What it does not do yet:**
TCP/UDP services, IPv6, VLANs, or blocking traffic meant for the machine itself.
See [AGENTS.md](AGENTS.md) for the roadmap.

---

## Requirements

- Linux, kernel 3.10 or newer, x86_64 or arm64. Any distribution: the release build is a static binary.
- A **wired** Ethernet interface that is up (`ip link set eth1 up`). It does not need an IP address.
- Root, or the capabilities `CAP_NET_RAW` and `CAP_NET_ADMIN`.
- To build: Rust 1.88 or newer (tested with 1.97), or Docker.

## Build

### With Cargo

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh   # install Rust once
cargo build --release
# binary: target/release/netnode
```

### Static binary that runs on any Linux

```bash
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
# binary: target/x86_64-unknown-linux-musl/release/netnode
```

On Debian or Ubuntu, `apt install musl-tools` first if the linker complains.
For arm64 boards and servers, cross-compile with
[cargo-zigbuild](https://github.com/rust-cross/cargo-zigbuild):

```bash
cargo install cargo-zigbuild        # also needs zig installed
rustup target add aarch64-unknown-linux-musl
cargo zigbuild --release --target aarch64-unknown-linux-musl
```

### With Docker

```bash
docker build -t netnode .
```

The image is built `FROM scratch`: it contains only the static binary (about 3 MB).

## Run

```bash
sudo ./netnode --iface eth1
```

To run without `sudo`, grant the capabilities once (repeat after every rebuild):

```bash
sudo setcap cap_net_raw,cap_net_admin=eip ./netnode
./netnode --iface eth1
```

| Flag | Default | Meaning |
| --- | --- | --- |
| `--iface <name>` | `eth1` | Interface to take over |
| `--config <file>` | none | TOML file of hosts to load at startup |
| `--log-level <level>` | `info` | `error`, `warn`, `info`, `debug` or `trace` |

The prompt is interactive. On a remote node, run it inside `tmux` or `screen`
so it survives a dropped SSH session.

### Run with Docker

```bash
docker run --rm -it --network host \
  --cap-add NET_RAW --cap-add NET_ADMIN \
  -v "$PWD:/data" \
  netnode --iface eth1 --config hosts.toml
```

- `--network host` is required, so the container sees the host's real `eth1`.
- `-it` gives you the interactive prompt.
- `-v "$PWD:/data"` lets `load` and `save` use files in your current directory.

## Commands

Type these at the `netnode>` prompt. Every change applies to the next packet,
with no restart. `help` and `help <command>` print full usage.

| Command | What it does |
| --- | --- |
| `host add <name> --ip <ip/prefix> [--mac <mac>] [--delay <dur>] [--jitter <dur>]` | Create a virtual host and announce it with gratuitous ARP |
| `host set <name> [--delay <dur>] [--jitter <dur>]` | Change delay or jitter live |
| `host del <name>` (or `host rm`) | Remove a host |
| `host list` (or `host ls`) | Hosts with address, MAC, delay and counters |
| `stats` / `stats reset` | Global counters / zero them |
| `sniff on [--proto all\|arp\|icmp\|ip] [--host <name>]` | Live one-line-per-frame packet log |
| `sniff off` | Stop the packet log |
| `save <file>` / `load <file>` | Write or read the host table as TOML |
| `iface` | Interface name, MAC, MTU and IPv4 address |
| `quit` (or `exit`, or Ctrl-D) | Exit; promiscuous mode is released automatically |

Durations accept `0`, `500us`, `20ms`, `1s`. The delay applies to everything a
host sends, ARP replies included, so the very first ping to a delayed host
takes about twice the delay (ARP, then the echo) and later pings take the delay.

Rules: names, IPs and MACs must be unique; the interface's own IP is rejected;
MACs must be unicast; delay is at most 10 s; jitter cannot exceed delay.
Generated MACs are random, locally administered addresses, so two nodes
running netnode on one segment will not collide.

## Configuration file

```toml
[[hosts]]
name = "alpha"
ip = "192.168.1.50/24"

[[hosts]]
name = "beta"
ip = "192.168.1.51/24"
mac = "02:4e:4e:00:00:02"   # optional, generated if missing
delay = "40ms"              # optional, default 0
jitter = "5ms"              # optional, default 0
```

See [hosts.example.toml](hosts.example.toml). `save` always writes the MACs,
so a saved table reloads with the same identities.

## Try it on one machine (no real network needed)

`scripts/testbed.sh` creates a virtual cable (veth pair) between netnode and a
"neighbour" network namespace with address `10.77.0.10/24`:

```bash
sudo scripts/testbed.sh up
sudo ./target/release/netnode --iface vn0
```

At the prompt:

```text
host add alpha --ip 10.77.0.50/24
host add beta --ip 10.77.0.51/24 --delay 40ms
```

In a second terminal, act as the neighbour:

```bash
sudo ip netns exec nn-peer ping 10.77.0.50      # ~0.1 ms
sudo ip netns exec nn-peer ping 10.77.0.51      # ~40 ms
sudo ip netns exec nn-peer ip neigh             # two different MACs
```

Remove the lab with `sudo scripts/testbed.sh down`.

You cannot test by pinging the virtual hosts from the netnode machine itself.
netnode only answers frames that arrive from the wire; the machine's own pings
leave through `eth1` and never come back in. Always test from another machine
or namespace.

## Troubleshooting

| Symptom | Likely cause and fix |
| --- | --- |
| `cannot open eth1 (run as root...)` | Missing privileges: use `sudo` or the `setcap` command above |
| `interface eth1 not found` | Wrong name: list interfaces with `ip link` and pass `--iface` |
| Neighbours get no ARP reply | Switch port security limits MACs per port; raise the limit for this port |
| Works on bare metal, not in a VM | The hypervisor drops unknown MACs. Allow promiscuous mode, MAC changes and forged transmits on that vNIC. Public-cloud VPCs do not support this at all |
| Nothing on Wi-Fi | Wi-Fi drivers refuse frames from extra MACs; use a wired port |
| `ip conflicts seen` grows in `stats` | Another machine uses one of your virtual IPs; pick a free address |
| `tx late` grows in `stats` | The machine is CPU-starved; delayed replies left more than 1 ms late |

To confirm promiscuous mode is held and released: `ip -d link show eth1 | grep promiscuity`
shows 1 or more while netnode runs and drops back when it exits.

## Development

```bash
cargo test                          # unit tests (no privileges needed)
cargo clippy --all-targets -- -D warnings
cargo fmt
```

Code layout and design rules for contributors and coding agents are in [AGENTS.md](AGENTS.md).
