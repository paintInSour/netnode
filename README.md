# netnode

netnode makes one Linux machine look like several machines on its Ethernet
segment. It takes over an interface (default `eth1`) and lets you create
**virtual hosts** from a live prompt. Each virtual host has its own IPv4 address,
its own MAC address and its own response delay, so neighbours see separate
machines at different "distances".

```text
netnode(eth1)> host add alpha --ip 192.168.1.50/24
added alpha 192.168.1.50/24 6a:b9:67:7d:f2:b2 delay=0s
netnode(eth1)> host add beta --ip 192.168.1.51/24 --delay 40ms --jitter 5ms
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
| `--wait <duration>` | `60s` | How long to wait for the interface to appear; `0` fails at once |
| `--control <path>` | `/tmp/netnode-<iface>.sock` | Control socket used by `netnode ctl` |
| `--log-level <level>` | `info` | `error`, `warn`, `info`, `debug` or `trace` |

### With or without a terminal

- **Started from a terminal:** you get the `netnode(eth1)>` prompt. `quit` or Ctrl-D stops netnode.
- **Started without a terminal** (a container without `-it`, a service, `nohup`):
  netnode runs headless until it receives SIGTERM or SIGINT, or a `shutdown` command.
  Commands piped into stdin are still run; end of input does not stop it.

### Controlling a running netnode: `netnode ctl`

Every netnode listens on a local control socket. `netnode ctl` connects to it,
from another terminal or with `docker exec`:

```bash
sudo netnode ctl host list                                      # one command
sudo netnode ctl host add beta --ip 192.168.1.51/24 --delay 40ms
sudo netnode ctl                                                # interactive prompt
```

| `ctl` option | Default | Meaning |
| --- | --- | --- |
| `--iface <name>` | `eth1` | Which netnode to talk to (picks the default socket path) |
| `--control <path>` | `/tmp/netnode-<iface>.sock` | Socket path, if netnode was started with `--control` |
| `--wait <duration>` | `10s` | How long to wait for netnode to start listening |

`ctl` options go before the command. A one-shot command exits with status 1
if it failed, so it can be used in scripts. In a `ctl` session, `quit` leaves the
session and `shutdown` stops netnode. The packet log (`sniff on`) is printed by
the netnode process itself, so in a container read it with `docker logs -f`.
The socket is accessible to its owner only, so run `ctl` as the same user as netnode.

On a remote machine, either keep the prompt in `tmux`/`screen`, or start netnode
headless (`nohup sudo netnode --iface eth1 </dev/null &`) and use `netnode ctl`.

### Run with Docker

Interactive:

```bash
docker run --rm -it --network host \
  --cap-add NET_RAW --cap-add NET_ADMIN \
  -v "$PWD:/data" \
  netnode --iface eth1 --config hosts.toml
```

In the background:

```bash
docker run -d --name netnode --network host --cap-add NET_RAW --cap-add NET_ADMIN netnode --iface eth1
docker exec -it netnode /netnode ctl        # prompt
docker logs -f netnode                      # output and packet log
docker stop netnode                         # clean shutdown
```

- `--network host` gives the container the host's real `eth1`. Leave it out when
  another tool (such as containerlab) plugs `eth1` into the container itself.
- `-v "$PWD:/data"` lets `load`, `save` and `--config` use files in your current directory.
- The image has no shell; run `/netnode ctl` with `docker exec` directly, as above.

## Containerlab

Containerlab starts each container first and adds its `eth1` a moment later,
without a terminal. netnode waits for `eth1` (up to `--wait`, default 60 s) and
runs headless, so a node needs no special setup. A complete example is in
[examples/containerlab](examples/containerlab):

```yaml
name: lab1
topology:
  nodes:
    h1:
      kind: linux
      image: alpine:3.20
      exec:
        - ip addr add 10.77.0.10/24 dev eth1
    h3:
      kind: linux
      image: netnode:latest
      cap-add: [NET_RAW, NET_ADMIN]
      binds:
        - hosts.toml:/data/hosts.toml:ro
      cmd: --iface eth1 --config /data/hosts.toml
  links:
    - endpoints: ["h1:eth1", "h3:eth1"]
```

```bash
docker build -t netnode:latest .                       # from the repository root
cd examples/containerlab && sudo containerlab deploy -t lab1.clab.yml
docker exec -it clab-lab1-h3 /netnode ctl              # live prompt inside netnode
docker exec clab-lab1-h1 ping -c 3 10.77.0.51          # ~40 ms
docker logs -f clab-lab1-h3                            # netnode output and packet log
```

Notes:

- `cmd` replaces the image's default arguments, so always include `--iface`.
- Without a config file, add hosts after deploy: `docker exec clab-lab1-h3 /netnode ctl host add ...`.
  A topology `exec:` entry works too, because `ctl` waits up to 10 s for netnode to start listening.
- After a container restart, containerlab does not re-create `eth1`. netnode then
  waits 60 s, exits with an error, and Docker restarts it; it recovers once the link is back.

`scripts/container-test.sh` reproduces this start-then-link sequence with plain
Docker, for testing images without containerlab.

## Commands

Type these at the `netnode(eth1)>` prompt or pass them to `netnode ctl`. Every
change applies to the next packet, with no restart. `help` and
`help <command>` print full usage.

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
| `quit` (or `exit`, or Ctrl-D) | Leave the prompt. At netnode's own prompt this stops netnode; in a `ctl` session it only ends the session |
| `shutdown` | Stop netnode from any prompt or `ctl`; promiscuous mode is released automatically |

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
| `cannot open eth1 (run as root...)` | Missing privileges: use `sudo` or the `setcap` command above; in Docker add `--cap-add NET_RAW --cap-add NET_ADMIN` |
| `eth1 ... did not appear within 1m` | Wrong name (list with `ip link`, pass `--iface`), or the link was never created; raise `--wait` if your lab is slow to cable |
| `netnode ctl`: `cannot connect` | netnode is not running, or uses a different `--iface`/`--control`; run `ctl` as the same user (often root) |
| `another netnode is already listening` | Two instances on one interface; stop one, or give each its own `--control` path |
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
