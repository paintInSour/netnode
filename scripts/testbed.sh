#!/usr/bin/env bash
# Creates (or removes) a two-machine lab on one Linux box:
#
#   [netnode on vn0] ===== veth cable ===== [vn1 in namespace nn-peer, 10.77.0.10/24]
#
# Usage:  sudo scripts/testbed.sh up     # create the lab
#         sudo scripts/testbed.sh down   # remove it
# Then:   sudo ./netnode --iface vn0
#         sudo ip netns exec nn-peer ping 10.77.0.50
set -euo pipefail

NS=nn-peer
case "${1:-up}" in
  up)
    ip netns add "$NS"
    ip link add vn0 type veth peer name vn1      # a virtual cable with two ends
    ip link set vn1 netns "$NS"                  # one end goes to the "neighbour"
    ip link set vn0 up                           # netnode's end needs no IP address
    ip netns exec "$NS" ip addr add 10.77.0.10/24 dev vn1
    ip netns exec "$NS" ip link set vn1 up
    ip netns exec "$NS" ip link set lo up
    echo "lab up: run 'sudo ./netnode --iface vn0', then ping from 'ip netns exec $NS'"
    ;;
  down)
    ip netns del "$NS" 2>/dev/null || true       # deleting the namespace removes both cable ends
    echo "lab removed"
    ;;
  *)
    echo "usage: $0 up|down" >&2
    exit 2
    ;;
esac
