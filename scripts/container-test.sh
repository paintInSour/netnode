#!/usr/bin/env bash
# Deploys netnode the way containerlab does, without needing containerlab:
# containers start first (no terminal), and the eth1 link is added afterwards.
#
#   peer (10.77.0.10) eth1 <==== veth ====> eth1 netnode
#
# Usage:  sudo scripts/container-test.sh [netnode-image] [peer-image]
# Needs:  docker, iproute2, nsenter. Cleans up with: docker rm -f nn-peer nn-node
set -euo pipefail

IMAGE=${1:-netnode:latest}
PEER_IMAGE=${2:-alpine:3.20}
pid() { docker inspect -f '{{.State.Pid}}' "$1"; }

docker rm -f nn-peer nn-node >/dev/null 2>&1 || true
docker run -d --name nn-node --cap-add NET_RAW --cap-add NET_ADMIN "$IMAGE" --iface eth1 >/dev/null
docker run -d --name nn-peer --cap-add NET_ADMIN "$PEER_IMAGE" sleep infinity >/dev/null

sleep 3 # containerlab also adds links only after the containers are running
if [ "$(pid nn-node)" = "0" ]; then
  echo "FAIL: netnode exited before its link was added"; docker logs nn-node; exit 1
fi
ip link add nn-a type veth peer name nn-b
ip link set nn-a netns "$(pid nn-peer)"
ip link set nn-b netns "$(pid nn-node)"
nsenter -t "$(pid nn-peer)" -n ip link set nn-a name eth1
nsenter -t "$(pid nn-node)" -n ip link set nn-b name eth1
nsenter -t "$(pid nn-peer)" -n ip link set eth1 up
nsenter -t "$(pid nn-node)" -n ip link set eth1 up
docker exec nn-peer ip addr add 10.77.0.10/24 dev eth1

docker exec nn-node /netnode ctl host add alpha --ip 10.77.0.50/24
docker exec nn-node /netnode ctl host add beta --ip 10.77.0.51/24 --delay 40ms
docker exec nn-peer ping -c 3 10.77.0.50
docker exec nn-peer ping -c 3 10.77.0.51
docker exec nn-node /netnode ctl host list

docker stop nn-node >/dev/null
echo "PASS (netnode exit code $(docker inspect -f '{{.State.ExitCode}}' nn-node))"
docker rm -f nn-peer nn-node >/dev/null
