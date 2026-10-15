#!/bin/bash
# SPDX-License-Identifier: MIT
#
# Copyright (C) 2026 christarcher. All Rights Reserved.
#
# End-to-end test of ws-wireguard-go between two network namespaces:
#
#   ┌───────────── $nss ─────────────┐        ┌───────────── $nsc ─────────────┐
#   │ $wgs: 10.77.0.1/24             │        │ $wgc: 10.77.0.2/24             │
#   │ veth-s: 192.168.77.1/32 ───────┼─ veth ─┼─ veth-c: 192.168.77.2/32       │
#   │   route 192.168.77.2 dev veth-s│        │   default dev veth-c           │
#   └────────────────────────────────┘        └────────────────────────────────┘
#
# The server only accepts WebSocket connections and the client only dials
# them. The client reaches the server through its default route only, so
# that the full-tunnel test shows the WebSocket connection carries the fwmark.
#
# Usage: ./ws-netns.sh <path to ws-wireguard-go>
# Needs root, ip, ping, ss, openssl, nc and wg from wireguard-tools.

set -e
umask 077

exec 3>&1
program=$(realpath "$1")
[[ -x $program ]] || { echo "Usage: $0 <path to ws-wireguard-go>" >&2; exit 1; }
for tool in ip ping ss openssl nc wg; do
	type -p $tool >/dev/null || { echo "Missing $tool" >&2; exit 1; }
done

nss="wsw-test-$$-s"
nsc="wsw-test-$$-c"
wgs="wgs$$"
wgc="wgc$$"
tmp=$(mktemp -d)
server_pid=""
export LOG_LEVEL=verbose

pretty() { echo -e "\x1b[32m\x1b[1m[+] $*\x1b[0m" >&3; }
fail() {
	echo -e "\x1b[31m\x1b[1m[!] $*\x1b[0m" >&3
	echo "--- server log ---" >&3; tail -n 25 "$tmp/server.log" >&3
	echo "--- client log ---" >&3; tail -n 25 "$tmp/client.log" >&3
	exit 1
}
ns() { local n=$1; shift; ip netns exec "$n" "$@"; }

stop_server() {
	[[ -n $server_pid ]] || return 0
	kill "$server_pid" 2>/dev/null || true
	wait "$server_pid" 2>/dev/null || true
	server_pid=""
}

# The client runs as a daemon, so it is found by its command line.
stop_client() {
	local pid
	pid=$(pgrep -f -- "$wgc\$" || true)
	[[ -n $pid ]] || return 0
	kill $pid
	while kill -0 $pid 2>/dev/null; do sleep 0.1; done
}

cleanup() {
	set +e
	exec 2>/dev/null
	stop_server
	stop_client
	ip netns del "$nss"
	ip netns del "$nsc"
	rm -rf "$tmp"
}
trap cleanup EXIT
trap 'exit 1' INT TERM

wait_for_socket() {
	for _ in {1..100}; do
		[[ -S /var/run/wireguard/$1.sock ]] && return
		sleep 0.1
	done
	fail "$1 did not create its UAPI socket"
}

# ping_ok NS ADDR TRIES pings ADDR once a second until a reply arrives.
ping_ok() {
	local i
	for ((i = 0; i < $3; i++)); do
		ns "$1" ping -c 1 -W 1 "$2" >/dev/null 2>&1 && return
	done
	fail "no reply from $2 in $1 after $3 attempts"
}

# start_server ARGS... starts the server daemon in the foreground with ARGS.
start_server() {
	# Not through ns(), so that $! is the daemon rather than a subshell.
	ip netns exec "$nss" "$program" -f "$@" "$wgs" >>"$tmp/server.log" 2>&1 &
	server_pid=$!
	wait_for_socket "$wgs"
	ns "$nss" wg set "$wgs" private-key "$tmp/server.key" peer "$client_pub" allowed-ips 10.77.0.2/32
	ip -n "$nss" addr add 10.77.0.1/24 dev "$wgs"
	ip -n "$nss" link set "$wgs" up
}

# start_client CONFIG ARGS... starts the client as a daemon and loads CONFIG.
start_client() {
	local config=$1
	shift
	ns "$nsc" "$@" "$wgc" >>"$tmp/client.log" 2>&1
	wait_for_socket "$wgc"
	ns "$nsc" wg setconf "$wgc" "$config"
	ip -n "$nsc" addr add 10.77.0.2/24 dev "$wgc"
	ip -n "$nsc" link set "$wgc" up
}

pretty "Setting up namespaces"
ip netns add "$nss"
ip netns add "$nsc"
ip -n "$nss" link set lo up
ip -n "$nsc" link set lo up
ip link add veth-s netns "$nss" type veth peer name veth-c netns "$nsc"
ip -n "$nss" addr add 192.168.77.1/32 dev veth-s
ip -n "$nsc" addr add 192.168.77.2/32 dev veth-c
ip -n "$nss" link set veth-s up
ip -n "$nsc" link set veth-c up
ip -n "$nss" route add 192.168.77.2/32 dev veth-s
ip -n "$nsc" route add default dev veth-c

wg genkey >"$tmp/server.key"
wg genkey >"$tmp/client.key"
server_pub=$(wg pubkey <"$tmp/server.key")
client_pub=$(wg pubkey <"$tmp/client.key")

# The client's peer has no endpoint: the bind supplies the server URL.
cat >"$tmp/client.conf" <<EOF
[Interface]
PrivateKey = $(cat "$tmp/client.key")

[Peer]
PublicKey = $server_pub
AllowedIPs = 10.77.0.1/32
PersistentKeepalive = 10
EOF

pretty "ws://: server listens on the UAPI listen-port, client configured by flags"
start_server --mode server --listen 192.168.77.1 --path /wg
ns "$nss" wg set "$wgs" listen-port 8080
start_client "$tmp/client.conf" "$program" --mode client --url ws://192.168.77.1:8080/wg
ping_ok "$nsc" 10.77.0.1 5
ping_ok "$nss" 10.77.0.2 3
[[ $(ns "$nss" wg show "$wgs" listen-port) == 8080 ]] || fail "server listen-port is not 8080"
[[ $(ns "$nsc" wg show "$wgc" listen-port) == 0 ]] || fail "client has a listen-port"
[[ $(ns "$nsc" wg show "$wgc" endpoints) == *"192.168.77.1:8080"* ]] || fail "client endpoint: $(ns "$nsc" wg show "$wgc" endpoints)"
[[ $(ns "$nss" wg show "$wgs" endpoints) == *"192.168.77.2:"* ]] || fail "server endpoint: $(ns "$nss" wg show "$wgs" endpoints)"
[[ $(ns "$nss" wg show "$wgs" latest-handshakes) != *$'\t0' ]] || fail "no handshake on the server"
ns "$nss" ss -tln | grep -q "192.168.77.1:8080" || fail "server is not listening on 192.168.77.1:8080"
ns "$nsc" ss -tln | grep -q LISTEN && fail "client is listening: $(ns "$nsc" ss -tln)"
ns "$nss" wg show "$wgs" >&3

pretty "wg syncconf, as systemctl reload does, keeps the WebSocket connection"
cat >"$tmp/server.conf" <<EOF
[Interface]
PrivateKey = $(cat "$tmp/server.key")
ListenPort = 8080

[Peer]
PublicKey = $client_pub
AllowedIPs = 10.77.0.2/32
EOF
accepted=$(grep -c "Accepted connection" "$tmp/server.log")
ns "$nss" wg syncconf "$wgs" "$tmp/server.conf"
ns "$nsc" wg syncconf "$wgc" "$tmp/client.conf"
ping_ok "$nsc" 10.77.0.1 3
[[ $(grep -c "Accepted connection" "$tmp/server.log") == "$accepted" ]] || fail "wg syncconf made the client reconnect"

pretty "Bulk transfer integrity"
head -c $((32 << 20)) /dev/urandom >"$tmp/blob"
ns "$nss" nc -l 10.77.0.1 5001 >"$tmp/blob.recv" &
nc_pid=$!
sleep 0.5
start=$(date +%s.%N)
ns "$nsc" nc -N 10.77.0.1 5001 <"$tmp/blob"
wait $nc_pid
end=$(date +%s.%N)
cmp -s "$tmp/blob" "$tmp/blob.recv" || fail "transferred data differs"
pretty "32 MiB in $(echo "$end - $start" | bc 2>/dev/null || echo "?") s"

pretty "Server restart: the client redials and handshakes again"
stop_server
start_server --mode server --listen 192.168.77.1:8080 --path /wg
ping_ok "$nsc" 10.77.0.1 30
ping_ok "$nss" 10.77.0.2 3

pretty "Client restart, configured by environment: keepalives make the client reachable at once"
stop_client
start_client "$tmp/client.conf" env WG_WS_MODE=client WG_WS_URL=ws://192.168.77.1:8080/wg "$program"
ping_ok "$nss" 10.77.0.2 15

pretty "Full tunnel with fwmark, as wg-quick sets up for AllowedIPs = 0.0.0.0/0"
ns "$nsc" wg set "$wgc" fwmark 51820 peer "$server_pub" allowed-ips 0.0.0.0/0
ip -n "$nsc" route add default dev "$wgc" table 51820
ip -n "$nsc" rule add not fwmark 51820 table 51820
ip -n "$nsc" rule add table main suppress_prefixlength 0
ping_ok "$nsc" 10.77.0.1 5
ns "$nsc" ss -tnie dst 192.168.77.1 2>/dev/null | grep -q "fwmark:0xca6c" || fail "WebSocket connection has no fwmark: $(ns "$nsc" ss -tnie)"
pretty "Full tunnel: the client must redial outside the tunnel"
stop_server
start_server --mode server --listen 192.168.77.1:8080 --path /wg
ping_ok "$nsc" 10.77.0.1 30
ns "$nsc" ss -tnie dst 192.168.77.1 2>/dev/null | grep -q "fwmark:0xca6c" || fail "redialed connection has no fwmark"
ip -n "$nsc" rule del table main suppress_prefixlength 0
ip -n "$nsc" rule del not fwmark 51820 table 51820
ns "$nsc" wg set "$wgc" fwmark off peer "$server_pub" allowed-ips 10.77.0.1/32

pretty "wss:// served directly with a certificate"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 1 -subj /CN=ws-test \
	-keyout "$tmp/tls.key" -out "$tmp/tls.crt" >/dev/null 2>&1
stop_server
stop_client
start_server --mode server --listen 192.168.77.1:8443 --path /wg --tls-cert "$tmp/tls.crt" --tls-key "$tmp/tls.key"
start_client "$tmp/client.conf" "$program" --url wss://192.168.77.1:8443/wg
sleep 3
grep -q "certificate" "$tmp/client.log" || fail "client accepted an untrusted certificate"
stop_client
start_client "$tmp/client.conf" "$program" --url wss://192.168.77.1:8443/wg --insecure
ping_ok "$nsc" 10.77.0.1 5
ping_ok "$nss" 10.77.0.2 3

pretty "All tests passed"
