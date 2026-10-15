# ws-wireguard-go: WireGuard over WebSocket

English | [简体中文](README.zh-CN.md)

ws-wireguard-go is a userspace WireGuard implementation modified from [wireguard-go](https://git.zx2c4.com/wireguard-go). It replaces WireGuard's UDP transport with WebSocket: WireGuard messages are sent and received directly as WebSocket messages, with no UDP socket anywhere in between. It is meant for networks where UDP is blocked, or where the target machine can only be reached through an HTTP(S) reverse proxy or CDN on ports 80/443.

Apart from the transport, everything is the same as in wireguard-go: the same Noise handshake and encryption, timers, TUN device and UAPI control interface, managed as usual with `wg` and `wg-quick`.

> Both ends must run ws-wireguard-go. It cannot talk to standard WireGuard over UDP (the kernel module or the official clients), but it can run alongside them on the same machine; see [Coexisting with kernel WireGuard](#coexisting-with-kernel-wireguard-mixed-deployment).

- [How it works](#how-it-works)
- [Building and installing](#building-and-installing)
- [Usage](#usage)
- [Deployment](#deployment)
- [Notes](#notes)
- [Testing](#testing)
- [Code layout](#code-layout)
- [License](#license)

## How it works

### Compared with wstunnel-style setups

The usual way to get WireGuard through WebSocket is to wrap it in another proxy (wstunnel, udp2raw and the like). WireGuard itself is unchanged and still sends UDP, but to a local proxy; the proxy wraps the UDP datagrams in WebSocket, and the proxy on the other end unwraps them and forwards them over UDP to the real WireGuard.

ws-wireguard-go does not work that way. It modifies the transport layer of wireguard-go directly, using WebSocket messages in place of UDP datagrams:

```
wstunnel-style (UDP relayed through a second proxy):
  wg ─UDP─► 127.0.0.1 wstunnel client ══WebSocket══► wstunnel server ─UDP─► 127.0.0.1 wg

ws-wireguard-go (WebSocket is the transport):
  ws-wireguard-go ══════════════════ WebSocket ════════════════════► ws-wireguard-go
```

|  | wg + wstunnel | ws-wireguard-go |
|---|---|---|
| Processes on each end | WireGuard plus a proxy | One |
| UDP | A local UDP hop on each end | None at all |
| Peer address seen by the server | Always the local proxy's `127.0.0.1` | Each peer's real address; behind a reverse proxy it can be taken from `X-Forwarded-For` |
| Multiple clients | The server-side proxy keeps a UDP socket per connection to forward through | Each WebSocket connection is itself an endpoint, roamed by WireGuard itself |
| Full tunnel (0.0.0.0/0) | The proxy is a separate process that wg-quick's fwmark does not cover, so the server address needs a manual route exception | WebSocket connections carry the fwmark set by wg-quick, no extra configuration needed |
| Connection state | WireGuard does not know when the proxy reconnects, and `wg show` cannot tell | The endpoint in `wg show` is the other end of the current WebSocket connection |

The WireGuard messages themselves do not change at all (same format, same encryption); only what carries them does.

### Code changes

wireguard-go keeps protocol and transport cleanly apart: the `device` package implements the WireGuard protocol and sends and receives packets through the `conn.Bind` interface, and the stock `conn.StdNetBind` is a UDP socket. This project adds the `conn/wsbind` package, which implements the same `conn.Bind` interface over WebSocket, so the protocol code in `device` barely changes:

| `conn.Bind` | Upstream (UDP) | wsbind (WebSocket) |
|---|---|---|
| `Open(port)` | Listens on a UDP port | server: starts an HTTP server on a TCP port and waits for WebSocket upgrades; client: listens on nothing |
| `Send(bufs, ep)` | Sends UDP datagrams to the address of `ep` | Writes each packet as one binary WebSocket message on the connection of `ep` |
| `ReceiveFunc` | Reads datagrams from the UDP socket | Binary messages from all connections go into one queue, which the device's receive goroutine reads in batches |
| `Endpoint` | The peer's IP:port | server: an accepted connection; client: a server URL (peers with the same URL share one connection) |
| `ParseEndpoint` | Parses `IP:port` | client: parses `ws://` and `wss://` URLs or `host:port`; server: accepts them but never connects |
| `SetMark` | Sets the fwmark on the UDP sockets | Sets the fwmark on the listening socket and on every WebSocket TCP connection |

One WireGuard message is one binary WebSocket message. WebSocket message boundaries take the place of UDP datagram boundaries, so no length field or other framing is needed.

There are only two functional changes to the core of wireguard-go:

- A new optional interface, `conn.DefaultEndpointer` (`conn/conn.go`, `device/uapi.go`), lets peers on a client that have no endpoint configured use the server URL automatically.
- Setting the listen port through UAPI no longer rebinds if the port is unchanged (`device/uapi.go`, matching the kernel module). `wg setconf` and `wg syncconf` always send the listen port; rebinding is harmless for UDP but drops every connection for WebSocket.

Besides that, `main.go` uses wsbind and gains the transport options, and a log message in `device/device.go` says "Bind" instead of "UDP bind".

### Connection management

- **The server only accepts, never dials.** Only WebSocket upgrade requests on the configured path are accepted; every other request gets a 404. Each accepted connection is an endpoint, and whichever peer authenticates over a connection has its endpoint roamed onto it. A connection that receives nothing for 80 seconds is closed.
- **The client only dials, never listens.** It dials when there is a packet to send, queues packets while dialing (up to 128), and sends them in order once connected. After the connection drops, the next packet triggers a redial; failed dials back off from 0.5 to 5 seconds. The client pings every 20 seconds, both to keep proxies from closing the connection as idle and to detect dead connections: if nothing arrives for 60 seconds, it disconnects and redials.
- **To WireGuard, it is still a lossy transport.** Packets are dropped while there is no usable connection, and WireGuard's own retransmission and handshake timers recover from that, just as from packet loss on UDP.

## Building and installing

Building needs Go 1.23 or later and make:

```
git clone https://github.com/christarcher/ws-wireguard-go.git
cd ws-wireguard-go
make            # builds ./ws-wireguard-go
make install    # installs ws-wireguard-go and ws-wg-quick into /usr/bin (PREFIX and DESTDIR can be set)
make test       # go test ./...
```

At runtime you need `wg` from [wireguard-tools](https://git.zx2c4.com/wireguard-tools). `ws-wg-quick` also needs `wg-quick` from wireguard-tools, and on Linux `ip` from iproute2.

### Platforms

| Platform | Status |
|---|---|
| Linux | Tested: unit tests, integration tests and the network namespace end-to-end test |
| macOS, FreeBSD, OpenBSD | Builds, not yet tested |
| Windows | Builds. As in upstream, `main_windows.go` is only a test program for debugging, and it needs [wintun.dll](https://www.wintun.net/) at runtime |

## Usage

```
ws-wireguard-go [-f/--foreground] [options] INTERFACE-NAME
```

Like wireguard-go, it creates a TUN interface and forks into the background (`-f` keeps it in the foreground); you then configure it with `wg` and `ip`. To stop it, run `ip link del INTERFACE-NAME` or delete `/var/run/wireguard/INTERFACE-NAME.sock`. The log level is set with `LOG_LEVEL=verbose|error|silent`. Options go before the interface name.

### Options

Every option can be given as an environment variable instead, so that programs which pass only the interface name, such as wg-quick and systemd, can start the daemon:

| Option | Environment variable | Mode | Description |
|---|---|---|---|
| `--mode server\|client` | `WG_WS_MODE` | both | If omitted, `--url` implies client, and `--listen` or `--tls-cert` implies server |
| `--listen HOST[:PORT]` | `WG_WS_LISTEN` | server | Listen address, see [the listen port](#server-listen-port); listens on all addresses by default |
| `--path PATH` | `WG_WS_PATH` | both | server: accept WebSocket only on this path. client: used to build the URL when the endpoint is `HOST:PORT`. Defaults to `/` |
| `--tls-cert FILE`, `--tls-key FILE` | `WG_WS_TLS_CERT`, `WG_WS_TLS_KEY` | server | Serve `wss://` directly; not needed when a reverse proxy terminates TLS |
| `--real-ip-header NAME` | `WG_WS_REAL_IP_HEADER` | server | Trust this header set by a reverse proxy (such as `X-Forwarded-For` or `X-Real-IP`) and use its last value as the peer address, which shows up in `wg show` and is used for handshake rate limiting and cookies |
| `--url URL` | `WG_WS_URL` | client | Server URL, `ws://` or `wss://`, optionally with `user:pass@` (sent as HTTP Basic authentication). All peers of the interface connect to it |
| `--insecure` | `WG_WS_INSECURE=1` | client | Do not verify the server certificate |

A `ListenPort` set on a client is ignored, and `wg show` reports its listening port as 0.

### Server listen port

The server listens on a TCP port, set in one of two ways:

1. **`--listen` gives only an address, and the port follows the interface's listen-port (recommended).** This works the same as standard WireGuard:
   - put `ListenPort = 8080` in the configuration file;
   - at runtime, `wg set ws0 listen-port 9090` makes the server close the old port and listen on the new one, without restarting the process.
2. **The port is fixed in `--listen`**, for example `--listen 127.0.0.1:8080`. It takes precedence, and changing the port means restarting the process.

The `listening port` in `wg show` is the port actually listened on. Keep in mind:

- **Changing the port at runtime drops every WebSocket connection.** Clients reconnect right away; the server's session keys are not affected, so no new handshake is needed.
- **Clients must be able to reach the new port.** Behind a reverse proxy, change the port the proxy forwards to and reload it; for clients that connect directly, change their URL.
- **If `--listen` includes a port, `wg set listen-port` cannot change it.** It only makes the server listen again on the same port, and clients briefly disconnect.
- **If neither gives a port, a random port is chosen.** Always set one behind a reverse proxy.
- This is a TCP port, so it does not clash with a kernel WireGuard UDP port of the same number on the same machine.

### Client endpoints

The `wg` tool can only pass endpoints of the form `host:port`, and it resolves domain names to IP addresses first. Therefore:

- **With `--url`**, peers without an Endpoint use this URL automatically, and peers configured with `Endpoint = host:port` are mapped to this URL as well. The URL determines where the client actually connects, along with the TLS SNI and the Host header, so client configurations usually need no Endpoint.
- **Without `--url`**, `Endpoint = HOST:PORT` means `ws://HOST:PORT/PATH`, which can only be unencrypted `ws://`.
- **To give a single peer its own URL**, bypass `wg` and write `endpoint=wss://...` directly through UAPI.
- **In `wg show`**, the endpoint is the server's IP:port while connected, and the host:port of the URL while not.

The server accepts endpoints configured on peers, so that configurations saved by `SaveConfig` can be loaded again, but it never connects to them; they are replaced once the peer connects.

### wg-quick and ws-wg-quick

On Linux, wg-quick only falls back to the userspace implementation named by `WG_QUICK_USERSPACE_IMPLEMENTATION` when the kernel has **no** WireGuard module. Whenever the module is present, it creates a kernel interface directly, which uses UDP.

That is why this project provides `contrib/ws-wg-quick`. It wraps wg-quick and takes exactly the same arguments (`up`, `down`, `strip`, `save`, ...), but replaces the step where wg-quick creates the interface with starting ws-wireguard-go. Everything else, including Address, DNS, MTU, routes, the fwmark and nft rules of full-tunnel mode, and PreUp/PostUp, is done by stock wg-quick. Transport options are passed in `WG_WS_*` environment variables:

```
WG_WS_MODE=client WG_WS_URL=wss://vpn.example.com/wg ws-wg-quick up ws0
```

Requirements:

- it must run as root;
- if ws-wireguard-go is not in `PATH`, set `WS_WIREGUARD_GO` to its path;
- it only affects the interface it starts, never other kernel WireGuard interfaces.

Either `ws-wg-quick down` or the stock `wg-quick down` brings the interface down.

On macOS and the BSDs, wg-quick always uses a userspace implementation, so setting `WG_QUICK_USERSPACE_IMPLEMENTATION=ws-wireguard-go` together with `WG_WS_*` is enough (not yet tested on these platforms).

## Deployment

### Typical topology: the target only exposes 80/443

```
              Internet, only 443 open                        Internal network
  client ws0 ══ wss://vpn.example.com/wg ══► nginx (TLS) ──► target ws0 (server)
  10.0.0.2                                   reverse proxy   listens on 127.0.0.1:8080
                                                             or internal IP:8080
                                                             10.0.0.1
```

The reverse proxy can run on the target itself or on another machine. The only difference is the address the server listens on:

| Setup | `WG_WS_LISTEN` | nginx `proxy_pass` |
|---|---|---|
| Proxy and target on the same machine | `127.0.0.1` | `http://127.0.0.1:8080` |
| Proxy on another machine | An internal address of the target that the proxy can reach, such as `10.1.2.3` | `http://10.1.2.3:8080` |

When you use `WG_WS_REAL_IP_HEADER`, make sure that only the reverse proxy can reach this port (listen on 127.0.0.1, or allow only the proxy's address in the firewall). Otherwise anyone can forge the source address in the header.

To manage everything with systemd or ws-wg-quick, the examples below keep the transport options of each interface in `/etc/wireguard/<interface>.ws`.

#### Server (target machine)

`/etc/wireguard/ws0.conf`, an entirely ordinary WireGuard configuration:

```ini
[Interface]
PrivateKey = <server private key>
Address = 10.0.0.1/24
ListenPort = 8080

[Peer]
PublicKey = <client public key>
AllowedIPs = 10.0.0.2/32
```

`/etc/wireguard/ws0.ws`:

```
WG_WS_MODE=server
WG_WS_LISTEN=127.0.0.1
WG_WS_PATH=/wg
WG_WS_REAL_IP_HEADER=X-Forwarded-For
```

`WG_WS_LISTEN` has no port, so the server listens on `ListenPort = 8080`.

#### Reverse proxy (nginx)

```nginx
server {
    listen 443 ssl;
    server_name vpn.example.com;
    # ssl_certificate ...; ssl_certificate_key ...;

    location = /wg {
        proxy_pass http://127.0.0.1:8080;          # the target's internal address if the proxy is on another machine
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_read_timeout 300s;
        proxy_send_timeout 300s;
        proxy_buffering off;
    }
}
```

The path `/wg` must match the server's `WG_WS_PATH`. nginx forwards the path unchanged, and the path itself can act as a shared secret, such as `/a8f3c1e9`. Other locations on the site are not affected.

If a CDN sits in front, it must support WebSocket. The last value of `X-Forwarded-For` is the address seen by the proxy closest to the server, so with several layers of proxies, use a header that carries the real client address instead (such as one provided by the CDN), or simply leave `WG_WS_REAL_IP_HEADER` unset. Without it, every client shows up with the reverse proxy's address, which does not affect anything else.

#### Client

`/etc/wireguard/ws0.conf`:

```ini
[Interface]
PrivateKey = <client private key>
Address = 10.0.0.2/24

[Peer]
PublicKey = <server public key>
AllowedIPs = 10.0.0.0/24        # 0.0.0.0/0 for a full tunnel
PersistentKeepalive = 25
```

`/etc/wireguard/ws0.ws`:

```
WG_WS_MODE=client
WG_WS_URL=wss://vpn.example.com/wg
```

The peer needs no Endpoint, because `WG_WS_URL` determines where to connect. A full tunnel (`AllowedIPs = 0.0.0.0/0`) works as is: the fwmark set by wg-quick applies to the WebSocket TCP connections, so they are not routed into the tunnel itself.

#### Starting

To start an interface by hand (the same on both ends):

```
set -a; . /etc/wireguard/ws0.ws; set +a
ws-wg-quick up ws0
```

To check the connection:

```
wg show ws0          # endpoint, latest handshake, transfer
ping 10.0.0.1        # on the client
```

### Managing with systemd

`/etc/systemd/system/ws-wg-quick@.service`, modeled on the official `wg-quick@.service` and not yet tested under systemd:

```ini
[Unit]
Description=WireGuard over WebSocket via ws-wg-quick for %I
After=network-online.target nss-lookup.target
Wants=network-online.target nss-lookup.target

[Service]
Type=oneshot
RemainAfterExit=yes
EnvironmentFile=/etc/wireguard/%i.ws
ExecStart=/usr/bin/ws-wg-quick up %i
ExecStop=/usr/bin/ws-wg-quick down %i
ExecReload=/bin/bash -c 'exec /usr/bin/wg syncconf %i <(exec /usr/bin/wg-quick strip %i)'

[Install]
WantedBy=multi-user.target
```

```
systemctl daemon-reload
systemctl enable --now ws-wg-quick@ws0
systemctl reload ws-wg-quick@ws0     # apply peer changes in ws0.conf without a restart
```

As long as the port stays the same, a reload does not drop existing WebSocket connections. The exception is a server whose port is fixed in `--listen` while `ws0.conf` has no `ListenPort`: `wg syncconf` then sends a listen-port of 0, which differs from the actual port, so every connection reconnects once (session keys are kept). Setting the port with `ListenPort`, as in the example above, avoids this. After changing `ws0.ws` (the transport options), run `systemctl restart`.

### Coexisting with kernel WireGuard (mixed deployment)

A common situation: some servers are reachable over UDP from the internet and use kernel WireGuard, while others can only be reached through a reverse proxy on 80/443 and use ws-wireguard-go. Both can run on the same machine. The rule to remember is **one transport per interface**: kernel interfaces use UDP and ws-wireguard-go interfaces use WebSocket, and one interface cannot have some peers on UDP and others on WebSocket. So split the peers into interfaces by transport:

```
/etc/wireguard/wg0.conf    # kernel module, UDP, to servers reachable over UDP
/etc/wireguard/ws0.conf    # ws-wireguard-go, to machines behind the a.example.com proxy
/etc/wireguard/ws0.ws
/etc/wireguard/ws1.conf    # ws-wireguard-go, to machines behind the b.example.com proxy
/etc/wireguard/ws1.ws
```

```
systemctl enable --now wg-quick@wg0       # kernel interface, as before
systemctl enable --now ws-wg-quick@ws0    # WebSocket interfaces
systemctl enable --now ws-wg-quick@ws1
```

`wg show` lists both kinds of interfaces, and they are managed the same way. Keep in mind:

- **Never start a WebSocket interface with the stock `wg-quick up` or `wg-quick@ws0`.** When the kernel module is present, stock wg-quick quietly creates a kernel interface that uses UDP. It appears to start fine, but does not work where only 80/443 are open. Naming WebSocket interfaces `ws0` and so on helps avoid this mistake.
- **A WebSocket client interface connects to a single server URL.** To reach several machines behind different reverse proxies, use one interface per machine (ws0, ws1, ...), each with its own `.ws` file.
- **The address ranges and AllowedIPs of different interfaces must not overlap**, since the kernel picks the interface for each packet by its route.
- **At most one interface can be a full tunnel (0.0.0.0/0).** Give the other interfaces the same `FwMark` in `[Interface]` (see it with `wg show <interface> fwmark`; wg-quick uses 51820 by default), so that their own transport traffic (UDP, or the TCP under WebSocket) bypasses the full tunnel and goes out directly. Otherwise it gets wrapped into the full tunnel.
- **The target machine can mix them too.** For example, a machine with UDP-reachable peers that also accepts WebSocket connections forwarded by a reverse proxy runs both a kernel `wg0` and a server-mode `ws0`. To forward between the two subnets, enable `net.ipv4.ip_forward` and set up routes and AllowedIPs accordingly.

### Serving wss directly (without a reverse proxy)

If port 443 on the target is not used by another service, ws-wireguard-go can serve TLS itself:

```
WG_WS_MODE=server
WG_WS_LISTEN=0.0.0.0:443
WG_WS_PATH=/wg
WG_WS_TLS_CERT=/etc/letsencrypt/live/vpn.example.com/fullchain.pem
WG_WS_TLS_KEY=/etc/letsencrypt/live/vpn.example.com/privkey.pem
```

The certificate is read again every time the interface comes up (including when the listen-port changes), so after renewing it, `systemctl restart ws-wg-quick@ws0` puts the new one into use.

### Without wg-quick

```
ws-wireguard-go --mode client --url wss://vpn.example.com/wg ws0
wg setconf ws0 <(wg-quick strip ws0)
ip address add 10.0.0.2/24 dev ws0
ip link set ws0 up
```

## Notes

- **Both ends must be ws-wireguard-go**; it cannot interoperate with standard WireGuard over UDP.
- **Keepalive**: the client's WebSocket pings only keep the connection itself from being closed as idle. The server only learns where to find a client after the client has connected and sent packets over that connection. So if the server needs to reach the client first, the client should set `PersistentKeepalive`, just like a client behind NAT.
- **Server restarts**: the client reconnects immediately, but the old session keys are gone along with the server, so traffic resumes only when WireGuard handshakes again by itself after about 15 seconds without replies (Keepalive-Timeout + Rekey-Timeout). This is the same as a server restart over UDP. Changing only the listen port does not cause this wait.
- **TCP over TCP**: TCP inside the tunnel runs on top of the TCP connection under WebSocket, and on lossy links it performs worse than over UDP, as with every TCP-based tunnel. WebSocket has no IP fragmentation problems; the MTU only sets the size of packets inside the tunnel, so the default 1420 is fine.
- **Security**: authentication and encryption are entirely up to WireGuard, and data arriving on a connection that has not completed a handshake is dropped. The WebSocket path can act as an extra shared secret: requests that are not WebSocket or use the wrong path all get a 404. Limits such as the number of connections can be configured on the reverse proxy.

## Testing

- `go test ./...`: unit tests, plus integration tests in which two WireGuard devices ping each other over WebSocket, including client and server restarts.
- `tests/ws-netns.sh ./ws-wireguard-go`: an end-to-end test with real TUN devices, network namespaces and the `wg` tool, which needs root. It covers ws, wss, server and client restarts, daemon mode, configuration through environment variables, and the fwmark in full-tunnel mode.

## Code layout

| Path | Contents |
|---|---|
| `conn/wsbind/wsbind.go` | The shared part of the `conn.Bind` implementation: options, Open/Close/Send, the receive queue |
| `conn/wsbind/server.go` | Server: HTTP listener, WebSocket upgrade, real IP |
| `conn/wsbind/client.go` | Client: on-demand dialing, queueing, redial backoff, ping |
| `conn/wsbind/mark_*.go` | Setting the fwmark on each platform |
| `options.go`, `main.go`, `main_windows.go` | Command line options and environment variables |
| `conn/conn.go`, `device/uapi.go` | `conn.DefaultEndpointer`: peers without an endpoint use the client's server URL; no rebind when the listen-port is unchanged |
| `contrib/ws-wg-quick` | wg-quick wrapper |
| `conn/wsbind/*_test.go`, `device/uapi_test.go` | Unit and integration tests |
| `tests/ws-netns.sh` | End-to-end test |

## License

ws-wireguard-go is a modified version of [wireguard-go](https://git.zx2c4.com/wireguard-go) and, like it, is released under the MIT license; see [LICENSE](LICENSE) for the full text:

- Original wireguard-go code: Copyright (C) 2017-2025 WireGuard LLC.
- Additions and changes made by this project: Copyright (C) 2026 christarcher.

The first commit in this repository is wireguard-go imported unchanged (upstream commit `2631ce9`), and every later commit is a change made by this project, so diffing against it shows everything that differs from upstream.

"WireGuard" and the WireGuard logo are registered trademarks of Jason A. Donenfeld. This is not an official WireGuard project, and it is not affiliated with, endorsed by or sponsored by the WireGuard project or its authors.
