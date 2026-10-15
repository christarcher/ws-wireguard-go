# ws-wireguard-go：基于 WebSocket 的 WireGuard

ws-wireguard-go 是在 [wireguard-go](https://git.zx2c4.com/wireguard-go) 基础上修改的 WireGuard 用户态实现。它把 WireGuard 的传输层从 UDP 换成了 WebSocket：WireGuard 报文直接作为 WebSocket 消息收发，中间不再经过任何 UDP 套接字。它适合这样的场景：UDP 被封锁，或者目标机器只能通过 80/443 端口上的 HTTP(S) 反向代理 / CDN 访问。

除了传输层，其余都与 wireguard-go 相同：同样的 Noise 握手与加密、计时器、TUN 设备和 UAPI 控制接口，照常用 `wg`、`wg-quick` 管理。

> 两端都必须运行 ws-wireguard-go。它不能和走 UDP 的标准 WireGuard（内核模块、官方客户端）互联，但可以和它们在同一台机器上共存，见[与内核 WireGuard 共存](#与内核-wireguard-共存混合部署)。

- [实现原理](#实现原理)
- [编译与安装](#编译与安装)
- [使用](#使用)
- [部署](#部署)
- [注意事项](#注意事项)
- [测试](#测试)
- [代码结构](#代码结构)

## 实现原理

### 与 wstunnel 类方案的区别

让 WireGuard 穿过 WebSocket，常见做法是在 WireGuard 外面再套一层代理（wstunnel、udp2raw 之类）：WireGuard 本身不变，仍然发 UDP，只是发给本机代理；代理把 UDP 数据报包进 WebSocket，对端代理拆出来，再用 UDP 转给真正的 WireGuard。

ws-wireguard-go 不是这样做的。它直接修改了 wireguard-go 的传输层，用 WebSocket 消息代替 UDP 数据报：

```
wstunnel 类方案（二次代理 UDP）：
  wg ─UDP─► 127.0.0.1 wstunnel 客户端 ══WebSocket══► wstunnel 服务端 ─UDP─► 127.0.0.1 wg

ws-wireguard-go（WebSocket 就是传输层）：
  ws-wireguard-go ══════════════════ WebSocket ════════════════════► ws-wireguard-go
```

|  | wg + wstunnel | ws-wireguard-go |
|---|---|---|
| 每端的进程 | WireGuard 加一个代理 | 一个 |
| UDP | 两端都还有一段本机 UDP 中转 | 完全不使用 UDP |
| 服务端看到的 peer 地址 | 都是本机代理的 `127.0.0.1` | 每个 peer 的真实地址，反代后面可以从 `X-Forwarded-For` 取 |
| 多个客户端 | 服务端代理要为每个连接维护一个 UDP 套接字做转发 | 每条 WebSocket 连接直接就是一个 endpoint，由 WireGuard 自己 roaming |
| 全局模式（0.0.0.0/0） | 代理是另一个进程，wg-quick 的 fwmark 管不到它，要手动给服务器地址加路由例外 | WebSocket 连接直接带上 wg-quick 设置的 fwmark，不用额外配置 |
| 连接状态 | 代理的断线重连 WireGuard 不知道，`wg show` 看不出来 | `wg show` 的 endpoint 就是当前 WebSocket 连接的对端 |

WireGuard 报文本身没有任何变化（同样的格式、同样的加密），变的只是承载它的东西。

### 代码层面的修改

wireguard-go 把协议和传输分得很清楚：`device` 包实现 WireGuard 协议，通过 `conn.Bind` 接口收发报文。原版的 `conn.StdNetBind` 就是 UDP 套接字。本项目新增了 `conn/wsbind` 包，用 WebSocket 实现同一个 `conn.Bind` 接口，`device` 里的协议代码基本不用改：

| `conn.Bind` 接口 | 原版（UDP） | wsbind（WebSocket） |
|---|---|---|
| `Open(port)` | 在 UDP 端口上监听 | server：在 TCP 端口上启动 HTTP 服务并等待 WebSocket 升级；client：什么都不监听 |
| `Send(bufs, ep)` | 向 `ep` 的地址发送 UDP 数据报 | 每个报文作为一条二进制 WebSocket 消息，写到 `ep` 对应的连接 |
| `ReceiveFunc` | 从 UDP 套接字读数据报 | 所有连接收到的二进制消息汇入一个队列，由设备的收包协程批量读取 |
| `Endpoint` | 对端 IP:端口 | server：一条已接入的连接；client：一个服务端 URL（同一 URL 的 peer 共用一条连接） |
| `ParseEndpoint` | 解析 `IP:端口` | client：解析 `ws://`、`wss://` URL 或 `host:port`；server：接受但不会去连接 |
| `SetMark` | 给 UDP 套接字设 fwmark | 给监听套接字和所有 WebSocket 的 TCP 连接设 fwmark |

一条 WireGuard 消息对应一条 WebSocket 二进制消息。WebSocket 的消息边界替代了 UDP 的数据报边界，所以不需要额外的长度字段或分帧。

对 wireguard-go 核心代码只有两处功能性改动：

- 新增可选接口 `conn.DefaultEndpointer`（`conn/conn.go`、`device/uapi.go`），让客户端上没有配置 Endpoint 的 peer 自动使用服务端 URL。
- 通过 UAPI 设置的 listen-port 没有变化时，不再重新绑定（`device/uapi.go`，与内核 WireGuard 的行为一致）。`wg setconf`、`wg syncconf` 每次都会发送 listen-port，对 UDP 来说重新绑定毫无影响，但对 WebSocket 来说会断开所有连接。

另外 `main.go` 改为使用 wsbind 并增加了传输选项，`device/device.go` 里一条日志中的 “UDP bind” 改成了 “Bind”。

### 连接管理

- **服务端只接受，不拨出**：只有配置的路径上的 WebSocket 升级请求会被接受，其它请求一律返回 404。每条接入的连接是一个 endpoint，哪个 peer 在这条连接上通过了 WireGuard 认证，服务端就把该 peer 的 endpoint 切换（roaming）到这条连接上。80 秒内什么都没收到的连接会被关闭。
- **客户端只拨出，不监听**：有报文要发时才拨号，拨号期间的报文先排队（最多 128 个），连上之后按顺序发出。连接断开后，下一个报文触发重拨；拨号失败按 0.5 秒到 5 秒退避。连接上每 20 秒发一次 WebSocket ping，既防止代理因空闲断开连接，也用来发现死连接：60 秒内什么都没收到就断开重连。
- **对 WireGuard 来说仍然是“有损”的传输**：没有可用连接时报文直接丢弃，由 WireGuard 自己的重传和握手计时器恢复，和 UDP 网络丢包一样处理。

## 编译与安装

需要 Go 1.23 或更高版本。

```
make            # 生成 ./ws-wireguard-go
make install    # 安装 ws-wireguard-go 和 ws-wg-quick 到 /usr/bin（PREFIX、DESTDIR 可改）
make test       # go test ./...
```

## 使用

```
ws-wireguard-go [-f/--foreground] [选项] INTERFACE-NAME
```

与 wireguard-go 一样，它会创建 TUN 接口并转入后台（`-f` 前台运行），然后用 `wg`、`ip` 配置。停止时执行 `ip link del INTERFACE-NAME`，或者删除 `/var/run/wireguard/INTERFACE-NAME.sock`。日志级别由 `LOG_LEVEL=verbose|error|silent` 控制，选项写在接口名之前。

### 选项

每个选项都可以用环境变量代替，方便被 wg-quick、systemd 这类只传接口名的程序启动：

| 选项 | 环境变量 | 模式 | 说明 |
|---|---|---|---|
| `--mode server\|client` | `WG_WS_MODE` | 两者 | 省略时，给了 `--url` 即为 client，给了 `--listen` 或 `--tls-cert` 即为 server |
| `--listen HOST[:PORT]` | `WG_WS_LISTEN` | server | 监听地址，见[监听端口](#服务端的监听端口)；默认监听所有地址 |
| `--path PATH` | `WG_WS_PATH` | 两者 | server：只在这个路径上接受 WebSocket。client：endpoint 为 `HOST:PORT` 时用来拼 URL。默认 `/` |
| `--tls-cert FILE`、`--tls-key FILE` | `WG_WS_TLS_CERT`、`WG_WS_TLS_KEY` | server | 直接提供 `wss://`；由反向代理终结 TLS 时不需要 |
| `--real-ip-header NAME` | `WG_WS_REAL_IP_HEADER` | server | 信任反向代理设置的请求头（如 `X-Forwarded-For`、`X-Real-IP`），取它的最后一个值作为对端地址，用于 `wg show`、握手限速和 cookie |
| `--url URL` | `WG_WS_URL` | client | 服务端地址，`ws://` 或 `wss://`，可以带 `user:pass@`（以 HTTP Basic 认证发送）。该接口的所有 peer 都连接它 |
| `--insecure` | `WG_WS_INSECURE=1` | client | 不校验服务端证书 |

客户端设置的 `ListenPort` 会被忽略，`wg show` 显示的监听端口为 0。

### 服务端的监听端口

监听的是 TCP 端口，有两种设置方式：

1. **`--listen` 只写地址，端口跟随接口的 listen-port（推荐）**，与原版 WireGuard 用法一致：
   - 配置文件里写 `ListenPort = 8080`；
   - 运行中执行 `wg set ws0 listen-port 9090`，服务端会关掉旧端口、在新端口上重新监听，不用重启进程。
2. **在 `--listen` 里写死**：例如 `--listen 127.0.0.1:8080`。以它为准，要改端口得重启进程。

`wg show` 里的 `listening port` 是实际监听的端口。注意：

- **运行中改端口会断开所有 WebSocket 连接**。客户端会立即重连；服务端的会话密钥不受影响，不需要重新握手。
- **客户端要能连到新端口**。在反代后面时，要同步修改反代的转发端口并重载；客户端直连时，要修改客户端的 URL。
- **`--listen` 写了端口时，`wg set listen-port` 改不了端口**，只会在原端口上重新监听一次，客户端会短暂断线。
- **两种方式都没指定端口时，会随机选一个端口**。放在反代后面时一定要指定。
- 这是 TCP 端口，和本机内核 WireGuard 的 UDP 端口数字相同也不冲突。

### 客户端的 Endpoint

`wg` 工具只能传递 `host:port` 形式的 endpoint，并且会先把域名解析成 IP，所以：

- **设置了 `--url`**：没有 Endpoint 的 peer 自动使用这个 URL；配置了 `Endpoint = host:port` 的 peer 同样映射到这个 URL。实际的连接目标、TLS SNI 和 Host 头都以 URL 为准，所以客户端配置里通常不需要写 Endpoint。
- **没有设置 `--url`**：`Endpoint = HOST:PORT` 表示 `ws://HOST:PORT/PATH`，只能是不加密的 `ws://`。
- **为单个 peer 指定 URL**：绕过 `wg`，直接通过 UAPI 写入 `endpoint=wss://...`。
- **`wg show` 中的显示**：已连接时是服务端的 IP:端口，未连接时是 URL 中的主机:端口。

服务端会接受 peer 上配置的 Endpoint（这样 `SaveConfig` 保存下来的配置还能再加载），但永远不会去连接它，对端连上来之后会自动替换。

### wg-quick 与 ws-wg-quick

Linux 上的 wg-quick 只有在内核**没有** WireGuard 模块时，才会改用 `WG_QUICK_USERSPACE_IMPLEMENTATION` 指定的用户态实现。只要模块存在，它就直接创建内核接口，走 UDP。

所以本项目提供了 `contrib/ws-wg-quick`。它是 wg-quick 的包装，参数与 wg-quick 完全相同（`up`、`down`、`strip`、`save`……），只是把 wg-quick 创建接口的那一步换成启动 ws-wireguard-go。其余步骤，包括 Address、DNS、MTU、路由、全局模式的 fwmark 与 nft 规则、PreUp/PostUp，都是原版 wg-quick 的逻辑。传输选项通过 `WG_WS_*` 环境变量传入：

```
WG_WS_MODE=client WG_WS_URL=wss://vpn.example.com/wg ws-wg-quick up ws0
```

使用要求：

- 需要以 root 运行；
- 如果 ws-wireguard-go 不在 `PATH` 中，用 `WS_WIREGUARD_GO` 指定它的路径；
- 只影响它自己启动的那一个接口，不影响其它内核 WireGuard 接口。

`down` 用 `ws-wg-quick down` 或原版 `wg-quick down` 都可以。

macOS 和 BSD 上的 wg-quick 本来就总是使用用户态实现，设置 `WG_QUICK_USERSPACE_IMPLEMENTATION=ws-wireguard-go` 和 `WG_WS_*` 即可（尚未在这些平台上实测）。

## 部署

### 典型拓扑：目标机器只开放 80/443

```
                      公网，只开放 443                      内网
  客户端 ws0 ══ wss://vpn.example.com/wg ══► nginx（TLS）──► 目标机 ws0（服务端）
  10.0.0.2                                    反代          监听 127.0.0.1:8080 或内网 IP:8080
                                                            10.0.0.1
```

反代可以和目标机在同一台机器上，也可以在另一台机器上，区别只在服务端的监听地址：

| 情况 | `WG_WS_LISTEN` | nginx `proxy_pass` |
|---|---|---|
| 反代和目标机是同一台 | `127.0.0.1` | `http://127.0.0.1:8080` |
| 反代在另一台机器上 | 目标机上反代能访问到的内网地址，如 `10.1.2.3` | `http://10.1.2.3:8080` |

使用 `WG_WS_REAL_IP_HEADER` 时，必须保证这个端口只有反代能访问（监听 127.0.0.1，或用防火墙限制只允许反代的地址），否则别人可以伪造请求头里的来源地址。

为了用 systemd 或 ws-wg-quick 统一管理，下面把每个接口的传输选项放在 `/etc/wireguard/<接口名>.ws` 文件里。

#### 服务端（目标机）

`/etc/wireguard/ws0.conf`，完全是普通的 WireGuard 配置：

```ini
[Interface]
PrivateKey = <服务端私钥>
Address = 10.0.0.1/24
ListenPort = 8080

[Peer]
PublicKey = <客户端公钥>
AllowedIPs = 10.0.0.2/32
```

`/etc/wireguard/ws0.ws`：

```
WG_WS_MODE=server
WG_WS_LISTEN=127.0.0.1
WG_WS_PATH=/wg
WG_WS_REAL_IP_HEADER=X-Forwarded-For
```

`WG_WS_LISTEN` 没写端口，所以监听端口取 `ListenPort = 8080`。

#### 反向代理（nginx）

```nginx
server {
    listen 443 ssl;
    server_name vpn.example.com;
    # ssl_certificate ...; ssl_certificate_key ...;

    location = /wg {
        proxy_pass http://127.0.0.1:8080;          # 反代在另一台机器上时写目标机内网地址
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

路径 `/wg` 要与服务端的 `WG_WS_PATH` 一致。nginx 原样转发路径，路径本身也可以当作一个暗号，例如 `/a8f3c1e9`。站点上的其它 location 不受影响。

如果前面还有 CDN，CDN 需要支持 WebSocket。`X-Forwarded-For` 的最后一个值是离服务端最近的那层代理看到的地址，经过多层代理时，改用能代表真实客户端的头（例如 CDN 提供的头），或者干脆不设置 `WG_WS_REAL_IP_HEADER`。不设置时，所有客户端都显示为反代的地址，不影响使用。

#### 客户端

`/etc/wireguard/ws0.conf`：

```ini
[Interface]
PrivateKey = <客户端私钥>
Address = 10.0.0.2/24

[Peer]
PublicKey = <服务端公钥>
AllowedIPs = 10.0.0.0/24        # 全局模式写 0.0.0.0/0
PersistentKeepalive = 25
```

`/etc/wireguard/ws0.ws`：

```
WG_WS_MODE=client
WG_WS_URL=wss://vpn.example.com/wg
```

peer 不需要写 Endpoint，连接目标由 `WG_WS_URL` 决定。全局模式（`AllowedIPs = 0.0.0.0/0`）可以直接用：wg-quick 设置的 fwmark 会应用到 WebSocket 的 TCP 连接上，这些连接不会被路由进隧道本身。

#### 启动

手动启动（两端相同）：

```
set -a; . /etc/wireguard/ws0.ws; set +a
ws-wg-quick up ws0
```

确认连通：

```
wg show ws0          # 看 endpoint、latest handshake、transfer
ping 10.0.0.1        # 在客户端上
```

### 用 systemd 管理

`/etc/systemd/system/ws-wg-quick@.service`。它是照官方 `wg-quick@.service` 写的，尚未在 systemd 上实测：

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
systemctl reload ws-wg-quick@ws0     # 修改 ws0.conf 中的 peer 后热加载
```

只要端口不变，reload 不会断开现有的 WebSocket 连接。例外是服务端用 `--listen` 写死了端口、`ws0.conf` 里又没写 `ListenPort`：这时 `wg syncconf` 发送的 listen-port 是 0，和实际端口不一致，所有连接会重连一次（会话密钥保留）。按上面的例子用 `ListenPort` 设置端口就不会这样。修改 `ws0.ws`（传输选项）后需要 `systemctl restart`。

### 与内核 WireGuard 共存（混合部署）

常见情况：有些服务器公网 UDP 可达，直接用内核 WireGuard；有些只能通过 80/443 的反代访问，用 ws-wireguard-go。两者可以在同一台机器上共存。要记住的原则是**一个接口只用一种传输**：内核接口走 UDP，ws-wireguard-go 的接口走 WebSocket，同一个接口里不能有的 peer 走 UDP、有的走 WebSocket。所以按传输方式把 peer 拆到不同的接口上：

```
/etc/wireguard/wg0.conf    # 内核模块，UDP，连公网 UDP 可达的服务器
/etc/wireguard/ws0.conf    # ws-wireguard-go，连 a.example.com 反代后面的机器
/etc/wireguard/ws0.ws
/etc/wireguard/ws1.conf    # ws-wireguard-go，连 b.example.com 反代后面的机器
/etc/wireguard/ws1.ws
```

```
systemctl enable --now wg-quick@wg0       # 内核接口，照旧
systemctl enable --now ws-wg-quick@ws0    # WebSocket 接口
systemctl enable --now ws-wg-quick@ws1
```

`wg show` 会同时列出两类接口，管理方式一样。需要注意：

- **WebSocket 接口不要用原版 `wg-quick up` 或 `wg-quick@ws0` 启动**。内核模块存在时，原版会悄悄建一个内核接口走 UDP。看起来启动成功了，但在只开 80/443 的环境里不通。给 WebSocket 接口起 `ws0` 这类名字，能少犯这个错。
- **一个 WebSocket 客户端接口只对应一个服务端 URL**。要连多台在不同反代后面的机器，就每台一个接口（ws0、ws1……），各自一个 `.ws` 文件。
- **不同接口的地址段和 AllowedIPs 不能重叠**，内核按路由决定报文走哪个接口。
- **全局模式（0.0.0.0/0）最多给一个接口**。其它接口在 `[Interface]` 中写上与它相同的 `FwMark`（用 `wg show <接口> fwmark` 查看，wg-quick 默认用 51820），这样其它接口自己的传输流量（UDP 或 WebSocket 的 TCP）就会绕过全局隧道直接出去，否则会被套进全局隧道里。
- **目标机上也可以混合**：例如一台机器既有 UDP 可达的 peer，又要接受反代转来的 WebSocket 连接，就同时运行内核的 `wg0` 和服务端模式的 `ws0`。需要在两个网段之间转发时，打开 `net.ipv4.ip_forward` 并配好路由和 AllowedIPs。

### 直接提供 wss（不用反代）

目标机的 443 端口没被别的服务占用时，可以让 ws-wireguard-go 直接提供 TLS：

```
WG_WS_MODE=server
WG_WS_LISTEN=0.0.0.0:443
WG_WS_PATH=/wg
WG_WS_TLS_CERT=/etc/letsencrypt/live/vpn.example.com/fullchain.pem
WG_WS_TLS_KEY=/etc/letsencrypt/live/vpn.example.com/privkey.pem
```

证书在每次接口启动（包括 listen-port 变更）时重新读取，续期后执行 `systemctl restart ws-wg-quick@ws0` 即可生效。

### 不用 wg-quick

```
ws-wireguard-go --mode client --url wss://vpn.example.com/wg ws0
wg setconf ws0 <(wg-quick strip ws0)
ip address add 10.0.0.2/24 dev ws0
ip link set ws0 up
```

## 注意事项

- **两端都必须是 ws-wireguard-go**，它不能和走 UDP 的标准 WireGuard 互联。
- **保活**：客户端的 WebSocket ping 只能保证连接本身不因空闲被断开。服务端只有在客户端连上来、并且在这条连接上发过报文之后，才知道去哪里找客户端。所以如果服务端需要主动访问客户端，客户端应设置 `PersistentKeepalive`，和 NAT 后面的客户端一样。
- **服务端重启**：客户端会立即重连，但旧的会话密钥已经随服务端一起失效，要等 WireGuard 在约 15 秒收不到回复后自己重新握手（Keepalive-Timeout + Rekey-Timeout）。这与 UDP 下服务端重启的表现相同。只修改监听端口不会出现这个等待。
- **TCP over TCP**：隧道内的 TCP 跑在 WebSocket 的 TCP 之上，在丢包严重的链路上表现会比 UDP 差，这是所有基于 TCP 的隧道的共性。WebSocket 没有 IP 分片问题，MTU 只决定隧道内报文的大小，保持默认的 1420 即可。
- **安全**：认证和加密完全由 WireGuard 负责，没有通过握手的连接发来的数据都会被丢弃。WebSocket 路径可以当作额外的暗号：非 WebSocket 请求或路径不对，一律返回 404。连接数限制之类可以在反向代理上配置。

## 测试

- `go test ./...`：单元测试，以及两个 WireGuard 设备通过 WebSocket 互相 ping 的集成测试，含客户端、服务端重启。
- `tests/ws-netns.sh ./ws-wireguard-go`：用真实的 TUN 设备、network namespace 和 `wg` 工具做端到端测试，需要 root。覆盖 ws、wss、服务端与客户端重启、后台运行、环境变量配置，以及全局模式下的 fwmark。

## 代码结构

| 路径 | 内容 |
|---|---|
| `conn/wsbind/wsbind.go` | `conn.Bind` 实现的公共部分：选项、Open/Close/Send、收包队列 |
| `conn/wsbind/server.go` | 服务端：HTTP 监听、WebSocket 升级、真实 IP |
| `conn/wsbind/client.go` | 客户端：按需拨号、排队、退避重连、ping |
| `conn/wsbind/mark_*.go` | 各平台的 fwmark 设置 |
| `options.go`、`main.go`、`main_windows.go` | 命令行选项与环境变量 |
| `conn/conn.go`、`device/uapi.go` | `conn.DefaultEndpointer`：没有 Endpoint 的 peer 使用客户端的服务端 URL；listen-port 不变时不重新绑定 |
| `contrib/ws-wg-quick` | wg-quick 包装 |
| `tests/ws-netns.sh` | 端到端测试 |

## License

    Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
    
    Permission is hereby granted, free of charge, to any person obtaining a copy of
    this software and associated documentation files (the "Software"), to deal in
    the Software without restriction, including without limitation the rights to
    use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
    of the Software, and to permit persons to whom the Software is furnished to do
    so, subject to the following conditions:
    
    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.
    
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
