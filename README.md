# newppp

WebTransport (QUIC/HTTP-3) 代理。

```
客户端 (SOCKS5/HTTP 代理)                          服务端
┌─────────────────────────┐        ┌──────────────────────────────┐
│ socks5 :1080  http :8081│        │ UDP 443  WebTransport (h3)   │ ← 主路径
│   └─ 连接池 (1..8 QUIC) │══QUIC══│ TCP 443  TLS POST 降级 (模式A)│
│   └─ E2E: HKDF+ChaCha20 │        │ TCP 80   301→https + ACME    │
└─────────────────────────┘        │ 内嵌伪装页 (nginx 欢迎页风格)   │
                                   └──────────────┬───────────────┘
                                                  ↓ dial
                                             目标 TCP / UDP
```

UDP 443 与 TCP 443 可由**同一进程**监听（协议不同不冲突），单机即可承载全链路；生产档位 1 下 UDP 443 由 nginx stream 透传、TCP 443 由 nginx 终止（详见 `deploy/nginx.conf`）。

## 部署形态

### 形态 A：完整形态（默认）

服务端监听 UDP 443（WebTransport 主路径）+ TCP 443（降级/伪装站）+ 80（301 门面）。客户端带 `--server` 与 `--url`，WT 不可用时自动落到降级通道。性能最优。

### 形态 B：纯网站形态（隐蔽切换）

把流量全部收敛到 `/api/ppp`（TCP 443 的模式 A 通道），TCP/UDP 代理都从这条双工 POST 走：

- 客户端只传 `--url`，去掉 `--server` —— 不碰 UDP；
- 服务端**省略 `--listen`** —— UDP 443 完全不监听，机器上不存在 UDP 套接字，**无需任何防火墙规则**。

服务端形态 B 示例：

```bash
newppp -s --auth alice:secret123 \
  --fallback-listen 0.0.0.0:443 \
  --http-listen     0.0.0.0:80 \
  --cert ./_.love4z.cn.pem --key ./_.love4z.cn.key
```

形态切换只改启动参数，密钥与 `/api/ppp` 不变。

### 形态 B-CF：Cloudflare 橙云变体

Cloudflare 标准代理会**缓冲完整请求体后才回源**（免费 100MB 上限同理），无限长的双工 POST 永远等不到结束 → 请求根本到不了源站；WT 主路径也不可行（CF 在边缘终止 h3，QUIC 不透传）。因此套 CF 必须换 WebSocket 承载：

- 客户端 `--url wss://newppp.love4z.cn/api/ppp`（scheme 由 https 换成 wss）；
- 服务端不变（`/api/ppp` 同时接受 POST 与 WS 升级，认证流程相同）；
- CF 侧无需任何配置（免费版完整支持 WebSocket，双向流式、无体积上限）；
- 内置 30s WS 层心跳防 CF 空闲断连。

**形态 B 的性能代价**：UDP 包改走可靠有序的 TLS 流，丢包会队头阻塞——DNS/普通请求无感（实测 DNS ~170ms），游戏等实时 UDP 受损。按威胁模型与用途选择形态，或随时切换。

**探测面的三层账**（为什么形态 B 更隐蔽但不"隐身"）：

| 探测层 | 形态 A (WT) | 形态 B (/api/ppp) |
|---|---|---|
| 端口扫描 | UDP 443 暴露"QUIC 服务" | ✅ 只有一个 TLS 网站端口（UDP 不监听，连"被过滤端口"的痕迹都没有） |
| 协议指纹 | quinn 指纹≠Chrome（主动探测可辨） | ✅ 无 QUIC 可探测 |
| 流量形态 | 长连接多流（像视频/云盘） | 无限长双向 POST/WS（内容级分析仍可标记）|

### 域名路由速查：走不走 CF 看云朵，不看 scheme

CF 路由由域名的 **DNS 代理状态**决定（橙云=代理、灰云=仅 DNS 直连）；`https://` / `wss://` 只是承载方式（双工 POST / WebSocket），与是否经过 CF 无关：

| 配置 | 实际走向 | 可用性 |
|---|---|---|
| `--url https://灰云域/api/ppp` | 直连 VPS | ✅ 速度最优的 POST 兜底 |
| `--url wss://灰云域/api/ppp` | 仍直连（wss 不会"激活"CF） | ✅ 与上行等价 |
| `--url https://橙云域/api/ppp` | 走 CF | ❌ CF 缓冲完整 POST 请求体才回源，双工 POST 永远到不了源站 |
| `--url wss://橙云域/api/ppp` | 走 CF | ✅ 橙云下唯一可用承载（WS 不被缓冲，免费版完整支持） |
| `--server` 指向橙云域 | WT 会话在 CF 边缘被终止 | ❌ CF 不透传 QUIC/WebTransport，主路径必须灰云域 |

**推荐组合**：`--server https://灰云域`（WT 主路径保带宽）+ `--url https://灰云域/api/ppp`（直连 POST 兜底，远快于经 CF）；仅当需要隐藏源站 IP 时，才把兜底换成 `--url wss://橙云域/api/ppp`（代价是 CF 免费版链路可能很慢，实测有低至 ~50KB/s 的情形）。

## 快速开始

### 服务端（单进程全链路，自签调试）

```bash
newppp -s --auth alice:secret123 --self-signed \
  --listen          0.0.0.0:443 \    # UDP: WebTransport 主路径
  --fallback-listen 0.0.0.0:443 \    # TCP: 伪装站 + 降级 API (h2/h1 自动协商)
  --http-listen     0.0.0.0:80       # 80: 301 → https（可选）
```

* UDP 443 与 TCP 443 不冲突，一个进程全占；防火墙放行 UDP 443 / TCP 443 / TCP 80。
* 80 端口是纯门面：一切请求 301 → `https://同Host/原路径`（带 HSTS），明文 API 已关闭。
* `--acme-dir /var/www/acme` 可选：在 80 上服务 Let's Encrypt http-01 验证文件（`certbot certonly --webroot -w /var/www/acme -d your.domain`），token 白名单校验防路径穿越。
* 未认证访问 443 伪装站与降级端点，得到的都是 nginx 欢迎页风格的 200 页面。

### 客户端

```bash
newppp -c --auth alice:secret123 \
  --server https://your.domain:443 \
  --url https://your.domain/api/ppp \
  --bind 127.0.0.1:1080 --http-bind 127.0.0.1:8081
```

* `--server` 与 `--url` 至少配一个；两者都配时 WT 优先、失败自动降级（连续传输层故障会熔断主路径一段时间，见「架构→降级链」）。
* **形态 B（纯网站形态）**：去掉 `--server` 只留 `--url`，并使用省略 `--listen` 的服务端（见上）；套 Cloudflare 时 `--url` 换成 `wss://`（见形态 B-CF）。
* 自签调试加 `--skip-verify`；换成 Let's Encrypt 证书后**去掉**该参数（走系统根证书校验）。
* 绑 `0.0.0.0`（NAS/局域网共享）时建议加 `--inbound-auth user:pass`：SOCKS5 走 RFC1929 用户名/密码、HTTP 代理走 Basic Auth，凭证用常量时间比较；不配则本地入站无认证。

### 验证

```bash
curl --socks5-hostname 127.0.0.1:1080 https://www.google.com
curl -x http://127.0.0.1:8081 https://www.google.com

# 启用 --inbound-auth user:pass 后：
curl --socks5-hostname user:pass@127.0.0.1:1080 https://www.google.com
curl -x http://user:pass@127.0.0.1:8081 https://www.google.com
```

## Docker 打包（build_docker.py）

把静态 musl Linux 二进制直接封装成标准 `docker save` 格式（v1.2）镜像 tar——**本机无需安装 Docker**，拷到任意有 Docker 的机器（服务器/NAS）直接 `docker load`。

### 前置：先出 Linux 二进制

```bat
build_linux.bat
```

产物 `target\x86_64-unknown-linux-musl\release\newppp`（静态链接，无需 libc）。

### 打包

```bash
py -3 build_docker.py                 # 交互输入版本号，生成 newppp-<版本号>.tar
```

把参数直接**烧进镜像**（推荐 NAS/无 shell 场景——容器管理器里不再需要填运行命令）：

```bash
py -3 build_docker.py --version 1.0.0 \
  --args '-c --auth alice:secret123 --server https://newppp2.love4z.cn --url wss://newppp.love4z.cn/api/ppp --bind 0.0.0.0:1080' \
  -o newppp-client-1.0.0.tar --tag newppp-client:1.0.0
```

| 选项 | 说明 |
|---|---|
| `--binary` | 二进制路径，默认 `target\x86_64-unknown-linux-musl\release\newppp`（自动校验 ELF/64 位） |
| `--version` | 版本号（不传则交互输入，作为镜像 tag 与 OCI label） |
| `--args` | 烧进镜像 Cmd 的启动参数，必须以 `-c` 或 `-s` 开头；`-c` 时 ExposedPorts 自动变为 1080/tcp |
| `--tag` / `-o` | 镜像标签与输出文件名，默认 `newppp:<版本号>` / `newppp-<版本号>.tar` |

### 导入与运行

```bash
docker load -i newppp-client-1.0.0.tar

# 服务端容器（自签调试；正式部署挂载证书改用 --cert/--key）
docker run -d -p 80:80 -p 443:443/tcp -p 443:443/udp newppp:1.0.0 -s \
  --auth alice:secret123 --listen 0.0.0.0:443 \
  --fallback-listen 0.0.0.0:443 --http-listen 0.0.0.0:80 --self-signed

# 客户端容器
docker run -d -p 1080:1080 newppp-client:1.0.0
```

### NAS 容器管理器要点

* 镜像 Cmd 已含完整启动参数时，**「容器运行命令」留空保持默认**，不要填——多数管理器会把整行命令当成单个参数导致 `container startup failed`。
* 端口映射只加 `本地端口 → 1080/TCP`（客户端）；443/udp、80 是服务端端口，客户端容器不需要。
* 容器内必须绑 `0.0.0.0`（如 `--bind 0.0.0.0:1080`），写 127.0.0.1 会导致映射失效。
* `--args` 里的密码会写进镜像配置（`docker inspect` 可见），镜像 tar 请妥善保管。
* **已知问题：容器内无法校验证书**（scratch 基座没有系统 CA 根证书，WT/wss 均报 `UnknownIssuer`）。应急：`--skip-verify`（不推荐生产）——内层 E2E（密码派生密钥 + AEAD）仍认证加密，窃听解不开流量，但失去 TLS 层服务器身份校验，中间人可盲转发或拒绝服务。正解：把系统 CA 烤进镜像（TODO.md「快速收益」#2），客户端挂载 `SSL_CERT_FILE` 方案实测走不通。

## 生产部署

### 档位 3：后端直出（无 nginx，单进程）

即上方快速开始的服务端命令，`--cert/--key` 换成真实证书（Let's Encrypt，`--acme-dir` 支持 http-01 续期）。伪装站与代理逻辑耦合在一个进程里，改伪装页要动后端。

### systemd 常驻（deploy/newppp.service）

档位 1 / 档位 3 的服务端都建议用 systemd 常驻。项目自带单元文件 `deploy/newppp.service`（含 `Restart=on-failure` 自动拉起与 `NoNewPrivileges`/`ProtectSystem=strict`/`ProtectHome`/`PrivateTmp` 加固）。

1. **放置二进制与证书**：

   ```bash
   sudo install -m 755 newppp /usr/local/bin/newppp
   sudo useradd -r -s /usr/sbin/nologin newppp     # 专用系统用户
   sudo mkdir -p /etc/newppp
   sudo cp cert.pem key.pem /etc/newppp/
   sudo chown -R newppp:newppp /etc/newppp
   sudo chmod 600 /etc/newppp/key.pem
   ```

2. **改 `ExecStart`**（单元文件内备好两种档位，改用户密码即可）：
   * 档位 1（nginx 前置，默认段）：后端只听回环 `--listen 127.0.0.1:8443 --fallback-listen 127.0.0.1:8444`；
   * 档位 3（后端直出，注释段）：`--listen 0.0.0.0:443 --fallback-listen 0.0.0.0:443`，防火墙放行 UDP/TCP 443、TCP 80。

3. **安装并启用**：

   ```bash
   sudo cp deploy/newppp.service /etc/systemd/system/newppp.service
   sudo systemctl daemon-reload
   sudo systemctl enable --now newppp
   ```

4. **验证**：

   ```bash
   systemctl status newppp
   journalctl -u newppp -f          # 应出现 "newppp server started (...)"
   ss -ulnp | grep 8443             # 档位1确认 UDP 监听
   ```

> 注意：`ProtectSystem=strict` 下整个文件系统只读，`/etc/newppp` 证书保持可读即可，不要把运行时需写的目录放进单元；`--self-signed` 开发模式写 `/tmp`，`PrivateTmp` 已覆盖。

### 简易常驻：screen

不想配 systemd 时，用 `screen` 把服务端挂后台（需先 `apt install screen` 或 `yum install screen`）。注意这只是简易方案：**开机不自启、崩溃不拉起**，长期运行请用上面的 systemd。

1. **创建会话并启动**：`session_name` 自取，回车后进入会话窗口，正常输入启动命令：

   ```bash
   screen -S newppp
   newppp -s --auth alice:secret123 --listen 0.0.0.0:443 \
     --fallback-listen 0.0.0.0:443 --http-listen 0.0.0.0:80 \
     --cert /etc/newppp/cert.pem --key /etc/newppp/key.pem
   ```

2. **分离会话**：按 `Ctrl+a` 再按 `d`——暂时退出窗口，进程继续在后台跑，可安全断开 SSH。

3. **重新连接**：

   ```bash
   screen -r newppp     # 回到会话（即可看到服务端日志）
   screen -ls           # 列出所有会话
   ```

4. **关闭会话/停止服务**：`screen -r newppp` 回到会话后，`Ctrl+C` 停掉服务端，再输入 `exit` 关闭会话；或一步到位（不进会话直接杀掉）：

   ```bash
   screen -S newppp -X quit
   ```

客户端同理：把启动命令换成 `-c ...` 参数即可。

### 档位 1：nginx 前置

nginx 无法反代 WebTransport/h3 会话，职责划分（`deploy/nginx.conf`）：

1. **UDP 443**：nginx `stream` 模块透传给后端 `--listen`（后端用同一张证书终止 QUIC-TLS）。
2. **TCP 443**：nginx 终止 TLS，`/api/ppp` 反代后端 `--fallback-listen`（降级），其余路径服务伪装静态站。
3. 服务端 systemd 直跑（`deploy/newppp.service`），双监听 `127.0.0.1:8443` / `127.0.0.1:8444`。
4. 证书：certbot（Let's Encrypt），证书同时给 nginx（TCP）与后端（QUIC）。
5. 防火墙仅放行 UDP 443 / TCP 443 / TCP 80。

所有流式路径必须 `proxy_request_buffering off; proxy_buffering off;`（见 nginx.conf），否则交互流量会被缓冲；本实现已发送 `X-Accel-Buffering: no`。

### 档位 2：Cloudflare 前置

CF 的代理模型是"**边缘终止一切，仅 TCP 回源**"——QUIC/UDP 在标准橙云代理下到不了源站。各路径可行性（均零代码改动）：

| 路径 | 可行性 | 原因 |
|---|---|---|
| WT 主路径穿 CF | ❌ | CF 边缘终止 QUIC，不转发 WT 会话（会话流被重置；客户端会自动回落） |
| WS/POST 通道用 QUIC | ❌ | 回源仅 TCP；客户端 wss 走 h1.1 升级，本就不经 QUIC |
| HTTP/3 回源 | ❌ | CF 即便 h3 回源也只发普通 h3 请求，源站 UDP 443 只应答 WT 会话 |
| Workers 桥接 | ❌ | Workers `connect()` 仅 TCP，无 UDP socket |
| cloudflared Tunnel | ❌ | cloudflared↔边缘之间是 QUIC，但客户端侧仍是 HTTP |
| **Spectrum** | ⚠️ 唯一例外 | L4 代理可转发 UDP：UDP 443 直通源站则 WT 全链路可用（付费，Enterprise/加购） |

**橙云下唯一可行承载是 WebSocket 降级通道（形态 B-CF）**：

1. DNS 橙云代理 `newppp.love4z.cn`（免费版即可，无需开启任何 WS 开关——CF 默认支持）；
2. SSL/TLS 模式建议 Full（strict）；
3. 客户端 `--url wss://newppp.love4z.cn/api/ppp`，其余不变；
4. 注意 WS 单条消息上限与空闲超时由 CF 管理：本实现帧 ≤~17KB、30s 心跳，均在安全范围内；
5. 服务端日志中 WS 通道与 POST 通道均表现为 mode-A 连接（认证/限速/回收逻辑一致）。

**推荐组合拳（免费、兼顾隐藏与性能）**：主域名橙云走 wss 保底，另开一个**灰云子域**（如 `wt.love4z.cn`，仅 DNS，A 记录指向源站）专跑 WT 主路径；客户端两个都配——WT 走灰云子域，传输层故障自动回落到橙云 wss 通道（不要求隐藏源站 IP 时，把兜底换成灰云直连 POST 更快，见「域名路由速查」）：

```bash
newppp -c --auth alice:secret123 \
  --server https://wt.love4z.cn \
  --url wss://newppp.love4z.cn/api/ppp \
  --bind 127.0.0.1:1080 --http-bind 127.0.0.1:8081
```

若完全不需要隐藏源站 IP，全灰云直连（`https://` POST 通道 + WT 主路径）延迟最低。

## 服务端参数

| 参数 | 默认 | 说明 |
|---|---|---|
| `--auth` | 必填 | `user:pass`，可重复注册多用户（uid 限 `[A-Za-z0-9_-]{1,32}`） |
| `--time` | pool.ntp.org | 内部时钟的 NTP 服务器（客户端+服务端均可用，见下方「内部时钟」） |
| `--listen` | - | WebTransport (QUIC/UDP) 监听；**省略则完全不监听 UDP**（形态 B 纯网站形态）。注意：提供时仅端口生效，IP 部分被忽略（总是绑定全部接口） |
| `--cert/--key` | - | TLS PEM（或 `--self-signed` 自签调试） |
| `--fallback-listen` | - | TLS TCP 降级/伪装站监听（模式 A POST + WebSocket 双承载） |
| `--http-listen` | - | 80 门面：301 → https + 可选 ACME 验证（明文 API 不可用） |
| `--acme-dir` | - | certbot http-01 验证文件目录 |
| `--path` | /api/ppp | 降级端点路径 |
| `--max-sessions` | 200 | 全局并发会话上限 |
| `--rate` | 100 | 每连接限速 Mbps（0 不限） |
| `--idle` | 60 | 空闲会话回收秒数 |
| `--recv-window` | 2 | QUIC 每流接收窗口 MB（1..=64，上传方向） |
| `--log` | info | 日志级别（trace/debug/info/warn/error） |

## 客户端参数

| 参数 | 默认 | 说明 |
|---|---|---|
| `--auth` | 必填 | `user:pass`（取第一组） |
| `--time` | pool.ntp.org | 内部时钟的 NTP 服务器（客户端+服务端均可用，见下方「内部时钟」） |
| `--server` | - | WT 服务端 URL（https://host[:port][/path]） |
| `--url` | - | 模式 A 降级 URL，scheme 决定承载：`https://`（双工 POST，直连用）或 `wss://`（WebSocket，套 Cloudflare 必用）；与 `--server` 至少配一个 |
| `--bind` | 127.0.0.1:1080 | SOCKS5 监听（CONNECT / UDP ASSOCIATE） |
| `--http-bind` | - | HTTP 代理监听（CONNECT + 简单转发，出口失败回 502） |
| `--inbound-auth` | - | 本地入站认证 `user:pass`：SOCKS5 RFC1929 用户名/密码 + HTTP 代理 Basic Auth；不配则无需认证（绑 `0.0.0.0` 时建议启用） |
| `--conns` | 2 | 连接池大小（1..8） |
| `--recv-window` | 2 | QUIC 每流接收窗口 MB（1..=64，下载方向）：优质高延迟线路可调大提速，高丢包调小抗 `too many gaps` |
| `--skip-verify` | off | 跳过证书校验（仅调试） |
| `--log` | info | 日志级别（trace/debug/info/warn/error） |

## 架构

| 路径 | 说明 |
|---|---|
| **WebTransport (h3/QUIC)** | 主路径。TCP 会话 = 1 条 bidi 流；UDP = QUIC DATAGRAM（超 MTU 自动落流降级）；控制帧走首条控制流 |
| **HTTPS POST（模式 A 降级）** | 单个双工 POST，请求/响应 Body 承载全部帧协议（TCP+UDP），SessionID 多路复用（DashMap + 有界 mpsc，容量 256） |
| **WebSocket（模式 A 变体）** | 同一套帧协议与认证，承载在一条 WebSocket 双工通道上（`wss://`）；专供 Cloudflare 等会缓冲请求体的代理环境使用 |

降级链：`WebTransport → HTTPS POST`，**按错误类型**切换：

* **传输层故障**（连接断、握手超时、`too many gaps` 等协议层异常）→ 杀掉该连接并回落 HTTPS POST，会话在降级通道上重建；
* **目标侧拒绝**（服务端拨号失败 `DialFailed`、目标非法、限额）→ 按会话直接返回错误：降级通道拨的是同一个目标、走同一个服务端，回退只会重复同样的失败，还会白白摧毁一条承载着其他会话的健康 QUIC 连接（仅限额类错误会尝试回退，因为降级通道有独立容量）；
* **熔断器**：连续 3 次传输层故障后主路径熔断 60s，期间新会话直接走兜底、零试错；到期放行一次探测，成功恢复、失败立即再熔断。目标侧拒绝不计入——那说明传输本身是健康的。

### 帧协议（20 字节定长头，小端）

```
0     1     2     4     8     12         20
+-----+-----+-----+-----+-----+----------+
| ver | type|flags| sid |ctlen| counter  | + ciphertext||tag
+-----+-----+-----+-----+-----+----------+
```

* `type`：Auth / AuthOk / Open / OpenOk / OpenErr / Data / Close / Ping / Pong / UdpAssociate / UdpOk / UdpData / Error
* `flags`：FIN（半关闭）、RST（中止）
* AAD = 头部前 12 字节；计数器即 AEAD nonce（流通道 < 2^63，数据报通道 ≥ 2^63，保证 nonce 不重不乱）
* 数据报接收端带 64 位滑动窗口抗重放

### 加密与认证

* 外层：QUIC-TLS（合法证书，标准握手）——QUIC 强制 TLS 1.3，流量全加密
* 内层 E2E：`static_key = HKDF-SHA256(password, salt="newppp-v1", info="newppp/auth/<uid>")`；会话密钥 = HKDF(static_key, 客户端随机 salt)；ChaCha20-Poly1305
* 双重认证：`Authorization: Bearer <uid>.<ts>.<nonce>.<HMAC>`（±60s 时间窗，饱和比较防溢出 + nonce 防重放缓存：同一 token 只接受一次；容量 5 万，按时间戳过期自动清理，不会整表清空）+ 首帧 AUTH（静态密钥封装，携带 salt 换会话密钥，nonce 同样防重放）
* **认证失败不返回 401**：WT 会话请求返回 404；HTTP 降级端点返回伪装页（200）
* 只用标准 Header，UA 伪装 Chrome
* 隐私边界与威胁模型取舍见下方「隐私与安全模型」章节

### 内部时钟（NTP 校准）

认证时间戳有 ±60s 窗口，要求两端时钟大致一致。现实部署中客户端机器时钟漂移几十秒并不罕见（**快 60s 以上时认证全部被拒**，表现为 `server rejected WebTransport session request` / `server rejected authentication`）。为此进程不直接信任系统时钟：

* 内部维护 UTC 时钟 `now = 系统时钟 + offset`，offset 由 SNTP 校准得出（内置客户端，无额外依赖）；
* **启动时立即同步一次，之后每 1 小时重新校准**；
* `--time` 可指定 NTP 服务器（`pool.ntp.org` 默认，支持 `host` / `host:port`）；
* 首次同步成功前退化为系统时钟；同步失败不阻塞启动、保留旧 offset 并告警；
* 客户端与服务端都校准：即使两端各差几十秒，校准后都贴近真实 UTC，±60s 窗口自然满足。

```bash
newppp -c ... --time ntp.aliyun.com     # 客户端
newppp -s ... --time 203.107.6.88:123   # 服务端
```

### 会话生命周期与稳健性

* **全局会话配额恰好一次释放**：配额释放与"注册句柄被移除"严格绑定——数据泵、空闲回收器、关闭帧三方竞争清理时不会重复释放或泄漏，杜绝配额漂移导致的服务器假死。
* **半关闭语义正确**：客户端 FIN 只关闭发送方向，服务端响应可继续传完（WT 专用流与模式 A 复用通道行为一致）；只有 RST/协议错误/连接销毁才中止整条会话。
* **数据报自愈**：单个损坏的 QUIC 数据报只丢弃其缓冲即恢复解析，不影响后续帧（防重放滑动窗口保留，不因错帧重置）。
* **代理入站失败可见**：SOCKS5/HTTP 入站的出口拨号失败时，HTTP 代理回 `502 Bad Gateway` 而非直接断连。
* **错误分类，连接不被误杀**：服务端拒拨等目标侧错误不会触发重连 churn；连接池 `acquire` 跳过满载连接、维护循环裁剪空载超编连接，被退役的连接会**显式关闭** QUIC 会话（不会因后台任务持有连接克隆而泄漏到服务端）。
* 超时兜底：握手 10s、出口拨号 10s、降级 POST 响应头 30s、空闲会话按 `--idle` 回收。

### 背压与容量

* 背压完全依赖 QUIC 流控（本地 TCP 阻塞 → 停读 → 对端停写），不做应用层流控
* 会话上限：客户端每连接 ≤ 50、服务端每连接 ≤ 64；连接池 1..8 条（自动补活）；全局会话上限 200（`--max-sessions`）
* 每连接令牌桶限速（`--rate` Mbps）；空闲会话 60s 回收（`--idle`）；无会话且无数据活动的空连接 3×`--idle` 回收（keepalive Pings 不计入，服务端主动关闭 QUIC，客户端自动重连）；30s PING 保活
* 100 并发流 × 64KB 会话缓冲 ≈ 数十 MB 内存；1Gbps 下 ChaCha20 约占 1 核

## 隐私与安全模型

**密码学底线两条路径等价**：所有代理帧（目标地址、payload、UDP 数据）都在内层 E2E 加密里（ChaCha20-Poly1305 + 每连接随机 salt 派生的会话密钥）——**CF 在任何情况下只能看到密文帧**，这是架构保证，不依赖 CF 的善意。"隐私"的差异在元数据层：

### wss + CF（橙云）

| 维度 | 状况 |
|---|---|
| 内容机密性 | ✅ E2E 层保证，CF 解不开帧 |
| CF 能看到 | ⚠️ SNI/域名、**Bearer 头里的 uid（明文）**、流量大小/时序/时长 |
| CF 看不到 | ✅ 目标主机、payload、DNS 查询、UDP 目标 |
| 信任代价 | ⚠️ CF 是"合法中间人"：受法律强制、可记录审计——等于多信任一方 |
| 附带收益 | ✅ 源站 IP 隐藏、L3/L4 DoS 由 CF 吸收、IP 不进 DNS 历史 |
| 隐蔽性风险 | ⚠️ 长连 WS 双向二进制流是可指纹的代理模式；CF 可挑战/限流；免费版无 SLA |

### 直连 UDP（灰云）

| 维度 | 状况 |
|---|---|
| 内容机密性 | ✅ 同样靠 E2E 层；QUIC-TLS 端到端（自己的证书，无中间人） |
| 元数据 | ✅ 无第三方中间人，只有两端 ISP 能看到"有 QUIC 流量到某 IP" |
| 最大弱点 | ❌ **源站 IP 公开**：域名直接解析到 VPS，DNS 历史会永久暴露 |
| 隐蔽性 | ❌ 主动探测可识别 quinn 指纹；跨境 UDP 常被 QoS/阻断（弱网 `too many gaps` 即此现实） |
| DoS 面 | ❌ 源站直接暴露，L3/L4 攻击自己扛 |

### 两条路径共同的真实弱点（比选路更重要）

1. **密钥根是 `HKDF(password)`，不是慢哈希 KDF**（无 Argon2/PBKDF2）。攻击者捕获 bearer/AUTH 材料后可**离线爆破弱密码**——密码必须强随机，这是整个体系真正的根。
2. 服务器本身知道一切（目标、流量），自建节点的固有边界，与传输无关。
3. `--skip-verify` 只限调试；生产两条路径都走真实证书链，服务器身份验证完整。

### 取舍结论

* **内容机密性**：两者等价，前提是密码够强。
* **元数据隐私**：直连略优（无中间人），代价是 IP 暴露 + 指纹/阻断风险。
* **抗封锁/隐蔽性**：wss+CF 优（探测面只有一个普通网站）。
* 组合方案见档位 2：灰云子域跑 WT 主路径 + 橙云 wss 兜底。

## 已知限制 / 风险

* **套 Cloudflare 时不要配 `--server`（WT 主路径）**：CF 边缘接受 h3 但不支持 WebTransport，会重置 WT 会话流——旧版 wtransport(0.6) 会因此 panic（0.7.2 已修复，重置被正常归类为连接错误并自动回落）；CF 后请用 `--url wss://`（见档位 2）。
* `--listen` 提供时仅端口生效（wtransport 绑定 API 限制），总是绑定全部接口；需要限定地址时用防火墙/iptables 收敛，或省略 `--listen` 完全不监听 UDP。
* 服务端对未认证连接数无显式上限（依赖 QUIC/TLS 层自身的限流）。
* quinn 的 QUIC/TLS 指纹与 Chrome 不同；主动 QUIC 指纹探测可区分（被动分类无特征）。缓解方向见 TODO.md「QUIC/TLS 指纹混淆」（拟合 Chrome 传输参数与 ClientHello）。
* `too many gaps in stream buffer`：quinn 对流重组缓冲乱序空洞数的内部保护，丢包/乱序严重的弱网 UDP 链路 + 大接收窗口下会触发，触发后该连接中止、会话自动回落 HTTPS POST。接收窗口默认 2MB（300ms RTT 单流 ≈ 53Mbps），可用 `--recv-window` 调节（1..=64 MB）：高丢包调小（如 1）、优质高延迟线路调大提速。
* **WT 主路径熔断**：连续 3 次传输层故障（连接被杀、握手失败等）后熔断 60s，期间新会话直接走兜底不再试错；到期放行一次探测，成功恢复、失败立即再熔断。目标侧拒绝（拨号失败/限额）不计入——那是传输健康、目标不可达。
* UDP 443 不应答普通 h3 GET（也不发 Alt-Svc）：浏览器不会来（无 Alt-Svc），但定制探测工具可发现"这个 QUIC 服务不是网页"；WT 握手探测则得到 404，与"不支持 WT 的普通源"一致。根治需换 quinn+h3 栈实现 GET/WT 同端口共宿——留作后续演进（TODO.md「暂缓项」）。
* 流量形态：长连接多流持续传输（像视频会议/云盘），内容级分析对任何形态都有告警可能。
* 降级路径（模式 A）依赖 nginx 关闭缓冲；本实现已发送 `X-Accel-Buffering: no`。
* UDP 数据报 >路径 MTU 时自动改走可靠流（PMTUD 上限 ~1200B 设计）；形态 B 下 UDP 全走可靠流。

## 构建与质量门

```bash
cargo build --release                              # 产物 target/release/newppp
cargo fmt --all -- --check                         # 格式检查
cargo clippy --all-targets -- -D warnings          # 静态检查（0 警告基线）
cargo test                                         # 单元测试 + property 测试（49 项，含回归）
cargo bench --bench frame                          # 帧热路径 criterion 基准
```

代码基线：无 `unsafe`、无 `#[allow]` 压制、无未用依赖；TLS/加密统一走 `ring`（已移除 `aws-lc-rs`，构建无需 cmake/nasm）；edition 2021，开发工具链 Rust 1.97（未声明 MSRV，建议用最新 stable 构建）。

## 性能（帧热路径）

每帧的加密与封装是代理吞吐的核心。`benches/frame.rs`（criterion）对 64B / 1KB / 16KB 负载分别测量裸 AEAD 与整帧编解码；生产路径已改为**单次分配 + `encrypt_in_place`**（`FrameCipher::seal_slice`、`FrameEncoder::encode_into`，`FrameWriter` 复用 `BytesMut`）：

| 场景（16KB 帧） | 优化前 | 优化后 |
|---|---|---|
| `frame/encode` | 17.34 µs | **13.31 µs（−23%）** |
| `frame/decode` | 15.86 µs | **13.47 µs（−15%）** |
| 裸 `aead/seal`（对照） | 14.63 µs | 13.26 µs |

整帧 encode 已与裸 AEAD 持平，说明封装/分配开销基本消除。1Gbps（≈7600 帧/s @16KB）下该路径约 10% 单核占用。

## 目录结构

```
src/
├── main.rs            # 入口：-c/-s 分发（薄封装，调用 lib）
├── lib.rs             # 库入口（供 bench/集成测试复用）
├── config.rs          # CLI 与运行时配置
├── clock.rs           # 内部 UTC 时钟：SNTP 校准（--time），认证时间戳来源
├── quic_tune.rs       # 共享 QUIC 传输调优（可调窗口 + BBR 拥塞控制）
├── proto/             # 共享协议层
│   ├── frame.rs       #   帧编解码（头/AAD/计数器/滑动窗口/异步读写器/坏帧恢复）
│   ├── crypto.rs      #   HKDF 派生、ChaCha20-Poly1305、Bearer/AUTH、防重放
│   ├── addr.rs        #   UDP 地址编码（内部 LE / SOCKS5 边界 BE）
│   ├── mux.rs         #   模式 A 多路复用器（客户端角色 + 服务端角色 + FrameSink）
│   └── stream.rs      #   字节流 → AsyncRead 桥接（POST body / WS 消息共用）
├── client/
│   ├── outbound.rs    #   出口选择、熔断器与自动降级
│   ├── wt.rs          #   WebTransport 连接池/控制流/专用流/datagram
│   ├── fallback.rs    #   HTTPS POST 降级出口（hyper + rustls）
│   ├── socks5.rs      #   SOCKS5 入站（CONNECT / UDP ASSOCIATE）
│   └── http_proxy.rs  #   HTTP 代理入站（CONNECT + 简单转发）
└── server/
    ├── wt.rs          #   WebTransport 监听/认证/控制流/datagram/专用流
    ├── fallback.rs    #   axum 降级端点（POST + WebSocket）+ 伪装站 + 80 重定向/ACME
    ├── hub.rs         #   TCP 拨号/双向泵/UDP 中继（两传输共用）
    ├── state.rs       #   全局与连接状态、会话表、空闲回收（配额恰好一次释放）
    ├── limit.rs       #   令牌桶限速
    └── disguise.rs    #   内嵌伪装页（nginx 欢迎页风格）
benches/
└── frame.rs           # 帧热路径 criterion 基准（AEAD / encode / decode）
```
