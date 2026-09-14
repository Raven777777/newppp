# newppp

一个面向个人、家庭和小型团队的高性能加密代理。

newppp 将本地的 SOCKS5 或 HTTP 代理请求安全转发到远端服务器，适合远程办公、家庭网络访问、跨网络连接和受控的内网访问场景。

## 核心功能

- **双入口**：支持标准 SOCKS5 代理和 HTTP 代理，可连接浏览器、命令行工具及常见网络应用。
- **高速主通道**：优先使用 WebTransport/QUIC，连接建立快，并发连接多时仍能保持良好吞吐。
- **自动备用通道**：主通道不可用时自动切换到 HTTPS 或 WebSocket，不需要手动重启客户端。
- **TCP 与 UDP**：支持网页访问、长连接、DNS、实时通信等常见 TCP/UDP 流量。
- **连接池**：客户端可维护多条远端连接，分散并发请求，降低单条连接拥堵的影响。
- **断线自愈**：自动检测失效连接、重新连接，并在网络不稳定时暂时避开故障通道。
- **访问保护**：服务端默认阻止回环地址、私有地址和云平台内网地址，降低开放代理和 SSRF 风险。
- **灵活认证**：支持多用户账号、配置文件、本地代理认证，以及证书指纹绑定。
- **轻量部署**：支持单进程运行、systemd、Docker、nginx 和 Cloudflare WebSocket 场景。

## 性能特点

- WebTransport/QUIC 适合高延迟和多并发网络，避免所有请求挤在一条 TCP 连接上。
- UDP 小数据包优先使用低延迟通道，超过路径容量时自动改走可靠流，减少大包失败；单帧上限可在握手时协商（`--max-frame-kb`），让较大的 UDP 数据报也能整帧承载。
- 帧处理采用 ChaCha20-Poly1305 加密，并复用编码缓冲区，降低频繁分配带来的开销。
- 服务端支持按用户共享的带宽限制，避免单个账号占满全部出口带宽。
- 服务端对 UDP 域名目标做带 TTL 的解析缓存（`--udp-dns-ttl`，默认 1 小时），避免逐包查询。
- 支持配置连接数量、接收窗口、帧上限、会话数量和空闲回收时间，可按网络质量调整。

性能会受到网络延迟、丢包率、服务器带宽和目标站点影响。项目提供本地 benchmark，用于比较帧加密和编解码性能，不能替代真实网络环境测试。

## 安全特点

- 代理数据使用加密通道保护，传输链路上的中间网络无法直接读取代理内容；服务端需要解密数据后才能完成转发，因此服务端本身属于受信任边界。
- 账号认证使用时间窗口和随机 nonce，重复使用的认证材料会被拒绝。
- TLS 证书默认进行正常校验，也支持使用 SHA-256 证书指纹固定服务器身份。
- 服务端默认拒绝访问本机、私网、链路本地和特殊保留地址；IPv4-mapped、NAT64、6to4 等 IPv6 转换前缀会先拆解出内嵌 IPv4 再按同一策略判断。
- `--skip-verify` 和 `--self-signed` 仅适合开发或本地测试，生产环境应使用正式证书。

注意：账号密码是内层密钥的重要组成部分，请使用足够长且随机的密码。
推荐64位大小写字母数字混合密码

## 快速开始

### 服务端

下面示例使用自签名证书，适合本地测试。生产环境请改用 `--cert` 和 `--key`。

```bash
newppp -s --auth alice:CHANGE_THIS_PASSWORD --self-signed \
  --listen 0.0.0.0:443 \
  --fallback-listen 0.0.0.0:443 \
  --http-listen 0.0.0.0:80
```

### 客户端

```bash
newppp -c --auth alice:CHANGE_THIS_PASSWORD \
  --server https://your.domain:443 \
  --url https://your.domain/api/ppp \
  --bind 127.0.0.1:1080 \
  --http-bind 127.0.0.1:8081
```

自签名测试时，客户端加上 `--skip-verify`。启动后即可使用：

```bash
curl --socks5-hostname 127.0.0.1:1080 https://example.com
curl -x http://127.0.0.1:8081 https://example.com
```

示例配置：

- 服务端：`deploy/server.example.conf`
- 客户端：`deploy/client.example.conf`

## 部署选择

| 场景 | 推荐方式 |
| --- | --- |
| 追求速度和 UDP 能力 | WebTransport 主通道 + HTTPS 备用通道 |
| 只开放网站端口 | 仅使用 HTTPS 备用通道，省略服务端 `--listen` |
| 使用 Cloudflare 代理 | 使用 `wss://.../api/ppp` 作为备用通道 |
| 家庭或 NAS 使用 | 客户端绑定 `0.0.0.0`，同时开启 `--inbound-auth` |
| 生产服务器 | 正式证书 + systemd 或 Docker + 健康检查 |

## 配置文件

长命令可以放入配置文件：

```bash
newppp --config /etc/newppp/server.conf
```

配置文件支持 `mode`、`auth`、监听地址、证书、连接限制和日志等长选项。配置文件中的密码请设置为仅管理员可读；项目会在权限过宽时给出警告。

## 文档

| 文档 | 内容 |
| --- | --- |
| [docs/手册.md](docs/手册.md) | 安装、启动、参数、配置文件和常用使用方式 |
| [docs/运维手册.md](docs/运维手册.md) | systemd、Docker、nginx、Cloudflare、健康检查和故障排查 |
| [docs/协议文档.md](docs/协议文档.md) | 通道、认证、加密、连接生命周期和安全模型 |
| [docs/变更记录.md](docs/变更记录.md) | 功能变更和历史修复记录 |
| [docs/待办_新.md](docs/待办_新.md) | 当前路线图和后续计划 |
| [docs/报告/RUST审查报告.md](docs/报告/RUST审查报告.md) | Rust 代码审查结果 |
| [docs/报告/文档审查报告.md](docs/报告/文档审查报告.md) | 文档与代码一致性审核结果 |

## 构建与测试

```bash
cargo build --release
cargo test --all-features
```

Windows 发布构建使用 `build_release.bat`；Linux 静态构建使用 `build_linux.bat`。完整质量检查和 Docker 打包流程见 [docs/运维手册.md](docs/运维手册.md)。

## 许可

MIT，见 [LICENSE](LICENSE)。
