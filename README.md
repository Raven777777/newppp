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

三种部署形态：

* **形态 A（默认）**：UDP 443 WebTransport 主路径 + TCP 443 降级/伪装站 + 80 门面，性能最优。
* **形态 B（纯网站）**：省略 `--listen` 完全不监听 UDP，流量收敛到 `/api/ppp`，探测面最小。
* **形态 B-CF**：套 Cloudflare 橙云时改用 `wss://.../api/ppp`（WebSocket 承载，CF 不透传 QUIC/WebTransport）。

## 快速开始

```bash
# 服务端（单进程全链路，自签调试）
newppp -s --auth alice:secret123 --self-signed \
  --listen          0.0.0.0:443 \
  --fallback-listen 0.0.0.0:443 \
  --http-listen     0.0.0.0:80

# 客户端
newppp -c --auth alice:secret123 \
  --server https://your.domain:443 \
  --url https://your.domain/api/ppp \
  --bind 127.0.0.1:1080 --http-bind 127.0.0.1:8081
```

完整参数、形态切换与验证命令见 [docs/手册.md](docs/手册.md)。

## 文档导航

本仓库文档分为「根目录简介 + docs 专题」，各文档路径与职责如下：

| 文档 | 内容 |
|---|---|
| [docs/手册.md](docs/手册.md) | 使用手册：部署形态（A / B / B-CF）、快速开始、服务端/客户端参数、验证 |
| [docs/运维手册.md](docs/运维手册.md) | 生产部署（systemd / screen / nginx / Cloudflare）、Docker 打包、服务端出站安全策略、已知限制/风险、构建与质量门 |
| [docs/协议文档.md](docs/协议文档.md) | 协议基线：架构与降级链、帧协议、加密与认证、内部时钟、会话生命周期、背压与容量、隐私与安全模型、性能 |
| [docs/变更记录.md](docs/变更记录.md) | 版本变更与修复历史 |
| [docs/待办_新.md](docs/待办_新.md) | 当前路线图、优先级与待办 |
| [docs/待办_废弃.md](docs/待办_废弃.md) | 已完成 / 废弃待办的归档 |
| [docs/RUST审查.md](docs/RUST审查.md) | Rust 代码审查清单与规范 |

> 路径引用约定：根目录 `README.md` 只保留项目简介与导航，正文内容已拆分至 `docs/`。正文中提及文档时使用**相对仓库根**的路径（如 `docs/手册.md`）；`docs/` 内文档互相引用使用同目录相对路径（如 `手册.md`），回指根简介使用 `../README.md`。

## 目录结构

```
src/
├── main.rs            # 入口：-c/-s 分发（薄封装，调用 lib）
├── lib.rs             # 库入口（供 bench/集成测试复用）
├── config.rs          # CLI 与运行时配置
├── clock.rs           # 内部 UTC 时钟：HTTP Date 头校准（--time），认证时间戳来源
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
tests/
└── e2e.rs             # 进程内端到端测试：真实 server+client（降级链/认证/半关闭/UDP/生命周期，10 项）
.github/
└── workflows/ci.yml   # CI 单文件：fmt / clippy / test + 每周 audit + tag 出 musl artifact
```

## 构建

```bash
cargo build --release
cargo test            # 61 项单元/property 测试 + 10 项进程内端到端（tests/e2e.rs）
```

完整质量门（fmt / clippy / test / CI）见 [docs/运维手册.md](docs/运维手册.md#构建与质量门)；CI 配置见 [.github/workflows/ci.yml](.github/workflows/ci.yml)。

## 许可

MIT，见 [LICENSE](LICENSE)。
