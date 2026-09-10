# TODO

## 已完成（2026-09-10）

| 项 | 说明 |
|---|---|
| **Bearer 重放缓存** | bearer token 的 (ts, nonce) 纳入 `seen_nonces` 服务端缓存：同一 token 只接受一次，堵 ±60s 重放窗口；MAC 先验，未认证流量无法污染缓存 |
| **conn 级空闲回收** | 无会话且无数据活动超 3×`--idle` 的连接由 reaper 主动 cancel + 移出 `conns`（keepalive Pings 不计入；WT 路径显式关闭 QUIC） |
| **WT 熔断器** | 连续 3 次传输层故障 → 冷却 60s，期间新会话直达兜底；到期放行一次探测，成功关闭、失败立即再熔断；目标侧拒绝不计入故障 |
| **`--recv-window` CLI 化** | QUIC 每流接收窗口 MB（1..=64 显式校验）暴露为参数，客户端（下载方向）与服务端（上传方向）共用，免重编译调优 |
| **模式 A 半关闭修复** | 服务端 `Close+FLAG_FIN` 由"整条会话拆除"改为半关闭（`feed_tcp(fin=true)`，与 WT 路径一致），不再截断响应；客户端收到 `Data+FLAG_FIN` 时传播 FIN 关闭本地流，修复目标 EOF 后本地连接挂起。新增 4 项回归测试 |
| **移除 aws-lc-rs** | `axum-server` 特性由 `tls-rustls` 改为 `tls-rustls-no-provider`（运行期仍用已安装的 ring provider），去掉全项目唯一的 aws-lc-rs C 依赖，构建更快、产物更小 |
| **本地入站认证** | 新增 `--inbound-auth USER:PASS`：SOCKS5 RFC1929 用户名/密码 + HTTP 代理 Basic Auth（常量时间比较）；未配置时行为不变，`--bind 0.0.0.0` 部署闭环 |
| **帧解码器 property 测试** | proptest 覆盖 `FrameDecoder`（任意分块输入不 panic、`clear` 后可恢复）、`unhex`（hex 往返、任意串不 panic）、`AuthPayload::decode`/编解码往返、`decode_open` |
| **WT 重连指数退避** | 池维护循环由固定 10s 并发重拨改为顺序重拨 + 10s→…→上限 5min 指数退避，成功即重置，更礼貌也更隐蔽 |
| **热路径内存复用** | 先建 `benches/frame.rs`（criterion）证明封装分配开销；再以 `FrameCipher::seal_slice` + `FrameEncoder::encode_into` 单次分配 + `FrameWriter` 复用 `BytesMut` 优化。16KB 帧 encode 17.3→13.3µs（−23%，与裸 AEAD 持平）、decode −15%；引入 lib 目标以支撑 bench/集成测试 |

## 待办

### 快速收益（小成本，优先做）

1. **Docker 镜像内置 CA 根证书**（`build_docker.py` 可选层，带 `/etc/ssl/certs/ca-certificates.crt`）：根治 NAS 容器 `UnknownIssuer`（`SSL_CERT_FILE` 挂载实测走不通），替代应急的 `--skip-verify`。
2. **Docker HEALTHCHECK**：镜像无健康检查，编排器无法自动拉起假死容器；80 端口 301 响应即可作探针，`build_docker.py` 加一行。

### 多用户治理与部署体验（中成本，配置文件先行统一设计）

3. **配置文件支持**：密码已出现在命令行（`ps` 可见）与镜像配置（`docker inspect` 可见）；`--config` 文件（0600）收敛秘密，多用户管理也靠它。
4. **每用户会话配额**：多用户部署时一个客户端可吃满全局 `--max-sessions` 饿死他人；按 uid 设上限（默认 `max-sessions/用户数` 或显式指定）。
5. **目标地址 ACL**（可选）：服务端对认证用户可拨任意目标；按用户限制网段（拒内网地址/白名单）防滥用与 SSRF 式误用。
6. **多兜底 URL 链**：`--url` 只能配一个，"灰云直连 POST 优先、橙云 wss 保底"做不到；`--url` 可重复 + 按序降级。
7. **`/metrics` 端点**（Prometheus 格式）：活跃会话数、每用户流量、WT/兜底使用比、限速触发次数——现在出问题只能看 debug 日志猜。
8. **未认证连接限流**：对未认证握手无显式上限（依赖 QUIC/TLS 自身限流）；加全局未认证速率/并发上限，stealth 补强。
9. **优雅停机 + 证书热重载**（重启 UX 一揽子）：现在 ctrl_c 直接弃运行时、certbot 续期后必须重启；改为"停止 accept → 限时排空 → 退出"，TCP 侧 `axum_server` 支持 `RustlsConfig::reload`。

### 工程质量（一次性投入长期受益）

10. **GitHub Actions CI**：`fmt + clippy -D warnings + test` 矩阵、定时 `cargo audit`、双平台构建产物。
11. **回环集成测试**：现有 47 项全是单元测试；补"起服务端→客户端连→SOCKS5 拉取"端到端冒烟，抓住配额、认证、降级链、半关闭这类跨模块回归。
12. **声明 MSRV**（`rust-version`）+ CHANGELOG。

### 观察项（先基准后动，避免过早优化）

- **限速器唤醒模型**：令牌桶不足时 sleep 循环重试，大缺口唤醒偏多；换带 waker 的异步令牌桶。
- **UDP relay 套接字池**：每 UDP 会话每族新 bind，DNS 密集场景 churn 明显；现状 128 socket/连接上限可接受，视需要再做。

### 暂缓项（大工程，单独立项）

- **同端口 H3/WT 伪装一体化**：同一 UDP 443 既能响应标准 H3 GET 静态网页（发 Alt-Svc），又能升级 WebTransport，补齐 QUIC 层探测漏洞。现状：UDP 443 不应答 h3 GET、不发 Alt-Svc，定制探测可发现"这个 QUIC 服务不是网页"。根治需把 wtransport 换成 quinn + h3 栈（传输层重构、伪装页走 h3、认证流程不变；两端都是自有客户端，无第三方互操作硬需求）；启动前先抽传输抽象层 + 钉死现有行为基准。
- **QUIC/TLS 指纹混淆**：进一步调优 quinn/wtransport 的 `TransportConfig`（初始/流控窗口、`max_idle_timeout`、ACK 策略、连接迁移、`active_connection_id_limit`、`max_udp_payload_size` 等），并人工拟合 Chrome 的 ClientHello 结构（扩展集合与顺序、GREASE、key_share/密码套件、ALPN、SNI 形态），降低主动/被动 DPI 的特征识别率（JA4/QUIC 指纹）。现状：quinn 指纹≠Chrome（README「已知限制」），被动分类无特征但主动探测可辨。难点：wtransport 封装了部分 TLS/传输配置、rustls 与 Chrome 的 ClientHello 存在结构性差异、Chrome 版本漂移需持续跟踪；改动限定在客户端出站配置，不破坏服务端互操作。启动前先建指纹采集/比对基线（如 `ja4`/`p0f` 类工具对两端握手抓包），再逐项拟合。
- **Argon2 慢哈希密码 KDF**：密码爆破是体系真正弱根，但属**协议 v2 破坏性改动**（需版本协商与两端同步升级）。
- 模式 A 单通道队头阻塞：架构固有，WT 主路径已覆盖大多数场景。

## 执行顺序

快速收益两件 → 多用户治理（配置文件先行，配额/ACL/metrics 随后）→ 优雅停机+证书热重载 → CI/集成测试 → 观察项按基准数据决策。
