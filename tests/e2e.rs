//! Process-local, in-process end-to-end tests (the Rust counterpart of
//! `tests/e2e_local.py`, reusing its scenarios).
//!
//! Everything runs on one runtime per test: the real server listeners
//! (`server::wt::run_wt`, `server::fallback::run_tls`) wired onto an
//! inspectable `ServerState`, the real client pieces (`Outbound`,
//! `socks5::run`, `http_proxy::run`), and loopback target servers. The tests
//! are driven with raw socket clients; no external processes are spawned.
//!
//! No wall-clock waits: `CircuitBreaker::new` takes threshold/cooldown
//! parameters, so the degradation test uses small values instead of 60s.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Once, OnceLock};
use std::time::Duration;

use anyhow::{anyhow, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::task::JoinHandle;
use tokio::time::timeout;

use newppp::client::fallback::HttpOutbound;
use newppp::client::http_proxy;
use newppp::client::outbound::{error_tag, target_error, CircuitBreaker, Outbound};
use newppp::client::socks5;
use newppp::client::wt::WtPool;
use newppp::config::{CertSource, ClientConfig, ServerConfig};
use newppp::proto::crypto::{
    auth_mac, derive_static_key, make_bearer, now_unix, AuthPayload, CounterGen, FrameCipher,
    SALT_LEN,
};
use newppp::proto::frame::{FrameReader, FrameType, FrameWriter, PROTO_VERSION};
use newppp::proto::mux::BoxStream;
use newppp::server::fallback as srv_fallback;
use newppp::server::wt as srv_wt;
use wtransport::endpoint::endpoint_side::Client as WtClientSide;
use wtransport::endpoint::ConnectOptions;
use wtransport::ClientConfig as WtClientConfig;
use wtransport::Endpoint;

const UID: &str = "e2e";
const PASS: &str = "e2e-pass";
const BODY: &str = "hello-e2e\n";
/// QUIC datagrams max out below ~1.5KB. An 8KB payload exceeds that (auto
/// fall-to-stream in both directions) while fitting in one 16KB frame.
const BIG_UDP_PAYLOAD: usize = 8 * 1024;
const HANDSHAKE: Duration = Duration::from_secs(30);

fn init_crypto() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

fn client_cfg(wt: Option<String>, fb: Option<String>) -> ClientConfig {
    ClientConfig {
        wt_url: wt,
        fb_url: fb,
        socks_bind: String::new(),
        http_bind: None,
        inbound_auth: None,
        conns: 1,
        uid: UID.into(),
        password: PASS.into(),
        skip_verify: true,
        recv_window: 2 * 1024 * 1024,
    }
}

// ---------------------------------------------------------------------------
// Server wiring
// ---------------------------------------------------------------------------

struct TestServer {
    state: Arc<newppp::server::state::ServerState>,
    wt_port: u16,
    fb_port: u16,
    tasks: Vec<JoinHandle<()>>,
}

impl TestServer {
    async fn shutdown(mut self) {
        for t in self.tasks.drain(..) {
            t.abort();
            let _ = t.await;
        }
    }

    fn wt_url(&self) -> String {
        format!("https://127.0.0.1:{}", self.wt_port)
    }

    fn fb_url(&self) -> String {
        format!("https://127.0.0.1:{}/api/ppp", self.fb_port)
    }

    fn fb_ws_url(&self) -> String {
        format!("wss://127.0.0.1:{}/api/ppp", self.fb_port)
    }
}

fn server_cfg(allow_private: bool, wrong_pass: bool) -> ServerConfig {
    ServerConfig {
        listen: None,
        cert: CertSource::Files {
            cert: String::new(),
            key: String::new(),
        },
        fallback_listen: None,
        http_listen: None,
        acme_dir: None,
        path: "/api/ppp".into(),
        users: vec![(
            UID.to_string(),
            if wrong_pass {
                "not-the-pass".into()
            } else {
                PASS.into()
            },
        )],
        max_sessions: 200,
        rate_mbps: 0,
        idle_secs: 60,
        allow_private_targets: allow_private,
        max_unauth: 128,
        recv_window: 2 * 1024 * 1024,
    }
}

/// Self-signed cert/key PEM files, unique per call so parallel tests never
/// race on the same files.
async fn dev_tls() -> Result<(std::path::PathBuf, std::path::PathBuf)> {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    init_crypto();
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".into(), "newppp.local".into()])?;
    let dir = std::env::temp_dir().join(format!(
        "newppp-e2e-tls-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir)?;
    let cert = dir.join("cert.pem");
    let key = dir.join("key.pem");
    std::fs::write(&cert, ck.cert.pem())?;
    std::fs::write(&key, ck.signing_key.serialize_pem())?;
    Ok((cert, key))
}

/// Full server: WT + TLS fallback listeners, with an inspectable state.
async fn spawn_server(allow_private: bool) -> Result<TestServer> {
    let (cert, key) = dev_tls().await?;
    let identity = wtransport::Identity::load_pemfiles(&cert, &key).await?;
    let state = newppp::server::build_state(&server_cfg(allow_private, false));

    let wt_port = free_port();
    let fb_port = free_port();

    let st_wt = state.clone();
    let st_fb = state.clone();
    let tasks = vec![
        tokio::spawn(async move {
            let _ = srv_wt::run_wt(
                st_wt,
                SocketAddr::from(([127, 0, 0, 1], wt_port)),
                identity,
                2 * 1024 * 1024,
            )
            .await;
        }),
        tokio::spawn(async move {
            let _ = srv_fallback::run_tls(
                st_fb,
                SocketAddr::from(([127, 0, 0, 1], fb_port)),
                cert,
                key,
            )
            .await;
        }),
    ];
    wait_tcp_port(fb_port).await?;
    // the WT endpoint binds in the same first poll batch; give it a moment
    tokio::time::sleep(Duration::from_millis(200)).await;
    Ok(TestServer {
        state,
        wt_port,
        fb_port,
        tasks,
    })
}

/// WT listener that always refuses credentials — a deterministic fast
/// "unreachable primary" for the degradation-chain test (same classified
/// outcome as a dead port: a transport-level failure, fast on loopback).
async fn spawn_refusing_wt() -> Result<u16> {
    let (cert, key) = dev_tls().await?;
    let identity = wtransport::Identity::load_pemfiles(&cert, &key).await?;
    let state = newppp::server::build_state(&server_cfg(false, true));
    let port = free_port();
    tokio::spawn(async move {
        let _ = srv_wt::run_wt(
            state,
            SocketAddr::from(([127, 0, 0, 1], port)),
            identity,
            2 * 1024 * 1024,
        )
        .await;
    });
    tokio::time::sleep(Duration::from_millis(200)).await;
    Ok(port)
}

// ---------------------------------------------------------------------------
// Client wiring
// ---------------------------------------------------------------------------

struct ClientStack {
    socks_port: u16,
    http_port: Option<u16>,
    tasks: Vec<JoinHandle<()>>,
}

impl ClientStack {
    async fn shutdown(mut self) {
        for t in self.tasks.drain(..) {
            t.abort();
            let _ = t.await;
        }
    }
}

/// Full local client: Outbound built from cfg + SOCKS5 (+ HTTP proxy)
/// inbounds on fresh loopback ports.
async fn start_client(cfg: ClientConfig, with_http: bool) -> Result<ClientStack> {
    let socks_port = free_port();
    let http_port = with_http.then(free_port);
    let mut cfg = cfg;
    cfg.socks_bind = format!("127.0.0.1:{socks_port}");
    cfg.http_bind = http_port.map(|p| format!("127.0.0.1:{p}"));

    let ob = Outbound::build(&cfg).await?;
    let ob_socks = ob.clone();
    let mut tasks = vec![tokio::spawn(async move {
        let _ = socks5::run(cfg.socks_bind.clone(), ob_socks, None).await;
    })];
    if let Some(hp) = cfg.http_bind {
        tasks.push(tokio::spawn(async move {
            let _ = http_proxy::run(hp, ob, None).await;
        }));
    }
    wait_tcp_port(socks_port).await?;
    if let Some(p) = http_port {
        wait_tcp_port(p).await?;
    }
    Ok(ClientStack {
        socks_port,
        http_port,
        tasks,
    })
}

fn wt_outbound(url: &str) -> Outbound {
    let cfg = client_cfg(Some(url.to_string()), None);
    let pool = Arc::new(WtPool::new(&cfg, url).expect("wt pool"));
    Outbound::Wt(pool)
}

fn post_outbound(url: &str) -> Outbound {
    let cfg = client_cfg(None, Some(url.to_string()));
    Outbound::Http(Arc::new(
        HttpOutbound::new(&cfg, url).expect("http outbound"),
    ))
}

// ---------------------------------------------------------------------------
// Target servers (the tunnel's dial destination)
// ---------------------------------------------------------------------------

/// Minimal HTTP/1.1 target: answers 200 + body, then closes.
async fn spawn_target() -> Result<u16> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let port = listener.local_addr()?.port();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let _ = read_http_head(&mut s).await;
                let resp = format!(                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{BODY}",
                    BODY.len()
                );
                let _ = s.write_all(resp.as_bytes()).await;
                let _ = s.shutdown().await;
            });
        }
    });
    Ok(port)
}

/// Reads its request to EOF (client half-close) before answering: the proxy
/// chain must forward the FIN and still deliver this response.
async fn spawn_halfclose_target(payload: &'static [u8]) -> Result<u16> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let port = listener.local_addr()?.port();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut drained = Vec::new();
                let mut chunk = [0u8; 4096];
                let _ = timeout(Duration::from_secs(10), async {
                    loop {
                        match s.read(&mut chunk).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => drained.extend_from_slice(&chunk[..n]),
                        }
                    }
                })
                .await;
                assert!(!drained.is_empty(), "target got no request before FIN");
                let _ = s.write_all(payload).await;
                let _ = s.shutdown().await;
            });
        }
    });
    Ok(port)
}

struct UdpEcho {
    port: u16,
    /// Must stay bound for the loop's lifetime.
    _sock: Arc<UdpSocket>,
}

/// Read one HTTP request head (best effort; echoes nothing).
async fn read_http_head(s: &mut TcpStream) {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    if timeout(Duration::from_secs(10), async {
        while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
            match s.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
        }
    })
    .await
    .is_err()
    {
        // slow client: proceed to answer anyway; the tunnel test only cares
        // that we received a request head before responding
    }
}

async fn spawn_udp_echo() -> Result<UdpEcho> {
    let sock = Arc::new(UdpSocket::bind(("127.0.0.1", 0)).await?);
    let port = sock.local_addr()?.port();
    let s2 = sock.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        while let Ok((n, from)) = s2.recv_from(&mut buf).await {
            let mut reply = b"echo:".to_vec();
            reply.extend_from_slice(&buf[..n]);
            let _ = s2.send_to(&reply, from).await;
        }
    });
    Ok(UdpEcho { port, _sock: sock })
}

// ---------------------------------------------------------------------------
// Raw client helpers
// ---------------------------------------------------------------------------

fn free_port() -> u16 {
    std::net::TcpListener::bind(("127.0.0.1", 0))
        .and_then(|l| l.local_addr())
        .map(|a| a.port())
        .expect("bind ephemeral")
}

async fn wait_tcp_port(port: u16) -> Result<()> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        match TcpStream::connect(("127.0.0.1", port)).await {
            Ok(_) => return Ok(()),
            Err(_) if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(e) => return Err(anyhow!("port {port} never opened: {e}")),
        }
    }
}

/// Block until the server-side session quota is back to zero.
async fn wait_sessions_zero(state: &Arc<newppp::server::state::ServerState>) {
    timeout(Duration::from_secs(10), async {
        while state.active_sessions.load(Ordering::Relaxed) != 0 {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("server did not release its session quota within 10s");
}

/// SOCKS5 CONNECT; `Ok(stream)` on success, `Err(reply_code)` on refusal.
async fn socks5_connect(proxy: u16, dst: &str, dst_port: u16) -> Result<TcpStream, u8> {
    let mut s = timeout(HANDSHAKE, TcpStream::connect(("127.0.0.1", proxy)))
        .await
        .expect("socks proxy connect timeout")
        .expect("socks proxy connect");
    s.write_all(b"\x05\x01\x00").await.expect("greeting");
    let mut method = [0u8; 2];
    s.read_exact(&mut method).await.expect("method reply");
    assert_eq!(method, [5, 0], "no-auth method not selected");
    let mut req = vec![5u8, 1, 0, 3, dst.len() as u8];
    req.extend_from_slice(dst.as_bytes());
    req.extend_from_slice(&dst_port.to_be_bytes());
    s.write_all(&req).await.expect("connect request");
    let mut head = [0u8; 4];
    s.read_exact(&mut head).await.expect("connect reply");
    assert_eq!(head[0], 5, "bad reply version");
    let mut skip = match head[3] {
        1 => 4usize,
        3 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l).await.expect("domain len");
            1 + usize::from(l[0])
        }
        4 => 16,
        t => panic!("unexpected reply atyp {t}"),
    };
    skip += 2; // bound port
    let mut rest = vec![0u8; skip];
    s.read_exact(&mut rest).await.expect("rest of reply");
    if head[1] != 0 {
        Err(head[1])
    } else {
        Ok(s)
    }
}

/// SOCKS5 GET through the proxy; asserts 200 + target body.
async fn socks5_get(proxy: u16, dst: &str, dst_port: u16) -> Result<String> {
    let mut s = socks5_connect(proxy, dst, dst_port)
        .await
        .map_err(|c| anyhow!("CONNECT refused with reply code 0x{c:02x}"))?;
    let req = format!("GET / HTTP/1.1\r\nHost: {dst}:{dst_port}\r\nConnection: close\r\n\r\n");
    s.write_all(req.as_bytes()).await?;
    let mut resp = Vec::new();
    timeout(HANDSHAKE, s.read_to_end(&mut resp))
        .await?
        .expect("read response");
    let text = String::from_utf8_lossy(&resp).into_owned();
    let status = text.lines().next().unwrap_or_default().to_string();
    assert!(status.contains("200"), "bad status: {status}");
    assert!(
        resp.windows(BODY.len()).any(|w| w == BODY.as_bytes()),
        "target body missing in {status}"
    );
    Ok(status)
}

/// HTTP proxy CONNECT; returns the raw response head (no assertions).
/// The returned socket is the tunnel on success.
async fn http_connect_proxy(proxy: u16, dst: &str, dst_port: u16) -> Result<(TcpStream, String)> {
    let mut s = TcpStream::connect(("127.0.0.1", proxy)).await?;
    let head = format!("CONNECT {dst}:{dst_port} HTTP/1.1\r\nHost: {dst}\r\n\r\n");
    s.write_all(head.as_bytes()).await?;
    let mut resp_head = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = timeout(HANDSHAKE, s.read(&mut chunk))
            .await?
            .expect("read connect reply");
        assert!(n > 0, "proxy closed during CONNECT");
        resp_head.extend_from_slice(&chunk[..n]);
        if resp_head.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if resp_head.len() > 64 * 1024 {
            anyhow::bail!("CONNECT response head too large");
        }
    }
    Ok((s, String::from_utf8_lossy(&resp_head).into_owned()))
}

/// HTTP proxy CONNECT + plain HTTP GET through the tunnel; asserts 200+body.
async fn http_connect_get(proxy: u16, dst: &str, dst_port: u16) -> Result<String> {
    let (mut s, head) = http_connect_proxy(proxy, dst, dst_port).await?;
    assert!(head.starts_with("HTTP/1.1 200"), "CONNECT rejected: {head}");
    let req = format!("GET / HTTP/1.1\r\nHost: {dst}:{dst_port}\r\nConnection: close\r\n\r\n");
    s.write_all(req.as_bytes()).await?;
    let mut resp = Vec::new();
    timeout(HANDSHAKE, s.read_to_end(&mut resp))
        .await?
        .expect("read response");
    let text = String::from_utf8_lossy(&resp).into_owned();
    assert!(text.starts_with("HTTP/1.1 200"), "bad status: {text}");
    assert!(text.contains(BODY), "target body missing");
    Ok(text)
}

/// HTTP proxy absolute-URI GET (plain HTTP forward proxy); asserts 200+body.
async fn http_absolute_get(proxy: u16, dst: &str, dst_port: u16) -> Result<String> {
    let mut s = TcpStream::connect(("127.0.0.1", proxy)).await?;
    let raw = format!(
        "GET http://{dst}:{dst_port}/ HTTP/1.1\r\nHost: {dst}:{dst_port}\r\nConnection: close\r\n\r\n"
    );
    s.write_all(raw.as_bytes()).await?;
    let mut resp = Vec::new();
    timeout(HANDSHAKE, s.read_to_end(&mut resp))
        .await?
        .expect("read response");
    let text = String::from_utf8_lossy(&resp).into_owned();
    assert!(text.starts_with("HTTP/1.1 200"), "bad status: {text}");
    assert!(text.contains(BODY), "target body missing");
    Ok(text)
}

/// SOCKS5 UDP ASSOCIATE; returns (control connection, relay address).
async fn socks5_udp_associate(proxy: u16) -> (TcpStream, SocketAddr) {
    let mut s = TcpStream::connect(("127.0.0.1", proxy))
        .await
        .expect("udp control connect");
    s.write_all(b"\x05\x01\x00").await.expect("greeting");
    let mut method = [0u8; 2];
    s.read_exact(&mut method).await.expect("method reply");
    assert_eq!(method, [5, 0]);
    s.write_all(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
        .await
        .expect("udp associate request");
    let mut head = [0u8; 4];
    s.read_exact(&mut head).await.expect("udp associate reply");
    assert_eq!(head[0], 5);
    assert_eq!(head[1], 0, "UDP ASSOCIATE rejected: code {}", head[1]);
    let bnd_ip = match head[3] {
        1 => {
            let mut b = [0u8; 4];
            s.read_exact(&mut b).await.expect("bnd ip");
            b
        }
        t => panic!("unexpected bnd atyp {t} (v4 loopback expected)"),
    };
    let mut p = [0u8; 2];
    s.read_exact(&mut p).await.expect("bnd port");
    let ip_addr = std::net::Ipv4Addr::from(bnd_ip);
    let ip = if ip_addr.is_unspecified() {
        std::net::IpAddr::from(std::net::Ipv4Addr::LOCALHOST)
    } else {
        std::net::IpAddr::from(ip_addr)
    };
    (s, SocketAddr::new(ip, u16::from_be_bytes(p)))
}

/// One datagram through an open SOCKS5 UDP relay; returns the echoed payload.
async fn udp_roundtrip(relay: &SocketAddr, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let u = UdpSocket::bind(("127.0.0.1", 0)).await.expect("udp bind");
    let mut pkt = vec![0u8, 0, 0, 1];
    pkt.extend_from_slice(&[127, 0, 0, 1]);
    pkt.extend_from_slice(&dst_port.to_be_bytes());
    pkt.extend_from_slice(payload);
    timeout(HANDSHAKE, u.send_to(&pkt, relay))
        .await
        .expect("udp send timeout")
        .expect("udp send");
    let mut buf = vec![0u8; 65535];
    let (n, _) = timeout(HANDSHAKE, u.recv_from(&mut buf))
        .await
        .expect("udp reply timeout")
        .expect("udp recv");
    assert!(n > 10, "reply too short: {n} bytes");
    assert_eq!(&buf[..3], &[0, 0, 0], "bad reply header");
    let mut idx = 4usize;
    match buf[3] {
        1 => idx += 4,
        3 => idx += 1 + usize::from(buf[4]),
        4 => idx += 16,
        t => panic!("bad reply atyp {t}"),
    }
    idx += 2;
    buf[idx..n].to_vec()
}

/// Plain HTTP request/response across an open tunneled session.
async fn tunnel_get(mut s: BoxStream, dst: &str, dst_port: u16) -> Result<String> {
    let req = format!("GET / HTTP/1.1\r\nHost: {dst}:{dst_port}\r\nConnection: close\r\n\r\n");
    s.write_all(req.as_bytes()).await?;
    let mut resp = Vec::new();
    timeout(HANDSHAKE, s.read_to_end(&mut resp))
        .await?
        .expect("read response");
    let text = String::from_utf8_lossy(&resp).into_owned();
    assert!(text.contains("200"), "bad tunneled status: {text}");
    assert!(text.contains(BODY), "target body missing in tunnel");
    Ok(text)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// 1+3: HTTPS POST fallback through SOCKS5 GET, plus the HTTP-proxy CONNECT
/// and absolute-GET inbounds over the same kind of session.
#[tokio::test]
async fn fallback_post_socks5_and_http_connect() {
    let srv = spawn_server(true).await.expect("server");
    let target = spawn_target().await.expect("target");
    let cli = start_client(client_cfg(None, Some(srv.fb_url())), true)
        .await
        .expect("client");
    let http_port = cli.http_port.expect("http proxy bound");

    socks5_get(cli.socks_port, "127.0.0.1", target)
        .await
        .expect("socks5 GET via POST fallback");
    http_connect_get(http_port, "127.0.0.1", target)
        .await
        .expect("http proxy CONNECT via POST fallback");
    http_absolute_get(http_port, "127.0.0.1", target)
        .await
        .expect("http proxy absolute GET via POST fallback");

    wait_sessions_zero(&srv.state).await;
    cli.shutdown().await;
    srv.shutdown().await;
}

/// 2: WebSocket fallback (wss) path end-to-end through SOCKS5.
#[tokio::test]
async fn fallback_ws_socks5_get() {
    let srv = spawn_server(true).await.expect("server");
    let target = spawn_target().await.expect("target");
    let cli = start_client(client_cfg(None, Some(srv.fb_ws_url())), false)
        .await
        .expect("client");
    socks5_get(cli.socks_port, "127.0.0.1", target)
        .await
        .expect("socks5 GET via wss fallback");
    cli.shutdown().await;
    srv.shutdown().await;
}

/// 4: SOCKS5 CONNECT + UDP ASSOCIATE roundtrip over the WT datagram path.
#[tokio::test]
async fn socks5_connect_and_udp_associate_over_wt() {
    let srv = spawn_server(true).await.expect("server");
    let target = spawn_target().await.expect("target");
    let echo = spawn_udp_echo().await.expect("udp echo");
    let cli = start_client(client_cfg(Some(srv.wt_url()), Some(srv.fb_url())), false)
        .await
        .expect("client");

    socks5_get(cli.socks_port, "127.0.0.1", target)
        .await
        .expect("socks5 CONNECT via WT");
    let (mut ctrl, relay) = socks5_udp_associate(cli.socks_port).await;
    let got = udp_roundtrip(&relay, echo.port, b"ping").await;
    assert_eq!(got, b"echo:ping", "UDP echo mismatch");
    // keep the control connection referenced until after the roundtrip;
    // the UDP relay stays open by design (idle timeout), so no quota check.
    let _ = &mut ctrl;

    cli.shutdown().await;
    srv.shutdown().await;
}

/// 5: an over-MTU UDP datagram automatically falls back to the stream
/// channel (frame encoding) and round-trips intact.
#[tokio::test]
async fn udp_over_mtu_falls_back_to_stream() {
    let srv = spawn_server(true).await.expect("server");
    let echo = spawn_udp_echo().await.expect("udp echo");
    let cli = start_client(client_cfg(Some(srv.wt_url()), Some(srv.fb_url())), false)
        .await
        .expect("client");

    let payload = vec![0xBEu8; BIG_UDP_PAYLOAD];
    let (_ctrl, relay) = socks5_udp_associate(cli.socks_port).await;
    let got = udp_roundtrip(&relay, echo.port, &payload).await;
    assert!(got.starts_with(b"echo:"), "missing echo prefix");
    assert_eq!(&got[5..], &payload[..], "payload corrupted over >MTU path");

    cli.shutdown().await;
    srv.shutdown().await;
}

/// 7: private targets denied by default (SOCKS 0x02; HTTP CONNECT 502 with
/// `X-Newppp-Error: private-target-denied`), allowed under the opt-in flag;
/// a refused dial is classified as 0x05.
#[tokio::test]
async fn private_target_policy() {
    let deny = spawn_server(false).await.expect("deny server");
    let allow = spawn_server(true).await.expect("allow server");
    let target = spawn_target().await.expect("target");
    let unbound = free_port(); // nothing listens here

    let cli_deny = start_client(client_cfg(Some(deny.wt_url()), Some(deny.fb_url())), true)
        .await
        .expect("deny client");
    let rep = match socks5_connect(cli_deny.socks_port, "127.0.0.1", target).await {
        Ok(_) => 0,
        Err(c) => c,
    };
    assert_eq!(rep, 0x02, "expected private-target-denied, got 0x{rep:02x}");
    let (_s, head) = http_connect_proxy(
        cli_deny.http_port.expect("http proxy bound"),
        "127.0.0.1",
        target,
    )
    .await
    .expect("http proxy reply");
    assert!(head.starts_with("HTTP/1.1 502"), "expected 502, got {head}");
    assert!(
        head.contains("X-Newppp-Error: private-target-denied"),
        "error classification header missing: {head}"
    );
    cli_deny.shutdown().await;

    let cli_allow = start_client(
        client_cfg(Some(allow.wt_url()), Some(allow.fb_url())),
        false,
    )
    .await
    .expect("allow client");
    socks5_get(cli_allow.socks_port, "127.0.0.1", target)
        .await
        .expect("opted-in server accepts private targets");
    let rep = match socks5_connect(cli_allow.socks_port, "127.0.0.1", unbound).await {
        Ok(_) => 0,
        Err(c) => c,
    };
    assert_eq!(rep, 0x05, "expected dial-failed, got 0x{rep:02x}");

    cli_allow.shutdown().await;
    deny.shutdown().await;
    allow.shutdown().await;
}

/// 6: auth matrix — bad bearer → disguise page over TLS; valid bearer with a
/// malformed in-band AUTH frame → disguise page; bad WT bearer → session
/// refused; AUTH frame under the wrong static key → closed without AuthOk;
/// used bearer nonce cannot be replayed on a fresh session.
#[tokio::test]
async fn auth_matrix() {
    let srv = spawn_server(false).await.expect("server");

    // (a) HTTPS GET with a garbage bearer → disguise page (200, text/html)
    let resp = https_get(srv.fb_port, "/api/ppp", Some("Bearer nope"))
        .await
        .expect("https get bad bearer");
    assert!(resp.starts_with("HTTP/1.1 200"), "bad status: {resp}");
    assert!(resp.contains("text/html"), "not a disguise page: {resp}");

    // (b) valid bearer + malformed in-band AUTH frame → disguise page
    let key = derive_static_key(PASS, UID);
    let bearer = make_bearer(&key, UID);
    let resp = https_post_raw(
        srv.fb_port,
        "/api/ppp",
        &format!("Bearer {bearer}"),
        b"garbage-not-a-frame",
    )
    .await
    .expect("https post bad auth frame");
    assert!(
        resp.contains("text/html"),
        "malformed AUTH frame not rejected: {resp}"
    );

    // (c) WT session request with a bad bearer → refused
    assert!(
        raw_wt_connect(&srv.wt_url(), Some("Bearer nope".into()))
            .await
            .is_err(),
        "bad bearer must be refused"
    );

    // (d) AUTH frame sealed with the wrong static key → rejected, no AuthOk
    let bearer = make_bearer(&key, UID);
    let conn = raw_wt_connect(&srv.wt_url(), Some(format!("Bearer {bearer}")))
        .await
        .expect("valid bearer accepted");
    let opening = conn.open_bi().await.expect("open control stream");
    let (send, recv) = timeout(HANDSHAKE, opening)
        .await
        .expect("control stream timeout")
        .expect("open control stream");
    let wrong_key = derive_static_key("wrong-password", UID);
    let mut writer = FrameWriter::new(
        send,
        Arc::new(FrameCipher::new(&wrong_key)),
        CounterGen::stream(),
    );
    let ts = now_unix();
    let ap = AuthPayload {
        proto_version: PROTO_VERSION,
        salt: [7u8; SALT_LEN],
        ts,
        nonce: [9u8; SALT_LEN],
        uid: UID.into(),
        mac: auth_mac(&wrong_key, UID, ts, &[9u8; SALT_LEN]),
    };
    writer
        .write(FrameType::Auth, 0, 0, &ap.encode())
        .await
        .expect("send auth frame");
    let mut reader = FrameReader::new(recv, None, None);
    reader.decoder_mut().raw = true;
    let got = timeout(Duration::from_secs(5), reader.read()).await;
    match got {
        Err(_) => {}       // connection dropped while waiting
        Ok(Err(_)) => {}   // stream error
        Ok(Ok(None)) => {} // clean EOF (connection closed)
        Ok(Ok(Some(f))) => {
            assert_ne!(f.ftype, FrameType::AuthOk, "wrong-key AUTH accepted")
        }
    }

    // (e) nonce replay: reusing a bearer token for a second session fails
    let good = make_bearer(&key, UID);
    let conn1 = raw_wt_connect(&srv.wt_url(), Some(format!("Bearer {good}")))
        .await
        .expect("first session");
    complete_wt_auth(conn1).await.expect("handshake 1");
    assert!(
        raw_wt_connect(&srv.wt_url(), Some(format!("Bearer {good}")))
            .await
            .is_err(),
        "replayed bearer must be refused"
    );

    srv.shutdown().await;
}

/// In-band AUTH handshake with the correct static key; asserts AuthOk.
async fn complete_wt_auth(conn: wtransport::Connection) -> Result<()> {
    let opening = conn.open_bi().await?;
    let (send, recv) = timeout(HANDSHAKE, opening)
        .await?
        .map_err(|e| anyhow!("open failed: {e}"))?;
    let key = derive_static_key(PASS, UID);
    let mut writer = FrameWriter::new(send, Arc::new(FrameCipher::new(&key)), CounterGen::stream());
    let salt = [3u8; SALT_LEN];
    let nonce = [5u8; SALT_LEN];
    let ts = now_unix();
    let ap = AuthPayload {
        proto_version: PROTO_VERSION,
        salt,
        ts,
        nonce,
        uid: UID.into(),
        mac: auth_mac(&key, UID, ts, &nonce),
    };
    writer
        .write(FrameType::Auth, 0, 0, &ap.encode())
        .await
        .map_err(|e| anyhow!("send auth: {e}"))?;
    let mut reader = FrameReader::new(recv, None, None);
    reader.decoder_mut().raw = true;
    let f = timeout(HANDSHAKE, reader.read())
        .await?
        .map_err(|e| anyhow!("read authok: {e}"))?
        .ok_or_else(|| anyhow!("connection closed before AuthOk"))?;
    assert_eq!(f.ftype, FrameType::AuthOk, "expected AuthOk");
    Ok(())
}

/// 8: TCP half-close — a client FIN must not truncate the session; the
/// target still finishes and the full response arrives (WT + POST paths).
#[tokio::test]
async fn tcp_half_close_target_finishes() {
    let srv = spawn_server(true).await.expect("server");
    let payload = b"late-response-after-client-fin".as_slice();
    let hc_port = spawn_halfclose_target(payload).await.expect("target");

    for (label, ob) in [
        ("WT", wt_outbound(&srv.wt_url())),
        ("POST", post_outbound(&srv.fb_url())),
    ] {
        let port = free_port();
        let _inbound = tokio::spawn(socks5::run(format!("127.0.0.1:{port}"), ob, None));
        wait_tcp_port(port).await.expect("socks inbound");
        let mut s = socks5_connect(port, "127.0.0.1", hc_port)
            .await
            .map_err(|c| anyhow!("/{label}: CONNECT refused 0x{c:02x}"))
            .expect("connect");
        s.write_all(b"client-request").await.expect("send request");
        s.shutdown().await.expect("send FIN");
        let mut got = Vec::new();
        timeout(HANDSHAKE, s.read_to_end(&mut got))
            .await
            .unwrap_or_else(|_| {
                panic!("{label}: read-after-FIN timed out (FIN lost or pump aborted)")
            })
            .expect("read");
        assert_eq!(got.as_slice(), payload, "{label}: response incomplete");
    }

    wait_sessions_zero(&srv.state).await;
    srv.shutdown().await;
}

/// 9: degradation chain — an unreachable primary is rebuilt through the
/// fallback on each failure; 3 consecutive transport failures trip the
/// breaker (short cooldown instead of 60s); it half-opens after the cooldown.
#[tokio::test]
async fn degradation_chain_dead_primary_fallback_and_breaker() {
    let srv = spawn_server(true).await.expect("server");
    let target = spawn_target().await.expect("target");
    let dead_wt = spawn_refusing_wt().await.expect("refusing server");

    let cfg = client_cfg(
        Some(format!("https://127.0.0.1:{dead_wt}")),
        Some(srv.fb_url()),
    );
    let pool = Arc::new(WtPool::new(&cfg, cfg.wt_url.as_ref().unwrap()).expect("wt pool"));
    let http =
        Arc::new(HttpOutbound::new(&cfg, cfg.fb_url.as_ref().unwrap()).expect("http fallback"));
    let cb = Arc::new(CircuitBreaker::new(3, Duration::from_millis(400)));
    let ob = Outbound::Both(pool, http, cb.clone());
    assert!(cb.can_try(), "fresh breaker must be closed");

    // 3 attempts: each fails on the primary and succeeds via the fallback.
    for i in 0..3 {
        let s = timeout(HANDSHAKE, ob.open_tcp("127.0.0.1", target))
            .await
            .expect("open timed out")
            .unwrap_or_else(|_| panic!("attempt {i} must succeed via fallback"));
        tunnel_get(s, "127.0.0.1", target)
            .await
            .expect("read over fallback");
        if i < 2 {
            assert!(cb.can_try(), "breaker must not trip below threshold");
        }
    }
    assert!(!cb.can_try(), "3 transport failures must trip the breaker");

    // With the breaker open the session is built purely through fallback.
    let s = timeout(HANDSHAKE, ob.open_tcp("127.0.0.1", target))
        .await
        .expect("open timed out")
        .expect("open must work via the fallback channel");
    tunnel_get(s, "127.0.0.1", target)
        .await
        .expect("read over fallback");

    // After the cooldown elapses the primary is probed again.
    tokio::time::sleep(Duration::from_millis(450)).await;
    assert!(cb.can_try(), "breaker must half-open after cooldown");

    srv.shutdown().await;
}

/// 10: target-side failure is classified — never a transport/breaker event,
/// never triggers fallback, never kills the WT connection.
#[tokio::test]
async fn target_failure_does_not_degrade_or_kill() {
    let srv = spawn_server(true).await.expect("server");
    let target = spawn_target().await.expect("target");
    let unbound = free_port(); // nothing listens here

    // The fallback URL points at a dead TCP port: if a target-side error
    // ever triggered fallback, the failure would surface as a transport
    // error from that dead port instead of a classified dial failure.
    let cfg = client_cfg(
        Some(srv.wt_url()),
        Some(format!("https://127.0.0.1:{unbound}/api/ppp")),
    );
    let pool = Arc::new(WtPool::new(&cfg, cfg.wt_url.as_ref().unwrap()).expect("wt pool"));
    let http = Arc::new(
        HttpOutbound::new(&cfg, cfg.fb_url.as_ref().unwrap()).expect("dead http fallback"),
    );
    let cb = Arc::new(CircuitBreaker::new(3, Duration::from_secs(60)));
    let ob = Outbound::Both(pool, http, cb.clone());

    let open = timeout(HANDSHAKE, ob.open_tcp("127.0.0.1", unbound))
        .await
        .expect("open timed out");
    let err = open.err().expect("dial to an unbound port must fail");
    assert_eq!(error_tag(&err), "dial-failed");
    assert!(
        target_error(&err).is_some(),
        "target errors must stay classified (proves the fallback was never contacted)"
    );
    assert!(cb.can_try(), "target errors must never trip the breaker");

    // The WT connection survived the refusal: a live target dial works.
    let s = timeout(HANDSHAKE, ob.open_tcp("127.0.0.1", target))
        .await
        .expect("open timed out")
        .expect("connection must survive a refused target");
    tunnel_get(s, "127.0.0.1", target)
        .await
        .expect("read over WT");

    // The refused session's quota must already be released server-side.
    wait_sessions_zero(&srv.state).await;

    srv.shutdown().await;
}

/// 11: lifecycle — finished sessions release their quota, and every listen
/// port is immediately reusable once all handles are dropped.
#[tokio::test]
async fn lifecycle_no_leak_ports_reusable() {
    let srv = spawn_server(true).await.expect("server");
    let wt_port = srv.wt_port;
    let fb_port = srv.fb_port;
    let target = spawn_target().await.expect("target");

    let ob = wt_outbound(&srv.wt_url());
    let socks_port = free_port();
    let inbound = tokio::spawn(socks5::run(
        format!("127.0.0.1:{socks_port}"),
        ob.clone(),
        None,
    ));
    wait_tcp_port(socks_port).await.expect("socks inbound");

    socks5_get(socks_port, "127.0.0.1", target)
        .await
        .expect("session through the stack");
    wait_sessions_zero(&srv.state).await;

    // Client teardown: inbound aborted, outbound dropped → port free at once.
    inbound.abort();
    let _ = inbound.await;
    drop(ob);
    TcpListener::bind(("127.0.0.1", socks_port))
        .await
        .expect("socks port must be immediately reusable after drop");

    // Server teardown: both listener ports immediately reusable.
    srv.shutdown().await;
    TcpListener::bind(("127.0.0.1", fb_port))
        .await
        .expect("fallback TCP port must be immediately reusable after drop");
    UdpSocket::bind(("0.0.0.0", wt_port))
        .await
        .expect("WT (UDP) port must be immediately reusable after drop");
}

// ---------------------------------------------------------------------------
// TLS helpers for the disguise-page assertions + raw WT session requests
// ---------------------------------------------------------------------------

/// HTTPS/1.1 GET with `--skip-verify` semantics; returns the raw response.
async fn https_get(port: u16, path: &str, auth: Option<&str>) -> Result<String> {
    let mut req = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n");
    if let Some(a) = auth {
        req.push_str(&format!("Authorization: {a}\r\n"));
    }
    req.push_str("Connection: close\r\n\r\n");
    https_roundtrip(port, req.into_bytes()).await
}

/// HTTPS/1.1 POST with an octet-stream body; returns the raw response.
async fn https_post_raw(port: u16, path: &str, auth: &str, body: &[u8]) -> Result<String> {
    let mut req = format!(
        "POST {path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: {auth}\r\n\
         Content-Type: application/octet-stream\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    req.extend_from_slice(body);
    https_roundtrip(port, req).await
}

async fn https_roundtrip(port: u16, raw: Vec<u8>) -> Result<String> {
    let tls = Arc::new(rustls_client_noverify());
    let tcp = TcpStream::connect(("127.0.0.1", port)).await?;
    let name = rustls::pki_types::ServerName::try_from("localhost".to_string())
        .map_err(|e| anyhow!("bad server name: {e}"))?
        .to_owned();
    let mut s = tokio_rustls::TlsConnector::from(tls)
        .connect(name, tcp)
        .await?;
    s.write_all(&raw).await?;
    let mut resp = Vec::new();
    timeout(HANDSHAKE, s.read_to_end(&mut resp))
        .await?
        .expect("read https response");
    Ok(String::from_utf8_lossy(&resp).into_owned())
}

fn rustls_client_noverify() -> rustls::ClientConfig {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .expect("tls versions");
    let mut tls = builder
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
    tls.dangerous()
        .set_certificate_verifier(Arc::new(NoVerify { provider }));
    tls
}

#[derive(Debug)]
struct NoVerify {
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Raw WT session request with a caller-chosen Authorization header
/// (skip-verify, same tuning as the production client).
async fn raw_wt_connect(url: &str, auth: Option<String>) -> Result<wtransport::Connection> {
    static EP: OnceLock<Endpoint<WtClientSide>> = OnceLock::new();
    let ep = EP.get_or_init(|| {
        use wtransport::tls::client::{build_default_tls_config, NoServerVerification};
        let verifier: Option<Arc<dyn rustls::client::danger::ServerCertVerifier>> =
            Some(Arc::new(NoServerVerification::new()));
        let tls = build_default_tls_config(Arc::new(rustls::RootCertStore::empty()), verifier);
        Endpoint::client(
            WtClientConfig::builder()
                .with_bind_default()
                .with_custom_tls_and_transport(tls, newppp::quic_tune::tuned(2 * 1024 * 1024))
                .build(),
        )
        .expect("wt client endpoint")
    });
    let mut opts = ConnectOptions::builder(url);
    if let Some(a) = auth {
        opts = opts.add_header("Authorization", a);
    }
    timeout(HANDSHAKE, ep.connect(opts.build()))
        .await?
        .map_err(|e| anyhow!("wt connect failed: {e}"))
}
