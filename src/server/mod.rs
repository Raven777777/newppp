//! Server entry: wiring, auth helpers, TLS setup, idle reaper.

pub mod disguise;
pub mod fallback;
pub mod hub;
pub mod limit;
pub mod state;
pub mod wt;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use dashmap::DashMap;
use tracing::{info, warn};
use wtransport::Identity;

use crate::config::{CertSource, ServerConfig};
use crate::proto::crypto::{self, AuthPayload, AUTH_WINDOW};
use crate::proto::frame::Frame;
use state::ServerState;

/// Build the shared server state. Public so integration tests can wire the
/// real listeners with an inspectable state.
pub fn build_state(cfg: &ServerConfig) -> Arc<ServerState> {
    let static_keys: HashMap<String, [u8; 32]> = cfg
        .users
        .iter()
        .map(|(u, p)| (u.clone(), crypto::derive_static_key(p, u)))
        .collect();
    Arc::new(ServerState {
        static_keys,
        conns: DashMap::new(),
        conn_seq: AtomicU64::new(1),
        active_sessions: AtomicU64::new(0),
        max_sessions: cfg.max_sessions,
        rate_mbps: cfg.rate_mbps,
        rates: DashMap::new(),
        idle: Duration::from_secs(cfg.idle_secs),
        allow_private_targets: cfg.allow_private_targets,
        unauth: Arc::new(limit::UnauthGate::new(
            cfg.max_unauth,
            (cfg.max_unauth / 8).clamp(2, 64),
        )),
        seen_nonces: DashMap::new(),
        nonce_lock: std::sync::Mutex::new(()),
        path: cfg.path.clone(),
        max_plaintext: cfg.max_plaintext,
        udp_dns: DashMap::new(),
        udp_dns_ttl: Duration::from_secs(cfg.udp_dns_ttl),
    })
}

pub async fn run(cfg: ServerConfig) -> Result<()> {
    let token = tokio_util::sync::CancellationToken::new();
    {
        let t = token.clone();
        tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            info!("shutdown signal received");
            t.cancel();
        });
    }
    run_with_shutdown(cfg, token).await
}

/// Run the server until `token` is cancelled (SIGINT/SIGTERM in `run`, tests
/// pass their own), then shut down gracefully:
///
/// 1. stop handling new connections (cancel live connection tokens — their
///    watchers close the QUIC transport with CONNECTION_CLOSE and session
///    tokens are children, so pumps unroll quickly);
/// 2. drain in-flight sessions up to `--shutdown-grace` (default 10s), then
///    force-close whatever is left;
/// 3. abort the listener tasks and drop their handles.
///
/// The teardown timing is the proven sequence from `tests/e2e.rs`
/// (`TestServer::shutdown`): cancelling before aborting the listeners is what
/// releases the QUIC endpoint driver (and its UDP socket) immediately — an
/// accept-loop abort alone leaves per-connection tasks holding `Connection`
/// clones and the port stranding for seconds. Returns Ok(()) so supervision
/// (systemd `Restart=on-failure`, docker `Restart=always`) sees exit code 0
/// and does not enter a restart loop.
pub async fn run_with_shutdown(
    cfg: ServerConfig,
    token: tokio_util::sync::CancellationToken,
) -> Result<()> {
    let st = build_state(&cfg);
    for u in st.static_keys.keys() {
        info!("user '{u}' registered");
    }

    let shutdown_grace = Duration::from_secs(cfg.shutdown_grace);
    tokio::spawn(reaper_loop(st.clone(), token.clone()));
    let transport: &'static str = match (
        cfg.listen.is_some(),
        cfg.fallback_listen.is_some() || cfg.http_listen.is_some(),
    ) {
        (true, true) => "mixed",
        (true, false) => "wt",
        (false, true) => "fallback",
        (false, false) => "none",
    };

    let health_task = match &cfg.health {
        Some(addr) => Some(
            crate::health::spawn(
                addr,
                Arc::new(crate::health::Health::new(
                    std::time::Instant::now(),
                    crate::health::Source::Server {
                        st: st.clone(),
                        transport,
                    },
                )),
                "server",
            )
            .await?,
        ),
        None => None,
    };

    let tls = setup_tls(cfg.cert).await.context("TLS setup")?;

    let mut tasks = tokio::task::JoinSet::new();
    match cfg.listen {
        Some(addr) => {
            let listen: SocketAddr = addr.parse().context("bad --listen address")?;
            tasks.spawn(wt::run_wt(
                st.clone(),
                listen,
                tls.identity,
                cfg.recv_window,
            ));
        }
        None => {
            info!("WebTransport (QUIC/UDP) listener disabled (--listen not set): pure-website mode")
        }
    }

    if let Some(fb) = cfg.fallback_listen {
        let fb: SocketAddr = fb.parse().context("bad --fallback-listen address")?;
        let cert = tls.cert.clone();
        let key = tls.key.clone();
        let st2 = st.clone();
        tasks.spawn(async move { fallback::run_tls(st2, fb, cert, key).await });
    }
    if let Some(h) = cfg.http_listen {
        let h: SocketAddr = h.parse().context("bad --http-listen address")?;
        let acme = cfg.acme_dir.clone().map(PathBuf::from);
        tasks.spawn(async move { fallback::run_plain(h, acme).await });
    }

    info!(
        "newppp server started (max_sessions={}, rate={}Mbps, idle={}s, shutdown_grace={}s)",
        cfg.max_sessions, cfg.rate_mbps, cfg.idle_secs, cfg.shutdown_grace
    );

    tokio::select! {
        _ = token.cancelled() => {}
        _ = wait_any(&mut tasks) => {
            warn!("a listener exited; shutting down");
        }
    }
    graceful_shutdown(&st, &mut tasks, shutdown_grace, &token).await;
    if let Some(t) = health_task {
        t.abort();
        let _ = t.await;
    }
    Ok(())
}

/// P3-1 teardown: cancel live connections → drain bounded by the grace
/// period → drop listener handles. See `run_with_shutdown` for the rationale.
async fn graceful_shutdown(
    st: &Arc<ServerState>,
    tasks: &mut tokio::task::JoinSet<Result<()>>,
    grace: Duration,
    token: &tokio_util::sync::CancellationToken,
) {
    let tokens: Vec<tokio_util::sync::CancellationToken> = st
        .conns
        .iter()
        .filter(|c| !c.value().cancel.is_cancelled())
        .map(|c| c.value().cancel.clone())
        .collect();
    info!(
        "graceful shutdown: closing {} live connection(s), draining up to {grace:?}",
        tokens.len()
    );
    for t in tokens {
        t.cancel();
    }
    let deadline = tokio::time::Instant::now() + grace;
    while st
        .active_sessions
        .load(std::sync::atomic::Ordering::Relaxed)
        != 0
        && tokio::time::Instant::now() < deadline
    {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let left = st
        .active_sessions
        .load(std::sync::atomic::Ordering::Relaxed);
    if left > 0 {
        warn!("drain timeout after {grace:?}: {left} in-flight session(s) force-closed");
    } else {
        info!("graceful shutdown: drain complete");
    }
    st.sweep_conns();
    token.cancel();
    tasks.abort_all();
}

/// Resolve as soon as any listener task finishes (success or failure).
async fn wait_any(tasks: &mut tokio::task::JoinSet<Result<()>>) {
    if let Some(res) = tasks.join_next().await {
        match res {
            Ok(Ok(())) => {}
            Ok(Err(e)) => warn!("listener error: {e:#}"),
            Err(_) => {}
        }
    }
}

async fn reaper_loop(st: Arc<ServerState>, token: tokio_util::sync::CancellationToken) {
    let mut iv = tokio::time::interval(Duration::from_secs(10));
    loop {
        tokio::select! {
            _ = token.cancelled() => return,
            _ = iv.tick() => {}
        }
        st.reap_idle();
        st.sweep_conns();
    }
}

struct TlsMaterial {
    identity: Identity,
    cert: PathBuf,
    key: PathBuf,
}

async fn setup_tls(src: CertSource) -> Result<TlsMaterial> {
    match src {
        CertSource::Files { cert, key } => {
            let cert_path = PathBuf::from(&cert);
            let key_path = PathBuf::from(&key);
            let identity = Identity::load_pemfiles(&cert_path, &key_path).await?;
            Ok(TlsMaterial {
                identity,
                cert: cert_path,
                key: key_path,
            })
        }
        CertSource::SelfSigned => {
            let ck = rcgen::generate_simple_self_signed(vec![
                "localhost".to_string(),
                "newppp.local".to_string(),
            ])?;
            let dir = std::env::temp_dir().join("newppp-dev-tls");
            std::fs::create_dir_all(&dir)?;
            let cert_path = dir.join("cert.pem");
            let key_path = dir.join("key.pem");
            std::fs::write(&cert_path, ck.cert.pem())?;
            std::fs::write(&key_path, ck.signing_key.serialize_pem())?;
            warn!(
                "using self-signed dev certificate ({}) — clients need --skip-verify",
                cert_path.display()
            );
            let identity = Identity::load_pemfiles(&cert_path, &key_path).await?;
            Ok(TlsMaterial {
                identity,
                cert: cert_path,
                key: key_path,
            })
        }
    }
}

// ---------------------------------------------------------------------------
// Auth helpers (shared by WT and fallback paths)
// ---------------------------------------------------------------------------

/// Verify the HTTP-level bearer header. Returns (uid, static_key).
///
/// The token's (ts, nonce) pair is recorded in the server-wide nonce cache:
/// the same bearer is accepted exactly once, so a captured token cannot be
/// replayed within the ±60s timestamp window. MAC verification runs first,
/// so unauthenticated traffic cannot pollute the cache.
pub fn bearer_user<'a>(
    st: &'a ServerState,
    header: Option<&str>,
) -> Option<(String, &'a [u8; 32])> {
    let h = header?;
    let token = h
        .strip_prefix("Bearer ")
        .or_else(|| h.strip_prefix("bearer "))?;
    let uid = crypto::bearer_uid(token)?;
    let key = st.static_keys.get(uid)?;
    let (ts, nonce) = crypto::verify_bearer_parts(token, key, uid, AUTH_WINDOW)?;
    if !st.check_and_remember_nonce(uid, &nonce, ts) {
        warn!("replayed bearer token for uid={uid}");
        return None;
    }
    Some((uid.to_string(), key))
}

/// Boolean variant used on the WT session-request path.
pub fn bearer_ok(st: &ServerState, header: Option<&str>) -> bool {
    bearer_user(st, header).is_some()
}

/// Outcome of verifying the in-band AUTH frame (first frame of a channel).
pub enum AuthOutcome {
    /// Authenticated: uid, static key and decoded payload.
    Ok(String, [u8; 32], AuthPayload),
    /// The payload authenticated under a known key, but advertises an
    /// incompatible protocol version. This is a configuration error, not an
    /// attacker — surface it explicitly instead of a generic decrypt failure.
    VersionMismatch { client: u8, server: u8 },
    /// Wrong key, malformed payload, expired timestamp or replay.
    Rejected,
}

/// Decrypt and verify the in-band AUTH frame. Runs the version check before
/// the replay cache so a version skew never consumes a nonce.
pub fn auth_from_frame(st: &ServerState, f: &Frame) -> AuthOutcome {
    for (uid, skey) in st.static_keys.iter() {
        let cipher = crypto::FrameCipher::new(skey);
        let Ok(pt) = cipher.open(f.counter, &f.aad, &f.payload) else {
            continue;
        };
        let Ok(ap) = AuthPayload::decode(&pt) else {
            continue;
        };
        if ap.uid != *uid {
            continue;
        }
        if !ap.proto_version_compatible() {
            return AuthOutcome::VersionMismatch {
                client: ap.proto_version,
                server: crate::proto::frame::PROTO_VERSION,
            };
        }
        if !ap.verify(skey, AUTH_WINDOW) {
            continue;
        }
        if !st.check_and_remember_nonce(uid, &ap.nonce, ap.ts) {
            warn!("replayed auth nonce from uid={uid}");
            return AuthOutcome::Rejected;
        }
        return AuthOutcome::Ok(uid.clone(), *skey, ap);
    }
    AuthOutcome::Rejected
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::state::ServerState;
    use dashmap::DashMap;
    use std::collections::HashMap;
    use std::sync::atomic::AtomicU64;
    use std::time::Duration;

    fn test_state() -> ServerState {
        let key = crypto::derive_static_key("pw", "alice");
        let mut static_keys = HashMap::new();
        static_keys.insert("alice".to_string(), key);
        ServerState {
            static_keys,
            conns: DashMap::new(),
            conn_seq: AtomicU64::new(1),
            active_sessions: AtomicU64::new(0),
            max_sessions: 10,
            rate_mbps: 0,
            rates: DashMap::new(),
            idle: Duration::from_secs(60),
            allow_private_targets: false,
            unauth: Arc::new(limit::UnauthGate::new(128, 16)),
            seen_nonces: DashMap::new(),
            nonce_lock: std::sync::Mutex::new(()),
            path: "/api/ppp".into(),
            max_plaintext: crate::proto::frame::MAX_PLAINTEXT,
            udp_dns: DashMap::new(),
            udp_dns_ttl: Duration::from_secs(3600),
        }
    }

    /// The same bearer token (same ts+nonce) must be accepted exactly once;
    /// a replay within the timestamp window is rejected.
    #[test]
    fn bearer_replay_rejected_second_use() {
        let st = test_state();
        let key = crypto::derive_static_key("pw", "alice");
        let header = format!("Bearer {}", crypto::make_bearer(&key, "alice"));
        assert!(bearer_user(&st, Some(header.as_str())).is_some());
        assert!(bearer_user(&st, Some(header.as_str())).is_none());
    }

    /// Fresh tokens (fresh nonce each mint) keep working normally.
    #[test]
    fn bearer_fresh_nonce_accepted_after_previous_use() {
        let st = test_state();
        let key = crypto::derive_static_key("pw", "alice");
        let h1 = format!("Bearer {}", crypto::make_bearer(&key, "alice"));
        let h2 = format!("Bearer {}", crypto::make_bearer(&key, "alice"));
        assert!(bearer_user(&st, Some(h1.as_str())).is_some());
        assert!(bearer_user(&st, Some(h2.as_str())).is_some());
    }

    /// Build the raw `Frame` carried by an AUTH payload sealed with `key`.
    fn auth_frame(key: &[u8; 32], ap: &AuthPayload) -> Frame {
        use crate::proto::crypto::CounterGen;
        use crate::proto::frame::{FrameDecoder, FrameEncoder, FrameType};
        let enc = FrameEncoder::new(
            Arc::new(crypto::FrameCipher::new(key)),
            CounterGen::stream(),
        );
        let wire = enc.encode(FrameType::Auth, 0, 0, &ap.encode()).unwrap();
        let mut dec = FrameDecoder::new(None, None);
        dec.raw = true;
        dec.feed(&wire);
        dec.next_frame().unwrap().unwrap()
    }

    fn versioned_payload(key: &[u8; 32], version: u8) -> AuthPayload {
        let nonce = [7u8; 16];
        let ts = crypto::now_unix();
        AuthPayload {
            proto_version: version,
            salt: [3u8; 16],
            ts,
            nonce,
            uid: "alice".into(),
            mac: crypto::auth_mac(key, "alice", ts, &nonce),
            max_plaintext: crate::proto::frame::MAX_PLAINTEXT as u32,
        }
    }

    /// A correctly authenticated peer advertising a different protocol
    /// version must be reported as a named mismatch, not silently rejected.
    #[test]
    fn auth_version_mismatch_is_explicit() {
        let st = test_state();
        let key = crypto::derive_static_key("pw", "alice");
        let ap = versioned_payload(&key, crate::proto::frame::PROTO_VERSION.wrapping_add(1));
        match auth_from_frame(&st, &auth_frame(&key, &ap)) {
            AuthOutcome::VersionMismatch { client, server } => {
                assert_eq!(client, crate::proto::frame::PROTO_VERSION.wrapping_add(1));
                assert_eq!(server, crate::proto::frame::PROTO_VERSION);
            }
            _ => panic!("expected VersionMismatch"),
        }
        // A mismatch must not consume the replay nonce.
        assert_eq!(st.seen_nonces.len(), 0);
    }

    /// Matching versions authenticate normally.
    #[test]
    fn auth_matching_version_succeeds() {
        let st = test_state();
        let key = crypto::derive_static_key("pw", "alice");
        let ap = versioned_payload(&key, crate::proto::frame::PROTO_VERSION);
        assert!(matches!(
            auth_from_frame(&st, &auth_frame(&key, &ap)),
            AuthOutcome::Ok(..)
        ));
    }

    /// The nonce cache must not be polluted by traffic that fails MAC
    /// verification (only verified tokens may record their nonce).
    #[test]
    fn bearer_bad_mac_does_not_pollute_nonce_cache() {
        let st = test_state();
        let key = crypto::derive_static_key("pw", "alice");
        let header = format!("Bearer {}", crypto::make_bearer(&key, "alice"));
        // tamper with the MAC (last hex chunk)
        let mut tampered = header.clone();
        let last = tampered.len() - 1;
        tampered.replace_range(last.., if &tampered[last..] == "0" { "1" } else { "0" });
        assert!(bearer_user(&st, Some(tampered.as_str())).is_none());
        // nonce map untouched by the failed attempt
        assert_eq!(st.seen_nonces.len(), 0);
    }
}
