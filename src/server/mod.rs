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

pub async fn run(cfg: ServerConfig) -> Result<()> {
    let static_keys: HashMap<String, [u8; 32]> = cfg
        .users
        .iter()
        .map(|(u, p)| (u.clone(), crypto::derive_static_key(p, u)))
        .collect();
    for u in static_keys.keys() {
        info!("user '{u}' registered");
    }

    let st = Arc::new(ServerState {
        static_keys,
        conns: DashMap::new(),
        conn_seq: AtomicU64::new(1),
        active_sessions: AtomicU64::new(0),
        max_sessions: cfg.max_sessions,
        rate_mbps: cfg.rate_mbps,
        idle: Duration::from_secs(cfg.idle_secs),
        seen_nonces: DashMap::new(),
        path: cfg.path.clone(),
    });

    tokio::spawn(reaper_loop(st.clone()));

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
        "newppp server started (max_sessions={}, rate={}Mbps, idle={}s)",
        cfg.max_sessions, cfg.rate_mbps, cfg.idle_secs
    );

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            info!("shutdown signal received");
        }
        _ = wait_any(&mut tasks) => {
            warn!("a listener exited; shutting down");
        }
    }
    tasks.abort_all();
    Ok(())
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

async fn reaper_loop(st: Arc<ServerState>) {
    let mut iv = tokio::time::interval(Duration::from_secs(10));
    loop {
        iv.tick().await;
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

/// Decrypt and verify the in-band AUTH frame (first frame of a channel).
/// Returns (uid, static_key, payload).
pub fn auth_from_frame(st: &ServerState, f: &Frame) -> Option<(String, [u8; 32], AuthPayload)> {
    for (uid, skey) in st.static_keys.iter() {
        let cipher = crypto::FrameCipher::new(skey);
        let Ok(pt) = cipher.open(f.counter, &f.aad, &f.payload) else {
            continue;
        };
        let Ok(ap) = AuthPayload::decode(&pt) else {
            continue;
        };
        if ap.uid != *uid || !ap.verify(skey, AUTH_WINDOW) {
            continue;
        }
        if !st.check_and_remember_nonce(uid, &ap.nonce, ap.ts) {
            warn!("replayed auth nonce from uid={uid}");
            return None;
        }
        return Some((uid.clone(), *skey, ap));
    }
    None
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
            idle: Duration::from_secs(60),
            seen_nonces: DashMap::new(),
            path: "/api/ppp".into(),
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
