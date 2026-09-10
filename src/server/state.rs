//! Server-wide and per-connection state.

use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::proto::crypto::{CounterGen, FrameCipher, AUTH_WINDOW};
use crate::server::limit::RateLimiter;

/// Upper bound for the replay-nonce cache; expired entries are purged when
/// it is exceeded (instead of clearing the whole table, which would open a
/// replay window for captured auth frames).
const NONCE_CAP: usize = 50_000;

/// Per-connection session handle (registered for reaping).
pub struct SessionHandle {
    pub cancel: CancellationToken,
    pub last_active: AtomicI64,
}
impl SessionHandle {
    pub fn from_token(token: CancellationToken) -> Self {
        Self {
            cancel: token,
            last_active: AtomicI64::new(now_millis()),
        }
    }

    pub fn touch(&self) {
        self.last_active
            .store(now_millis(), std::sync::atomic::Ordering::Relaxed);
    }

    pub fn idle_for(&self) -> Duration {
        let last = self.last_active.load(std::sync::atomic::Ordering::Relaxed);
        let now = now_millis();
        Duration::from_millis(now.saturating_sub(last) as u64)
    }
}

pub fn now_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// State for one authenticated remote connection (one user session).
pub struct ConnState {
    pub id: u64,
    pub uid: String,
    pub cipher: Arc<FrameCipher>,
    pub stream_counters: CounterGen,
    pub rate: RateLimiter,
    pub cancel: CancellationToken,
    pub sessions: DashMap<u32, Arc<SessionHandle>>,
    /// mux-path TCP routing: sid -> inbound data queue
    pub tcp_routes: DashMap<u32, mpsc::Sender<(Vec<u8>, bool)>>,
    /// mux-path UDP relays: sid -> sockets
    pub udp_routes: DashMap<u32, Arc<UdpRelay>>,
    pub max_per_conn: usize,
}

impl ConnState {
    /// Register a session whose token is a CHILD of the connection token:
    /// when the connection dies (or is swept), every session is cancelled
    /// and its global quota released.
    pub fn register(&self, sid: u32) -> CancellationToken {
        let token = self.cancel.child_token();
        self.sessions
            .insert(sid, Arc::new(SessionHandle::from_token(token.clone())));
        token
    }

    pub fn register_with(&self, sid: u32, token: CancellationToken) -> Arc<SessionHandle> {
        let h = Arc::new(SessionHandle::from_token(token));
        self.sessions.insert(sid, h.clone());
        h
    }

    /// Tear down a session. Returns true when a registered session handle
    /// was removed — exactly once per acquired global quota, so callers can
    /// release the quota precisely on `true`.
    pub fn drop_session(&self, sid: u32) -> bool {
        self.tcp_routes.remove(&sid);
        if let Some((_, r)) = self.udp_routes.remove(&sid) {
            r.cancel.cancel();
        }
        if let Some((_, h)) = self.sessions.remove(&sid) {
            h.cancel.cancel();
            true
        } else {
            false
        }
    }

    pub fn touch(&self, sid: u32) {
        if let Some(h) = self.sessions.get(&sid) {
            h.touch();
        }
    }

    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }
}

/// Lazily-bound UDP relay sockets for one UDP session.
pub struct UdpRelay {
    pub cancel: CancellationToken,
    pub v4: tokio::sync::OnceCell<Arc<tokio::net::UdpSocket>>,
    pub v6: tokio::sync::OnceCell<Arc<tokio::net::UdpSocket>>,
}

impl UdpRelay {
    pub fn new() -> Self {
        Self {
            cancel: CancellationToken::new(),
            v4: tokio::sync::OnceCell::new(),
            v6: tokio::sync::OnceCell::new(),
        }
    }
}

/// Global server state.
pub struct ServerState {
    pub static_keys: HashMap<String, [u8; 32]>,
    pub conns: DashMap<u64, Arc<ConnState>>,
    pub conn_seq: AtomicU64,
    pub active_sessions: AtomicU64,
    pub max_sessions: usize,
    pub rate_mbps: u64,
    pub idle: Duration,
    /// uid -> replay-nonce cache; value is the auth timestamp used for expiry.
    pub seen_nonces: DashMap<String, u64>,
    pub path: String,
}

impl ServerState {
    pub fn try_acquire_session(&self) -> bool {
        loop {
            let cur = self.active_sessions.load(Ordering::Relaxed);
            if cur >= self.max_sessions as u64 {
                return false;
            }
            if self
                .active_sessions
                .compare_exchange(cur, cur + 1, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                return true;
            }
        }
    }

    pub fn release_session(&self) {
        self.active_sessions.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn check_and_remember_nonce(&self, uid: &str, nonce: &[u8], ts: u64) -> bool {
        let key = format!("{uid}|{ts}|{}", crate::proto::crypto::hex(nonce));
        if self.seen_nonces.insert(key, ts).is_some() {
            return false;
        }
        if self.seen_nonces.len() > NONCE_CAP {
            // Purge only entries that are past any plausible auth window so
            // captured nonces stay rejected; only authenticated users can
            // insert here, so the cache cannot be flooded anonymously.
            let cutoff = crate::proto::crypto::now_unix().saturating_sub(2 * AUTH_WINDOW);
            self.seen_nonces.retain(|_, v| *v > cutoff);
        }
        true
    }

    /// Close sessions idle longer than the configured timeout. Removing a
    /// registered handle also releases its global session quota (the pump
    /// tasks observe `false` from `drop_session` and skip their release).
    pub fn reap_idle(&self) {
        let idle = self.idle;
        for c in self.conns.iter() {
            // Collect first: `drop_session` removes from `sessions`, which
            // must not happen inside an iteration over the same map.
            let expired: Vec<u32> = c
                .sessions
                .iter()
                .filter(|e| e.value().idle_for() > idle)
                .map(|e| *e.key())
                .collect();
            for sid in expired {
                tracing::debug!(
                    "reaping idle session sid={sid} of conn {} (uid={})",
                    c.id,
                    c.uid
                );
                // `drop_session` (unlike plain handle removal) also drops the
                // stale tcp/udp route entries and cancels the UDP relay, so
                // the relay socket is unbound instead of receiving forever.
                if c.drop_session(sid) {
                    self.release_session();
                }
            }
        }
    }

    /// Periodically drop conn entries whose token is cancelled.
    pub fn sweep_conns(&self) {
        self.conns.retain(|_, c| !c.cancel.is_cancelled());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn test_state() -> ServerState {
        ServerState {
            static_keys: HashMap::new(),
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

    fn test_conn(id: u64) -> Arc<ConnState> {
        Arc::new(ConnState {
            id,
            uid: "u".into(),
            cipher: Arc::new(FrameCipher::new(&[0u8; 32])),
            stream_counters: CounterGen::stream(),
            rate: RateLimiter::new(0),
            cancel: CancellationToken::new(),
            sessions: Default::default(),
            tcp_routes: Default::default(),
            udp_routes: Default::default(),
            max_per_conn: 8,
        })
    }

    #[test]
    fn drop_session_reports_first_removal_only() {
        let conn = test_conn(1);
        conn.register(7);
        assert!(conn.drop_session(7));
        assert!(!conn.drop_session(7));
    }

    #[test]
    fn reap_idle_releases_global_quota() {
        let st = test_state();
        let conn = test_conn(1);
        st.conns.insert(1, conn.clone());
        conn.register(7);
        st.active_sessions.store(1, Ordering::Relaxed);
        // backdate the session beyond the idle timeout
        conn.sessions
            .get(&7)
            .expect("session registered")
            .last_active
            .store(now_millis() - 120_000, Ordering::Relaxed);
        st.reap_idle();
        assert!(conn.sessions.get(&7).is_none());
        assert_eq!(st.active_sessions.load(Ordering::Relaxed), 0);
    }

    /// Reaping an idle UDP session must also drop the relay route and cancel
    /// the relay (unbinding the recv task), not just the session handle.
    #[test]
    fn reap_idle_cancels_udp_relay_route() {
        let st = test_state();
        let conn = test_conn(1);
        st.conns.insert(1, conn.clone());
        conn.register(9);
        let relay = Arc::new(UdpRelay::new());
        conn.udp_routes.insert(9, relay.clone());
        st.active_sessions.store(1, Ordering::Relaxed);
        conn.sessions
            .get(&9)
            .expect("session registered")
            .last_active
            .store(now_millis() - 120_000, Ordering::Relaxed);
        st.reap_idle();
        assert!(conn.sessions.get(&9).is_none());
        assert!(conn.udp_routes.get(&9).is_none());
        assert!(relay.cancel.is_cancelled());
        assert_eq!(st.active_sessions.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn nonce_replay_rejected() {
        let st = test_state();
        assert!(st.check_and_remember_nonce("u", &[1u8; 16], 1000));
        assert!(!st.check_and_remember_nonce("u", &[1u8; 16], 1000));
    }
}
