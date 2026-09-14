//! Server-wide and per-connection state.

use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::proto::crypto::{CounterGen, FrameCipher, AUTH_WINDOW};
use crate::proto::frame::FrameLimit;
use crate::server::limit::{RateLimiter, UnauthGate};

/// Upper bound for the replay-nonce cache; expired entries are purged when
/// it is exceeded (instead of clearing the whole table, which would open a
/// replay window for captured auth frames).
const NONCE_CAP: usize = 50_000;

/// Upper bound for the UDP target DNS cache (attacker-chosen names must not
/// grow it without limit).
const UDP_DNS_CACHE_CAP: usize = 4096;

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

/// Monotonic milliseconds since the first call (process-relative uptime).
///
/// Idle/liveness tracking must not be perturbed by wall-clock (NTP) jumps, so
/// this deliberately uses `Instant`, not `SystemTime`. Callers only ever
/// compare two values from this function; absolute wall time is never needed
/// in this module (the `/healthz` timestamp uses its own wall clock).
pub fn now_millis() -> i64 {
    static BASE: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    BASE.get_or_init(Instant::now).elapsed().as_millis() as i64
}

/// State for one authenticated remote connection (one user session).
pub struct ConnState {
    pub id: u64,
    pub uid: String,
    pub cipher: Arc<FrameCipher>,
    pub stream_counters: CounterGen,
    /// Shared (per-uid) egress+ingress limiter: all of a user's connections
    /// draw from the same bucket, so the `--rate` cap is per-user, not
    /// per-connection.
    pub rate: Arc<RateLimiter>,
    pub cancel: CancellationToken,
    pub sessions: DashMap<u32, Arc<SessionHandle>>,
    /// mux-path TCP routing: sid -> inbound data queue
    pub tcp_routes: DashMap<u32, mpsc::Sender<(Vec<u8>, bool)>>,
    /// mux-path UDP relays: sid -> sockets
    pub udp_routes: DashMap<u32, Arc<UdpRelay>>,
    pub max_per_conn: usize,
    /// Connection-level liveness (any register/touch refreshes it). Note
    /// that keepalive Pings deliberately do NOT count: idle connections
    /// with no sessions are reaped by the reaper regardless.
    pub last_active: AtomicI64,
    /// Negotiated plaintext frame limit, shared by every encoder/decoder of
    /// this connection (control stream, session streams, datagrams).
    pub limit: FrameLimit,
}

impl ConnState {
    /// Register a session whose token is a CHILD of the connection token:
    /// when the connection dies (or is swept), every session is cancelled
    /// and its global quota released.
    pub fn register(&self, sid: u32) -> CancellationToken {
        let token = self.cancel.child_token();
        let registered = self.try_register_with(sid, token.clone());
        debug_assert!(registered.is_some(), "session sid {sid} already registered");
        drop(registered);
        token
    }

    /// Atomically register a session handle for `sid`. Returns `None` when the
    /// sid is already taken, so callers can release any quota they acquired
    /// instead of silently overwriting (and leaking) the existing handle.
    ///
    /// TCP and UDP sessions both go through this one namespace, so a UDP
    /// associate can never clobber a TCP session's handle.
    pub fn try_register_with(
        &self,
        sid: u32,
        token: CancellationToken,
    ) -> Option<Arc<SessionHandle>> {
        self.last_active
            .store(now_millis(), std::sync::atomic::Ordering::Relaxed);
        match self.sessions.entry(sid) {
            dashmap::mapref::entry::Entry::Occupied(_) => None,
            dashmap::mapref::entry::Entry::Vacant(e) => {
                let h = Arc::new(SessionHandle::from_token(token));
                e.insert(h.clone());
                Some(h)
            }
        }
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
        self.last_active
            .store(now_millis(), std::sync::atomic::Ordering::Relaxed);
        if let Some(h) = self.sessions.get(&sid) {
            h.touch();
        }
    }

    /// Connection-level idle duration (any register/touch resets it).
    pub fn idle_for(&self) -> Duration {
        let last = self.last_active.load(std::sync::atomic::Ordering::Relaxed);
        Duration::from_millis(now_millis().saturating_sub(last) as u64)
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

impl Default for UdpRelay {
    fn default() -> Self {
        Self::new()
    }
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
    /// uid -> shared token bucket (`rate_for` is the only accessor).
    pub rates: DashMap<String, Arc<RateLimiter>>,
    pub idle: Duration,
    pub allow_private_targets: bool,
    /// Cap on concurrent connections that have not completed in-band AUTH yet.
    pub unauth: Arc<UnauthGate>,
    /// uid -> replay-nonce cache; value is the auth timestamp used for expiry.
    pub seen_nonces: DashMap<String, u64>,
    pub(crate) nonce_lock: std::sync::Mutex<()>,
    pub path: String,
    /// Advertised plaintext frame limit (bytes) for new sessions.
    pub max_plaintext: usize,
    /// UDP target DNS cache: "host:port" (lowercased) -> address + insert time.
    pub udp_dns: DashMap<String, (std::net::SocketAddr, Instant)>,
    /// TTL of [`ServerState::udp_dns`] entries (zero disables caching).
    pub udp_dns_ttl: Duration,
}

impl ServerState {
    /// Return (creating on first use) the per-uid rate limiter so every
    /// connection of the same user shares one bucket.
    pub fn rate_for(&self, uid: &str) -> Arc<RateLimiter> {
        self.rates
            .entry(uid.to_owned())
            .or_insert_with(|| Arc::new(RateLimiter::new(self.rate_mbps)))
            .clone()
    }

    /// Cached UDP target resolution for `key` (see [`ServerState::udp_dns_store`]).
    pub fn udp_dns_cached(&self, key: &str, now: Instant) -> Option<std::net::SocketAddr> {
        if self.udp_dns_ttl.is_zero() {
            return None;
        }
        let entry = self.udp_dns.get(key)?;
        let (addr, at) = *entry;
        if now.duration_since(at) <= self.udp_dns_ttl {
            Some(addr)
        } else {
            None
        }
    }

    /// Cache a resolved UDP target. Expired entries are purged when the table
    /// is full; a still-full table simply skips caching (the datagram is still
    /// sent with the freshly resolved address).
    pub fn udp_dns_store(&self, key: String, addr: std::net::SocketAddr, now: Instant) {
        if self.udp_dns_ttl.is_zero() {
            return;
        }
        if self.udp_dns.len() >= UDP_DNS_CACHE_CAP {
            let ttl = self.udp_dns_ttl;
            self.udp_dns
                .retain(|_, (_, at)| now.duration_since(*at) <= ttl);
            if self.udp_dns.len() >= UDP_DNS_CACHE_CAP {
                return;
            }
        }
        self.udp_dns.insert(key, (addr, now));
    }

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
        let prev = self.active_sessions.fetch_sub(1, Ordering::Relaxed);
        // A mismatched release would wrap to `u64::MAX` and permanently lock
        // out every new session; catch any regression in debug builds while
        // keeping release behavior unchanged.
        debug_assert!(
            prev > 0,
            "session quota released without a matching acquire"
        );
    }

    pub fn check_and_remember_nonce(&self, uid: &str, nonce: &[u8], ts: u64) -> bool {
        let _guard = self.nonce_lock.lock().unwrap_or_else(|e| e.into_inner());
        let key = format!("{uid}|{ts}|{}", crate::proto::crypto::hex(nonce));
        if self.seen_nonces.contains_key(&key) {
            return false;
        }
        let cutoff = crate::proto::crypto::now_unix().saturating_sub(2 * AUTH_WINDOW);
        self.seen_nonces.retain(|_, v| *v > cutoff);
        if self.seen_nonces.len() >= NONCE_CAP {
            return false;
        }
        self.seen_nonces.insert(key, ts);
        true
    }

    /// Close sessions idle longer than the configured timeout. Removing a
    /// registered handle also releases its global session quota (the pump
    /// tasks observe `false` from `drop_session` and skip their release).
    pub fn reap_idle(&self) {
        let idle = self.idle;
        // A connection with no sessions left and no data activity for a
        // while is dead weight (its state entry, pumps and QUIC transport
        // all linger): tear it down too. Clients reconnect transparently on
        // their next request. 3× the session idle keeps clear separation
        // from per-session reaping.
        let conn_idle = idle * 3;
        let mut dead_conns: Vec<u64> = Vec::new();
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
            // Remove from the map only after the iteration ends (DashMap).
            if c.sessions.is_empty() && c.idle_for() > conn_idle {
                tracing::debug!("reaping idle conn {} (uid={})", c.id, c.uid);
                c.cancel.cancel();
                dead_conns.push(c.id);
            }
        }
        for id in dead_conns {
            self.conns.remove(&id);
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
            allow_private_targets: false,
            unauth: Arc::new(UnauthGate::new(128, 16)),
            seen_nonces: DashMap::new(),
            nonce_lock: std::sync::Mutex::new(()),
            path: "/api/ppp".into(),
            rates: DashMap::new(),
            max_plaintext: crate::proto::frame::MAX_PLAINTEXT,
            udp_dns: DashMap::new(),
            udp_dns_ttl: Duration::from_secs(3600),
        }
    }

    fn test_conn(id: u64) -> Arc<ConnState> {
        Arc::new(ConnState {
            id,
            uid: "u".into(),
            cipher: Arc::new(FrameCipher::new(&[0u8; 32])),
            stream_counters: CounterGen::stream_server(),
            rate: Arc::new(RateLimiter::new(0)),
            cancel: CancellationToken::new(),
            sessions: Default::default(),
            tcp_routes: Default::default(),
            udp_routes: Default::default(),
            max_per_conn: 8,
            last_active: AtomicI64::new(now_millis()),
            limit: FrameLimit::new(crate::proto::frame::MAX_PLAINTEXT),
        })
    }

    #[test]
    fn drop_session_reports_first_removal_only() {
        let conn = test_conn(1);
        conn.register(7);
        assert!(conn.drop_session(7));
        assert!(!conn.drop_session(7));
    }

    /// Atomic registration must refuse a duplicate sid instead of overwriting
    /// the existing handle (which would orphan its token and leak its quota).
    #[test]
    fn try_register_rejects_duplicate_sid() {
        let conn = test_conn(1);
        assert!(conn
            .try_register_with(7, conn.cancel.child_token())
            .is_some());
        assert!(conn
            .try_register_with(7, conn.cancel.child_token())
            .is_none());
        assert!(conn.drop_session(7));
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

    /// A connection with no sessions and no data activity beyond 3×idle is
    /// cancelled and swept out of the connection table (keepalive pings do
    /// not count as activity).
    #[test]
    fn reap_idle_cancels_long_idle_empty_conn() {
        let st = test_state();
        let conn = test_conn(1);
        st.conns.insert(1, conn.clone());
        conn.last_active
            .store(now_millis() - 200_000, Ordering::Relaxed);
        st.reap_idle();
        assert!(st.conns.get(&1).is_none());
        assert!(conn.cancel.is_cancelled());
    }

    /// A connection with recent activity must never be conn-reaped, even
    /// right after its sessions were individually reaped.
    #[test]
    fn reap_idle_keeps_active_conn() {
        let st = test_state();
        let conn = test_conn(1);
        st.conns.insert(1, conn.clone());
        conn.register(5);
        conn.touch(5); // recent activity
        st.reap_idle();
        assert!(st.conns.get(&1).is_some());
        assert!(!conn.cancel.is_cancelled());
    }

    #[test]
    fn nonce_replay_rejected() {
        let st = test_state();
        assert!(st.check_and_remember_nonce("u", &[1u8; 16], 1000));
        assert!(!st.check_and_remember_nonce("u", &[1u8; 16], 1000));
    }

    /// All connections of one user share a single bucket (`--rate` is a
    /// per-user cap); different users get independent buckets.
    #[test]
    fn rate_for_shares_one_bucket_per_uid() {
        let st = test_state();
        let a1 = st.rate_for("alice");
        let a2 = st.rate_for("alice");
        let b = st.rate_for("bob");
        assert!(Arc::ptr_eq(&a1, &a2));
        assert!(!Arc::ptr_eq(&a1, &b));
        assert_eq!(st.rates.len(), 2);
    }

    #[test]
    fn udp_dns_cache_respects_ttl_and_disable() {
        let mut st = test_state();
        let key = "dns.google:53".to_string();
        let addr: std::net::SocketAddr = "8.8.8.8:53".parse().unwrap();
        let now = Instant::now();
        st.udp_dns_store(key.clone(), addr, now);
        assert_eq!(st.udp_dns_cached(&key, now), Some(addr));
        // Past the TTL the entry is stale.
        let later = now + st.udp_dns_ttl + Duration::from_secs(1);
        assert_eq!(st.udp_dns_cached(&key, later), None);
        // TTL 0 disables caching entirely.
        st.udp_dns_ttl = Duration::ZERO;
        st.udp_dns_store(key.clone(), addr, now);
        assert_eq!(st.udp_dns_cached(&key, now), None);
    }
}
