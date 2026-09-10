//! Outbound transport selection with automatic degradation:
//! WebTransport (h3/QUIC) primary -> HTTPS POST (mode A) fallback.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use anyhow::Result;

use crate::config::ClientConfig;
use crate::proto::mux::{BoxStream, OpenError, UdpPipe};

use super::fallback::HttpOutbound;
use super::wt::WtPool;

/// Per-target failure reported by the server for one session (dial refused,
/// bad target, limit). It is independent of the transport: the HTTPS POST
/// fallback reaches the same server and dials the same target, so dial
/// errors would repeat identically after a fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TargetError(pub OpenError);

impl std::fmt::Display for TargetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "target refused: {}", self.0)
    }
}

impl std::error::Error for TargetError {}

impl TargetError {
    /// Whether switching to the HTTPS fallback could plausibly succeed.
    /// Dial/target errors fail identically on any transport; a limit may
    /// clear on a fresh fallback connection.
    pub fn fallback_worthwhile(self) -> bool {
        matches!(self.0, OpenError::Limit)
    }
}

/// Classify an opaque error: `Some` when it is a per-target refusal.
pub fn target_error(e: &anyhow::Error) -> Option<TargetError> {
    e.downcast_ref::<TargetError>().copied()
}

/// How many consecutive transport failures trip the breaker...
const BREAKER_THRESHOLD: u32 = 3;
/// ...and how long the primary path stays skipped afterwards.
const BREAKER_COOLDOWN: Duration = Duration::from_secs(60);

/// Circuit breaker for the WT primary path (`Both` mode).
///
/// Counts consecutive *transport-level* failures (target-side refusals count
/// as successes — the transport demonstrably answered). After `threshold`
/// consecutive failures the breaker trips: the primary path is skipped for
/// `cooldown`, so weak-network sessions go straight to the fallback instead
/// of paying the dial/handshake cost per request. When the cooldown elapses
/// one probe is let through — success closes the breaker, failure re-trips
/// it immediately.
pub struct CircuitBreaker {
    inner: Mutex<Inner>,
    threshold: u32,
    cooldown: Duration,
}

struct Inner {
    consecutive_failures: u32,
    /// `Some(until)` while tripped; a probe is allowed once `now >= until`.
    tripped_until: Option<Instant>,
}

impl CircuitBreaker {
    pub fn new(threshold: u32, cooldown: Duration) -> Self {
        Self {
            inner: Mutex::new(Inner {
                consecutive_failures: 0,
                tripped_until: None,
            }),
            threshold,
            cooldown,
        }
    }

    /// Whether the primary path may be attempted right now.
    pub fn can_try(&self) -> bool {
        let g = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        !g.tripped_until.is_some_and(|t| Instant::now() < t)
    }

    pub fn record_success(&self) {
        let mut g = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        g.consecutive_failures = 0;
        g.tripped_until = None;
    }

    pub fn record_failure(&self) {
        let mut g = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        if g.tripped_until.is_some_and(|t| Instant::now() < t) {
            return; // breaker already open
        }
        if g.tripped_until.is_some() {
            // half-open probe failed: re-trip immediately
            g.tripped_until = Some(Instant::now() + self.cooldown);
            return;
        }
        g.consecutive_failures += 1;
        if g.consecutive_failures >= self.threshold {
            g.tripped_until = Some(Instant::now() + self.cooldown);
            g.consecutive_failures = 0;
            tracing::warn!(
                "WebTransport unstable: primary path cooling down for {:?}",
                self.cooldown
            );
        }
    }
}

#[derive(Clone)]
pub enum Outbound {
    Wt(ArcPool),
    Http(ArcHttp),
    Both(ArcPool, ArcHttp, Arc<CircuitBreaker>),
}

type ArcPool = Arc<WtPool>;
type ArcHttp = Arc<HttpOutbound>;

impl Outbound {
    pub async fn build(cfg: &ClientConfig) -> Result<Outbound> {
        match (&cfg.wt_url, &cfg.fb_url) {
            (Some(u), Some(f)) => {
                let pool = Arc::new(WtPool::new(cfg, u)?);
                pool.spawn_maintenance();
                let http = Arc::new(HttpOutbound::new(cfg, f)?);
                Ok(Outbound::Both(
                    pool,
                    http,
                    Arc::new(CircuitBreaker::new(BREAKER_THRESHOLD, BREAKER_COOLDOWN)),
                ))
            }
            (Some(u), None) => {
                let pool = Arc::new(WtPool::new(cfg, u)?);
                pool.spawn_maintenance();
                Ok(Outbound::Wt(pool))
            }
            (None, Some(f)) => Ok(Outbound::Http(Arc::new(HttpOutbound::new(cfg, f)?))),
            (None, None) => anyhow::bail!("no outbound configured"),
        }
    }

    pub fn describe(&self) -> &'static str {
        match self {
            Outbound::Wt(_) => "WebTransport",
            Outbound::Http(h) => h.describe(),
            Outbound::Both(_, _, _) => "WebTransport + fallback",
        }
    }

    pub async fn open_tcp(&self, host: &str, port: u16) -> Result<BoxStream> {
        match self {
            Outbound::Wt(p) => p.open_tcp(host, port).await,
            Outbound::Http(h) => h.open_tcp(host, port).await,
            Outbound::Both(p, h, cb) => {
                if cb.can_try() {
                    match p.open_tcp(host, port).await {
                        Ok(s) => {
                            cb.record_success();
                            return Ok(s);
                        }
                        Err(e) => {
                            if target_error(&e).is_some() {
                                // The transport answered (server-side
                                // refusal): evidence it is healthy — never a
                                // breaker event.
                                cb.record_success();
                                if target_error(&e).is_some_and(|t| !t.fallback_worthwhile()) {
                                    return Err(e);
                                }
                            } else {
                                cb.record_failure();
                            }
                            tracing::warn!(
                                "WebTransport open failed ({e:#}); falling back to HTTPS POST"
                            );
                        }
                    }
                } else {
                    tracing::debug!("WT circuit open: {host}:{port} goes to fallback directly");
                }
                h.open_tcp(host, port).await
            }
        }
    }

    pub async fn udp_associate(&self) -> Result<UdpPipe> {
        match self {
            Outbound::Wt(p) => p.udp_associate().await,
            Outbound::Http(h) => h.udp_associate().await,
            Outbound::Both(p, h, cb) => {
                if cb.can_try() {
                    match p.udp_associate().await {
                        Ok(s) => {
                            cb.record_success();
                            return Ok(s);
                        }
                        Err(e) => {
                            if target_error(&e).is_some() {
                                cb.record_success();
                                if target_error(&e).is_some_and(|t| !t.fallback_worthwhile()) {
                                    return Err(e);
                                }
                            } else {
                                cb.record_failure();
                            }
                            tracing::warn!(
                                "WebTransport UDP failed ({e:#}); falling back to HTTPS POST"
                            );
                        }
                    }
                } else {
                    tracing::debug!("WT circuit open: UDP goes to fallback directly");
                }
                h.udp_associate().await
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_errors_are_classified() {
        let e = anyhow::Error::new(TargetError(OpenError::DialFailed));
        assert_eq!(target_error(&e), Some(TargetError(OpenError::DialFailed)));
        assert!(!target_error(&e).expect("classified").fallback_worthwhile());

        let e = anyhow::Error::new(TargetError(OpenError::Limit));
        assert!(target_error(&e).expect("classified").fallback_worthwhile());

        // plain errors are transport-level and always fall back
        let e = anyhow::anyhow!("connection lost");
        assert_eq!(target_error(&e), None);
    }

    #[test]
    fn breaker_trips_after_threshold_and_recovers() {
        let cb = CircuitBreaker::new(3, Duration::from_millis(50));
        assert!(cb.can_try());
        cb.record_failure();
        cb.record_failure();
        assert!(cb.can_try()); // below threshold: still trying
        cb.record_failure();
        assert!(!cb.can_try()); // tripped

        // cooldown elapses -> half-open probe allowed
        std::thread::sleep(Duration::from_millis(60));
        assert!(cb.can_try());
        // probe fails -> immediate re-trip, no need for a full streak again
        cb.record_failure();
        assert!(!cb.can_try());

        // cooldown elapses -> probe succeeds -> breaker closed for good
        std::thread::sleep(Duration::from_millis(60));
        assert!(cb.can_try());
        cb.record_success();
        cb.record_failure();
        assert!(cb.can_try()); // single isolated failure never trips
    }

    #[test]
    fn breaker_success_resets_streak() {
        let cb = CircuitBreaker::new(3, Duration::from_secs(60));
        cb.record_failure();
        cb.record_failure();
        cb.record_success(); // transport recovered
        cb.record_failure();
        cb.record_failure();
        assert!(cb.can_try()); // only 2 consecutive after the reset
    }
}
