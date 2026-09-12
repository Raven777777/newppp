//! Per-connection token-bucket rate limiter (server egress) and the
//! unauthenticated-connection gate.

use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use dashmap::DashMap;

/// Caps concurrent *unauthenticated* connections, globally and (when a peer
/// address is known) per source IP. A [`UnauthGuard`] is held from connection
/// accept until the in-band AUTH frame verifies; dropping it — on success,
/// failure or abrupt disconnect — returns the slot.
pub struct UnauthGate {
    global: AtomicU64,
    per_ip: DashMap<IpAddr, u64>,
    max_global: u64,
    max_per_ip: u64,
}

impl UnauthGate {
    pub fn new(max_global: u64, max_per_ip: u64) -> Self {
        Self {
            global: AtomicU64::new(0),
            per_ip: DashMap::new(),
            max_global: max_global.max(1),
            max_per_ip: max_per_ip.max(1),
        }
    }

    /// Reserve a slot, or `None` when the global/per-IP cap is reached.
    /// `ip = None` (e.g. a fallback request behind a CDN) skips per-IP.
    pub fn try_admit(self: &Arc<Self>, ip: Option<IpAddr>) -> Option<UnauthGuard> {
        if let Some(ip) = ip {
            let mut e = self.per_ip.entry(ip).or_insert(0);
            if *e >= self.max_per_ip {
                return None;
            }
            *e += 1;
        }
        loop {
            let cur = self.global.load(Ordering::Relaxed);
            if cur >= self.max_global {
                if let Some(ip) = ip {
                    self.release_ip(ip);
                }
                return None;
            }
            if self
                .global
                .compare_exchange(cur, cur + 1, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                break;
            }
        }
        Some(UnauthGuard {
            gate: self.clone(),
            ip,
        })
    }

    fn release_ip(&self, ip: IpAddr) {
        if let Some(mut e) = self.per_ip.get_mut(&ip) {
            *e = e.saturating_sub(1);
            if *e == 0 {
                drop(e);
                self.per_ip.remove(&ip);
            }
        }
    }

    #[cfg(test)]
    pub fn pending(&self) -> u64 {
        self.global.load(Ordering::Relaxed)
    }
}

/// RAII slot for one unauthenticated connection.
pub struct UnauthGuard {
    gate: Arc<UnauthGate>,
    ip: Option<IpAddr>,
}

impl Drop for UnauthGuard {
    fn drop(&mut self) {
        self.gate.global.fetch_sub(1, Ordering::Relaxed);
        if let Some(ip) = self.ip {
            self.gate.release_ip(ip);
        }
    }
}

#[derive(Clone)]
pub struct RateLimiter {
    inner: Arc<Mutex<Inner>>,
    enabled: bool,
}

struct Inner {
    rate_bps: f64,
    cap: f64,
    tokens: f64,
    last: Instant,
}

impl RateLimiter {
    /// `mbps` = 0 disables limiting.
    pub fn new(mbps: u64) -> Self {
        let enabled = mbps > 0;
        let rate_bps = (mbps as f64) * 1_000_000.0 / 8.0;
        let inner = Inner {
            rate_bps,
            cap: rate_bps.max(64.0 * 1024.0), // >=64KB burst
            tokens: rate_bps.max(64.0 * 1024.0),
            last: Instant::now(),
        };
        Self {
            inner: Arc::new(Mutex::new(inner)),
            enabled,
        }
    }

    /// Await until `n` bytes of budget are available.
    pub async fn acquire(&self, n: usize) {
        if !self.enabled {
            return;
        }
        loop {
            let wait = {
                let mut g = self
                    .inner
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let now = Instant::now();
                let dt = now.duration_since(g.last).as_secs_f64();
                g.last = now;
                g.tokens = (g.tokens + dt * g.rate_bps).min(g.cap);
                // A charge larger than the bucket capacity can never be
                // satisfied (tokens refill only up to `cap`): charge the cap
                // instead of looping forever.
                let n = (n as f64).min(g.cap);
                if g.tokens >= n {
                    g.tokens -= n;
                    None
                } else {
                    Some(Duration::from_secs_f64((n - g.tokens) / g.rate_bps))
                }
            };
            match wait {
                None => return,
                Some(d) => tokio::time::sleep(d).await,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn limiter_throttles() {
        let rl = RateLimiter::new(1); // 125 KB/s, initial budget 125KB
        let t = std::time::Instant::now();
        for _ in 0..4 {
            rl.acquire(64 * 1024).await; // 256KB total
        }
        let elapsed = t.elapsed();
        // expected: (262144 - 125000) / 125000 ≈ 1.10s
        assert!(
            elapsed >= Duration::from_millis(1000),
            "elapsed {elapsed:?}"
        );
        assert!(elapsed <= Duration::from_secs(5), "elapsed {elapsed:?}");
    }

    #[tokio::test]
    async fn unlimited_is_fast() {
        let rl = RateLimiter::new(0);
        let t = std::time::Instant::now();
        for _ in 0..100 {
            rl.acquire(64 * 1024).await;
        }
        assert!(t.elapsed() < Duration::from_millis(100));
    }

    #[test]
    fn unauth_gate_enforces_per_ip_and_global_caps() {
        let gate = Arc::new(UnauthGate::new(3, 2));
        let a: IpAddr = "10.0.0.1".parse().unwrap();
        let b: IpAddr = "10.0.0.2".parse().unwrap();
        let g1 = gate.try_admit(Some(a)).expect("first");
        let g2 = gate.try_admit(Some(a)).expect("second");
        assert!(gate.try_admit(Some(a)).is_none(), "per-IP cap");
        assert_eq!(gate.pending(), 2);
        let g3 = gate.try_admit(Some(b)).expect("other ip");
        assert_eq!(gate.pending(), 3);
        assert!(gate.try_admit(Some(b)).is_none(), "global cap");
        // Releasing one connection frees exactly one slot.
        drop(g1);
        assert_eq!(gate.pending(), 2);
        let g4 = gate.try_admit(Some(b)).expect("slot freed");
        assert_eq!(gate.pending(), 3);
        drop(g2);
        drop(g3);
        drop(g4);
        assert_eq!(gate.pending(), 0);
    }

    #[test]
    fn unauth_gate_global_only_for_cdn_peers() {
        let gate = Arc::new(UnauthGate::new(2, 1));
        let g1 = gate.try_admit(None).expect("first");
        let g2 = gate.try_admit(None).expect("second");
        assert!(gate.try_admit(None).is_none());
        drop(g1);
        assert!(gate.try_admit(Some("10.0.0.9".parse().unwrap())).is_some());
        drop(g2);
    }

    /// Authenticated traffic must be unaffected by the unauth gate: the gate
    /// only counts slots explicitly taken from it.
    #[test]
    fn unauth_gate_does_not_touch_other_state() {
        let gate = Arc::new(UnauthGate::new(1, 1));
        let _held = gate.try_admit(None).unwrap();
        assert!(gate.try_admit(None).is_none());
        assert_eq!(gate.pending(), 1);
    }
}
