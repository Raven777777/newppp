//! Per-connection token-bucket rate limiter (server egress).

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

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
}
