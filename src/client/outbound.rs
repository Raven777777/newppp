//! Outbound transport selection with automatic degradation:
//! WebTransport (h3/QUIC) primary -> HTTPS POST (mode A) fallback.

use std::sync::Arc;

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

#[derive(Clone)]
pub enum Outbound {
    Wt(ArcPool),
    Http(ArcHttp),
    Both(ArcPool, ArcHttp),
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
                Ok(Outbound::Both(pool, http))
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
            Outbound::Both(_, _) => "WebTransport + fallback",
        }
    }

    pub async fn open_tcp(&self, host: &str, port: u16) -> Result<BoxStream> {
        match self {
            Outbound::Wt(p) => p.open_tcp(host, port).await,
            Outbound::Http(h) => h.open_tcp(host, port).await,
            Outbound::Both(p, h) => match p.open_tcp(host, port).await {
                Ok(s) => Ok(s),
                Err(e) => {
                    // Per-target refusals are transport-independent; only
                    // fall back when the fallback could actually succeed.
                    if target_error(&e).is_some_and(|t| !t.fallback_worthwhile()) {
                        return Err(e);
                    }
                    tracing::warn!("WebTransport open failed ({e:#}); falling back to HTTPS POST");
                    h.open_tcp(host, port).await
                }
            },
        }
    }

    pub async fn udp_associate(&self) -> Result<UdpPipe> {
        match self {
            Outbound::Wt(p) => p.udp_associate().await,
            Outbound::Http(h) => h.udp_associate().await,
            Outbound::Both(p, h) => match p.udp_associate().await {
                Ok(s) => Ok(s),
                Err(e) => {
                    if target_error(&e).is_some_and(|t| !t.fallback_worthwhile()) {
                        return Err(e);
                    }
                    tracing::warn!("WebTransport UDP failed ({e:#}); falling back to HTTPS POST");
                    h.udp_associate().await
                }
            },
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
}
