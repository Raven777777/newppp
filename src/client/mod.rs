//! Client entry: builds the outbound and starts the local inbounds.

pub mod fallback;
pub mod http_proxy;
pub mod outbound;
pub mod socks5;
pub mod wt;

use anyhow::Result;
use tracing::info;

use crate::config::ClientConfig;
use outbound::Outbound;

/// Constant-time byte comparison (used for local inbound credentials).
pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

pub async fn run(cfg: ClientConfig) -> Result<()> {
    let ob = Outbound::build(&cfg).await?;
    info!("newppp client up (outbound: {})", ob.describe());

    let socks = tokio::spawn({
        let ob = ob.clone();
        let bind = cfg.socks_bind.clone();
        let auth = cfg.inbound_auth.clone();
        async move { socks5::run(bind, ob, auth).await }
    });

    let mut http_task = None;
    if let Some(hb) = cfg.http_bind.clone() {
        let ob = ob.clone();
        let auth = cfg.inbound_auth.clone();
        http_task = Some(tokio::spawn(
            async move { http_proxy::run(hb, ob, auth).await },
        ));
    }

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            info!("shutdown signal received");
        }
        r = socks => {
            r??;
        }
        r = async {
            match http_task {
                Some(t) => t.await,
                None => std::future::pending().await,
            }
        } => {
            r??;
        }
    }
    Ok(())
}
