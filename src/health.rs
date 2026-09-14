//! Health endpoint (`--health`) and the self-contained `healthcheck`
//! subcommand used by docker HEALTHCHECK (scratch images have no shell).
//!
//! `/healthz` answers a small JSON snapshot shared by client and server mode.
//! It exists so container managers and supervision tools can tell "process
//! alive but link dead" apart: transport mix, breaker state and the last time
//! the HTTPS fallback had to carry traffic are all visible without logs.

use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::header;
use axum::response::Response;
use axum::routing::get;
use axum::Router;
use tokio::task::JoinHandle;
use tracing::info;

use crate::client::outbound::{Outbound, LAST_FALLBACK_MILLIS};
use crate::server::state::ServerState;

/// Where `/healthz` reads its numbers from.
pub enum Source {
    /// Server mode: live counter from `ServerState` plus the transport mix
    /// configured via `--listen` / `--fallback-listen` (wt|fallback|mixed).
    Server {
        st: Arc<ServerState>,
        transport: &'static str,
    },
    /// Client mode: what the Outbound can reach (primary / fallback / both)
    /// and whether the circuit breaker is open.
    Client { outbound: Outbound },
}

pub struct Health {
    started: Instant,
    source: Source,
}

impl Health {
    pub fn new(started: Instant, source: Source) -> Self {
        Self { started, source }
    }

    fn transport(&self) -> &'static str {
        match &self.source {
            Source::Server { transport, .. } => transport,
            Source::Client { outbound } => match outbound {
                Outbound::Wt(_) => "wt",
                Outbound::Http(_) => "fallback",
                Outbound::Both(_, _, _) => "mixed",
            },
        }
    }

    fn circuit(&self) -> &'static str {
        match &self.source {
            Source::Server { .. } => "closed",
            Source::Client { outbound } => match outbound {
                Outbound::Both(_, _, cb) if !cb.can_try() => "open",
                _ => "closed",
            },
        }
    }

    pub fn snapshot(&self) -> String {
        let uptime = self.started.elapsed().as_secs();
        let (active_sessions, wt_conns) = match &self.source {
            Source::Server { st, .. } => {
                (st.active_sessions.load(Ordering::Relaxed), st.conns.len())
            }
            Source::Client { .. } => (0, 0),
        };
        let millis = LAST_FALLBACK_MILLIS.load(Ordering::Relaxed);
        let last_fallback_at = if millis == 0 {
            "null".to_string()
        } else {
            millis.to_string()
        };
        format!(
            r#"{{"uptime":{uptime},"active_sessions":{active_sessions},"wt_conns":{wt_conns},"transport":"{}","circuit":"{}","last_fallback_at":{last_fallback_at}}}"#,
            self.transport(),
            self.circuit()
        )
    }
}

pub fn router(h: Arc<Health>) -> Router {
    Router::new().route("/healthz", get(healthz)).with_state(h)
}

async fn healthz(State(h): State<Arc<Health>>, _req: Request) -> Response {
    Response::builder()
        .status(200)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::from(h.snapshot()))
        .expect("static response")
}

/// Bind now (so bind failures are fatal at startup) and serve `/healthz`
/// until the handle is dropped or aborted.
pub async fn spawn(addr: &str, h: Arc<Health>, label: &str) -> Result<JoinHandle<()>> {
    let a: SocketAddr = addr
        .parse()
        .context(format!("bad --health address {addr}"))?;
    let listener = tokio::net::TcpListener::bind(a)
        .await
        .context(format!("bind --health {a}"))?;
    info!("{label} health endpoint on http://{a}/healthz");
    let app = router(h);
    Ok(tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            tracing::warn!("health endpoint {a} exited: {e}");
        }
    }))
}

// ---------------------------------------------------------------------------
// healthcheck subcommand (docker HEALTHCHECK; no shell in scratch)
// ---------------------------------------------------------------------------

/// `newppp healthcheck --url http://127.0.0.1:9100/healthz`.
/// Exit 0 when `/healthz` answers 200 with a plausible body, 1 otherwise.
pub fn healthcheck(url: &str) -> i32 {
    match healthcheck_once(url) {
        Ok(body) => {
            println!("healthy: {url} ({body})");
            0
        }
        Err(e) => {
            eprintln!("unhealthy: {url}: {e:#}");
            1
        }
    }
}

fn healthcheck_once(url: &str) -> Result<String> {
    use std::io::{Read, Write};
    use std::net::TcpStream;

    let (host, port, path) = parse_url(url)?;
    let target = format!("{host}:{port}");
    let addr = target
        .to_socket_addrs()
        .context("healthcheck: resolve failed")?
        .next()
        .context("healthcheck: no address")?;
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(5))
        .context("healthcheck: connect failed")?;
    let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = s.set_write_timeout(Some(Duration::from_secs(5)));
    let host_header = if port == 80 {
        host.clone()
    } else {
        target.clone()
    };
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: newppp-healthcheck/1\r\nConnection: close\r\n\r\n"
    );
    s.write_all(req.as_bytes())
        .context("healthcheck: write failed")?;
    let mut resp = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match s.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => resp.extend_from_slice(&chunk[..n]),
            Err(e) => return Err(e).context("healthcheck: read failed"),
        }
    }
    let text = String::from_utf8_lossy(&resp).into_owned();
    let status = text.lines().next().unwrap_or_default();
    anyhow::ensure!(status.contains(" 200 "), "bad status: {status}");
    anyhow::ensure!(text.contains("uptime"), "response lacks /healthz snapshot");
    Ok(text
        .lines()
        .filter(|l| !l.is_empty())
        .find(|l| l.starts_with('{'))
        .map(str::to_string)
        .unwrap_or_default())
}

/// Split `http://host[:port][/path]`; the health listener is plain HTTP only.
fn parse_url(url: &str) -> Result<(String, u16, String)> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| anyhow::anyhow!("--url must be http://host:port/path, got '{url}'"))?;
    let (hostport, path) = match rest.split_once('/') {
        Some((h, p)) => (h, format!("/{}", p)),
        None => (rest, "/".to_string()),
    };
    let path = if path == "/" {
        "/healthz".to_string()
    } else {
        path
    };
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) => (h, p.parse::<u16>().context("bad healthcheck port")?),
        None => (hostport, 80),
    };
    anyhow::ensure!(!host.is_empty(), "http:// URL needs a host");
    Ok((host.trim().to_string(), port, path))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The snapshot must be exactly the documented field set, whether or not
    /// a fallback has ever been used.
    #[test]
    fn snapshot_json_shape() {
        use crate::config::{CertSource, ServerConfig};
        use crate::server::build_state;
        let cfg = ServerConfig {
            listen: None,
            cert: CertSource::SelfSigned,
            fallback_listen: Some("127.0.0.1:1".into()),
            http_listen: None,
            acme_dir: None,
            path: "/api/ppp".into(),
            users: vec![],
            max_sessions: 1,
            rate_mbps: 0,
            idle_secs: 60,
            allow_private_targets: false,
            max_unauth: 1,
            recv_window: 1024,
            shutdown_grace: 10,
            health: None,
        };
        let st = build_state(&cfg);
        let h = Health::new(
            Instant::now(),
            Source::Server {
                st,
                transport: "fallback",
            },
        );
        let s = h.snapshot();
        assert!(s.starts_with('{') && s.ends_with('}'), "not an object: {s}");
        assert!(s.contains("\"uptime\":"), "{s}");
        assert!(s.contains("\"active_sessions\":"), "{s}");
        assert!(s.contains("\"wt_conns\":"), "{s}");
        assert!(s.contains(r#""transport":"fallback""#), "{s}");
        assert!(s.contains(r#""circuit":"closed""#), "{s}");
        assert!(s.contains("\"last_fallback_at\":null"), "{s}");
    }

    #[test]
    fn parse_urls() {
        assert_eq!(
            parse_url("http://127.0.0.1:9100/healthz").unwrap(),
            ("127.0.0.1".into(), 9100, "/healthz".into())
        );
        assert_eq!(
            parse_url("http://127.0.0.1:9100").unwrap(),
            ("127.0.0.1".into(), 9100, "/healthz".into())
        );
        assert_eq!(
            parse_url("http://127.0.0.1/").unwrap(),
            ("127.0.0.1".into(), 80, "/healthz".into())
        );
        assert!(parse_url("https://127.0.0.1").is_err());
        assert!(parse_url("http://").is_err());
    }
}
