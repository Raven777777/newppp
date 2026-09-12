//! Internal UTC clock calibrated from HTTP `Date` headers.
//!
//! Auth timestamps must agree between client and server within a ±60s
//! window, but both sides may run on hosts with skewed or unsynchronized
//! clocks. Instead of trusting the local wall clock, the process keeps its
//! own notion of UTC:
//!
//! * an offset (http_time − system_time) measured from the `Date` header of
//!   an HTTPS response (RFC 7231, second precision — ample for a ±60s
//!   window);
//! * `now_unix()` = system clock + offset, so between calibrations the
//!   (monotonic enough) system clock still advances normally;
//! * offset = 0 until the first successful sync, i.e. we degrade to the
//!   system clock and never block startup on network availability.
//!
//! A background task re-synchronizes every [`SYNC_INTERVAL`]. HTTP was
//! chosen over SNTP deliberately: TCP 443 egress is practically never
//! blocked, while NTP's single UDP/123 exchange is routinely dropped by
//! firewalls and lossy paths.

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{debug, info, warn};

/// Default time source (any HTTPS endpoint that echoes a truthful `Date`).
pub const DEFAULT_TIME_URL: &str = "https://www.cloudflare.com/cdn-cgi/trace";
/// Re-sync cadence.
pub const SYNC_INTERVAL: Duration = Duration::from_secs(3600);
/// HTTP attempts per sync round (transient failures are common).
pub const SYNC_ATTEMPTS: u32 = 3;
/// Pause between attempts within a round.
const RETRY_PAUSE: Duration = Duration::from_secs(2);
/// Per-attempt total timeout (connect + request + response headers).
const QUERY_TIMEOUT: Duration = Duration::from_secs(10);

/// Current offset to add to the system clock, in whole seconds.
static CLOCK_OFFSET: AtomicI64 = AtomicI64::new(0);

/// Internal UTC time (Unix seconds) = system clock + calibrated offset.
pub fn now_unix() -> u64 {
    let sys = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let off = CLOCK_OFFSET.load(Ordering::Relaxed);
    (sys + off).max(0) as u64
}

/// Spawn the hourly calibration loop. `url` is any `https://` (or `http://`)
/// endpoint; its `Date` response header supplies the reference time. Never
/// fails: sync failures are logged and the previous offset is kept.
pub fn spawn(url: &str) {
    let url = url.to_string();
    tokio::spawn(async move {
        let mut iv = tokio::time::interval(SYNC_INTERVAL);
        iv.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // First tick fires immediately: sync at startup, then hourly.
        loop {
            iv.tick().await;
            let mut last_err = None;
            let mut synced = false;
            for attempt in 1..=SYNC_ATTEMPTS {
                match http_date_query(&url).await {
                    Ok(off) => {
                        let prev = CLOCK_OFFSET.swap(off, Ordering::Relaxed);
                        if prev != off {
                            info!("clock synced with {url} (offset {off}s)");
                        } else {
                            debug!("clock synced with {url} (offset {off}s)");
                        }
                        synced = true;
                        break;
                    }
                    Err(e) => {
                        debug!("clock sync attempt {attempt}/{SYNC_ATTEMPTS} failed: {e}");
                        last_err = Some(e);
                        // Brief pause before retrying (except after the last try).
                        if attempt < SYNC_ATTEMPTS {
                            tokio::time::sleep(RETRY_PAUSE).await;
                        }
                    }
                }
            }
            if !synced {
                let e = last_err.expect("at least one attempt was made");
                warn!("clock sync with {url} failed after {SYNC_ATTEMPTS} attempts: {e}; keeping old offset");
            }
        }
    });
}

/// Fetch the URL, read the `Date` response header, return the offset
/// (http_utc − system_utc) in whole seconds.
async fn http_date_query(url: &str) -> anyhow::Result<i64> {
    // Minimal one-off HTTP(S) client over raw TCP + tokio-rustls: the clock
    // must not depend on the wtransport/hyper stacks (which may be mid-
    // reconnect when we need it most), only on the TLS crate they share.
    let (host, port, path, tls) = parse_url(url)?;

    let tcp = {
        use std::net::ToSocketAddrs;
        let host2 = host.clone();
        let addr = tokio::task::spawn_blocking(move || {
            (host2.as_str(), port)
                .to_socket_addrs()
                .map(|mut i| i.next())
                .map_err(|e| anyhow::anyhow!("resolve failed: {e}"))
        })
        .await
        .map_err(|e| anyhow::anyhow!("resolve task failed: {e}"))??;
        let addr = addr.ok_or_else(|| anyhow::anyhow!("host unresolved"))?;
        timeout(QUERY_TIMEOUT, TcpStream::connect(addr))
            .await
            .map_err(|_| anyhow::anyhow!("connect timeout"))??
    };

    let mut stream: Box<dyn AsyncStream> = if tls {
        let name = rustls::pki_types::ServerName::try_from(host.clone())
            .map_err(|e| anyhow::anyhow!("bad server name: {e}"))?
            .to_owned();
        let tls_stream = timeout(
            QUERY_TIMEOUT,
            tokio_rustls::TlsConnector::from(tls_config()?).connect(name, tcp),
        )
        .await
        .map_err(|_| anyhow::anyhow!("tls handshake timeout"))?
        .map_err(|e| anyhow::anyhow!("tls connect failed: {e}"))?;
        Box::new(tls_stream)
    } else {
        Box::new(tcp)
    };

    // Minimal HTTP/1.1 HEAD request — headers only, no body to drain.
    let req = format!(
        "HEAD {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {}\r\nConnection: close\r\n\r\n",
        crate::proto::USER_AGENT
    );
    timeout(QUERY_TIMEOUT, stream.write_all(req.as_bytes()))
        .await
        .map_err(|_| anyhow::anyhow!("send timeout"))??;

    // Read just the header block (Date is always up front).
    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 1024];
    timeout(QUERY_TIMEOUT, async {
        loop {
            if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() > 16 * 1024 {
                break;
            }
            let n = stream.read(&mut chunk).await?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
        }
        anyhow::Ok(())
    })
    .await
    .map_err(|_| anyhow::anyhow!("response timeout"))??;

    let head = String::from_utf8_lossy(&buf);
    let date = head
        .lines()
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.eq_ignore_ascii_case("date").then(|| v.trim().to_string())
        })
        .ok_or_else(|| anyhow::anyhow!("no Date header in response"))?;

    let server_ts = parse_http_date(&date).ok_or_else(|| anyhow::anyhow!("bad Date: {date}"))?;
    let sys_ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    // Any response with a valid Date header works — HTTP semantics make the
    // header truthful regardless of the status code, so no status check.
    Ok(server_ts - sys_ts)
}

/// RFC 7231 IMF-fixdate: `Sat, 12 Sep 2026 03:51:12 GMT`. Returns Unix secs.
fn parse_http_date(s: &str) -> Option<i64> {
    const MONTHS: [(&str, i64); 12] = [
        ("Jan", 1),
        ("Feb", 2),
        ("Mar", 3),
        ("Apr", 4),
        ("May", 5),
        ("Jun", 6),
        ("Jul", 7),
        ("Aug", 8),
        ("Sep", 9),
        ("Oct", 10),
        ("Nov", 11),
        ("Dec", 12),
    ];

    // "Sat, 12 Sep 2026 03:51:12 GMT" -> tokens
    let t: Vec<&str> = s.split_whitespace().collect();
    if t.len() < 6 || !t[0].ends_with(',') {
        return None;
    }
    let day: i64 = t[1].parse().ok()?;
    let month = MONTHS.iter().find(|(m, _)| *m == t[2])?.1;
    let year: i64 = t[3].parse().ok()?;
    let hms: Vec<&str> = t[4].split(':').collect();
    if hms.len() != 3 {
        return None;
    }
    let (h, mi, sec): (i64, i64, i64) = (
        hms[0].parse().ok()?,
        hms[1].parse().ok()?,
        hms[2].parse().ok()?,
    );

    // Days from civil epoch (Howard Hinnant's algorithm), UTC.
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;

    Some(days * 86_400 + h * 3600 + mi * 60 + sec)
}

/// Split an http(s) URL into (host, port, path, use_tls).
fn parse_url(url: &str) -> anyhow::Result<(String, u16, String, bool)> {
    let (tls, rest) = if let Some(r) = url.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = url.strip_prefix("http://") {
        (false, r)
    } else {
        anyhow::bail!("time URL must start with http:// or https://");
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (
            h.to_string(),
            p.parse::<u16>().map_err(|_| anyhow::anyhow!("bad port"))?,
        ),
        None => (authority.to_string(), if tls { 443 } else { 80 }),
    };
    anyhow::ensure!(!host.is_empty(), "empty host");
    Ok((host, port, path.to_string(), tls))
}

/// Shared TLS root configuration (system roots only; this clock must verify
/// the server — a MITM here could shift every auth timestamp).
fn tls_config() -> anyhow::Result<Arc<rustls::ClientConfig>> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| anyhow::anyhow!("tls versions: {e}"))?;
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs().certs {
        let _ = roots.add(cert);
    }
    Ok(Arc::new(
        builder.with_root_certificates(roots).with_no_client_auth(),
    ))
}

trait AsyncStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> AsyncStream for T {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn now_unix_without_sync_uses_system_clock() {
        let sys = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let ours = now_unix();
        assert!((ours as i64 - sys as i64).abs() <= 1);
    }

    #[test]
    fn parse_http_date_samples() {
        assert_eq!(parse_http_date("Thu, 01 Jan 1970 00:00:00 GMT"), Some(0));
        // Leap-year day
        assert_eq!(
            parse_http_date("Sat, 29 Feb 2020 12:00:00 GMT"),
            Some(1_582_977_600)
        );
        assert_eq!(
            parse_http_date("Sat, 12 Sep 2026 03:51:12 GMT"),
            Some(1_789_185_072)
        );
        assert_eq!(parse_http_date("garbage"), None);
    }

    #[test]
    fn parse_url_variants() {
        let (h, p, path, tls) = parse_url("https://example.com/a?b=c").unwrap();
        assert_eq!(
            (h.as_str(), p, path.as_str(), tls),
            ("example.com", 443, "/a?b=c", true)
        );
        let (h, p, path, tls) = parse_url("http://host:8080").unwrap();
        assert_eq!(
            (h.as_str(), p, path.as_str(), tls),
            ("host", 8080, "/", false)
        );
    }
}
