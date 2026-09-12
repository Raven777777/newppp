//! Internal UTC clock with SNTP calibration.
//!
//! Auth timestamps must agree between client and server within a ±60s
//! window, but both sides may run on hosts with skewed or unsynchronized
//! clocks. Instead of trusting the local wall clock, the process keeps its
//! own notion of UTC:
//!
//! * an offset (sntp_time − system_time) measured from the NTP server;
//! * `now_unix()` = system clock + offset, so between calibrations the
//!   (monotonic enough) system clock still advances normally;
//! * offset = 0 until the first successful sync, i.e. we degrade to the
//!   system clock and never block startup on network availability.
//!
//! A background task re-synchronizes every [`SYNC_INTERVAL`]. The SNTP
//! client below is a minimal RFC 4330 client over a tokio UDP socket — no
//! extra dependencies.

use std::net::ToSocketAddrs;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::time::timeout;
use tracing::{debug, info, warn};

/// Default NTP server pool.
pub const DEFAULT_NTP_SERVER: &str = "pool.ntp.org";
/// Re-sync cadence.
pub const SYNC_INTERVAL: Duration = Duration::from_secs(3600);
/// SNTP queries per sync round (UDP is lossy; one query is not enough).
pub const SYNC_ATTEMPTS: u32 = 3;
/// Pause between attempts within a round.
const RETRY_PAUSE: Duration = Duration::from_secs(2);
/// Per-attempt SNTP reply timeout.
const QUERY_TIMEOUT: Duration = Duration::from_secs(5);
/// SNTP request payload: LI=0, VN=4, Mode=3 (client), rest zero.
const NTP_PACKET_LEN: usize = 48;
/// Seconds between 1900-01-01 (NTP epoch) and 1970-01-01 (Unix epoch).
const NTP_UNIX_DELTA: u64 = 2_208_988_800;

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

/// Spawn the hourly calibration loop. `server` may be `"pool.ntp.org"` or a
/// `host:port` NTP source. Never fails: sync failures are logged and the
/// previous offset is kept.
///
/// Each round tries up to [`SYNC_ATTEMPTS`] times: SNTP is a single UDP
/// exchange with no retransmission, so individual queries are routinely
/// lost on lossy paths (especially servers under load).
pub fn spawn(server: &str) {
    let server = server.to_string();
    tokio::spawn(async move {
        let mut iv = tokio::time::interval(SYNC_INTERVAL);
        iv.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // First tick fires immediately: sync at startup, then hourly.
        loop {
            iv.tick().await;
            let mut last_err = None;
            let mut synced = false;
            for attempt in 1..=SYNC_ATTEMPTS {
                match sntp_query(&server).await {
                    Ok(off) => {
                        let prev = CLOCK_OFFSET.swap(off, Ordering::Relaxed);
                        if prev != off {
                            info!("clock synced with {server} (offset {off}s)");
                        } else {
                            debug!("clock synced with {server} (offset {off}s)");
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
                warn!("clock sync with {server} failed after {SYNC_ATTEMPTS} attempts: {e}; keeping old offset");
            }
        }
    });
}

/// Query the NTP server, return the offset (sntp_utc − system_utc) in whole
/// seconds.
async fn sntp_query(server: &str) -> anyhow::Result<i64> {
    use tokio::net::UdpSocket;

    // NTP is UDP/123 unless the address already carries a port.
    let addr = if server
        .rsplit_once(':')
        .is_some_and(|(_, p)| p.parse::<u16>().is_ok())
    {
        server.to_string()
    } else {
        format!("{server}:123")
    };
    let resolved = tokio::task::spawn_blocking(move || {
        addr.to_socket_addrs()
            .map(|mut i| i.next())
            .map_err(|e| anyhow::anyhow!("resolve failed: {e}"))
    })
    .await
    .map_err(|e| anyhow::anyhow!("resolve task failed: {e}"))??;
    let resolved = resolved.ok_or_else(|| anyhow::anyhow!("NTP server unresolved"))?;

    let sock = UdpSocket::bind(if resolved.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }).await?;
    timeout(QUERY_TIMEOUT, sock.connect(resolved)).await??;

    let mut req = [0u8; NTP_PACKET_LEN];
    req[0] = 0b00_100_011; // LI=0, VN=4, Mode=3 (client)
    // Transmit timestamp (T1) in NTP epoch: some servers ignore/reject
    // requests without it. The offset formula below uses the *Unix* epoch
    // value (`t1_unix`), so keep the two representations separate.
    let t1_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);
    let t1_ntp = t1_unix + NTP_UNIX_DELTA as f64;
    let secs = (t1_ntp.floor() as u32).to_be_bytes();
    let frac = (((t1_ntp - t1_ntp.floor()) * u32::MAX as f64) as u32).to_be_bytes();
    req[40..44].copy_from_slice(&secs);
    req[44..48].copy_from_slice(&frac);
    sock.send(&req).await?;

    let mut buf = [0u8; NTP_PACKET_LEN];
    let (n, _) = timeout(QUERY_TIMEOUT, sock.recv_from(&mut buf)).await??;
    anyhow::ensure!(n >= NTP_PACKET_LEN, "short NTP reply ({n} bytes)");

    // Mode must be server (4); KoD (rate limiting) replies carry LI=4.
    anyhow::ensure!(buf[0] & 0b0000_0111 == 4, "not an NTP server reply");
    anyhow::ensure!(buf[0] >> 6 != 4, "NTP kiss-of-death reply");

    let t3 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);
    let t2 = read_ts(&buf[32..40]);
    anyhow::ensure!(t2 > 0.0, "NTP reply lacks timestamps");

    // Standard NTP offset formula (all values in the Unix epoch).
    let offset = ((t2 - t1_unix) + (t2 - t3)) / 2.0;
    Ok(offset.round() as i64)
}

/// NTP 64-bit timestamp (seconds.fraction) → Unix seconds.
fn read_ts(b: &[u8]) -> f64 {
    let secs = u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as f64;
    if secs == 0.0 {
        return 0.0;
    }
    let frac = u32::from_be_bytes([b[4], b[5], b[6], b[7]]) as f64 / u32::MAX as f64;
    secs + frac - NTP_UNIX_DELTA as f64
}

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
    fn read_ts_converts_to_unix_epoch() {
        // 1970-01-01T00:00:00Z in NTP seconds
        let mut b = [0u8; 8];
        b[..4].copy_from_slice(&(NTP_UNIX_DELTA as u32).to_be_bytes());
        assert!((read_ts(&b) - 0.0).abs() < 1e-6);
        // zero timestamp reads as zero (missing)
        assert_eq!(read_ts(&[0u8; 8]), 0.0);
    }
}
