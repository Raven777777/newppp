//! Shared QUIC transport tuning (client + server).
//!
//! quinn's defaults assume 100ms RTT and a clean path:
//! * stream window 1.2MB — collapses throughput on high-BDP (300ms RTT) links
//! * CUBIC congestion control — collapses to ~60KB/s at 1% loss / 300ms RTT
//!
//! We raise the windows and switch to BBR, which sustains throughput on
//! lossy, high-latency paths. The receive window is CLI-tunable
//! (`--recv-window`, default 2MB): on lossy paths a big window lets too many
//! out-of-order fragments accumulate and trips quinn's "too many gaps"
//! protection, which aborts the whole connection mid-transfer.

use std::sync::Arc;

use quinn_proto::VarInt;
use wtransport::config::QuicTransportConfig;

/// Detected signature of quinn's stream-reassembly gap guard ("too many gaps
/// in stream buffer"). On a lossy/reordering path a large receive window lets
/// too many holes accumulate and quinn aborts the whole connection.
const GAP_SIGNATURE: &str = "too many gaps";

/// Tuning hint to append when a QUIC connection dies from the gap guard, so
/// the log line itself tells the operator what to change (D5).
pub fn gap_hint(reason: &str) -> &'static str {
    if reason.contains(GAP_SIGNATURE) {
        " — weak-network tuning hint: lower --recv-window to 1..2 (MB) on the lossy side"
    } else {
        ""
    }
}

pub fn tuned(recv_window: u32) -> QuicTransportConfig {
    let mut t = QuicTransportConfig::default();

    // Per-stream receive window (quinn default ~1.2MB). The 2MB default
    // keeps ~5x headroom below quinn's reassembly-gap limit while still
    // allowing ~50Mbps per stream at 300ms RTT; raise it on clean
    // high-BDP links, lower it on very lossy ones.
    t.stream_receive_window(VarInt::from(recv_window));
    // Total bytes in flight per stream without peer acknowledgement.
    t.send_window(32 * 1024 * 1024);

    // BBR congestion control (quinn default is CUBIC).
    let bbr = Arc::new(quinn_proto::congestion::BbrConfig::default());
    let factory: Arc<dyn quinn_proto::congestion::ControllerFactory + Send + Sync> = bbr;
    t.congestion_controller_factory(factory);

    t
}
