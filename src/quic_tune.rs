//! Shared QUIC transport tuning (client + server).
//!
//! quinn's defaults assume 100ms RTT and a clean path:
//! * stream window 1.2MB — collapses throughput on high-BDP (300ms RTT) links
//! * CUBIC congestion control — collapses to ~60KB/s at 1% loss / 300ms RTT
//!
//! We raise the windows and switch to BBR, which sustains throughput on
//! lossy, high-latency paths.

use std::sync::Arc;

use quinn_proto::VarInt;
use wtransport::config::QuicTransportConfig;

pub fn tuned() -> QuicTransportConfig {
    let mut t = QuicTransportConfig::default();

    // Per-stream receive window (quinn default ~1.2MB).
    t.stream_receive_window(VarInt::from(8 * 1024 * 1024u32));
    // Total bytes in flight per stream without peer acknowledgement.
    t.send_window(32 * 1024 * 1024);

    // BBR congestion control (quinn default is CUBIC).
    let bbr = Arc::new(quinn_proto::congestion::BbrConfig::default());
    let factory: Arc<dyn quinn_proto::congestion::ControllerFactory + Send + Sync> = bbr;
    t.congestion_controller_factory(factory);

    t
}
