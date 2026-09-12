//! Library target for `newppp`.
//!
//! The binary (`src/main.rs`) is a thin entry point; all logic lives here so
//! it can be exercised by benchmarks (`benches/`) and integration tests.

pub mod client;
pub mod clock;
pub mod config;
pub mod proto;
pub mod quic_tune;
pub mod server;
