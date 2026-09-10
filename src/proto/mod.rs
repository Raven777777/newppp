//! Shared wire protocol: framing, crypto, auth, addressing and the
//! mode-A (single duplex stream) multiplexer used by the HTTP fallback.

pub mod addr;
pub mod crypto;
pub mod frame;
pub mod mux;
pub mod stream;

/// Browser-like default User-Agent (avoids proxy-specific fingerprints).
pub const USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";
