//! Inner end-to-end crypto layer.
//!
//! * Static per-user key: HKDF-SHA256(password, salt="newppp-v1", info="newppp/auth/<uid>")
//! * Session key: HKDF-SHA256(static_key, salt=<client random salt>, info="newppp/session")
//! * Frame protection: ChaCha20-Poly1305, nonce = 32 zero bits || u64 counter (BE)
//! * Counter spaces: stream frames use counters < 2^63, datagrams use >= 2^63
//!   (guarantees nonce uniqueness across channels of one session)

use anyhow::{ensure, Result};
use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

pub const SALT_LEN: usize = 16;
pub const KEY_LEN: usize = 32;
pub const MAC_LEN: usize = 32;
/// ChaCha20-Poly1305 authentication tag length.
pub const TAG_LEN: usize = 16;
/// Bearer token timestamp tolerance (seconds, +/-).
pub const AUTH_WINDOW: u64 = 60;

fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8]) -> [u8; KEY_LEN] {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = [0u8; KEY_LEN];
    hk.expand(info, &mut okm)
        .expect("32 bytes is a valid length");
    okm
}

pub fn derive_static_key(password: &str, uid: &str) -> [u8; KEY_LEN] {
    hkdf_sha256(
        password.as_bytes(),
        b"newppp-v1",
        format!("newppp/auth/{uid}").as_bytes(),
    )
}

pub fn derive_session_key(static_key: &[u8; KEY_LEN], salt: &[u8; SALT_LEN]) -> [u8; KEY_LEN] {
    hkdf_sha256(static_key, salt, b"newppp/session")
}

fn nonce_for(counter: u64) -> Nonce {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&counter.to_be_bytes());
    Nonce::from(n)
}

/// AEAD wrapper (one instance per key, cheap to share via Arc).
pub struct FrameCipher {
    aead: ChaCha20Poly1305,
}

impl FrameCipher {
    pub fn new(key: &[u8; KEY_LEN]) -> Self {
        Self {
            aead: ChaCha20Poly1305::new(Key::from_slice(key)),
        }
    }

    /// Encrypt `buf` in place and return the detached tag (not appended).
    /// Lets callers encrypt directly inside a pre-sized buffer, avoiding the
    /// intermediate `Vec` allocation and copy of [`FrameCipher::seal`].
    pub fn seal_slice(&self, counter: u64, aad: &[u8], buf: &mut [u8]) -> Result<[u8; TAG_LEN]> {
        let tag = self
            .aead
            .encrypt_in_place_detached(&nonce_for(counter), aad, buf)
            .map_err(|_| anyhow::anyhow!("aead seal failed"))?;
        let mut out = [0u8; TAG_LEN];
        out.copy_from_slice(tag.as_slice());
        Ok(out)
    }

    /// Encrypt `plaintext`, returns ciphertext || 16-byte tag (single
    /// allocation: capacity is exact, so appending the tag never reallocs).
    pub fn seal(&self, counter: u64, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut buf = Vec::with_capacity(plaintext.len() + TAG_LEN);
        buf.extend_from_slice(plaintext);
        let tag = self.seal_slice(counter, aad, &mut buf)?;
        buf.extend_from_slice(&tag);
        Ok(buf)
    }

    /// Decrypt `ciphertext` (payload || tag), returns plaintext.
    pub fn open(&self, counter: u64, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        ensure!(ciphertext.len() >= TAG_LEN, "ciphertext too short");
        let (ct, tag) = ciphertext.split_at(ciphertext.len() - TAG_LEN);
        let mut buf = Vec::with_capacity(ct.len());
        buf.extend_from_slice(ct);
        self.aead
            .decrypt_in_place_detached(
                &nonce_for(counter),
                aad,
                &mut buf,
                chacha20poly1305::Tag::from_slice(tag),
            )
            .map_err(|_| anyhow::anyhow!("aead open failed"))?;
        Ok(buf)
    }
}

/// Monotonic nonce counter generator.
///
/// The 64-bit counter space is split into four disjoint ranges. Both peers of
/// a session share the same session key, so in addition to separating stream
/// frames from datagrams the ranges must also separate the two *directions* —
/// otherwise a client stream frame and a server stream frame can carry the
/// same counter, i.e. the same AEAD nonce under the same key, which is
/// catastrophic for both confidentiality and integrity.
///
/// | channel       | direction | range                     |
/// |---------------|-----------|---------------------------|
/// | stream frames | client    | `[1, 2^62)`               |
/// | stream frames | server    | `[2^62, 2^63)`            |
/// | datagrams     | client    | `[2^63, 2^63 + 2^62)`     |
/// | datagrams     | server    | `[2^63 + 2^62, 2^64)`     |
///
/// Sharing one generator across every stream of a single direction is what
/// keeps counters unique within that direction.
#[derive(Clone)]
pub struct CounterGen {
    base: u64,
    next: Arc<AtomicU64>,
}

impl CounterGen {
    /// Client-side stream frames (also fine for tests and benchmarks).
    pub fn stream() -> Self {
        Self {
            base: 1,
            next: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Server-side stream frames — disjoint from [`CounterGen::stream`].
    pub fn stream_server() -> Self {
        Self {
            base: 1u64 << 62,
            next: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Client-side datagrams.
    pub fn datagram() -> Self {
        Self {
            base: 1u64 << 63,
            next: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Server-side datagrams — disjoint from [`CounterGen::datagram`].
    pub fn datagram_server() -> Self {
        Self {
            base: (1u64 << 63) | (1u64 << 62),
            next: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn next(&self) -> u64 {
        self.base + self.next.fetch_add(1, Ordering::Relaxed)
    }
}

/// Sliding-window replay filter for the unreliable datagram channel.
pub struct ReplayWindow {
    highest: u64,
    mask: u64,
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplayWindow {
    pub fn new() -> Self {
        Self {
            highest: 0,
            mask: 0,
        }
    }

    /// Returns false if the counter was already seen (or is out of window).
    pub fn check(&mut self, counter: u64) -> bool {
        if counter == 0 {
            return false;
        }
        if self.highest == 0 {
            self.highest = counter;
            self.mask = 1;
            return true;
        }
        if counter > self.highest {
            let shift = (counter - self.highest).min(64);
            self.mask = if shift == 64 {
                1
            } else {
                (self.mask << shift) | 1
            };
            self.highest = counter;
            true
        } else {
            let d = self.highest - counter;
            if d >= 64 || self.mask & (1u64 << d) != 0 {
                false
            } else {
                self.mask |= 1u64 << d;
                true
            }
        }
    }
}

/// HMAC-SHA256 over uid|ts|nonce with the user's static key.
pub fn auth_mac(key: &[u8; KEY_LEN], uid: &str, ts: u64, nonce: &[u8; SALT_LEN]) -> [u8; MAC_LEN] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("hmac accepts any key len");
    mac.update(b"newppp-auth|");
    mac.update(uid.as_bytes());
    mac.update(b"|");
    mac.update(&ts.to_le_bytes());
    mac.update(b"|");
    mac.update(nonce);
    let out = mac.finalize().into_bytes();
    let mut m = [0u8; MAC_LEN];
    m.copy_from_slice(out.as_slice());
    m
}

pub fn now_unix() -> u64 {
    // Delegates to the calibrated internal clock (see crate::clock): NTP-synced
    // when the SNTP loop has run at least once, system clock otherwise.
    crate::clock::now_unix()
}

/// Bearer token: "uid.ts.nonce_hex.mac_hex" (standard Authorization header only).
pub fn make_bearer(key: &[u8; KEY_LEN], uid: &str) -> String {
    let ts = now_unix();
    let mut nonce = [0u8; SALT_LEN];
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let mac = auth_mac(key, uid, ts, &nonce);
    format!("{uid}.{ts}.{}.{}", hex(&nonce), hex(&mac))
}

/// Parse and verify a bearer token for `expected_uid`. On success returns
/// the embedded `(ts, nonce)` so callers can record it in a replay cache.
pub fn verify_bearer_parts(
    token: &str,
    key: &[u8; KEY_LEN],
    expected_uid: &str,
    window: u64,
) -> Option<(u64, [u8; SALT_LEN])> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 4 || parts[0] != expected_uid {
        return None;
    }
    let ts: u64 = parts[1].parse().ok()?;
    let nonce = match unhex(parts[2]) {
        Some(v) if v.len() == SALT_LEN => {
            let mut n = [0u8; SALT_LEN];
            n.copy_from_slice(&v);
            n
        }
        _ => return None,
    };
    let mac = match unhex(parts[3]) {
        Some(v) if v.len() == MAC_LEN => {
            let mut m = [0u8; MAC_LEN];
            m.copy_from_slice(&v);
            m
        }
        _ => return None,
    };
    let now = now_unix();
    // saturating: `ts` is attacker-controlled and must not overflow
    if now.saturating_sub(ts) > window || ts.saturating_sub(now) > window {
        return None;
    }
    let expect = auth_mac(key, expected_uid, ts, &nonce);
    // constant-time compare
    let mut diff = 0u8;
    for (a, b) in expect.iter().zip(mac.iter()) {
        diff |= a ^ b;
    }
    if diff == 0 {
        Some((ts, nonce))
    } else {
        None
    }
}

pub fn hex(b: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

/// Extract the uid from a bearer token without verifying it.
pub fn bearer_uid(token: &str) -> Option<&str> {
    token.split('.').next().filter(|s| !s.is_empty())
}

pub fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let b = s.as_bytes();
    for i in (0..b.len()).step_by(2) {
        let hi = (b[i] as char).to_digit(16)?;
        let lo = (b[i + 1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
    }
    Some(out)
}

/// AUTH frame payload (carried as the encrypted payload of an Auth frame,
/// sealed with the user's *static* key).
#[derive(Clone, Debug)]
pub struct AuthPayload {
    /// Explicit protocol version, checked by the server so a version skew
    /// surfaces as a named mismatch instead of a generic decrypt/decode
    /// failure.
    pub proto_version: u8,
    pub salt: [u8; SALT_LEN],
    pub ts: u64,
    pub nonce: [u8; SALT_LEN],
    pub uid: String,
    pub mac: [u8; MAC_LEN],
}

impl AuthPayload {
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(1 + 16 + 8 + 16 + 1 + self.uid.len() + 32);
        v.push(self.proto_version);
        v.extend_from_slice(&self.salt);
        v.extend_from_slice(&self.ts.to_le_bytes());
        v.extend_from_slice(&self.nonce);
        v.push(self.uid.len() as u8);
        v.extend_from_slice(self.uid.as_bytes());
        v.extend_from_slice(&self.mac);
        v
    }

    pub fn decode(b: &[u8]) -> Result<Self> {
        ensure!(
            b.len() >= 1 + 16 + 8 + 16 + 1 + 32,
            "auth payload truncated"
        );
        let mut p = 0;
        let proto_version = b[p];
        p += 1;
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&b[p..p + 16]);
        p += 16;
        let mut ts_b = [0u8; 8];
        ts_b.copy_from_slice(&b[p..p + 8]);
        let ts = u64::from_le_bytes(ts_b);
        p += 8;
        let mut nonce = [0u8; SALT_LEN];
        nonce.copy_from_slice(&b[p..p + 16]);
        p += 16;
        let ul = b[p] as usize;
        p += 1;
        ensure!(b.len() >= p + ul + 32, "auth payload truncated");
        let uid = String::from_utf8(b[p..p + ul].to_vec())?;
        p += ul;
        let mut mac = [0u8; MAC_LEN];
        mac.copy_from_slice(&b[p..p + 32]);
        Ok(Self {
            proto_version,
            salt,
            ts,
            nonce,
            uid,
            mac,
        })
    }

    /// Compare the peer's advertised protocol version with the local one.
    /// A mismatch is a configuration error, not an authentication failure.
    pub fn proto_version_compatible(&self) -> bool {
        self.proto_version == crate::proto::frame::PROTO_VERSION
    }

    pub fn verify(&self, static_key: &[u8; KEY_LEN], window: u64) -> bool {
        let now = now_unix();
        // saturating: guards against overflow panics on crafted timestamps
        if now.saturating_sub(self.ts) > window || self.ts.saturating_sub(now) > window {
            return false;
        }
        let expect = auth_mac(static_key, &self.uid, self.ts, &self.nonce);
        let mut diff = 0u8;
        for (a, b) in expect.iter().zip(self.mac.iter()) {
            diff |= a ^ b;
        }
        diff == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip() {
        let key = [7u8; 32];
        let c = FrameCipher::new(&key);
        let ct = c.seal(42, b"aad", b"hello world").unwrap();
        assert_ne!(ct[..11], *b"hello world");
        let pt = c.open(42, b"aad", &ct).unwrap();
        assert_eq!(pt, b"hello world");
        assert!(c.open(43, b"aad", &ct).is_err());
        assert!(c.open(42, b"other", &ct).is_err());
    }

    #[test]
    fn replay_window() {
        let mut w = ReplayWindow::new();
        assert!(w.check(1));
        assert!(!w.check(1));
        assert!(w.check(100));
        assert!(w.check(99));
        assert!(!w.check(99));
        assert!(!w.check(20)); // out of window (100-79)
        assert!(w.check(101));
    }

    #[test]
    fn counter_spaces_are_disjoint() {
        let s = CounterGen::stream();
        let d = CounterGen::datagram();
        let s0 = s.next();
        let d0 = d.next();
        assert!(s0 < (1u64 << 63));
        assert!(d0 >= (1u64 << 63));
    }

    /// Client and server share the session key, so the four
    /// channel/direction counter ranges must never overlap: an overlap means
    /// two frames encrypt different plaintexts under the same AEAD nonce.
    #[test]
    fn counter_spaces_are_direction_disjoint() {
        const N: u64 = 1_000_000;
        let mut ranges = [
            (CounterGen::stream(), "client stream"),
            (CounterGen::stream_server(), "server stream"),
            (CounterGen::datagram(), "client datagram"),
            (CounterGen::datagram_server(), "server datagram"),
        ]
        .map(|(g, name)| {
            let first = g.next();
            let mut last = first;
            for _ in 1..N {
                last = g.next();
            }
            (first, last, name)
        });
        ranges.sort_by_key(|(first, _, _)| *first);
        for pair in ranges.windows(2) {
            let (af, al, an) = pair[0];
            let (bf, _, bn) = pair[1];
            assert!(
                al < bf,
                "AEAD counter ranges overlap: {an} [{af}, {al}] vs {bn} starts at {bf}"
            );
        }
    }

    #[test]
    fn bearer_roundtrip() {
        let key = derive_static_key("pw", "alice");
        let tok = make_bearer(&key, "alice");
        assert!(verify_bearer_parts(&tok, &key, "alice", AUTH_WINDOW).is_some());
        assert!(verify_bearer_parts(&tok, &key, "bob", AUTH_WINDOW).is_none());
        let key2 = derive_static_key("pw2", "alice");
        assert!(verify_bearer_parts(&tok, &key2, "alice", AUTH_WINDOW).is_none());
    }

    #[test]
    fn bearer_rejects_huge_timestamp_without_overflow() {
        let key = derive_static_key("pw", "alice");
        let nonce = [0u8; SALT_LEN];
        let mac = auth_mac(&key, "alice", u64::MAX, &nonce);
        let tok = format!("alice.{}.{}.{}", u64::MAX, hex(&nonce), hex(&mac));
        assert!(verify_bearer_parts(&tok, &key, "alice", AUTH_WINDOW).is_none());
    }

    #[test]
    fn auth_payload_rejects_huge_timestamp_without_overflow() {
        let key = derive_static_key("pw", "u1");
        let nonce = [0u8; SALT_LEN];
        let ap = AuthPayload {
            proto_version: crate::proto::frame::PROTO_VERSION,
            salt: [0u8; SALT_LEN],
            ts: u64::MAX,
            nonce,
            uid: "u1".into(),
            mac: auth_mac(&key, "u1", u64::MAX, &nonce),
        };
        assert!(!ap.verify(&key, AUTH_WINDOW));
    }

    #[test]
    fn auth_payload_roundtrip() {
        let key = derive_static_key("pw", "u1");
        let mut nonce = [0u8; 16];
        nonce[..4].copy_from_slice(b"abcd");
        let ts = now_unix();
        let mac = auth_mac(&key, "u1", ts, &nonce);
        let ap = AuthPayload {
            proto_version: crate::proto::frame::PROTO_VERSION,
            salt: [9u8; 16],
            ts,
            nonce,
            uid: "u1".into(),
            mac,
        };
        let enc = ap.encode();
        let dec = AuthPayload::decode(&enc).unwrap();
        assert!(dec.verify(&key, AUTH_WINDOW));
        assert!(dec.proto_version_compatible());
        assert_eq!(dec.salt, [9u8; 16]);

        // A wrong version must survive decode and be reported as incompatible
        // (not swallowed by a generic decrypt failure).
        let skewed = AuthPayload {
            proto_version: crate::proto::frame::PROTO_VERSION.wrapping_add(1),
            ..ap.clone()
        };
        let dec = AuthPayload::decode(&skewed.encode()).unwrap();
        assert!(!dec.proto_version_compatible());
        assert!(dec.verify(&key, AUTH_WINDOW)); // still authenticated

        // stale timestamp must be rejected
        let old = AuthPayload {
            ts: ts - AUTH_WINDOW - 10,
            mac: auth_mac(&key, "u1", ts - AUTH_WINDOW - 10, &nonce),
            ..ap.clone()
        };
        assert!(!old.verify(&key, AUTH_WINDOW));
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn unhex_roundtrips_hex(bytes in proptest::collection::vec(any::<u8>(), 0..64)) {
            prop_assert_eq!(unhex(&hex(&bytes)), Some(bytes));
        }

        #[test]
        fn unhex_never_panics(s in ".*") {
            let _ = unhex(&s);
        }

        /// The decoder is the first layer facing hostile input: any byte
        /// sequence must yield a value (or error), never a panic.
        #[test]
        fn auth_payload_decode_never_panics(b in proptest::collection::vec(any::<u8>(), 0..256)) {
            let _ = AuthPayload::decode(&b);
        }

        #[test]
        fn auth_payload_encode_decode_roundtrip(
            salt in proptest::array::uniform16(any::<u8>()),
            nonce in proptest::array::uniform16(any::<u8>()),
            ts in any::<u64>(),
            uid in "[A-Za-z0-9_-]{1,32}",
        ) {
            let key = derive_static_key("pw", &uid);
            let mac = auth_mac(&key, &uid, ts, &nonce);
            let ap = AuthPayload {
                proto_version: crate::proto::frame::PROTO_VERSION,
                salt,
                ts,
                nonce,
                uid: uid.clone(),
                mac,
            };
            let dec = AuthPayload::decode(&ap.encode()).expect("valid encoding");
            prop_assert_eq!(dec.proto_version, crate::proto::frame::PROTO_VERSION);
            prop_assert_eq!(dec.salt, salt);
            prop_assert_eq!(dec.ts, ts);
            prop_assert_eq!(dec.nonce, nonce);
            prop_assert_eq!(dec.uid, uid);
            prop_assert_eq!(dec.mac, mac);
        }
    }
}
