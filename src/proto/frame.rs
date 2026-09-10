//! Frame protocol.
//!
//! Wire layout (20-byte header, little-endian):
//!
//! ```text
//! 0        1        2        4        8        12       20
//! +--------+--------+--------+--------+--------+--------+
//! |  ver   |  type  | flags  |  sid   | ct_len |counter |
//! +--------+--------+--------+--------+--------+--------+
//! |                  ciphertext || tag                  |
//! +-----------------------------------------------------+
//! ```
//!
//! AAD = header[0..12]. Payload is encrypted with the session key
//! (the Auth frame is sealed with the user's static key instead).

use std::sync::Arc;

use anyhow::{ensure, Result};
use bytes::{Buf, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

// Re-exported for downstream modules (mux, server, client).
pub use super::crypto::{CounterGen, FrameCipher, ReplayWindow, TAG_LEN};

pub const PROTO_VERSION: u8 = 1;
pub const HEADER_LEN: usize = 20;
pub const MAX_PLAINTEXT: usize = 16 * 1024;
pub const MAX_CIPHERTEXT: usize = MAX_PLAINTEXT + TAG_LEN;

pub const FLAG_FIN: u16 = 0x0001;
pub const FLAG_RST: u16 = 0x0002;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum FrameType {
    Auth = 1,
    AuthOk = 2,
    Open = 3,
    OpenOk = 4,
    OpenErr = 5,
    Data = 6,
    Close = 7,
    Ping = 8,
    Pong = 9,
    UdpAssociate = 10,
    UdpOk = 11,
    UdpData = 12,
    Error = 13,
}

impl FrameType {
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            1 => FrameType::Auth,
            2 => FrameType::AuthOk,
            3 => FrameType::Open,
            4 => FrameType::OpenOk,
            5 => FrameType::OpenErr,
            6 => FrameType::Data,
            7 => FrameType::Close,
            8 => FrameType::Ping,
            9 => FrameType::Pong,
            10 => FrameType::UdpAssociate,
            11 => FrameType::UdpOk,
            12 => FrameType::UdpData,
            13 => FrameType::Error,
            _ => return None,
        })
    }
}

#[derive(Clone, Debug)]
pub struct Frame {
    pub ftype: FrameType,
    pub flags: u16,
    pub sid: u32,
    pub counter: u64,
    /// AEAD additional data (header[0..12]) needed for out-of-band decryption
    /// (e.g. the initial Auth frame on the server).
    pub aad: [u8; 12],
    pub payload: Vec<u8>,
}

pub struct HeaderInfo {
    pub ftype: FrameType,
    pub flags: u16,
    pub sid: u32,
    pub ct_len: usize,
    pub counter: u64,
    /// first 12 bytes of the header (used as AEAD additional data)
    pub aad: [u8; 12],
}

pub fn build_header(
    ftype: FrameType,
    flags: u16,
    sid: u32,
    ct_len: usize,
    counter: u64,
) -> [u8; HEADER_LEN] {
    let mut h = [0u8; HEADER_LEN];
    h[0] = PROTO_VERSION;
    h[1] = ftype as u8;
    h[2..4].copy_from_slice(&flags.to_le_bytes());
    h[4..8].copy_from_slice(&sid.to_le_bytes());
    h[8..12].copy_from_slice(&(ct_len as u32).to_le_bytes());
    h[12..20].copy_from_slice(&counter.to_le_bytes());
    h
}

pub fn parse_header(h: &[u8; HEADER_LEN]) -> Result<HeaderInfo> {
    ensure!(
        h[0] == PROTO_VERSION,
        "unsupported protocol version {}",
        h[0]
    );
    let ftype =
        FrameType::from_u8(h[1]).ok_or_else(|| anyhow::anyhow!("bad frame type {}", h[1]))?;
    let flags = u16::from_le_bytes([h[2], h[3]]);
    let sid = u32::from_le_bytes([h[4], h[5], h[6], h[7]]);
    let ct_len = u32::from_le_bytes([h[8], h[9], h[10], h[11]]) as usize;
    let counter = u64::from_le_bytes([h[12], h[13], h[14], h[15], h[16], h[17], h[18], h[19]]);
    let mut aad = [0u8; 12];
    aad.copy_from_slice(&h[0..12]);
    Ok(HeaderInfo {
        ftype,
        flags,
        sid,
        ct_len,
        counter,
        aad,
    })
}

/// Stateless frame encoder (shared counters ensure nonce uniqueness).
#[derive(Clone)]
pub struct FrameEncoder {
    cipher: Arc<FrameCipher>,
    counters: CounterGen,
}

impl FrameEncoder {
    pub fn new(cipher: Arc<FrameCipher>, counters: CounterGen) -> Self {
        Self { cipher, counters }
    }

    /// Append one encoded frame to `out`. `out` can be reused across frames
    /// (`clear()` keeps its capacity), avoiding a per-frame allocation.
    pub fn encode_into(
        &self,
        ftype: FrameType,
        flags: u16,
        sid: u32,
        payload: &[u8],
        out: &mut BytesMut,
    ) -> Result<()> {
        ensure!(payload.len() <= MAX_PLAINTEXT, "frame payload too large");
        let counter = self.counters.next();
        let header = build_header(ftype, flags, sid, payload.len() + TAG_LEN, counter);
        out.extend_from_slice(&header);
        let start = out.len();
        out.extend_from_slice(payload);
        let tag = self
            .cipher
            .seal_slice(counter, &header[..12], &mut out[start..])?;
        out.extend_from_slice(&tag);
        Ok(())
    }

    pub fn encode(&self, ftype: FrameType, flags: u16, sid: u32, payload: &[u8]) -> Result<Bytes> {
        let mut out = BytesMut::with_capacity(HEADER_LEN + payload.len() + TAG_LEN);
        self.encode_into(ftype, flags, sid, payload, &mut out)?;
        Ok(out.freeze())
    }
}

/// Buffered frame decoder. `raw = true` yields undecrypted payloads
/// (used by the server for the very first Auth frame).
pub struct FrameDecoder {
    cipher: Option<Arc<FrameCipher>>,
    window: Option<ReplayWindow>,
    buf: BytesMut,
    pub raw: bool,
}

impl FrameDecoder {
    pub fn new(cipher: Option<Arc<FrameCipher>>, window: Option<ReplayWindow>) -> Self {
        Self {
            cipher,
            window,
            buf: BytesMut::new(),
            raw: false,
        }
    }

    pub fn set_cipher(&mut self, cipher: Arc<FrameCipher>) {
        self.cipher = Some(cipher);
        self.raw = false;
    }

    pub fn feed(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// Drop all buffered bytes (e.g. after a decode error on an unreliable
    /// channel) while keeping the cipher and replay window intact.
    pub fn clear(&mut self) {
        self.buf.clear();
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn next_frame(&mut self) -> Result<Option<Frame>> {
        if self.buf.len() < HEADER_LEN {
            return Ok(None);
        }
        let mut header = [0u8; HEADER_LEN];
        header.copy_from_slice(&self.buf[..HEADER_LEN]);
        let info = parse_header(&header)?;
        ensure!(
            info.ct_len >= TAG_LEN && info.ct_len <= MAX_CIPHERTEXT,
            "invalid frame length {}",
            info.ct_len
        );
        if self.buf.len() < HEADER_LEN + info.ct_len {
            self.buf.reserve(HEADER_LEN + info.ct_len - self.buf.len());
            return Ok(None);
        }
        self.buf.advance(HEADER_LEN);
        let ct = self.buf.split_to(info.ct_len);
        let payload = if self.raw {
            ct.to_vec()
        } else if let Some(cipher) = self.cipher.as_ref() {
            if let Some(w) = &mut self.window {
                ensure!(w.check(info.counter), "replayed datagram counter");
            }
            cipher.open(info.counter, &info.aad, &ct)?
        } else {
            ct.to_vec()
        };
        Ok(Some(Frame {
            ftype: info.ftype,
            flags: info.flags,
            sid: info.sid,
            counter: info.counter,
            aad: info.aad,
            payload,
        }))
    }
}

/// Pull-decoder over any `AsyncRead`.
pub struct FrameReader<R> {
    r: R,
    dec: FrameDecoder,
}

impl<R: AsyncRead + Unpin> FrameReader<R> {
    pub fn new(r: R, cipher: Option<Arc<FrameCipher>>, window: Option<ReplayWindow>) -> Self {
        Self {
            r,
            dec: FrameDecoder::new(cipher, window),
        }
    }

    pub fn set_cipher(&mut self, cipher: Arc<FrameCipher>) {
        self.dec.set_cipher(cipher);
    }

    pub fn decoder_mut(&mut self) -> &mut FrameDecoder {
        &mut self.dec
    }

    /// Returns None on clean EOF. Errors on corrupt frames.
    pub async fn read(&mut self) -> Result<Option<Frame>> {
        loop {
            if let Some(f) = self.dec.next_frame()? {
                return Ok(Some(f));
            }
            let mut buf = [0u8; 16 * 1024];
            let n = self.r.read(&mut buf).await?;
            if n == 0 {
                ensure!(self.dec.is_empty(), "truncated frame at EOF");
                return Ok(None);
            }
            self.dec.feed(&buf[..n]);
        }
    }
}

/// Push-encoder over any `AsyncWrite`. Keeps a reusable encode buffer so a
/// steady write loop performs no per-frame allocation.
pub struct FrameWriter<W> {
    w: W,
    enc: FrameEncoder,
    buf: BytesMut,
}

impl<W: AsyncWrite + Unpin> FrameWriter<W> {
    pub fn new(w: W, cipher: Arc<FrameCipher>, counters: CounterGen) -> Self {
        Self {
            w,
            enc: FrameEncoder::new(cipher, counters),
            buf: BytesMut::new(),
        }
    }

    pub fn set_cipher(&mut self, cipher: Arc<FrameCipher>) {
        self.enc = FrameEncoder::new(cipher, self.enc.counters.clone());
    }

    pub async fn write(
        &mut self,
        ftype: FrameType,
        flags: u16,
        sid: u32,
        payload: &[u8],
    ) -> Result<()> {
        self.buf.clear(); // keeps capacity
        self.enc
            .encode_into(ftype, flags, sid, payload, &mut self.buf)?;
        self.w.write_all(&self.buf).await?;
        Ok(())
    }

    /// Gracefully finish the underlying stream (QUIC: sends FIN).
    pub async fn shutdown(&mut self) -> Result<()> {
        self.w.shutdown().await?;
        Ok(())
    }
}

/// Encode an Open/OpenOk target.
pub fn encode_open(host: &str, port: u16) -> Vec<u8> {
    let mut v = Vec::with_capacity(2 + host.len() + 2);
    v.extend_from_slice(&(host.len() as u16).to_le_bytes());
    v.extend_from_slice(host.as_bytes());
    v.extend_from_slice(&port.to_le_bytes());
    v
}

pub fn decode_open(payload: &[u8]) -> Result<(String, u16)> {
    ensure!(payload.len() >= 4, "open payload truncated");
    let hl = u16::from_le_bytes([payload[0], payload[1]]) as usize;
    ensure!(
        payload.len() >= 2 + hl + 2 && hl > 0 && hl <= 255,
        "open host invalid"
    );
    let host = String::from_utf8(payload[2..2 + hl].to_vec())?;
    let p = &payload[2 + hl..2 + hl + 2];
    Ok((host, u16::from_le_bytes([p[0], p[1]])))
}

/// OpenErr reason codes.
pub const OPEN_ERR_DIAL: u8 = 1;
pub const OPEN_ERR_LIMIT: u8 = 2;
pub const OPEN_ERR_BAD_TARGET: u8 = 3;
pub const OPEN_ERR_DENIED: u8 = 4;

#[cfg(test)]
mod tests {
    use super::super::crypto::FrameCipher;
    use super::*;

    fn roundtrip(cipher: Arc<FrameCipher>) {
        let enc = FrameEncoder::new(cipher.clone(), CounterGen::stream());
        let mut dec = FrameDecoder::new(Some(cipher), None);
        let payloads: Vec<Vec<u8>> = vec![vec![], b"x".to_vec(), vec![42u8; MAX_PLAINTEXT]];
        for (i, p) in payloads.iter().enumerate() {
            let wire = enc.encode(FrameType::Data, 0, i as u32, p).unwrap();
            dec.feed(&wire);
            let f = dec.next_frame().unwrap().unwrap();
            assert_eq!(f.ftype, FrameType::Data);
            assert_eq!(f.sid, i as u32);
            assert_eq!(&f.payload, p);
        }
        assert!(dec.next_frame().unwrap().is_none());
    }

    #[test]
    fn frame_roundtrip() {
        roundtrip(Arc::new(FrameCipher::new(&[1u8; 32])));
    }

    #[test]
    fn frame_corrupt_rejected() {
        let cipher = Arc::new(FrameCipher::new(&[2u8; 32]));
        let enc = FrameEncoder::new(cipher.clone(), CounterGen::stream());
        let mut dec = FrameDecoder::new(Some(cipher), None);
        let mut wire = enc
            .encode(FrameType::Data, 0, 1, b"payload")
            .unwrap()
            .to_vec();
        let last = wire.len() - 1;
        wire[last] ^= 0xff;
        dec.feed(&wire);
        assert!(dec.next_frame().is_err());
    }

    #[test]
    fn fragmented_feed() {
        let cipher = Arc::new(FrameCipher::new(&[3u8; 32]));
        let enc = FrameEncoder::new(cipher.clone(), CounterGen::stream());
        let mut dec = FrameDecoder::new(Some(cipher), None);
        let wire = enc.encode(FrameType::Ping, 0, 7, b"12345678").unwrap();
        for chunk in wire.chunks(3) {
            dec.feed(chunk);
            if let Some(f) = dec.next_frame().unwrap() {
                assert_eq!(f.payload, b"12345678");
                return;
            }
        }
        panic!("frame never completed");
    }

    #[test]
    fn decoder_clear_recovers_after_corruption() {
        let cipher = Arc::new(FrameCipher::new(&[4u8; 32]));
        let enc = FrameEncoder::new(cipher.clone(), CounterGen::stream());
        let mut dec = FrameDecoder::new(Some(cipher), None);
        let wire = enc.encode(FrameType::Ping, 0, 1, b"abcdef").unwrap();
        // truncated frame + garbage: an unrecoverable buffer state
        dec.feed(&wire[..wire.len() - 2]);
        assert!(dec.next_frame().unwrap().is_none());
        dec.feed(&[0xff; 8]);
        // clearing the buffer lets the next datagram parse cleanly
        dec.clear();
        dec.feed(&wire);
        let f = dec.next_frame().unwrap().unwrap();
        assert_eq!(f.payload, b"abcdef");
    }

    #[test]
    fn open_roundtrip() {
        let p = encode_open("example.com", 443);
        let (h, po) = decode_open(&p).unwrap();
        assert_eq!(h, "example.com");
        assert_eq!(po, 443);
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// Arbitrary chunked input must never panic; on a decode error the
        /// decoder is cleared and remains usable.
        #[test]
        fn decoder_never_panics_on_arbitrary_input(
            chunks in proptest::collection::vec(
                proptest::collection::vec(any::<u8>(), 0..64),
                0..32,
            )
        ) {
            let cipher = Arc::new(FrameCipher::new(&[0x5a; 32]));
            let mut dec = FrameDecoder::new(Some(cipher), None);
            for c in chunks {
                dec.feed(&c);
                loop {
                    match dec.next_frame() {
                        Ok(Some(_)) => {}
                        Ok(None) => break,
                        Err(_) => {
                            dec.clear();
                            break;
                        }
                    }
                }
            }
        }

        /// After arbitrary garbage and a `clear()`, a well-formed frame must
        /// still decode (state is recoverable, buffer is not poisoned).
        #[test]
        fn decoder_recovers_after_clear(
            garbage in proptest::collection::vec(any::<u8>(), 0..256),
            payload in proptest::collection::vec(any::<u8>(), 0..4096),
        ) {
            let cipher = Arc::new(FrameCipher::new(&[0x33; 32]));
            let enc = FrameEncoder::new(cipher.clone(), CounterGen::stream());
            let wire = enc.encode(FrameType::Data, 0, 5, &payload).unwrap();

            let mut dec = FrameDecoder::new(Some(cipher), None);
            dec.feed(&garbage);
            while let Ok(Some(_)) = dec.next_frame() {}
            dec.clear();
            dec.feed(&wire);
            let f = dec.next_frame().expect("no error").expect("frame");
            prop_assert_eq!(f.payload, payload);
        }

        #[test]
        fn open_encode_decode_roundtrip(host in "[a-z0-9.]{1,50}", port in any::<u16>()) {
            let p = encode_open(&host, port);
            let (h, po) = decode_open(&p).unwrap();
            prop_assert_eq!(h, host);
            prop_assert_eq!(po, port);
        }

        #[test]
        fn decode_open_never_panics(b in proptest::collection::vec(any::<u8>(), 0..300)) {
            let _ = decode_open(&b);
        }
    }
}
