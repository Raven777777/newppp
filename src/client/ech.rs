//! HPKE backend for rustls ECH (RFC 9180), wired to the `hpke` crate.
//!
//! rustls 0.23 ships ECH support (`EchMode::Grease` / `EchMode::Ech`) but no
//! HPKE implementation behind the `ring` provider (only aws-lc-rs has one,
//! and switching providers would change the whole crypto stack). This module
//! implements rustls' `crypto::hpke::Hpke` trait with the pure-Rust `hpke`
//! crate instead, so GREASE ECH works on the existing ring-based build.
//!
//! Suite: DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + ChaCha20-Poly1305 —
//! the suite Chrome uses for ECH.

use std::sync::Arc;

use hpke::aead::ChaCha20Poly1305;
use hpke::aead::{AeadCtxR, AeadCtxS};
use hpke::kdf::HkdfSha256;
use hpke::kem::Kem as _;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable as _, OpModeR, OpModeS, Serializable as _};
use rustls::crypto::hpke::{
    EncapsulatedSecret, Hpke, HpkePrivateKey, HpkePublicKey, HpkeSealer, HpkeSuite,
};
use rustls::internal::msgs::enums::{HpkeAead, HpkeKdf, HpkeKem};
use rustls::internal::msgs::handshake::HpkeSymmetricCipherSuite;

#[derive(Debug)]
pub struct HpkeX25519Sha256ChaCha20;

/// DHKEM(X25519, HKDF-SHA256) encapped key length (compressed X25519 point).
const ENC_LEN: usize = 32;

type Kem = X25519HkdfSha256;

impl HpkeX25519Sha256ChaCha20 {
    pub fn suite_static() -> HpkeSuite {
        HpkeSuite {
            kem: HpkeKem::DHKEM_X25519_HKDF_SHA256,
            sym: HpkeSymmetricCipherSuite {
                kdf_id: HpkeKdf::HKDF_SHA256,
                aead_id: HpkeAead::CHACHA20_POLY_1305,
            },
        }
    }
}

impl Hpke for HpkeX25519Sha256ChaCha20 {
    fn seal(
        &self,
        info: &[u8],
        aad: &[u8],
        plaintext: &[u8],
        pub_key: &HpkePublicKey,
    ) -> Result<(EncapsulatedSecret, Vec<u8>), rustls::Error> {
        let pk = <Kem as hpke::kem::Kem>::PublicKey::from_bytes(&pub_key.0).map_err(hpke_err)?;
        let (enc, ct) = hpke::single_shot_seal::<ChaCha20Poly1305, HkdfSha256, Kem>(
            &OpModeS::Base,
            &pk,
            info,
            plaintext,
            aad,
        )
        .map_err(hpke_err)?;
        let enc_bytes = enc.to_bytes().to_vec();
        debug_assert_eq!(enc_bytes.len(), ENC_LEN);
        Ok((EncapsulatedSecret(enc_bytes), ct))
    }

    fn setup_sealer(
        &self,
        info: &[u8],
        pub_key: &HpkePublicKey,
    ) -> Result<(EncapsulatedSecret, Box<dyn HpkeSealer + 'static>), rustls::Error> {
        let pk = <Kem as hpke::kem::Kem>::PublicKey::from_bytes(&pub_key.0).map_err(hpke_err)?;
        let (enc, ctx) =
            hpke::setup_sender::<ChaCha20Poly1305, HkdfSha256, Kem>(&OpModeS::Base, &pk, info)
                .map_err(hpke_err)?;
        let enc_bytes = enc.to_bytes().to_vec();
        Ok((EncapsulatedSecret(enc_bytes), Box::new(Sealer(ctx))))
    }

    fn open(
        &self,
        enc: &EncapsulatedSecret,
        info: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
        secret_key: &HpkePrivateKey,
    ) -> Result<Vec<u8>, rustls::Error> {
        let sk = <Kem as hpke::kem::Kem>::PrivateKey::from_bytes(secret_key.secret_bytes())
            .map_err(hpke_err)?;
        let enc = <Kem as hpke::kem::Kem>::EncappedKey::from_bytes(&enc.0).map_err(hpke_err)?;
        hpke::single_shot_open::<ChaCha20Poly1305, HkdfSha256, Kem>(
            &OpModeR::Base,
            &sk,
            &enc,
            info,
            ciphertext,
            aad,
        )
        .map_err(hpke_err)
    }

    fn setup_opener(
        &self,
        enc: &EncapsulatedSecret,
        info: &[u8],
        secret_key: &HpkePrivateKey,
    ) -> Result<Box<dyn rustls::crypto::hpke::HpkeOpener + 'static>, rustls::Error> {
        let sk = <Kem as hpke::kem::Kem>::PrivateKey::from_bytes(secret_key.secret_bytes())
            .map_err(hpke_err)?;
        let enc = <Kem as hpke::kem::Kem>::EncappedKey::from_bytes(&enc.0).map_err(hpke_err)?;
        let ctx = hpke::setup_receiver::<ChaCha20Poly1305, HkdfSha256, Kem>(
            &OpModeR::Base,
            &sk,
            &enc,
            info,
        )
        .map_err(hpke_err)?;
        Ok(Box::new(Opener(ctx)))
    }

    fn generate_key_pair(&self) -> Result<(HpkePublicKey, HpkePrivateKey), rustls::Error> {
        let (sk, pk) = Kem::gen_keypair();
        Ok((
            HpkePublicKey(pk.to_bytes().to_vec()),
            HpkePrivateKey::from(sk.to_bytes().to_vec()),
        ))
    }

    fn suite(&self) -> HpkeSuite {
        Self::suite_static()
    }
}

fn hpke_err(e: hpke::HpkeError) -> rustls::Error {
    rustls::Error::Other(rustls::OtherError(Arc::new(e)))
}

struct Sealer(AeadCtxS<ChaCha20Poly1305, HkdfSha256, Kem>);

impl std::fmt::Debug for Sealer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Sealer")
    }
}

impl HpkeSealer for Sealer {
    fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        self.0.seal(plaintext, aad).map_err(hpke_err)
    }
}

struct Opener(AeadCtxR<ChaCha20Poly1305, HkdfSha256, Kem>);

impl std::fmt::Debug for Opener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Opener")
    }
}

impl rustls::crypto::hpke::HpkeOpener for Opener {
    fn open(&mut self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        self.0.open(ciphertext, aad).map_err(hpke_err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 9180 base-mode round trip through the rustls trait surface.
    #[test]
    fn seal_open_roundtrip_via_trait() {
        let hpke = HpkeX25519Sha256ChaCha20;
        let (pk, sk) = hpke.generate_key_pair().unwrap();
        let info = b"newppp ech test";
        let aad = b"aad";
        let (enc, ct) = hpke.seal(info, aad, b"payload", &pk).unwrap();
        assert_eq!(enc.0.len(), ENC_LEN);
        let pt = hpke.open(&enc, info, aad, &ct, &sk).unwrap();
        assert_eq!(pt, b"payload");
    }

    #[test]
    fn context_seal_open_roundtrip() {
        let hpke = HpkeX25519Sha256ChaCha20;
        let (pk, sk) = hpke.generate_key_pair().unwrap();
        let info = b"ctx";
        let (enc, mut sealer) = hpke.setup_sealer(info, &pk).unwrap();
        let mut opener = hpke.setup_opener(&enc, info, &sk).unwrap();
        let ct = sealer.seal(b"aad", b"hello").unwrap();
        let pt = opener.open(b"aad", &ct).unwrap();
        assert_eq!(pt, b"hello");
    }

    /// Wire-level suite IDs must match RFC 9180 / the ECH spec expectations.
    #[test]
    fn suite_ids_match() {
        let s = HpkeX25519Sha256ChaCha20::suite_static();
        assert_eq!(u16::from(s.kem), 0x0020);
        assert_eq!(u16::from(s.sym.kdf_id), 0x0001);
        assert_eq!(u16::from(s.sym.aead_id), 0x0003);
    }
}
