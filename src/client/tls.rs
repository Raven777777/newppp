//! Client TLS identity: certificate pinning verifier (F-6).
//!
//! `--pin <sha256>` replaces CA verification: the server's identity is
//! exactly the pinned certificate. This is the required companion of
//! `--sni` (masquerade SNI) — with a masqueraded name the server certificate
//! cannot match it, so identity must be anchored to the fingerprint instead.
//! For a private proxy this is strictly stronger than public CA validation:
//! there is no CA issuance chain to trust, and no CA-side failure mode.

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as RustlsError, SignatureScheme};
use sha2::{Digest, Sha256};
use wtransport::config::DnsResolver;

/// DNS resolver that redirects every lookup to one fixed address.
///
/// The masquerade flow: the URL carries the masquerade hostname (which
/// becomes the TLS SNI), and this resolver maps that hostname (and anything
/// else) to the real server address. Pure address URLs (no-host) skip DNS
/// entirely on the WT path, so the redirect only matters when the URL uses
/// the masquerade hostname.
#[derive(Debug, Clone)]
pub struct FixedResolver {
    addr: SocketAddr,
}

impl FixedResolver {
    pub fn new(addr: SocketAddr) -> Self {
        Self { addr }
    }
}

impl DnsResolver for FixedResolver {
    fn resolve(&self, _host: &str) -> Pin<Box<dyn wtransport::config::DnsLookupFuture>> {
        let addr = self.addr;
        Box::pin(async move { Ok(Some(addr)) })
    }
}

/// hyper-side twin of [`FixedResolver`]: every lookup returns one fixed
/// address (used by the fallback POST connector when `--sni` masquerades the
/// URL host). hyper-util's `Resolve` is a sealed trait blanket-implemented
/// for `tower_service::Service<Name>` with `Iterator<Item = SocketAddr>`
/// responses, so we implement the Service shape.
#[derive(Debug, Clone)]
pub struct HyperFixedResolver {
    /// Fixed address when masquerading; zeroed when this resolver is the
    /// system-DNS fallback (the `call` impl branches on `fixed`).
    addr: SocketAddr,
    fixed: bool,
}

impl HyperFixedResolver {
    pub fn new(addr: SocketAddr) -> Self {
        Self { addr, fixed: true }
    }

    /// System-DNS resolver used when masquerade is off: blocking
    /// getaddrinfo off-thread (mirrors hyper's GaiResolver, but keeps a
    /// single connector type so the Client generic stays uniform).
    pub fn system_fallback() -> Self {
        Self {
            addr: SocketAddr::from(([0, 0, 0, 0], 0)),
            fixed: false,
        }
    }
}

impl tower_service::Service<hyper_util::client::legacy::connect::dns::Name> for HyperFixedResolver {
    type Response = std::vec::IntoIter<SocketAddr>;
    type Error = std::io::Error;
    type Future =
        Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(
        &mut self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, name: hyper_util::client::legacy::connect::dns::Name) -> Self::Future {
        if self.fixed {
            let addr = self.addr;
            Box::pin(async move { Ok(vec![addr].into_iter()) })
        } else {
            // System DNS: blocking getaddrinfo off the async thread.
            let host = name.as_str().to_string();
            Box::pin(async move {
                let addrs: Vec<SocketAddr> = tokio::task::spawn_blocking(move || {
                    use std::net::ToSocketAddrs;
                    let v: Vec<SocketAddr> =
                        (host.as_str(), 0).to_socket_addrs().map(|i| i.collect())?;
                    Ok::<Vec<SocketAddr>, std::io::Error>(v)
                })
                .await
                .map_err(std::io::Error::other)??;
                Ok(addrs.into_iter())
            })
        }
    }
}

/// Verifier that accepts exactly one certificate: SHA-256(end_entity DER)
/// must equal the pinned fingerprint. Signature verification still runs
/// against the provider's algorithms (the handshake must remain
/// cryptographically sound; only the trust anchor decision is replaced).
#[derive(Debug)]
pub struct PinVerifier {
    fingerprint: [u8; 32],
    provider: Arc<CryptoProvider>,
}

impl PinVerifier {
    pub fn new(fingerprint: [u8; 32], provider: Arc<CryptoProvider>) -> Self {
        Self {
            fingerprint,
            provider,
        }
    }
}

impl ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        let digest: [u8; 32] = Sha256::digest(end_entity.as_ref()).into();
        // Constant-time compare: the fingerprint is not secret, but keep the
        // same discipline as every other credential comparison here.
        let mut diff = 0u8;
        for (a, b) in digest.iter().zip(self.fingerprint.iter()) {
            diff |= a ^ b;
        }
        if diff == 0 {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(RustlsError::Other(rustls::OtherError(Arc::new(
                std::io::Error::other("certificate fingerprint mismatch (--pin)"),
            ))))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider() -> Arc<CryptoProvider> {
        Arc::new(rustls::crypto::ring::default_provider())
    }

    fn dummy_cert(byte: u8) -> CertificateDer<'static> {
        CertificateDer::from(vec![byte; 64])
    }

    #[test]
    fn pin_matches_exact_certificate() {
        let cert = dummy_cert(0x42);
        let digest: [u8; 32] = Sha256::digest(cert.as_ref()).into();
        let v = PinVerifier::new(digest, provider());
        assert!(v
            .verify_server_cert(
                &cert,
                &[],
                &ServerName::try_from("whatever.example").unwrap(),
                &[],
                UnixTime::now()
            )
            .is_ok());
    }

    #[test]
    fn pin_rejects_any_other_certificate() {
        let good = dummy_cert(0x42);
        let digest: [u8; 32] = Sha256::digest(good.as_ref()).into();
        let v = PinVerifier::new(digest, provider());
        let evil = dummy_cert(0x43);
        assert!(v
            .verify_server_cert(
                &evil,
                &[],
                &ServerName::try_from("whatever.example").unwrap(),
                &[],
                UnixTime::now()
            )
            .is_err());
    }
}
