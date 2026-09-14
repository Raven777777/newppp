//! Fallback outbound (mode A): maintains one duplex channel whose two
//! directions carry the frame protocol; reconnects transparently.
//!
//! Transport variants, selected by the URL scheme:
//! * `https://` / `http://` — long-lived POST (direct connections)
//! * `wss://` / `ws://`     — WebSocket (required behind proxies that buffer
//!   request bodies, e.g. Cloudflare; works on CF's free plan)

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use hyper::body::Frame as HttpFrame;
use hyper::header::{AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE};
use hyper::http;
use hyper::Request;
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use hyper_util::rt::TokioExecutor;
use tokio::io::AsyncRead;
use tokio::sync::{mpsc, Mutex};
use tokio::time::timeout;
use tokio_stream::wrappers::ReceiverStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tokio_tungstenite::Connector;
use tracing::debug;
use {futures_util::SinkExt, futures_util::StreamExt};

use crate::client::tls::HyperFixedResolver;
use crate::config::ClientConfig;
use crate::proto::crypto::{
    auth_mac, derive_session_key, make_bearer, AuthPayload, CounterGen, FrameCipher, SALT_LEN,
};
use crate::proto::frame::{random_padding, FrameEncoder, FrameType};
use crate::proto::mux::{BoxStream, MuxClient, UdpPipe};
use crate::proto::stream::StreamAsRead;
use crate::proto::USER_AGENT;

type HyperClient = Client<HttpsConnector<HttpConnector>, BoxBody<Bytes, std::io::Error>>;

pub struct HttpOutbound {
    url: String,
    /// `true` → WebSocket transport (wss:// / ws:// URL).
    ws: bool,
    static_key: [u8; 32],
    uid: String,
    client: Option<HyperClient>,
    ws_tls: Option<Arc<rustls::ClientConfig>>,
    mux: Mutex<Option<Arc<MuxClient>>>,
}

impl HttpOutbound {
    pub async fn new(cfg: &ClientConfig, url: &str) -> Result<HttpOutbound> {
        let static_key = crate::proto::crypto::derive_static_key(&cfg.password, &cfg.uid);
        let ws = url.starts_with("wss://") || url.starts_with("ws://");
        // `--sni` masquerade: the URL host is rewritten to the masquerade
        // name (driving TLS SNI and the HTTP Host/`:authority`), and a
        // fixed-address hyper resolver points the connection at the real
        // server address from the original URL. wss is rejected at config
        // validation (CF routes by real SNI), so masquerade is POST-only.
        let (dial_url, _sni_name) = match &cfg.sni {
            Some(sni) => {
                let mut u = url::Url::parse(url).map_err(|e| anyhow!("bad --url: {e}"))?;
                u.set_host(Some(sni))
                    .map_err(|_| anyhow!("--sni '{sni}' cannot replace the URL host"))?;
                (u.to_string(), Some(sni.clone()))
            }
            None => (url.to_string(), None),
        };
        let resolver = match &cfg.sni {
            Some(_) => {
                let (addr, _port) = super::wt::url_host_and_port(url).await?;
                Some(HyperFixedResolver::new(addr))
            }
            None => None,
        };
        let (client, ws_tls) = if ws {
            (
                None,
                Some(Arc::new(build_ws_tls(cfg.skip_verify, cfg.pin)?)),
            )
        } else {
            (
                Some(build_client(cfg.skip_verify, cfg.pin, resolver)?),
                None,
            )
        };
        Ok(HttpOutbound {
            url: dial_url,
            ws,
            static_key,
            uid: cfg.uid.clone(),
            client,
            ws_tls,
            mux: Mutex::new(None),
        })
    }

    pub fn describe(&self) -> &'static str {
        if self.ws {
            "WebSocket fallback"
        } else {
            "HTTPS POST fallback"
        }
    }

    async fn ensure_mux(self: &Arc<Self>) -> Result<Arc<MuxClient>> {
        let mut g = self.mux.lock().await;
        if let Some(m) = g.as_ref() {
            if !m.is_closed() {
                return Ok(m.clone());
            }
        }
        let m = Arc::new(self.connect().await?);
        *g = Some(m.clone());
        Ok(m)
    }

    async fn connect(&self) -> Result<MuxClient> {
        // session keys + in-band auth payload
        let mut salt = [0u8; SALT_LEN];
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut salt);
        let mut nonce = [0u8; SALT_LEN];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let ts = crate::proto::crypto::now_unix();
        let mac = auth_mac(&self.static_key, &self.uid, ts, &nonce);
        let auth = AuthPayload {
            proto_version: crate::proto::frame::PROTO_VERSION,
            salt,
            ts,
            nonce,
            uid: self.uid.clone(),
            mac,
        };
        let session_key = derive_session_key(&self.static_key, &salt);
        let cipher = Arc::new(FrameCipher::new(&session_key));
        let enc = FrameEncoder::new(cipher.clone(), CounterGen::stream());

        // prelude: AUTH frame sealed with the static key, first bytes either
        // way. Random tail pads the ciphertext length away from a fixed
        // protocol signature (server decodes by field prefix).
        let static_cipher = Arc::new(FrameCipher::new(&self.static_key));
        let mut auth_payload = auth.encode();
        auth_payload.extend_from_slice(&random_padding());
        let auth_wire = FrameEncoder::new(static_cipher, CounterGen::stream()).encode(
            FrameType::Auth,
            0,
            0,
            &auth_payload,
        )?;

        if self.ws {
            self.connect_ws(auth_wire, enc, cipher).await
        } else {
            self.connect_post(auth_wire, enc, cipher).await
        }
    }

    async fn connect_post(
        &self,
        auth_wire: Bytes,
        enc: FrameEncoder,
        cipher: Arc<FrameCipher>,
    ) -> Result<MuxClient> {
        let client = self
            .client
            .as_ref()
            .ok_or_else(|| anyhow!("not a POST url"))?;

        let (body_tx, body_rx) = mpsc::channel::<Bytes>(256);
        if body_tx.send(auth_wire).await.is_err() {
            anyhow::bail!("body channel closed");
        }

        // Fresh bearer per POST: the token embeds a timestamp checked with a
        // +/-60s window on the server.
        let bearer = make_bearer(&self.static_key, &self.uid);

        let req = Request::builder()
            .method(http::Method::POST)
            .uri(&self.url)
            .header(AUTHORIZATION, format!("Bearer {bearer}"))
            .header(CONTENT_TYPE, "application/octet-stream")
            .header(CACHE_CONTROL, "no-store")
            .header(hyper::header::USER_AGENT, USER_AGENT)
            .header(hyper::header::ACCEPT, "*/*")
            .body(BoxBody::new(RequestBody {
                rx: Some(body_rx),
                pending: VecDeque::new(),
            }))
            .map_err(|e| anyhow!("build request: {e}"))?;

        debug!("fallback: POST {}", self.url);
        let resp = timeout(Duration::from_secs(30), client.request(req))
            .await
            .map_err(|_| anyhow!("POST timeout"))?
            .map_err(|e| anyhow!("POST failed: {e}"))?;

        let ct = resp
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_ascii_lowercase();
        if !resp.status().is_success() || ct.starts_with("text/html") {
            // disguise page or error: authentication failed
            anyhow::bail!("fallback rejected (status={}, ct={ct})", resp.status());
        }

        let reader = BodyAsRead::new(resp.into_body());
        Ok(MuxClient::start_with_tx(reader, enc, cipher, body_tx))
    }

    async fn connect_ws(
        &self,
        auth_wire: Bytes,
        enc: FrameEncoder,
        cipher: Arc<FrameCipher>,
    ) -> Result<MuxClient> {
        let tls = self
            .ws_tls
            .as_ref()
            .ok_or_else(|| anyhow!("not a websocket url"))?;

        let mut req: tokio_tungstenite::tungstenite::http::Request<()> = self
            .url
            .as_str()
            .into_client_request()
            .map_err(|e| anyhow!("bad ws url: {e}"))?;
        // Fresh bearer per upgrade (same ±60s window check on the server).
        let bearer = make_bearer(&self.static_key, &self.uid);
        req.headers_mut().insert(
            AUTHORIZATION,
            http::HeaderValue::from_str(&format!("Bearer {bearer}"))
                .map_err(|e| anyhow!("bearer header: {e}"))?,
        );
        req.headers_mut().insert(
            hyper::header::USER_AGENT,
            http::HeaderValue::from_static(USER_AGENT),
        );

        // Bounded like every other connect step: on a blackholed path an
        // unbounded await would hang while holding the mux lock, stalling
        // every subsequent open_tcp/udp_associate behind it.
        let (ws, _resp) = timeout(
            Duration::from_secs(30),
            tokio_tungstenite::connect_async_tls_with_config(
                req,
                None,
                false,
                Some(Connector::Rustls(tls.clone())),
            ),
        )
        .await
        .map_err(|_| anyhow!("ws connect timeout"))?
        .map_err(|e| anyhow!("ws connect failed: {e}"))?;
        debug!("fallback: ws channel up {}", self.url);

        let (mut sink, mut stream) = ws.split();

        // incoming binary messages -> AsyncRead for the mux frame decoder
        let (in_tx, in_rx) = mpsc::channel::<Bytes>(256);
        tokio::spawn(async move {
            while let Some(Ok(msg)) = stream.next().await {
                match msg {
                    WsMessage::Binary(b) => {
                        if in_tx.send(b).await.is_err() {
                            break;
                        }
                    }
                    WsMessage::Close(_) => break,
                    _ => {}
                }
            }
        });

        // outgoing wire bytes -> binary messages, plus a 30s WS-level ping
        // to keep intermediaries (e.g. Cloudflare idle timers) alive
        let (body_tx, mut body_rx) = mpsc::channel::<Bytes>(256);
        if body_tx.send(auth_wire).await.is_err() {
            anyhow::bail!("body channel closed");
        }
        tokio::spawn(async move {
            let mut ping = tokio::time::interval(Duration::from_secs(30));
            ping.tick().await; // skip immediate tick
            loop {
                tokio::select! {
                    _ = ping.tick() => {
                        if sink.send(WsMessage::Ping(Bytes::new())).await.is_err() {
                            break;
                        }
                    }
                    b = body_rx.recv() => match b {
                        Some(b) => {
                            if sink.send(WsMessage::Binary(b)).await.is_err() {
                                break;
                            }
                        }
                        None => break,
                    }
                }
            }
            let _ = sink.close().await;
        });

        let reader =
            StreamAsRead::new(ReceiverStream::new(in_rx).map(Ok::<_, std::convert::Infallible>));
        Ok(MuxClient::start_with_tx(reader, enc, cipher, body_tx))
    }

    pub async fn open_tcp(self: &Arc<Self>, host: &str, port: u16) -> Result<BoxStream> {
        let mux = self.ensure_mux().await?;
        match mux.open_tcp(host, port).await {
            Ok(s) => return Ok(s),
            Err(e) if !mux.is_closed() => return Err(e),
            Err(e) => debug!("fallback channel died; reconnecting: {e:#}"),
        }
        let mux = self.ensure_mux().await?;
        mux.open_tcp(host, port).await
    }

    pub async fn udp_associate(self: &Arc<Self>) -> Result<UdpPipe> {
        let mux = self.ensure_mux().await?;
        match mux.udp_associate().await {
            Ok(s) => return Ok(s),
            Err(e) if !mux.is_closed() => return Err(e),
            Err(e) => debug!("fallback channel died; reconnecting: {e:#}"),
        }
        let mux = self.ensure_mux().await?;
        mux.udp_associate().await
    }
}

fn build_client(
    skip_verify: bool,
    pin: Option<[u8; 32]>,
    resolver: Option<super::tls::HyperFixedResolver>,
) -> Result<HyperClient> {
    // Large/adaptive h2 flow-control windows: the spec default (64KB stream
    // window) collapses throughput on high-RTT links (~200KB/s @ 300ms).
    // The client-advertised window governs the download direction.
    // NOTE: hyper-util builder setters take &mut and return &mut, so the
    // chain must stay a single expression per branch.
    if !skip_verify && pin.is_none() && resolver.is_none() {
        let https = HttpsConnectorBuilder::new()
            .with_native_roots()?
            .https_or_http()
            .enable_http2()
            .build();
        return Ok(Client::builder(TokioExecutor::new())
            .http2_adaptive_window(true)
            .http2_initial_stream_window_size(8 * 1024 * 1024)
            .http2_initial_connection_window_size(24 * 1024 * 1024)
            .build(https));
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let tls_builder = rustls::ClientConfig::builder_with_provider(provider.clone());
    let tls_builder = if pin.is_some() {
        tls_builder
            .with_ech(rustls::client::EchMode::Grease(
                rustls::client::EchGreaseConfig::new(
                    &super::ech::HpkeX25519Sha256ChaCha20,
                    rustls::crypto::hpke::HpkePublicKey(vec![0u8; 32]),
                ),
            ))
            .map_err(|e| anyhow!("ech grease enable: {e}"))?
    } else {
        tls_builder
            .with_safe_default_protocol_versions()
            .map_err(|e| anyhow!("tls versions: {e}"))?
    };
    let mut tls = if pin.is_some() {
        tls_builder
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth()
    } else {
        let mut roots = rustls::RootCertStore::empty();
        if !skip_verify {
            for cert in rustls_native_certs::load_native_certs().certs {
                let _ = roots.add(cert);
            }
        }
        tls_builder
            .with_root_certificates(roots)
            .with_no_client_auth()
    };
    if let Some(fp) = pin {
        tls.dangerous()
            .set_certificate_verifier(Arc::new(super::tls::PinVerifier::new(fp, provider)));
    } else if skip_verify {
        tls.dangerous()
            .set_certificate_verifier(Arc::new(NoVerify { provider }));
    }
    // One connector type for both branches: the fixed resolver is a no-op
    // stand-in when masquerade is off (never consulted — GaiResolver would
    // be the natural choice, but mixing connector types would split the
    // Client generic).
    let mut http: HttpConnector<HyperFixedResolver> = match resolver {
        Some(r) => HttpConnector::new_with_resolver(r),
        None => HttpConnector::new_with_resolver(HyperFixedResolver::system_fallback()),
    };
    http.set_nodelay(true);
    let https = HttpsConnectorBuilder::new()
        .with_tls_config(tls)
        .https_or_http()
        .enable_http2()
        .build();
    Ok(Client::builder(TokioExecutor::new())
        .http2_adaptive_window(true)
        .http2_initial_stream_window_size(8 * 1024 * 1024)
        .http2_initial_connection_window_size(24 * 1024 * 1024)
        .build(https))
}

/// TLS config for the WebSocket transport. Deliberately **no ALPN**: the WS
/// handshake must ride HTTP/1.1 (an h2 connection cannot be upgraded).
/// `--pin` is accepted here for uniformity but the config layer rejects the
/// wss + masquerade combination; pinning alone (no `--sni`) is valid.
fn build_ws_tls(skip_verify: bool, pin: Option<[u8; 32]>) -> Result<rustls::ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| anyhow!("tls versions: {e}"))?;
    let mut roots = rustls::RootCertStore::empty();
    if !skip_verify && pin.is_none() {
        for cert in rustls_native_certs::load_native_certs().certs {
            let _ = roots.add(cert);
        }
    }
    let mut tls = builder.with_root_certificates(roots).with_no_client_auth();
    if let Some(fp) = pin {
        tls.dangerous()
            .set_certificate_verifier(Arc::new(super::tls::PinVerifier::new(fp, provider)));
    } else if skip_verify {
        tls.dangerous()
            .set_certificate_verifier(Arc::new(NoVerify { provider }));
    }
    Ok(tls)
}

/// Certificate verifier that accepts anything (development only).
#[derive(Debug)]
struct NoVerify {
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

// ---------------------------------------------------------------------------
// Body adapters
// ---------------------------------------------------------------------------

/// Streaming request body fed by the mux writer task.
struct RequestBody {
    rx: Option<mpsc::Receiver<Bytes>>,
    pending: VecDeque<Bytes>,
}

impl http_body::Body for RequestBody {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<HttpFrame<Self::Data>, Self::Error>>> {
        loop {
            if let Some(b) = self.pending.pop_front() {
                return std::task::Poll::Ready(Some(Ok(HttpFrame::data(b))));
            }
            match self.rx.as_mut() {
                None => return std::task::Poll::Ready(None),
                Some(rx) => match std::pin::Pin::new(rx).poll_recv(cx) {
                    std::task::Poll::Ready(Some(b)) => self.pending.push_back(b),
                    std::task::Poll::Ready(None) => {
                        self.rx = None;
                        return std::task::Poll::Ready(None);
                    }
                    std::task::Poll::Pending => return std::task::Poll::Pending,
                },
            }
        }
    }
}

/// AsyncRead adapter over a hyper response body.
pub struct BodyAsRead<B> {
    body: B,
    buf: bytes::BytesMut,
    done: bool,
}

impl<B> BodyAsRead<B> {
    pub fn new(body: B) -> Self {
        Self {
            body,
            buf: bytes::BytesMut::new(),
            done: false,
        }
    }
}

impl<B> AsyncRead for BodyAsRead<B>
where
    B: http_body::Body<Data = Bytes> + Unpin,
    B::Error: std::fmt::Display,
{
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        out: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        loop {
            if !this.buf.is_empty() {
                let n = this.buf.len().min(out.remaining());
                let b = this.buf.split_to(n);
                out.put_slice(&b);
                return std::task::Poll::Ready(Ok(()));
            }
            if this.done {
                return std::task::Poll::Ready(Ok(()));
            }
            match std::pin::Pin::new(&mut this.body).poll_frame(cx) {
                std::task::Poll::Pending => return std::task::Poll::Pending,
                std::task::Poll::Ready(Some(Ok(frame))) => {
                    if let Some(d) = frame.data_ref() {
                        if !d.is_empty() {
                            this.buf.extend_from_slice(d);
                        }
                    }
                }
                std::task::Poll::Ready(Some(Err(e))) => {
                    return std::task::Poll::Ready(Err(std::io::Error::other(e.to_string())))
                }
                std::task::Poll::Ready(None) => this.done = true,
            }
        }
    }
}
