//! WebTransport client: connection pool (1..8 conns), one authenticated
//! control stream per connection, one dedicated bidi stream per TCP session,
//! datagrams for UDP.

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use dashmap::DashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};
use wtransport::endpoint::endpoint_side::Client as WtClientSide;
use wtransport::endpoint::ConnectOptions;
use wtransport::{ClientConfig as WtClientConfig, Endpoint};

use crate::config::ClientConfig;
use crate::proto::addr::UdpAddr;
use crate::proto::crypto::{
    auth_mac, derive_session_key, make_bearer, AuthPayload, CounterGen, FrameCipher, ReplayWindow,
    SALT_LEN,
};
use crate::proto::frame::{
    encode_open, random_padding, FrameDecoder, FrameEncoder, FrameReader, FrameType, FrameWriter,
    FLAG_FIN, MAX_PLAINTEXT,
};
use crate::proto::mux::{
    next_rand_u32, BoxStream, OpenError, OutFrame, UdpPipe, HANDSHAKE_TIMEOUT, SESSION_BUF,
};

use super::outbound::{target_error, TargetError};

pub const MAX_PER_CONN: usize = 50;

pub(crate) struct PoolCfg {
    url: String,
    static_key: [u8; 32],
    uid: String,
    size: usize,
}

/// Build the WT pool from the client config. `--sni` masquerade rewires the
/// URL: the masquerade hostname replaces the URL host (driving TLS SNI and
/// the WebTransport `:authority`), while a fixed-address resolver points the
/// connection at the real server address taken from the original URL.
pub async fn new_pool(cfg: &ClientConfig, url: &str) -> Result<WtPool> {
    let (dial_url, resolver): (String, Option<super::tls::FixedResolver>) = match &cfg.sni {
        Some(sni) => {
            let (real_addr, _port) = url_host_and_port(url).await?;
            let mut u = url::Url::parse(url).map_err(|e| anyhow!("bad --server URL: {e}"))?;
            u.set_host(Some(sni))
                .map_err(|_| anyhow!("--sni '{sni}' cannot replace the URL host"))?;
            u.set_port(None).ok(); // keep default 443 semantics of the original
            (
                u.to_string(),
                Some(super::tls::FixedResolver::new(real_addr)),
            )
        }
        None => (url.to_string(), None),
    };
    // Build the endpoint from the (possibly masqueraded) URL; the resolver
    // must be attached at config time — wtransport's Endpoint exposes no
    // post-construction config mutation for clients.
    let mut wt_cfg = build_tls_config_inner(cfg.skip_verify, cfg.pin, cfg.recv_window, cfg.conns)?;
    if let Some(r) = resolver {
        wt_cfg.set_dns_resolver(r);
    }
    let endpoint = Endpoint::client(wt_cfg)?;

    let static_key = crate::proto::crypto::derive_static_key(&cfg.password, &cfg.uid);
    Ok(WtPool {
        cfg: Arc::new(PoolCfg {
            url: dial_url,
            static_key,
            uid: cfg.uid.clone(),
            size: cfg.conns,
        }),
        endpoint,
        conns: Mutex::new(Vec::new()),
    })
}

pub struct WtPool {
    cfg: Arc<PoolCfg>,
    pub(crate) endpoint: Endpoint<WtClientSide>,
    conns: Mutex<Vec<Arc<WtConn>>>,
}

pub struct WtConn {
    conn: wtransport::Connection,
    cipher: Arc<FrameCipher>,
    ctrl_tx: mpsc::Sender<OutFrame>,
    counters: CounterGen,
    dgram_enc: Arc<FrameEncoder>,
    next_sid: AtomicU32,
    sessions: AtomicUsize,
    alive: AtomicBool,
    /// Set when a Pong arrives in the current heartbeat window; reset by
    /// the ping task on each tick.
    pong_seen: AtomicBool,
    /// Consecutive heartbeat ticks without a Pong. Reaching
    /// PONG_MISS_LIMIT marks the link half-dead (TCP may still be up).
    missed_pings: AtomicUsize,
    udp: DashMap<u32, mpsc::Sender<(UdpAddr, Vec<u8>)>>,
    pending_udp: DashMap<u32, oneshot::Sender<Result<(), OpenError>>>,
    close: CancellationToken,
}

const PONG_MISS_LIMIT: usize = 2;

/// Base heartbeat period.
const HEARTBEAT_SECS: u64 = 30;

fn source_cid_len(_conns: usize) -> usize {
    // The pool may create a temporary extra connection when concurrent
    // callers race during startup or when a connection reaches its session
    // limit, even when the configured pool size is one.
    8
}

/// Next heartbeat period: 30s ± 20% (24s..36s), uniform. Public for tests.
fn heartbeat_interval() -> Duration {
    use rand::Rng;
    let band = (HEARTBEAT_SECS / 5) as i64; // 20% of base = 6s
    let jitter: i64 = rand::rngs::OsRng.gen_range(-band..=band);
    Duration::from_secs((HEARTBEAT_SECS as i64 + jitter) as u64)
}

impl WtPool {
    /// Background maintenance: drop dead conns, keep the pool warm, trim
    /// surplus idle conns.
    ///
    /// Refills use exponential backoff (10s → 20s → … → 5min) while the
    /// server is unreachable, resetting as soon as a dial succeeds. This is
    /// both more polite and less fingerprintable than a fixed 10s retry.
    pub fn spawn_maintenance(self: &Arc<Self>) {
        const BASE_BACKOFF: Duration = Duration::from_secs(10);
        const MAX_BACKOFF: Duration = Duration::from_secs(300);

        let this = self.clone();
        tokio::spawn(async move {
            let mut iv = tokio::time::interval(BASE_BACKOFF);
            let mut backoff = BASE_BACKOFF;
            let mut next_attempt = Instant::now();
            loop {
                iv.tick().await;
                let alive_now = {
                    let mut g = this.conns.lock().await;
                    g.retain(|c| c.alive.load(Ordering::Relaxed));
                    // bound growth: on-demand dials may push the pool past
                    // its target size; retire live conns with no sessions
                    while g.len() > this.cfg.size {
                        let Some(idx) = g
                            .iter()
                            .position(|c| c.sessions.load(Ordering::Relaxed) == 0)
                        else {
                            break;
                        };
                        let victim = g.remove(idx);
                        victim.alive.store(false, Ordering::Relaxed);
                        victim.close.cancel();
                    }
                    g.len()
                };
                let need = this.cfg.size.saturating_sub(alive_now);
                if need == 0 {
                    // Pool healthy again: reset the backoff.
                    backoff = BASE_BACKOFF;
                    next_attempt = Instant::now();
                    continue;
                }
                if Instant::now() < next_attempt {
                    continue; // still cooling down after failed dials
                }
                // Dial sequentially so success/failure is observed here and
                // the backoff reflects reality (spawned dials cannot report).
                let mut any_ok = false;
                for _ in 0..need {
                    match WtConn::connect(&this.cfg, &this.endpoint).await {
                        Ok(c) => {
                            this.conns.lock().await.push(c);
                            any_ok = true;
                        }
                        Err(e) => debug!("pool maintenance connect failed: {e:#}"),
                    }
                }
                if any_ok {
                    backoff = BASE_BACKOFF;
                    next_attempt = Instant::now();
                } else {
                    backoff = (backoff * 2).min(MAX_BACKOFF);
                    next_attempt = Instant::now() + backoff;
                    debug!("pool maintenance backing off for {backoff:?}");
                }
            }
        });
    }

    async fn acquire(&self) -> Result<Arc<WtConn>> {
        {
            let g = self.conns.lock().await;
            if let Some(c) = g
                .iter()
                .filter(|c| {
                    c.alive.load(Ordering::Relaxed)
                        && c.sessions.load(Ordering::Relaxed) < MAX_PER_CONN
                })
                .min_by_key(|c| c.sessions.load(Ordering::Relaxed))
                .cloned()
            {
                return Ok(c);
            }
        }
        // also reached when every pooled conn is full: dial a fresh one
        let c = WtConn::connect(&self.cfg, &self.endpoint).await?;
        {
            let mut g = self.conns.lock().await;
            g.retain(|x| x.alive.load(Ordering::Relaxed));
            g.push(c.clone());
        }
        Ok(c)
    }

    pub async fn open_tcp(&self, host: &str, port: u16) -> Result<BoxStream> {
        let c = self.acquire().await?;
        match c.open_tcp(host, port).await {
            Ok(s) => Ok(s),
            Err(e) => {
                // Per-target refusals leave the connection healthy — only
                // transport-level failures mark it dead (killing a conn also
                // drops every session multiplexed on it).
                if target_error(&e).is_none() {
                    c.alive.store(false, Ordering::Relaxed);
                    c.close.cancel();
                }
                Err(e)
            }
        }
    }

    pub async fn udp_associate(&self) -> Result<UdpPipe> {
        let c = self.acquire().await?;
        match c.udp_associate().await {
            Ok(p) => Ok(p),
            Err(e) => {
                if target_error(&e).is_none() {
                    c.alive.store(false, Ordering::Relaxed);
                    c.close.cancel();
                }
                Err(e)
            }
        }
    }
}

/// Build the WebTransport client TLS config with an optional `--pin`
/// fingerprint: when set, the pinned-certificate verifier replaces CA
/// validation entirely (the server's identity is exactly that certificate —
/// required for `--sni` masquerade, where the cert cannot match the
/// masqueraded name).
fn build_tls_config_inner(
    skip_verify: bool,
    pin: Option<[u8; 32]>,
    recv_window: u32,
    conns: usize,
) -> Result<WtClientConfig> {
    use wtransport::tls::client::NoServerVerification;

    // Custom TLS + transport: mirrors wtransport's stock builder (native
    // roots / no-verification) but built by hand so GREASE ECH can be
    // inserted at the builder stage (rustls 0.23 has no post-hoc config
    // rewrite; `with_ech` must be called before root stores are attached).
    let mut root_store = rustls::RootCertStore::empty();
    if !skip_verify && pin.is_none() {
        for cert in rustls_native_certs::load_native_certs().certs {
            let _ = root_store.add(cert);
        }
    }

    // GREASE ECH: offer a dummy encrypted_client_hello extension exactly like
    // Chrome does for servers without published ECH configs. Anti-
    // ossification (middleboxes must tolerate the extension) + one more
    // ClientHello field aligned with the browser. Zero-interaction by
    // design: a server that ignores ECH simply proceeds with the outer SNI.
    let grease = rustls::client::EchGreaseConfig::new(
        &super::ech::HpkeX25519Sha256ChaCha20,
        rustls::crypto::hpke::HpkePublicKey(rand_bytes_32()),
    );

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_ech(rustls::client::EchMode::Grease(grease))
        .map_err(|e| anyhow!("ech grease enable: {e}"))?
        .with_root_certificates(root_store)
        .with_no_client_auth();
    if let Some(fp) = pin {
        tls.dangerous()
            .set_certificate_verifier(Arc::new(super::tls::PinVerifier::new(fp, provider)));
    } else if skip_verify {
        tls.dangerous()
            .set_certificate_verifier(Arc::new(NoServerVerification::new()));
    }
    tls.alpn_protocols = [wtransport::tls::WEBTRANSPORT_ALPN.to_vec()].to_vec();

    // Browser fingerprint alignment (borrowed from hysteria's Chrome parrot
    // idea, implemented with the knobs wtransport actually exposes):
    // * 8-byte source CID — required because the pool can temporarily create
    //   multiple connections even when its configured size is one;
    // * 8-byte initial destination CID — Chrome uses 8; quinn defaults to
    //   MAX_CID_SIZE (20), which makes the very first datagram stand out.
    // Both are public configuration on the built config (feature "quinn"),
    // no forking required.
    let mut config = WtClientConfig::builder()
        .with_bind_default()
        .with_custom_tls_and_transport(tls, crate::quic_tune::tuned(recv_window))
        .keep_alive_interval(Some(Duration::from_secs(15)))
        .build();
    // A zero-length source CID cannot distinguish multiple connections sharing
    // one endpoint. Use a normal CID for every pooled connection so response
    // packets cannot be dispatched to the wrong connection.
    let source_cid_size = source_cid_len(conns);
    config.quic_endpoint_config_mut().cid_generator(move || {
        Box::new(quinn_proto::RandomConnectionIdGenerator::new(
            source_cid_size,
        ))
    });
    config
        .quic_config_mut()
        .initial_dst_cid_provider(Arc::new(|| {
            use quinn_proto::ConnectionIdGenerator as _;
            quinn_proto::RandomConnectionIdGenerator::new(8).generate_cid()
        }));

    Ok(config)
}

/// Random 32 bytes for the GREASE ECH placeholder public key.
fn rand_bytes_32() -> Vec<u8> {
    use rand::RngCore;
    let mut k = vec![0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut k);
    k
}

impl WtConn {
    pub(crate) async fn connect(
        cfg: &PoolCfg,
        endpoint: &Endpoint<WtClientSide>,
    ) -> Result<Arc<WtConn>> {
        // Fresh bearer per connection: the token embeds a timestamp checked
        // with a +/-60s window on the server, so reusing one minted at pool
        // creation would get later connections rejected.
        let bearer = make_bearer(&cfg.static_key, &cfg.uid);
        let opts = ConnectOptions::builder(&cfg.url)
            .add_header("Authorization", format!("Bearer {bearer}"))
            .build();
        // QUIC handshake must be bounded like every other step: on a UDP
        // path that blackholes packets, an unbounded await would hang the
        // pool maintenance task (slow-CI guard).
        let conn = timeout(HANDSHAKE_TIMEOUT, endpoint.connect(opts))
            .await
            .map_err(|_| anyhow!("wt connect timeout"))?
            .context("wt connect failed")?;

        // ---- control stream + AUTH handshake ----
        let opening = conn.open_bi().await?;
        let (send, recv) = timeout(HANDSHAKE_TIMEOUT, opening)
            .await
            .map_err(|_| anyhow!("control stream open timeout"))??;

        let mut salt = [0u8; SALT_LEN];
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut salt);
        let mut nonce = [0u8; SALT_LEN];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let ts = crate::proto::crypto::now_unix();
        let mac = auth_mac(&cfg.static_key, &cfg.uid, ts, &nonce);
        let auth = AuthPayload {
            proto_version: crate::proto::frame::PROTO_VERSION,
            salt,
            ts,
            nonce,
            uid: cfg.uid.clone(),
            mac,
        };
        let session_key = derive_session_key(&cfg.static_key, &salt);
        let cipher = Arc::new(FrameCipher::new(&session_key));

        let counters = CounterGen::stream();
        let static_cipher = Arc::new(FrameCipher::new(&cfg.static_key));
        let mut writer = FrameWriter::new(send, static_cipher, counters.clone());
        // Handshake payload + random tail: the AUTH ciphertext length stops
        // being a fixed protocol signature (server decodes by field prefix).
        let mut auth_payload = auth.encode();
        auth_payload.extend_from_slice(&random_padding());
        writer
            .write(FrameType::Auth, 0, 0, &auth_payload)
            .await
            .context("send auth")?;
        writer.set_cipher(cipher.clone());

        let mut reader = FrameReader::new(recv, Some(cipher.clone()), None);
        let reply = timeout(HANDSHAKE_TIMEOUT, reader.read())
            .await
            .map_err(|_| anyhow!("auth reply timeout"))??;
        match reply {
            Some(f) if f.ftype == FrameType::AuthOk => {}
            _ => return Err(anyhow!("server rejected authentication")),
        }
        debug!("wt conn authenticated uid={}", cfg.uid);

        let (ctrl_tx, ctrl_rx) = mpsc::channel::<OutFrame>(128);
        let dgram_counters = CounterGen::datagram();
        let dgram_enc = Arc::new(FrameEncoder::new(cipher.clone(), dgram_counters.clone()));

        let this = Arc::new(WtConn {
            conn: conn.clone(),
            cipher: cipher.clone(),
            ctrl_tx: ctrl_tx.clone(),
            counters,
            dgram_enc,
            next_sid: AtomicU32::new(next_rand_u32()),
            sessions: AtomicUsize::new(0),
            alive: AtomicBool::new(true),
            pong_seen: AtomicBool::new(false),
            missed_pings: AtomicUsize::new(0),
            udp: DashMap::new(),
            pending_udp: DashMap::new(),
            close: CancellationToken::new(),
        });

        // ---- control stream writer ----
        tokio::spawn(async move {
            let mut ctrl_rx = ctrl_rx;
            while let Some(f) = ctrl_rx.recv().await {
                if writer
                    .write(f.ftype, f.flags, f.sid, &f.payload)
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });

        // ---- control stream reader (UDP fallback frames + PONG) ----
        {
            let this2 = this.clone();
            tokio::spawn(async move {
                while let Ok(Some(f)) = reader.read().await {
                    this2.dispatch(f).await;
                }
                this2.expire("control stream closed").await;
            });
        }

        // ---- datagram receive loop ----
        {
            let this2 = this.clone();
            let cipher2 = cipher.clone();
            tokio::spawn(async move {
                let mut dec = FrameDecoder::new(Some(cipher2), Some(ReplayWindow::new()));
                while let Ok(d) = this2.conn.receive_datagram().await {
                    dec.feed(&d);
                    loop {
                        match dec.next_frame() {
                            Ok(Some(f)) => this2.dispatch(f).await,
                            Ok(None) => break,
                            // A corrupt datagram must not desync the decoder
                            // for the rest of the connection: drop the
                            // buffered bytes (the replay window is kept).
                            Err(e) => {
                                debug!("wt datagram: bad frame: {e}");
                                dec.clear();
                                break;
                            }
                        }
                    }
                }
                this2.expire("datagram channel closed").await;
            });
        }

        // ---- death watcher + heartbeat (Ping/Pong keepalive) ----
        {
            let this2 = this.clone();
            tokio::spawn(async move {
                tokio::select! {
                    e = this2.conn.closed() => {
                        let reason = format!("quic closed: {e:?}");
                        this2.expire(&reason).await;
                    }
                    _ = this2.close.cancelled() => {
                        // Background tasks hold their own Connection clones;
                        // an explicit close is required for the QUIC
                        // connection (and those tasks) to actually end.
                        this2.conn.close(wtransport::VarInt::from_u32(0), b"pool retired");
                        this2.expire("connection retired").await;
                    }
                }
                this2.close.cancel();
            });
            let this3 = this.clone();
            tokio::spawn(async move {
                // Fixed-interval heartbeats are a textbook beaconing signal
                // (a passive observer can pick the connection out of a CDN's
                // traffic by the 30s periodicity alone). Jitter each period
                // by ±20% so the cadence carries no exploitable signature.
                // The jitter must stay well inside the Pong-judge budget:
                // PONG_MISS_LIMIT=2 with a 36s worst case still gives the
                // link ~72s before being declared half-dead.
                let mut iv = tokio::time::interval(heartbeat_interval());
                iv.tick().await; // skip immediate tick
                loop {
                    tokio::select! {
                        _ = iv.tick() => {}
                        _ = this3.close.cancelled() => break,
                    }
                    // Pong liveness judge: each tick marks whether the last
                    // heartbeat got a reply. PONG_MISS_LIMIT consecutive
                    // misses (default 2) mean the link is half-dead — the
                    // TCP session layer may still look fine while the QUIC
                    // path is unreachable. Retire the conn so the pool
                    // redials instead of stalling in request timeouts.
                    if this3.pong_seen.swap(false, Ordering::Relaxed) {
                        this3.missed_pings.store(0, Ordering::Relaxed);
                    } else {
                        let missed = this3.missed_pings.fetch_add(1, Ordering::Relaxed) + 1;
                        if missed >= PONG_MISS_LIMIT {
                            this3
                                .expire(&format!(
                                    "pong timeout: {missed} consecutive pings unanswered"
                                ))
                                .await;
                            break;
                        }
                    }
                    if this3
                        .ctrl_tx
                        .send(OutFrame::new(FrameType::Ping, 0, 0, Vec::new()))
                        .await
                        .is_err()
                    {
                        break;
                    }
                    // Re-arm the next period with fresh jitter.
                    iv = tokio::time::interval(heartbeat_interval());
                    iv.tick().await; // consume the immediate first tick
                }
            });
        }

        info!("wt connection established -> {}", cfg.url);
        Ok(this)
    }

    /// Route inbound control/datagram frames.
    async fn dispatch(&self, f: crate::proto::frame::Frame) {
        match f.ftype {
            FrameType::UdpData => {
                let mut r = crate::proto::addr::Reader::new(&f.payload);
                if let Ok(src) = UdpAddr::decode(&mut r) {
                    let data = r.rest().to_vec();
                    if let Some(tx) = self.udp.get(&f.sid).map(|t| t.clone()) {
                        let _ = tx.send((src, data)).await;
                    }
                }
            }
            FrameType::UdpOk => {
                if let Some((_, tx)) = self.pending_udp.remove(&f.sid) {
                    let _ = tx.send(Ok(()));
                }
            }
            FrameType::OpenErr | FrameType::Error => {
                if let Some((_, tx)) = self.pending_udp.remove(&f.sid) {
                    let _ = tx.send(Err(OpenError::from_code(
                        f.payload.first().copied().unwrap_or(0),
                    )));
                }
            }
            FrameType::Pong => {
                self.pong_seen.store(true, Ordering::Relaxed);
            }
            _ => {}
        }
    }

    /// Mark the connection dead, log the death reason once, and wake the
    /// death watcher (the pool maintenance loop redials from here).
    async fn expire(self: &Arc<Self>, reason: &str) {
        if self.alive.swap(false, Ordering::Relaxed) {
            warn!(
                "wt connection dead: {reason}{}",
                crate::quic_tune::gap_hint(reason)
            );
        }
        // Fail fast: drop pending UDP associate waiters and UDP routes so
        // callers error out immediately instead of waiting out the
        // HANDSHAKE_TIMEOUT on a dead connection.
        self.pending_udp.clear();
        self.udp.clear();
        self.close.cancel();
    }

    pub async fn open_tcp(self: &Arc<Self>, host: &str, port: u16) -> Result<BoxStream> {
        if !self.alive.load(Ordering::Relaxed) {
            anyhow::bail!("connection closed");
        }
        if self.sessions.fetch_add(1, Ordering::Relaxed) >= MAX_PER_CONN {
            self.sessions.fetch_sub(1, Ordering::Relaxed);
            // healthy conn at capacity: a target-side style refusal (do not
            // kill the conn, let the caller retry elsewhere)
            return Err(anyhow::Error::new(TargetError(OpenError::Limit)));
        }
        match self.do_open_tcp(host, port).await {
            Ok(s) => Ok(s),
            Err(e) => {
                self.sessions.fetch_sub(1, Ordering::Relaxed);
                Err(e)
            }
        }
    }

    async fn do_open_tcp(self: &Arc<Self>, host: &str, port: u16) -> Result<BoxStream> {
        let sid = self.alloc_sid();
        let opening = timeout(HANDSHAKE_TIMEOUT, self.conn.open_bi())
            .await
            .map_err(|_| anyhow!("open_bi timeout"))??;
        let (send, recv) = timeout(HANDSHAKE_TIMEOUT, opening)
            .await
            .map_err(|_| anyhow!("stream open timeout"))??;

        let mut writer = FrameWriter::new(send, self.cipher.clone(), self.counters.clone());
        let mut reader = FrameReader::new(recv, Some(self.cipher.clone()), None);

        // Open payload + random tail (server decodes by field prefix).
        let mut open_payload = encode_open(host, port);
        open_payload.extend_from_slice(&random_padding());
        writer.write(FrameType::Open, 0, sid, &open_payload).await?;
        let reply = timeout(HANDSHAKE_TIMEOUT, reader.read())
            .await
            .map_err(|_| anyhow!("open reply timeout"))??;
        match reply {
            Some(f) if f.sid == sid && f.ftype == FrameType::OpenOk => {}
            Some(f) if f.ftype == FrameType::OpenErr => {
                let code = OpenError::from_code(f.payload.first().copied().unwrap_or(0));
                return Err(anyhow::Error::new(TargetError(code)));
            }
            _ => return Err(anyhow!("unexpected open reply")),
        }

        let (a, b) = tokio::io::duplex(SESSION_BUF);
        let (mut rb, mut wb) = tokio::io::split(b);

        // user -> frames (owns writer)
        {
            tokio::spawn(async move {
                let mut chunk = vec![0u8; MAX_PLAINTEXT];
                loop {
                    match rb.read(&mut chunk).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if writer
                                .write(FrameType::Data, 0, sid, &chunk[..n])
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                    }
                }
                let _ = writer.write(FrameType::Close, FLAG_FIN, sid, &[]).await;
                let _ = writer.shutdown().await;
            });
        }

        // frames -> user (owns reader; owns the session counter decrement)
        {
            let this2 = self.clone();
            tokio::spawn(async move {
                while let Ok(Some(f)) = reader.read().await {
                    match f.ftype {
                        FrameType::Data => {
                            if wb.write_all(&f.payload).await.is_err() {
                                break;
                            }
                            if f.flags & FLAG_FIN != 0 {
                                break;
                            }
                        }
                        FrameType::Close => break,
                        _ => {}
                    }
                }
                let _ = wb.shutdown().await;
                this2.sessions.fetch_sub(1, Ordering::Relaxed);
            });
        }

        Ok(Box::new(a))
    }

    pub async fn udp_associate(self: &Arc<Self>) -> Result<UdpPipe> {
        if !self.alive.load(Ordering::Relaxed) {
            anyhow::bail!("connection closed");
        }
        let sid = self.alloc_sid();
        let (os, orx) = oneshot::channel();
        self.pending_udp.insert(sid, os);
        if self
            .ctrl_tx
            .send(OutFrame::new(FrameType::UdpAssociate, 0, sid, Vec::new()))
            .await
            .is_err()
        {
            self.pending_udp.remove(&sid);
            anyhow::bail!("control channel closed");
        }
        let reply = match timeout(HANDSHAKE_TIMEOUT, orx).await {
            Ok(Ok(r)) => r,
            _ => {
                self.pending_udp.remove(&sid);
                anyhow::bail!("udp_associate timeout");
            }
        };
        reply.map_err(|e| anyhow::Error::new(TargetError(e)))?;

        let (out_tx, mut out_rx) = mpsc::channel::<(UdpAddr, Vec<u8>)>(256);
        let (in_tx, in_rx) = mpsc::channel::<(UdpAddr, Vec<u8>)>(256);
        self.udp.insert(sid, in_tx);

        {
            let conn = self.conn.clone();
            let enc = self.dgram_enc.clone();
            let ctrl = self.ctrl_tx.clone();
            // Shared Arc<WtConn>: `self.udp.clone()` would deep-copy the
            // DashMap and remove from the copy instead of the live route.
            let this = self.clone();
            tokio::spawn(async move {
                while let Some((dst, data)) = out_rx.recv().await {
                    let mut payload = Vec::with_capacity(24 + data.len());
                    dst.encode(&mut payload);
                    payload.extend_from_slice(&data);
                    // datagram first, frame fallback when it does not fit
                    let wire = match enc.encode(FrameType::UdpData, 0, sid, &payload) {
                        Ok(w) => w,
                        Err(_) => break,
                    };
                    let max = conn.max_datagram_size().unwrap_or(0);
                    if wire.len() <= max && conn.send_datagram(wire).is_ok() {
                        continue;
                    }
                    if ctrl
                        .send(OutFrame::new(FrameType::UdpData, 0, sid, payload))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                this.udp.remove(&sid);
            });
        }

        Ok(UdpPipe {
            outbound: out_tx,
            inbound: in_rx,
        })
    }

    fn alloc_sid(&self) -> u32 {
        loop {
            let v = self.next_sid.fetch_add(1, Ordering::Relaxed);
            if v != 0 && !self.udp.contains_key(&v) {
                return v;
            }
        }
    }
}

/// Extract the host and port from a `https://host[:port][/path]` URL.
/// Used by the `--sni` masquerade to recover the real server address before
/// the URL host is replaced with the masquerade name.
///
/// Resolution is async (`tokio::net::lookup_host`) and bounded, so a slow or
/// blocked resolver at startup cannot stall the runtime thread.
pub(crate) async fn url_host_and_port(url: &str) -> Result<(std::net::SocketAddr, u16)> {
    let u = url::Url::parse(url).map_err(|e| anyhow!("bad URL '{url}': {e}"))?;
    let host = u
        .host_str()
        .ok_or_else(|| anyhow!("URL '{url}' has no host"))?;
    let port = u.port().unwrap_or(443);
    let mut addrs = timeout(HANDSHAKE_TIMEOUT, tokio::net::lookup_host((host, port)))
        .await
        .map_err(|_| anyhow!("resolve '{host}': timeout"))?
        .map_err(|e| anyhow!("resolve '{host}': {e}"))?;
    let addr = addrs
        .next()
        .ok_or_else(|| anyhow!("no address for '{host}'"))?;
    Ok((addr, port))
}

#[cfg(test)]
mod heartbeat_tests {
    use super::*;

    #[test]
    fn pooled_connections_use_distinguishable_source_cids() {
        assert_eq!(source_cid_len(1), 8);
        assert_eq!(source_cid_len(2), 8);
        assert_eq!(source_cid_len(8), 8);
    }

    #[test]
    fn heartbeat_jitter_stays_in_band() {
        for _ in 0..1000 {
            let d = heartbeat_interval();
            let s = d.as_secs();
            assert!((24..=36).contains(&s), "jitter out of band: {s}s");
        }
    }

    /// The band must keep the Pong-judge budget healthy: 2 missed periods at
    /// the worst-case interval still leaves ~72s before declaring the link
    /// half-dead (well above any plausible one-off network stall).
    #[test]
    fn heartbeat_budget_covers_pong_miss_limit() {
        let worst = heartbeat_interval();
        let budget = worst * (PONG_MISS_LIMIT as u32 + 1);
        assert!(budget >= Duration::from_secs(60), "budget {budget:?}");
    }
}
