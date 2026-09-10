//! WebTransport client: connection pool (1..8 conns), one authenticated
//! control stream per connection, one dedicated bidi stream per TCP session,
//! datagrams for UDP.

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use dashmap::DashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};
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
    encode_open, FrameDecoder, FrameEncoder, FrameReader, FrameType, FrameWriter, FLAG_FIN,
    MAX_PLAINTEXT,
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

pub struct WtPool {
    cfg: Arc<PoolCfg>,
    endpoint: Endpoint<WtClientSide>,
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
    udp: DashMap<u32, mpsc::Sender<(UdpAddr, Vec<u8>)>>,
    pending_udp: DashMap<u32, oneshot::Sender<Result<(), OpenError>>>,
    close: CancellationToken,
}

impl WtPool {
    pub fn new(cfg: &ClientConfig, url: &str) -> Result<WtPool> {
        let static_key = crate::proto::crypto::derive_static_key(&cfg.password, &cfg.uid);
        let endpoint = Endpoint::client(build_tls_config(cfg.skip_verify, cfg.recv_window)?)?;
        Ok(WtPool {
            cfg: Arc::new(PoolCfg {
                url: url.to_string(),
                static_key,
                uid: cfg.uid.clone(),
                size: cfg.conns,
            }),
            endpoint,
            conns: Mutex::new(Vec::new()),
        })
    }

    /// Background maintenance: drop dead conns, keep the pool warm, trim
    /// surplus idle conns.
    pub fn spawn_maintenance(self: &Arc<Self>) {
        let this = self.clone();
        tokio::spawn(async move {
            let mut iv = tokio::time::interval(Duration::from_secs(10));
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
                for _ in 0..need {
                    let this2 = this.clone();
                    tokio::spawn(async move {
                        match WtConn::connect(&this2.cfg, &this2.endpoint).await {
                            Ok(c) => {
                                this2.conns.lock().await.push(c);
                            }
                            Err(e) => debug!("pool maintenance connect failed: {e:#}"),
                        }
                    });
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

fn build_tls_config(skip_verify: bool, recv_window: u32) -> Result<WtClientConfig> {
    use wtransport::tls::client::build_default_tls_config;
    use wtransport::tls::client::NoServerVerification;

    // Custom transport requires building the TLS layer ourselves; this
    // mirrors what the stock builder does (native roots / no-verification).
    let mut root_store = rustls::RootCertStore::empty();
    if !skip_verify {
        for cert in rustls_native_certs::load_native_certs().certs {
            let _ = root_store.add(cert);
        }
    }
    let verifier: Option<Arc<dyn rustls::client::danger::ServerCertVerifier>> = if skip_verify {
        Some(Arc::new(NoServerVerification::new()))
    } else {
        None
    };
    let tls = build_default_tls_config(Arc::new(root_store), verifier);

    Ok(WtClientConfig::builder()
        .with_bind_default()
        .with_custom_tls_and_transport(tls, crate::quic_tune::tuned(recv_window))
        .keep_alive_interval(Some(Duration::from_secs(15)))
        .build())
}

impl WtConn {
    pub async fn connect(cfg: &PoolCfg, endpoint: &Endpoint<WtClientSide>) -> Result<Arc<WtConn>> {
        // Fresh bearer per connection: the token embeds a timestamp checked
        // with a +/-60s window on the server, so reusing one minted at pool
        // creation would get later connections rejected.
        let bearer = make_bearer(&cfg.static_key, &cfg.uid);
        let opts = ConnectOptions::builder(&cfg.url)
            .add_header("Authorization", format!("Bearer {bearer}"))
            .build();
        let conn = endpoint.connect(opts).await.context("wt connect failed")?;

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
        writer
            .write(FrameType::Auth, 0, 0, &auth.encode())
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
                this2.alive.store(false, Ordering::Relaxed);
                this2.close.cancel();
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
                this2.alive.store(false, Ordering::Relaxed);
                this2.close.cancel();
            });
        }

        // ---- death watcher + keepalive ----
        {
            let this2 = this.clone();
            tokio::spawn(async move {
                tokio::select! {
                    _ = this2.conn.closed() => {}
                    _ = this2.close.cancelled() => {
                        // Background tasks hold their own Connection clones;
                        // an explicit close is required for the QUIC
                        // connection (and those tasks) to actually end.
                        this2.conn.close(wtransport::VarInt::from_u32(0), b"pool retired");
                    }
                }
                this2.alive.store(false, Ordering::Relaxed);
                this2.close.cancel();
            });
            let this3 = this.clone();
            tokio::spawn(async move {
                let mut iv = tokio::time::interval(Duration::from_secs(30));
                iv.tick().await; // skip immediate tick
                loop {
                    tokio::select! {
                        _ = iv.tick() => {}
                        _ = this3.close.cancelled() => break,
                    }
                    if this3
                        .ctrl_tx
                        .send(OutFrame::new(FrameType::Ping, 0, 0, Vec::new()))
                        .await
                        .is_err()
                    {
                        break;
                    }
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
            FrameType::Pong => {}
            _ => {}
        }
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

        writer
            .write(FrameType::Open, 0, sid, &encode_open(host, port))
            .await?;
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
            let udp = self.udp.clone();
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
                udp.remove(&sid);
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
