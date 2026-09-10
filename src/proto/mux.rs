//! Mode-A multiplexer: many logical sessions over one duplex frame channel
//! (used by the HTTPS POST fallback, both roles) plus the shared `FrameSink`
//! the server uses to emit frames.

use std::future::Future;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{ensure, Result};
use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use super::addr::UdpAddr;
use super::frame::{
    decode_open, encode_open, FrameCipher, FrameDecoder, FrameEncoder, FrameReader, FrameType,
    MAX_PLAINTEXT, OPEN_ERR_BAD_TARGET, OPEN_ERR_DENIED, OPEN_ERR_DIAL, OPEN_ERR_LIMIT,
};
use super::frame::{FLAG_FIN, FLAG_RST};

pub const SESSION_BUF: usize = 64 * 1024;
pub const ROUTE_CHAN: usize = 256;
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Bounded outbound frame queue entry.
#[derive(Debug)]
pub struct OutFrame {
    pub ftype: FrameType,
    pub flags: u16,
    pub sid: u32,
    pub payload: Vec<u8>,
}

impl OutFrame {
    pub fn new(ftype: FrameType, flags: u16, sid: u32, payload: Vec<u8>) -> Self {
        Self {
            ftype,
            flags,
            sid,
            payload,
        }
    }
}

/// Server-side frame emission endpoint.
///
/// * `Chan` – frames go through a bounded queue into a writer task
///   (HTTP fallback response body, or a dedicated WT stream).
/// * `Datagram` – QUIC datagrams when they fit, otherwise the fallback chan.
#[derive(Clone)]
pub enum FrameSink {
    Chan(mpsc::Sender<OutFrame>),
    Datagram {
        conn: wtransport::Connection,
        enc: Arc<FrameEncoder>,
        fallback: mpsc::Sender<OutFrame>,
    },
}

impl FrameSink {
    pub async fn send(&self, ftype: FrameType, flags: u16, sid: u32, payload: &[u8]) -> Result<()> {
        match self {
            FrameSink::Chan(tx) => {
                tx.send(OutFrame::new(ftype, flags, sid, payload.to_vec()))
                    .await
                    .map_err(|_| anyhow::anyhow!("sink closed"))?;
                Ok(())
            }
            FrameSink::Datagram {
                conn,
                enc,
                fallback,
            } => {
                let wire = enc.encode(ftype, flags, sid, payload)?;
                let max = conn.max_datagram_size().unwrap_or(0);
                if wire.len() <= max && conn.send_datagram(wire).is_ok() {
                    return Ok(());
                }
                fallback
                    .send(OutFrame::new(ftype, flags, sid, payload.to_vec()))
                    .await
                    .map_err(|_| anyhow::anyhow!("sink closed"))?;
                Ok(())
            }
        }
    }

    /// Fire-and-forget send for lossy UDP replies (drops when the queue is
    /// full instead of applying backpressure).
    pub fn try_send_lossy(&self, ftype: FrameType, flags: u16, sid: u32, payload: &[u8]) -> bool {
        let out = OutFrame::new(ftype, flags, sid, payload.to_vec());
        match self {
            FrameSink::Chan(tx) => matches!(tx.try_send(out), Ok(())),
            FrameSink::Datagram {
                conn,
                enc,
                fallback,
            } => {
                if let Ok(wire) = enc.encode(ftype, flags, sid, payload) {
                    let max = conn.max_datagram_size().unwrap_or(0);
                    if wire.len() <= max && conn.send_datagram(wire).is_ok() {
                        return true;
                    }
                }
                matches!(fallback.try_send(out), Ok(()))
            }
        }
    }
}

/// Errors surfaced to clients when opening sessions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenError {
    DialFailed,
    Limit,
    BadTarget,
    Denied,
}

impl std::fmt::Display for OpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            OpenError::DialFailed => "dial failed",
            OpenError::Limit => "session limit reached",
            OpenError::BadTarget => "invalid target",
            OpenError::Denied => "denied",
        };
        f.write_str(s)
    }
}

impl std::error::Error for OpenError {}

impl OpenError {
    pub fn to_code(self) -> u8 {
        match self {
            OpenError::DialFailed => OPEN_ERR_DIAL,
            OpenError::Limit => OPEN_ERR_LIMIT,
            OpenError::BadTarget => OPEN_ERR_BAD_TARGET,
            OpenError::Denied => OPEN_ERR_DENIED,
        }
    }

    pub fn from_code(c: u8) -> Self {
        match c {
            OPEN_ERR_DIAL => OpenError::DialFailed,
            OPEN_ERR_LIMIT => OpenError::Limit,
            OPEN_ERR_BAD_TARGET => OpenError::BadTarget,
            _ => OpenError::Denied,
        }
    }
}

fn code_to_open_error(payload: &[u8]) -> OpenError {
    OpenError::from_code(payload.first().copied().unwrap_or(0))
}

/// Object-safe stream returned by `open_tcp`.
pub trait AsyncReadWrite: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> AsyncReadWrite for T {}
pub type BoxStream = Box<dyn AsyncReadWrite>;

/// A bidirectional UDP pipe (client side view).
pub struct UdpPipe {
    /// (dst, payload) toward the remote network.
    pub outbound: mpsc::Sender<(UdpAddr, Vec<u8>)>,
    /// (src, payload) from the remote network.
    pub inbound: mpsc::Receiver<(UdpAddr, Vec<u8>)>,
}

// ---------------------------------------------------------------------------
// Client role
// ---------------------------------------------------------------------------

struct MuxInner {
    cmd_tx: mpsc::Sender<OutFrame>,
    sessions: dashmap::DashMap<u32, mpsc::Sender<Vec<u8>>>,
    udp: dashmap::DashMap<u32, mpsc::Sender<(UdpAddr, Vec<u8>)>>,
    pending_open: dashmap::DashMap<u32, oneshot::Sender<Result<(), OpenError>>>,
    pending_udp: dashmap::DashMap<u32, oneshot::Sender<Result<(), OpenError>>>,
    next_sid: AtomicU32,
    closed: CancellationToken,
}

impl MuxInner {
    fn alloc_sid(&self) -> u32 {
        loop {
            let v = self.next_sid.fetch_add(1, Ordering::Relaxed);
            if v != 0 && !self.sessions.contains_key(&v) && !self.udp.contains_key(&v) {
                return v;
            }
        }
    }

    fn teardown_all(&self) {
        self.closed.cancel();
        self.sessions.clear();
        self.udp.clear();
    }
}

/// Client-side multiplexer over one duplex frame channel.
#[derive(Clone)]
pub struct MuxClient {
    inner: Arc<MuxInner>,
}

impl MuxClient {
    pub fn is_closed(&self) -> bool {
        self.inner.closed.is_cancelled()
    }

    /// Start the mux with an existing body channel: `body_tx` is given to the
    /// internal writer task (the caller already put any prelude bytes into
    /// the channel, e.g. the in-band AUTH frame).
    pub fn start_with_tx<R>(
        reader: R,
        enc: FrameEncoder,
        cipher: Arc<FrameCipher>,
        body_tx: mpsc::Sender<Bytes>,
    ) -> MuxClient
    where
        R: AsyncRead + Unpin + Send + 'static,
    {
        let (cmd_tx, cmd_rx): (mpsc::Sender<OutFrame>, mpsc::Receiver<OutFrame>) =
            mpsc::channel(ROUTE_CHAN);

        // writer task: frames -> wire bytes -> body
        tokio::spawn(async move {
            let mut cmd_rx = cmd_rx;
            while let Some(f) = cmd_rx.recv().await {
                match enc.encode(f.ftype, f.flags, f.sid, &f.payload) {
                    Ok(wire) => {
                        if body_tx.send(wire).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => warn!("mux encode failed: {e}"),
                }
            }
        });

        let inner = Arc::new(MuxInner {
            cmd_tx,
            sessions: dashmap::DashMap::new(),
            udp: dashmap::DashMap::new(),
            pending_open: dashmap::DashMap::new(),
            pending_udp: dashmap::DashMap::new(),
            next_sid: AtomicU32::new(rand_sid_base()),
            closed: CancellationToken::new(),
        });

        let i2 = inner.clone();
        tokio::spawn(run_client_reader(i2, reader, cipher));

        MuxClient { inner }
    }

    pub async fn open_tcp(&self, host: &str, port: u16) -> Result<BoxStream> {
        ensure!(!host.is_empty() && host.len() <= 255, "invalid host");
        let sid = self.inner.alloc_sid();
        let (a, b) = tokio::io::duplex(SESSION_BUF);
        let (mut rb, mut wb) = tokio::io::split(b);
        let (in_tx, mut in_rx) = mpsc::channel::<Vec<u8>>(ROUTE_CHAN);

        self.inner.sessions.insert(sid, in_tx);
        let (os, orx) = oneshot::channel();
        self.inner.pending_open.insert(sid, os);

        let payload = encode_open(host, port);
        if self
            .inner
            .cmd_tx
            .send(OutFrame::new(FrameType::Open, 0, sid, payload))
            .await
            .is_err()
        {
            self.inner.sessions.remove(&sid);
            anyhow::bail!("mux channel closed");
        }

        let reply = match timeout(HANDSHAKE_TIMEOUT, orx).await {
            Ok(Ok(r)) => r,
            _ => {
                self.inner.sessions.remove(&sid);
                self.inner.pending_open.remove(&sid);
                anyhow::bail!("open_tcp {host}:{port}: no reply from server");
            }
        };
        if let Err(e) = reply {
            self.inner.sessions.remove(&sid);
            return Err(anyhow::anyhow!("open_tcp {host}:{port}: {e:?}"));
        }

        // pump: user -> frames
        let cmd = self.inner.cmd_tx.clone();
        let sessions = self.inner.sessions.clone();
        tokio::spawn(async move {
            let mut chunk = vec![0u8; MAX_PLAINTEXT];
            loop {
                match rb.read(&mut chunk).await {
                    Ok(0) => break,
                    Ok(n) => {
                        if cmd
                            .send(OutFrame::new(FrameType::Data, 0, sid, chunk[..n].to_vec()))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            // half-close: tell the server we are done sending
            let _ = cmd
                .send(OutFrame::new(FrameType::Close, FLAG_FIN, sid, Vec::new()))
                .await;
            sessions.remove(&sid);
        });

        // pump: frames -> user
        tokio::spawn(async move {
            while let Some(data) = in_rx.recv().await {
                if wb.write_all(&data).await.is_err() {
                    break;
                }
            }
            let _ = wb.shutdown().await;
        });

        Ok(Box::new(a))
    }

    pub async fn udp_associate(&self) -> Result<UdpPipe> {
        let sid = self.inner.alloc_sid();
        let (out_tx, mut out_rx) = mpsc::channel::<(UdpAddr, Vec<u8>)>(ROUTE_CHAN);
        let (in_tx, in_rx) = mpsc::channel::<(UdpAddr, Vec<u8>)>(ROUTE_CHAN);
        self.inner.udp.insert(sid, in_tx);
        let (os, orx) = oneshot::channel();
        self.inner.pending_udp.insert(sid, os);

        if self
            .inner
            .cmd_tx
            .send(OutFrame::new(FrameType::UdpAssociate, 0, sid, Vec::new()))
            .await
            .is_err()
        {
            self.inner.udp.remove(&sid);
            anyhow::bail!("mux channel closed");
        }
        let reply = match timeout(HANDSHAKE_TIMEOUT, orx).await {
            Ok(Ok(r)) => r,
            _ => {
                self.inner.udp.remove(&sid);
                anyhow::bail!("udp_associate: no reply");
            }
        };
        if let Err(e) = reply {
            self.inner.udp.remove(&sid);
            return Err(anyhow::anyhow!("udp_associate: {e:?}"));
        }

        // outbound pump: (dst, data) -> UdpData frames
        let cmd = self.inner.cmd_tx.clone();
        let udp = self.inner.udp.clone();
        tokio::spawn(async move {
            while let Some((dst, data)) = out_rx.recv().await {
                let mut payload = Vec::with_capacity(24 + data.len());
                dst.encode(&mut payload);
                payload.extend_from_slice(&data);
                if cmd
                    .send(OutFrame::new(FrameType::UdpData, 0, sid, payload))
                    .await
                    .is_err()
                {
                    break;
                }
            }
            udp.remove(&sid);
        });

        Ok(UdpPipe {
            outbound: out_tx,
            inbound: in_rx,
        })
    }
}

async fn run_client_reader<R: AsyncRead + Unpin>(
    inner: Arc<MuxInner>,
    mut r: R,
    cipher: Arc<FrameCipher>,
) {
    let mut dec = FrameDecoder::new(Some(cipher), None);
    let mut buf = [0u8; 16 * 1024];
    loop {
        let n = match r.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => break,
        };
        dec.feed(&buf[..n]);
        loop {
            match dec.next_frame() {
                Ok(Some(f)) => {
                    if handle_client_frame(&inner, f).await {
                        return;
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    debug!("mux client: bad frame: {e}");
                    inner.teardown_all();
                    return;
                }
            }
        }
    }
    inner.teardown_all();
}

/// Returns true when the connection must be torn down.
async fn handle_client_frame(inner: &Arc<MuxInner>, f: super::frame::Frame) -> bool {
    match f.ftype {
        FrameType::OpenOk => {
            if let Some((_, tx)) = inner.pending_open.remove(&f.sid) {
                let _ = tx.send(Ok(()));
            }
            false
        }
        FrameType::OpenErr => {
            let e = code_to_open_error(&f.payload);
            if let Some((_, tx)) = inner.pending_open.remove(&f.sid) {
                let _ = tx.send(Err(e));
            }
            false
        }
        FrameType::UdpOk => {
            if let Some((_, tx)) = inner.pending_udp.remove(&f.sid) {
                let _ = tx.send(Ok(()));
            }
            false
        }
        FrameType::Error => {
            let e = code_to_open_error(&f.payload);
            if let Some((_, tx)) = inner.pending_udp.remove(&f.sid) {
                let _ = tx.send(Err(e));
            }
            inner.sessions.remove(&f.sid);
            false
        }
        FrameType::Data => {
            let tx = inner.sessions.get(&f.sid).map(|s| s.clone());
            if let Some(tx) = tx {
                if tx.send(f.payload).await.is_err() {
                    inner.sessions.remove(&f.sid);
                }
            }
            if f.flags & FLAG_FIN != 0 {
                // Half-close from the server: drop the session sender so the
                // user->frames pump observes channel closure and shuts the
                // local stream's write side down (same as the WT path). The
                // final payload was queued above, so ordering is preserved.
                inner.sessions.remove(&f.sid);
            }
            false
        }
        FrameType::Close => {
            // FIN (half-close) and RST both drop the session sender here;
            // the rx pump observes closure and shuts the user stream down.
            inner.sessions.remove(&f.sid);
            inner.udp.remove(&f.sid);
            false
        }
        FrameType::UdpData => {
            let mut r = super::addr::Reader::new(&f.payload);
            match UdpAddr::decode(&mut r) {
                Ok(src) => {
                    let data = r.rest().to_vec();
                    let tx = inner.udp.get(&f.sid).map(|s| s.clone());
                    if let Some(tx) = tx {
                        let _ = tx.send((src, data)).await;
                    }
                }
                Err(_) => warn!("mux: bad UdpData payload"),
            }
            false
        }
        FrameType::Pong => false,
        FrameType::Ping => {
            let _ = inner
                .cmd_tx
                .send(OutFrame::new(FrameType::Pong, 0, 0, Vec::new()))
                .await;
            false
        }
        _ => false,
    }
}

fn rand_sid_base() -> u32 {
    use rand::Rng;
    rand::rngs::OsRng.gen::<u32>().max(1)
}

/// Random non-zero u32 seed for per-connection sid allocators.
pub fn next_rand_u32() -> u32 {
    rand_sid_base()
}

// ---------------------------------------------------------------------------
// Server role
// ---------------------------------------------------------------------------

/// Hooks the server provides to the mode-A mux loop.
pub trait ServerHooks: Send + Sync {
    /// Establish a TCP session for an Open frame (dials the target and
    /// spawns pumps); Data frames for `sid` are routed internally afterwards.
    fn open_tcp(&self, sid: u32, host: String, port: u16) -> BoxFutOpen;
    /// Route Data toward the target.
    fn feed_tcp(&self, sid: u32, data: Vec<u8>, fin: bool, rst: bool) -> BoxFutUnit;
    /// Tear down a session (rst = abort).
    fn close_tcp(&self, sid: u32, rst: bool);
    fn udp_associate(&self, sid: u32, sink: FrameSink) -> BoxFutOpen;
    fn udp_feed(&self, sid: u32, dst: UdpAddr, data: Vec<u8>) -> BoxFutUnit;
    /// Refresh the session liveness timestamp.
    fn touch(&self, sid: u32);
}

pub type BoxFutOpen = std::pin::Pin<Box<dyn Future<Output = Result<(), OpenError>> + Send>>;
pub type BoxFutUnit = std::pin::Pin<Box<dyn Future<Output = ()> + Send>>;

/// Drives the server side of a mode-A channel: consumes frames from the
/// (already authenticated) frame reader, emits replies through `sink`.
pub async fn run_server_mux<R: AsyncRead + Unpin>(
    mut reader: FrameReader<R>,
    sink: FrameSink,
    hooks: Arc<dyn ServerHooks>,
    cancel: CancellationToken,
) {
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            f = reader.read() => {
                match f {
                    Ok(Some(f)) =>                     handle_server_frame(&sink, &hooks, f).await,
                    Ok(None) => break,
                    Err(e) => {
                        debug!("server mux: bad frame: {e}");
                        break;
                    }
                }
            }
        }
    }
    cancel.cancel();
}

async fn handle_server_frame(
    sink: &FrameSink,
    hooks: &Arc<dyn ServerHooks>,
    f: super::frame::Frame,
) {
    match f.ftype {
        FrameType::Open => match decode_open(&f.payload) {
            Ok((host, port)) => match hooks.open_tcp(f.sid, host, port).await {
                Ok(()) => {
                    let _ = sink.send(FrameType::OpenOk, 0, f.sid, &[]).await;
                }
                Err(e) => {
                    let _ = sink
                        .send(FrameType::OpenErr, 0, f.sid, &[e.to_code()])
                        .await;
                }
            },
            Err(_) => {
                let _ = sink
                    .send(
                        FrameType::OpenErr,
                        0,
                        f.sid,
                        &[OpenError::BadTarget.to_code()],
                    )
                    .await;
            }
        },
        FrameType::Data => {
            hooks.touch(f.sid);
            let fin = f.flags & FLAG_FIN != 0;
            let rst = f.flags & FLAG_RST != 0;
            hooks.feed_tcp(f.sid, f.payload, fin, rst).await;
        }
        FrameType::Close => {
            let rst = f.flags & FLAG_RST != 0;
            let fin = f.flags & FLAG_FIN != 0;
            if fin && !rst {
                // Half-close: stop the client->target direction only and let
                // the target->client pump own teardown, matching the WT path.
                // A full teardown here would truncate the response.
                hooks.feed_tcp(f.sid, Vec::new(), true, false).await;
            } else {
                hooks.close_tcp(f.sid, rst);
            }
        }
        FrameType::Ping => {
            let _ = sink.send(FrameType::Pong, 0, 0, &[]).await;
        }
        FrameType::UdpAssociate => match hooks.udp_associate(f.sid, sink.clone()).await {
            Ok(()) => {
                let _ = sink.send(FrameType::UdpOk, 0, f.sid, &[]).await;
            }
            Err(e) => {
                let _ = sink
                    .send(FrameType::OpenErr, 0, f.sid, &[e.to_code()])
                    .await;
            }
        },
        FrameType::UdpData => {
            let mut r = super::addr::Reader::new(&f.payload);
            match UdpAddr::decode(&mut r) {
                Ok(dst) => {
                    hooks.touch(f.sid);
                    hooks.udp_feed(f.sid, dst, r.rest().to_vec()).await;
                }
                Err(_) => warn!("server mux: bad UdpData payload"),
            }
        }
        FrameType::Error => {
            hooks.close_tcp(f.sid, true);
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::frame::Frame;
    use std::sync::atomic::AtomicU32;
    use std::sync::Mutex;

    fn data_frame(flags: u16, sid: u32, payload: &[u8]) -> Frame {
        Frame {
            ftype: FrameType::Data,
            flags,
            sid,
            counter: 0,
            aad: [0u8; 12],
            payload: payload.to_vec(),
        }
    }

    fn close_frame(flags: u16, sid: u32) -> Frame {
        Frame {
            ftype: FrameType::Close,
            flags,
            sid,
            counter: 0,
            aad: [0u8; 12],
            payload: Vec::new(),
        }
    }

    fn test_inner() -> Arc<MuxInner> {
        let (cmd_tx, _cmd_rx) = mpsc::channel::<OutFrame>(4);
        Arc::new(MuxInner {
            cmd_tx,
            sessions: dashmap::DashMap::new(),
            udp: dashmap::DashMap::new(),
            pending_open: dashmap::DashMap::new(),
            pending_udp: dashmap::DashMap::new(),
            next_sid: AtomicU32::new(1),
            closed: CancellationToken::new(),
        })
    }

    /// A Data frame with FLAG_FIN must deliver its payload and then close the
    /// session sender so the local user stream sees EOF (mode-A target EOF).
    #[tokio::test]
    async fn client_data_fin_closes_session() {
        let inner = test_inner();
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(4);
        inner.sessions.insert(7, tx);

        assert!(!handle_client_frame(&inner, data_frame(FLAG_FIN, 7, b"last")).await);
        assert_eq!(rx.recv().await.as_deref(), Some(&b"last"[..]));
        assert!(rx.recv().await.is_none(), "sender must be dropped on FIN");
        assert!(inner.sessions.get(&7).is_none());
    }

    /// A plain Data frame (no FIN) keeps the session open.
    #[tokio::test]
    async fn client_data_without_fin_keeps_session() {
        let inner = test_inner();
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(4);
        inner.sessions.insert(7, tx);

        assert!(!handle_client_frame(&inner, data_frame(0, 7, b"chunk")).await);
        assert_eq!(rx.recv().await.as_deref(), Some(&b"chunk"[..]));
        assert!(inner.sessions.get(&7).is_some());
    }

    #[derive(Default)]
    struct MockHooks {
        feeds: Mutex<Vec<(u32, bool, bool)>>,
        closes: Mutex<Vec<(u32, bool)>>,
    }

    impl ServerHooks for MockHooks {
        fn open_tcp(&self, _sid: u32, _host: String, _port: u16) -> BoxFutOpen {
            Box::pin(async { Ok(()) })
        }
        fn feed_tcp(&self, sid: u32, _data: Vec<u8>, fin: bool, rst: bool) -> BoxFutUnit {
            self.feeds.lock().unwrap().push((sid, fin, rst));
            Box::pin(async {})
        }
        fn close_tcp(&self, sid: u32, rst: bool) {
            self.closes.lock().unwrap().push((sid, rst));
        }
        fn udp_associate(&self, _sid: u32, _sink: FrameSink) -> BoxFutOpen {
            Box::pin(async { Ok(()) })
        }
        fn udp_feed(&self, _sid: u32, _dst: UdpAddr, _data: Vec<u8>) -> BoxFutUnit {
            Box::pin(async {})
        }
        fn touch(&self, _sid: u32) {}
    }

    fn test_sink() -> FrameSink {
        FrameSink::Chan(mpsc::channel(1).0)
    }

    /// Close+FIN from the client is a half-close: route it to `feed_tcp` and
    /// leave teardown to the target->client pump (WT parity).
    #[tokio::test]
    async fn server_close_fin_is_half_close() {
        let hooks = Arc::new(MockHooks::default());
        let dyn_hooks: Arc<dyn ServerHooks> = hooks.clone();
        handle_server_frame(&test_sink(), &dyn_hooks, close_frame(FLAG_FIN, 3)).await;
        assert_eq!(*hooks.feeds.lock().unwrap(), vec![(3, true, false)]);
        assert!(hooks.closes.lock().unwrap().is_empty());
    }

    /// Close+RST (and flag-less Close) must tear the session down.
    #[tokio::test]
    async fn server_close_rst_tears_down() {
        let hooks = Arc::new(MockHooks::default());
        let dyn_hooks: Arc<dyn ServerHooks> = hooks.clone();
        handle_server_frame(&test_sink(), &dyn_hooks, close_frame(FLAG_RST, 3)).await;
        handle_server_frame(&test_sink(), &dyn_hooks, close_frame(0, 4)).await;
        assert_eq!(*hooks.closes.lock().unwrap(), vec![(3, true), (4, false)]);
        assert!(hooks.feeds.lock().unwrap().is_empty());
    }
}
