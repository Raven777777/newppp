//! Server-side session engine: TCP dialing/piping and UDP relaying for both
//! transports (dedicated WebTransport streams + mode-A mux).

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tracing::debug;

use crate::proto::addr::UdpAddr;
use crate::proto::frame::{decode_open, FrameReader, FrameType, FrameWriter, FLAG_FIN, FLAG_RST};
use crate::proto::mux::{FrameSink, OpenError, ServerHooks};
use crate::server::state::{ConnState, ServerState, UdpRelay};

pub const DIAL_TIMEOUT: Duration = Duration::from_secs(10);
pub const READ_BUF: usize = 16 * 1024;
pub const TCP_ROUTE_CAP: usize = 64;

pub async fn dial_target(host: &str, port: u16) -> std::result::Result<TcpStream, OpenError> {
    if host.is_empty() || host.len() > 255 {
        return Err(OpenError::BadTarget);
    }
    match timeout(DIAL_TIMEOUT, TcpStream::connect((host, port))).await {
        Ok(Ok(s)) => {
            let _ = s.set_nodelay(true);
            Ok(s)
        }
        Ok(Err(_)) => Err(OpenError::DialFailed),
        Err(_) => Err(OpenError::DialFailed),
    }
}

// ---------------------------------------------------------------------------
// Mode-A mux hooks (HTTP fallback path)
// ---------------------------------------------------------------------------

/// Hooks implementation binding the mux loop to one connection's state.
pub struct Hooks {
    pub st: Arc<ServerState>,
    pub conn: Arc<ConnState>,
    pub sink: FrameSink,
}

impl Hooks {
    fn admit(&self, sid: u32) -> std::result::Result<CancellationToken, OpenError> {
        if self.conn.sessions.contains_key(&sid) {
            return Err(OpenError::Denied);
        }
        if self.conn.session_count() >= self.conn.max_per_conn {
            return Err(OpenError::Limit);
        }
        if !self.st.try_acquire_session() {
            return Err(OpenError::Limit);
        }
        Ok(self.conn.register(sid))
    }
}

impl ServerHooks for Hooks {
    fn open_tcp(&self, sid: u32, host: String, port: u16) -> crate::proto::mux::BoxFutOpen {
        let st = self.st.clone();
        let conn = self.conn.clone();
        let sink = self.sink.clone();
        Box::pin(async move {
            // `admit` acquires the global quota only right before registering;
            // on its error paths nothing was acquired, so nothing is released.
            let token = Hooks {
                st: st.clone(),
                conn: conn.clone(),
                sink: sink.clone(),
            }
            .admit(sid)?;
            let sock = match dial_target(&host, port).await {
                Ok(s) => s,
                Err(e) => {
                    if conn.drop_session(sid) {
                        st.release_session();
                    }
                    return Err(e);
                }
            };
            spawn_tcp_pumps(st, conn, sink, sid, sock, token);
            Ok(())
        })
    }

    fn feed_tcp(
        &self,
        sid: u32,
        data: Vec<u8>,
        fin: bool,
        rst: bool,
    ) -> crate::proto::mux::BoxFutUnit {
        let st = self.st.clone();
        let conn = self.conn.clone();
        Box::pin(async move {
            if rst {
                if conn.drop_session(sid) {
                    st.release_session();
                }
                return;
            }
            conn.touch(sid);
            let tx = conn.tcp_routes.get(&sid).map(|t| t.clone());
            if let Some(tx) = tx {
                if tx.send((data, fin)).await.is_err() && conn.drop_session(sid) {
                    st.release_session();
                }
            } // unknown/closed session: ignore
        })
    }

    fn close_tcp(&self, sid: u32, _rst: bool) {
        // Release only when this call actually removed the registered handle;
        // late/duplicate Close frames must not corrupt the global quota.
        if self.conn.drop_session(sid) {
            self.st.release_session();
        }
    }

    fn udp_associate(&self, sid: u32, _sink: FrameSink) -> crate::proto::mux::BoxFutOpen {
        let st = self.st.clone();
        let conn = self.conn.clone();
        Box::pin(async move {
            if conn.udp_routes.contains_key(&sid) {
                return Err(OpenError::Denied);
            }
            if conn.session_count() >= conn.max_per_conn {
                return Err(OpenError::Limit);
            }
            if !st.try_acquire_session() {
                return Err(OpenError::Limit);
            }
            let token = conn.cancel.child_token();
            conn.register_with(sid, token.clone());
            let relay = Arc::new(UdpRelay::new());
            let relay2 = relay.clone();
            let conn2 = conn.clone();
            let st2 = st.clone();
            tokio::spawn(async move {
                tokio::select! {
                    _ = token.cancelled() => {}
                    _ = relay2.cancel.cancelled() => {}
                }
                if conn2.drop_session(sid) {
                    st2.release_session();
                }
            });
            conn.udp_routes.insert(sid, relay);
            Ok(())
        })
    }

    fn udp_feed(&self, sid: u32, dst: UdpAddr, data: Vec<u8>) -> crate::proto::mux::BoxFutUnit {
        let conn = self.conn.clone();
        let sink = self.sink.clone();
        Box::pin(async move {
            let relay = conn.udp_routes.get(&sid).map(|r| r.clone());
            let Some(relay) = relay else {
                debug!("udp_feed: no relay for sid={sid}");
                return;
            };
            conn.touch(sid);
            let Ok(addr) = dst.resolve().await else {
                debug!("udp_feed: resolve failed sid={sid}");
                return;
            };
            let res = match addr {
                std::net::SocketAddr::V4(_) => get_or_bind_v4(&conn, &sink, sid, &relay).await,
                std::net::SocketAddr::V6(_) => get_or_bind_v6(&conn, &sink, sid, &relay).await,
            };
            let Ok(sock) = res else {
                debug!("udp_feed: bind failed sid={sid}");
                return;
            };
            debug!(
                "udp_feed: sending {} bytes to {addr} (sid={sid})",
                data.len()
            );
            let _ = sock.send_to(&data, addr).await;
        })
    }

    fn touch(&self, sid: u32) {
        self.conn.touch(sid);
    }
}

macro_rules! bind_relay {
    ($fn_name:ident, $bind_addr:expr, $fam:ident) => {
        async fn $fn_name(
            conn: &Arc<ConnState>,
            sink: &FrameSink,
            sid: u32,
            relay: &Arc<UdpRelay>,
        ) -> Result<Arc<UdpSocket>, OpenError> {
            let conn2 = conn.clone();
            let sink2 = sink.clone();
            let sid2 = sid;
            let relay2 = relay.clone();
            relay
                .$fam
                .get_or_try_init(|| async move {
                    let s = UdpSocket::bind($bind_addr)
                        .await
                        .map_err(|_| OpenError::Denied)?;
                    let arc = Arc::new(s);
                    spawn_udp_recv(conn2, sink2, sid2, relay2, arc.clone());
                    Ok(arc)
                })
                .await
                .cloned()
        }
    };
}

bind_relay!(get_or_bind_v4, "0.0.0.0:0", v4);
bind_relay!(get_or_bind_v6, "[::]:0", v6);

fn spawn_udp_recv(
    conn: Arc<ConnState>,
    sink: FrameSink,
    sid: u32,
    relay: Arc<UdpRelay>,
    sock: Arc<UdpSocket>,
) {
    tokio::spawn(async move {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            tokio::select! {
                _ = relay.cancel.cancelled() => break,
                _ = conn.cancel.cancelled() => break,
                r = sock.recv_from(&mut buf) => {
                    match r {
                        Ok((n, src)) => {
                            conn.touch(sid);
                            let mut payload = Vec::with_capacity(24 + n);
                            match src {
                                std::net::SocketAddr::V4(a) => UdpAddr::V4(a).encode(&mut payload),
                                std::net::SocketAddr::V6(a) => UdpAddr::V6(a).encode(&mut payload),
                            }
                            payload.extend_from_slice(&buf[..n]);
                            if !sink.try_send_lossy(FrameType::UdpData, 0, sid, &payload) {
                                debug!("udp reply dropped (sink full), sid={sid}");
                            }
                        }
                        Err(_) => break,
                    }
                }
            }
        }
    });
}

// ---------------------------------------------------------------------------
// TCP piping (shared by both paths)
// ---------------------------------------------------------------------------

/// Spawn the two direction pumps for a mux-path TCP session.
pub fn spawn_tcp_pumps(
    st: Arc<ServerState>,
    conn: Arc<ConnState>,
    sink: FrameSink,
    sid: u32,
    sock: TcpStream,
    token: CancellationToken,
) {
    let (mut rd, mut wr) = sock.into_split();
    let (tx, mut rx) = mpsc::channel::<(Vec<u8>, bool)>(TCP_ROUTE_CAP);
    conn.tcp_routes.insert(sid, tx);
    let token2 = token.clone();

    // client -> target
    // Note: this pump never drops the session — a client FIN here is a
    // half-close and the target -> client pump owns the teardown/release.
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = token.cancelled() => break,
                m = rx.recv() => {
                    if let Some((data, fin)) = m {
                        if wr.write_all(&data).await.is_err() {
                            break;
                        }
                        if fin {
                            let _ = wr.shutdown().await;
                            break;
                        }
                    } else {
                        break;
                    }
                }
            }
        }
        // half-close: the target may still be sending; pump_out ends it.
    });

    // target -> client
    tokio::spawn(async move {
        let mut buf = vec![0u8; READ_BUF];
        loop {
            tokio::select! {
                _ = token2.cancelled() => break,
                r = rd.read(&mut buf) => {
                    match r {
                        Ok(0) => {
                            let _ = sink.send(FrameType::Data, FLAG_FIN, sid, &[]).await;
                            break;
                        }
                        Ok(n) => {
                            conn.touch(sid);
                            conn.rate.acquire(n).await;
                            if sink.send(FrameType::Data, 0, sid, &buf[..n]).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => {
                            let _ = sink.send(FrameType::Close, FLAG_RST, sid, &[]).await;
                            break;
                        }
                    }
                }
            }
        }
        if conn.drop_session(sid) {
            st.release_session();
        }
    });
}

/// Dedicated WebTransport-stream TCP session: OPEN/DATA/CLOSE ride one
/// bidi stream. Handles the full lifecycle after the control handshake.
pub async fn handle_wt_stream(
    st: Arc<ServerState>,
    conn: Arc<ConnState>,
    send: wtransport::SendStream,
    recv: wtransport::RecvStream,
) {
    let mut writer = FrameWriter::new(send, conn.cipher.clone(), conn.stream_counters.clone());
    let mut reader = FrameReader::new(recv, Some(conn.cipher.clone()), None);

    let first = match timeout(crate::proto::mux::HANDSHAKE_TIMEOUT, reader.read()).await {
        Ok(Ok(Some(f))) => f,
        _ => return,
    };
    if first.ftype != FrameType::Open {
        return;
    }
    let sid = first.sid;
    if conn.sessions.contains_key(&sid) {
        return;
    }
    if conn.session_count() >= conn.max_per_conn || !st.try_acquire_session() {
        let _ = writer
            .write(FrameType::OpenErr, 0, sid, &[OpenError::Limit.to_code()])
            .await;
        return;
    }
    // Register immediately after acquiring the quota: the dial below can
    // block up to DIAL_TIMEOUT, and a second stream reusing this sid must be
    // rejected meanwhile (otherwise both register and one quota leaks).
    let token = conn.cancel.child_token();
    conn.register_with(sid, token.clone());
    let (host, port) = match decode_open(&first.payload) {
        Ok(v) => v,
        Err(_) => {
            let _ = writer
                .write(
                    FrameType::OpenErr,
                    0,
                    sid,
                    &[OpenError::BadTarget.to_code()],
                )
                .await;
            if conn.drop_session(sid) {
                st.release_session();
            }
            return;
        }
    };
    let sock = match dial_target(&host, port).await {
        Ok(s) => s,
        Err(e) => {
            let _ = writer
                .write(FrameType::OpenErr, 0, sid, &[e.to_code()])
                .await;
            if conn.drop_session(sid) {
                st.release_session();
            }
            return;
        }
    };
    if writer.write(FrameType::OpenOk, 0, sid, &[]).await.is_err() {
        if conn.drop_session(sid) {
            st.release_session();
        }
        return;
    }
    debug!("wt stream session sid={sid} -> {host}:{port}");

    let (mut sock_rd, mut sock_wr) = tokio::io::split(sock);

    // target -> client (owns the frame writer; owns the teardown/release)
    {
        let st2 = st.clone();
        let conn2 = conn.clone();
        let token2 = token.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; READ_BUF];
            loop {
                tokio::select! {
                    _ = token2.cancelled() => break,
                    r = sock_rd.read(&mut buf) => {
                        match r {
                            Ok(0) => {
                                let _ = writer.write(FrameType::Data, FLAG_FIN, sid, &[]).await;
                                break;
                            }
                            Ok(n) => {
                                conn2.touch(sid);
                                conn2.rate.acquire(n).await;
                                if writer.write(FrameType::Data, 0, sid, &buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                            Err(_) => {
                                let _ = writer.write(FrameType::Close, FLAG_RST, sid, &[]).await;
                                break;
                            }
                        }
                    }
                }
            }
            let _ = writer.shutdown().await;
            if conn2.drop_session(sid) {
                st2.release_session();
            }
        });
    }

    // client -> target (owns the frame reader)
    //
    // A client FIN (FLAG_FIN Data / Close+FIN / stream EOF) is a half-close:
    // shut the write half down but keep the session alive so the
    // target -> client pump can finish the response. Only aborts (RST,
    // protocol error, connection teardown) drop the session here.
    {
        let st2 = st.clone();
        let conn2 = conn.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = token.cancelled() => break,
                    r = reader.read() => {
                        match r {
                            Ok(Some(f)) => match f.ftype {
                                FrameType::Data => {
                                    conn2.touch(sid);
                                    if sock_wr.write_all(&f.payload).await.is_err() {
                                        break;
                                    }
                                    if f.flags & FLAG_FIN != 0 {
                                        let _ = sock_wr.shutdown().await;
                                        return; // half-close: defer teardown
                                    }
                                }
                                FrameType::Close => {
                                    if f.flags & FLAG_FIN != 0 {
                                        let _ = sock_wr.shutdown().await;
                                        return; // half-close: defer teardown
                                    }
                                    break; // RST: abort the session
                                }
                                _ => {}
                            },
                            Ok(None) => {
                                let _ = sock_wr.shutdown().await;
                                return; // client stream EOF: half-close
                            }
                            Err(_) => break,
                        }
                    }
                }
            }
            if conn2.drop_session(sid) {
                st2.release_session();
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::crypto::FrameCipher;
    use crate::proto::mux::FrameSink;
    use crate::server::state::now_millis;
    use dashmap::DashMap;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

    fn setup() -> (Arc<ServerState>, Arc<ConnState>) {
        use crate::server::limit::RateLimiter;
        let st = Arc::new(ServerState {
            static_keys: HashMap::new(),
            conns: DashMap::new(),
            conn_seq: AtomicU64::new(1),
            active_sessions: AtomicU64::new(0),
            max_sessions: 10,
            rate_mbps: 0,
            idle: Duration::from_secs(60),
            seen_nonces: dashmap::DashMap::new(),
            path: "/api/ppp".into(),
        });
        let conn = Arc::new(ConnState {
            id: 1,
            uid: "u".into(),
            cipher: Arc::new(FrameCipher::new(&[0u8; 32])),
            stream_counters: crate::proto::crypto::CounterGen::stream(),
            rate: RateLimiter::new(0),
            cancel: CancellationToken::new(),
            sessions: Default::default(),
            tcp_routes: Default::default(),
            udp_routes: Default::default(),
            max_per_conn: 8,
            last_active: AtomicI64::new(now_millis()),
        });
        st.conns.insert(1, conn.clone());
        (st, conn)
    }

    /// A duplicate Close frame (arriving after the session was already torn
    /// down by a pump) must not decrement the global quota twice — the old
    /// code underflowed `active_sessions` here, permanently locking the
    /// server out of new sessions.
    #[test]
    fn close_tcp_releases_quota_exactly_once() {
        let (st, conn) = setup();
        let hooks = Hooks {
            st: st.clone(),
            conn: conn.clone(),
            sink: FrameSink::Chan(tokio::sync::mpsc::channel(1).0),
        };
        assert!(st.try_acquire_session());
        conn.register(1);
        hooks.close_tcp(1, false);
        assert_eq!(st.active_sessions.load(Ordering::Relaxed), 0);
        // duplicate close on an already-removed session
        hooks.close_tcp(1, false);
        assert_eq!(st.active_sessions.load(Ordering::Relaxed), 0);
    }

    /// Opening with an already-registered sid is refused before any quota is
    /// acquired; the counter must stay untouched.
    #[tokio::test]
    async fn open_admit_denial_does_not_release_quota() {
        let (st, conn) = setup();
        let hooks = Hooks {
            st: st.clone(),
            conn: conn.clone(),
            sink: FrameSink::Chan(tokio::sync::mpsc::channel(1).0),
        };
        assert!(st.try_acquire_session());
        conn.register(1);
        assert_eq!(st.active_sessions.load(Ordering::Relaxed), 1);
        // duplicate sid -> Denied, and (unlike the old code) no release
        assert_eq!(
            hooks.open_tcp(1, "h".into(), 80).await,
            Err(OpenError::Denied)
        );
        assert_eq!(st.active_sessions.load(Ordering::Relaxed), 1);
    }
}
