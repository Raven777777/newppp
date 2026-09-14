//! WebTransport (QUIC/h3) listener — primary transport.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};
use wtransport::{Connection, Endpoint, Identity, ServerConfig};

use crate::proto::crypto::{self, CounterGen, FrameCipher};
use crate::proto::frame::{
    negotiate, FrameDecoder, FrameEncoder, FrameLimit, FrameReader, FrameType, FrameWriter,
    ReplayWindow,
};
use crate::proto::mux::{FrameSink, OutFrame, ServerHooks};
use crate::server::hub::{handle_wt_stream, Hooks};
use crate::server::state::{ConnState, ServerState};

pub const AUTH_TIMEOUT: Duration = Duration::from_secs(10);
pub const MAX_PER_CONN: usize = 64;

pub async fn run_wt(
    st: Arc<ServerState>,
    addr: std::net::SocketAddr,
    identity: Identity,
    recv_window: u32,
) -> Result<()> {
    let config = ServerConfig::builder()
        .with_bind_default(addr.port())
        .with_custom_transport(identity, crate::quic_tune::tuned(recv_window))
        .build();
    let endpoint = Endpoint::server(config)?;
    info!("WebTransport (QUIC/h3) listening on udp://{addr}");

    loop {
        let incoming = endpoint.accept().await;
        let st = st.clone();
        let remote = incoming.remote_address();
        // Unauthenticated-connection gate (D1): reject before spawning so a
        // connection flood does not churn a task per attempt. The guard is
        // held until the in-band AUTH frame verifies, then released so
        // authenticated sessions are not throttled by it.
        let Some(guard) = st.unauth.try_admit(Some(remote.ip())) else {
            debug!("refusing connection from {remote}: unauthenticated cap reached");
            continue;
        };
        tokio::spawn(async move {
            let request = match incoming.await {
                Ok(r) => r,
                Err(e) => {
                    debug!("incoming connection failed: {e}");
                    return;
                }
            };
            // Bearer check at the session-request level: failures look like a
            // plain 404 from a normal web service.
            let auth = header_value(request.headers(), "authorization");
            if !crate::server::bearer_ok(&st, auth.as_deref()) {
                let _ = request.not_found().await;
                return;
            }
            let conn = match request.accept().await {
                Ok(c) => c,
                Err(e) => {
                    debug!("session accept failed: {e}");
                    return;
                }
            };
            if let Err(e) = handle_wt_conn(st, conn, guard).await {
                let msg = format!("{e:#}");
                debug!("wt conn ended: {msg}{}", crate::quic_tune::gap_hint(&msg));
            }
        });
    }
}

fn header_value(headers: &std::collections::HashMap<String, String>, name: &str) -> Option<String> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.clone())
}

async fn handle_wt_conn(
    st: Arc<ServerState>,
    conn: Connection,
    guard: crate::server::limit::UnauthGuard,
) -> Result<()> {
    // ---- control stream: first bidi stream carries the AUTH handshake ----
    // Bound the wait for it: a connection that never opens a stream must not
    // pin an unauthenticated-gate slot until the QUIC idle timeout.
    let (send, recv) = match timeout(AUTH_TIMEOUT, conn.accept_bi()).await {
        Ok(Ok(pair)) => pair,
        // Silent drop: no error signature for probes.
        _ => return Ok(()),
    };
    let mut reader = FrameReader::new(recv, None, None);
    reader.decoder_mut().raw = true;

    let auth_frame = match timeout(AUTH_TIMEOUT, reader.read()).await {
        Ok(Ok(Some(f))) if f.ftype == FrameType::Auth => f,
        _ => {
            // Silent drop: no error signature for probes.
            return Ok(());
        }
    };

    let (uid, static_key, ap) = match crate::server::auth_from_frame(&st, &auth_frame) {
        crate::server::AuthOutcome::Ok(uid, key, ap) => (uid, key, ap),
        crate::server::AuthOutcome::VersionMismatch { client, server } => {
            // Explicit, greppable error: the peer authenticated but speaks a
            // different protocol version. Upgrade both ends together.
            tracing::error!(
                "wt auth: protocol version mismatch (client={client}, server={server}); \
                 this build requires both ends on proto v{server}"
            );
            return Ok(());
        }
        // Failed in-band auth: quietly disappear (stealth).
        crate::server::AuthOutcome::Rejected => return Ok(()),
    };
    // Authenticated: this connection no longer counts against the unauth cap.
    drop(guard);

    let session_key = crypto::derive_session_key(&static_key, &ap.salt);
    let cipher = Arc::new(FrameCipher::new(&session_key));
    // v2 negotiation: the session uses the smaller of both advertised limits.
    let negotiated = negotiate(ap.max_plaintext, st.max_plaintext as u32);
    let limit = FrameLimit::new(negotiated);
    reader.set_cipher(cipher.clone());
    reader.limit().set(negotiated);

    let stream_counters = CounterGen::stream_server();
    let dgram_counters = CounterGen::datagram_server();
    let mut writer =
        FrameWriter::with_limit(send, cipher.clone(), stream_counters.clone(), limit.clone());
    // Echo the negotiated limit so the client can size its encoders before
    // sending any data frame (>16 KiB frames are otherwise unencodable).
    writer
        .write(FrameType::AuthOk, 0, 0, &(negotiated as u32).to_le_bytes())
        .await?;
    info!("wt conn authenticated uid={uid}");

    // ---- build connection state ----
    let conn_id = st
        .conn_seq
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let cancel = CancellationToken::new();
    let rate = st.rate_for(&uid);
    let conn_state = Arc::new(ConnState {
        id: conn_id,
        uid,
        cipher: cipher.clone(),
        stream_counters: stream_counters.clone(),
        rate,
        cancel: cancel.clone(),
        sessions: Default::default(),
        tcp_routes: Default::default(),
        udp_routes: Default::default(),
        max_per_conn: MAX_PER_CONN,
        last_active: std::sync::atomic::AtomicI64::new(crate::server::state::now_millis()),
        limit: limit.clone(),
    });
    st.conns.insert(conn_id, conn_state.clone());

    // ---- control stream writer ----
    let (ctrl_tx, ctrl_rx) = mpsc::channel::<OutFrame>(128);
    spawn_ctrl_writer(ctrl_rx, writer);

    let sink_dgram = FrameSink::Datagram {
        conn: conn.clone(),
        enc: Arc::new(FrameEncoder::with_limit(
            cipher.clone(),
            dgram_counters.clone(),
            limit.clone(),
        )),
        fallback: ctrl_tx.clone(),
    };

    // ---- control stream reader: UDP + PING ----
    spawn_ctrl_reader(
        st.clone(),
        conn_state.clone(),
        sink_dgram.clone(),
        ctrl_tx.clone(),
        reader,
    );

    // ---- datagram receive loop ----
    spawn_dgram_reader(
        st.clone(),
        conn_state.clone(),
        sink_dgram.clone(),
        cipher.clone(),
        conn.clone(),
        limit.clone(),
    );

    // ---- connection death watcher ----
    spawn_death_watcher(st.clone(), conn_state.clone(), conn.clone());

    // ---- dedicated TCP sessions: one bidi stream each ----
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            a = conn.accept_bi() => {
                match a {
                    Ok((send, recv)) => {
                        let st2 = st.clone();
                        let cs2 = conn_state.clone();
                        tokio::spawn(handle_wt_stream(st2, cs2, send, recv));
                    }
                    Err(_) => break,
                }
            }
        }
    }
    Ok(())
}

/// Drain encoded control frames onto the WT control stream until it dies.
fn spawn_ctrl_writer(
    ctrl_rx: mpsc::Receiver<OutFrame>,
    mut writer: FrameWriter<wtransport::SendStream>,
) {
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
}

/// Handle control-stream frames: UDP ASSOCIATE/DATA plus keepalive PING, and
/// release the session quota on Close/Error.
fn spawn_ctrl_reader(
    st: Arc<ServerState>,
    cs: Arc<ConnState>,
    sink_dgram: FrameSink,
    ctrl_tx: mpsc::Sender<OutFrame>,
    mut reader: FrameReader<wtransport::RecvStream>,
) {
    let sink_ctrl = FrameSink::Chan(ctrl_tx);
    tokio::spawn(async move {
        while let Ok(Some(f)) = reader.read().await {
            match f.ftype {
                FrameType::Ping => {
                    let _ = sink_ctrl.send(FrameType::Pong, 0, 0, &[]).await;
                }
                FrameType::UdpAssociate => {
                    let hooks = Hooks {
                        st: st.clone(),
                        conn: cs.clone(),
                        sink: sink_dgram.clone(),
                    };
                    let res = hooks.udp_associate(f.sid, sink_dgram.clone()).await;
                    let frame = match res {
                        Ok(()) => OutFrame::new(FrameType::UdpOk, 0, f.sid, Vec::new()),
                        Err(e) => OutFrame::new(FrameType::OpenErr, 0, f.sid, vec![e.to_code()]),
                    };
                    let _ = sink_ctrl
                        .send(frame.ftype, frame.flags, frame.sid, &frame.payload)
                        .await;
                }
                FrameType::UdpData => {
                    let mut r = crate::proto::addr::Reader::new(&f.payload);
                    if let Ok(dst) = crate::proto::addr::UdpAddr::decode(&mut r) {
                        cs.touch(f.sid);
                        let hooks = Hooks {
                            st: st.clone(),
                            conn: cs.clone(),
                            sink: sink_dgram.clone(),
                        };
                        hooks.udp_feed(f.sid, dst, r.rest().to_vec()).await;
                    }
                }
                FrameType::Close | FrameType::Error
                    // Release only when this call actually removed the
                    // registered handle (parity with hub.rs close_tcp);
                    // duplicate frames must not corrupt the global quota.
                    if cs.drop_session(f.sid) =>
                {
                    st.release_session();
                }
                _ => {}
            }
        }
        cs.cancel.cancel();
    });
}

/// Receive QUIC datagrams (the UDP fast path) into the UDP hooks.
fn spawn_dgram_reader(
    st: Arc<ServerState>,
    cs: Arc<ConnState>,
    sink_dgram: FrameSink,
    cipher: Arc<FrameCipher>,
    conn: wtransport::Connection,
    limit: FrameLimit,
) {
    tokio::spawn(async move {
        let mut dec = FrameDecoder::with_limit(Some(cipher), Some(ReplayWindow::new()), limit);
        while let Ok(d) = conn.receive_datagram().await {
            dec.feed(&d);
            loop {
                match dec.next_frame() {
                    Ok(Some(f)) => {
                        if f.ftype != FrameType::UdpData {
                            continue;
                        }
                        let mut r = crate::proto::addr::Reader::new(&f.payload);
                        if let Ok(dst) = crate::proto::addr::UdpAddr::decode(&mut r) {
                            cs.touch(f.sid);
                            let hooks = Hooks {
                                st: st.clone(),
                                conn: cs.clone(),
                                sink: sink_dgram.clone(),
                            };
                            hooks.udp_feed(f.sid, dst, r.rest().to_vec()).await;
                        }
                    }
                    Ok(None) => break,
                    // A corrupt datagram must not desync the decoder for the
                    // rest of the connection: drop the buffered bytes (the
                    // replay window itself is kept) and carry on.
                    Err(e) => {
                        debug!("wt datagram: bad frame: {e}");
                        dec.clear();
                        break;
                    }
                }
            }
        }
    });
}

/// Watch for connection death (or reaper cancellation) and remove the state.
fn spawn_death_watcher(st: Arc<ServerState>, cs: Arc<ConnState>, conn: wtransport::Connection) {
    tokio::spawn(async move {
        tokio::select! {
            _ = conn.closed() => {}
            _ = cs.cancel.cancelled() => {
                // Reaper-initiated teardown: cancel alone doesn't end the
                // QUIC transport (background tasks hold their own clones),
                // so close it explicitly.
                conn.close(wtransport::VarInt::from_u32(0), b"idle conn reaped");
            }
        }
        cs.cancel.cancel();
        st.conns.remove(&cs.id);
    });
}
