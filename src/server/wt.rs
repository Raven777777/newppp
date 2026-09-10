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
    FrameDecoder, FrameEncoder, FrameReader, FrameType, FrameWriter, ReplayWindow,
};
use crate::proto::mux::{FrameSink, OutFrame, ServerHooks};
use crate::server::hub::{handle_wt_stream, Hooks};
use crate::server::limit::RateLimiter;
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
            if let Err(e) = handle_wt_conn(st, conn).await {
                debug!("wt conn ended: {e:#}");
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

async fn handle_wt_conn(st: Arc<ServerState>, conn: Connection) -> Result<()> {
    // ---- control stream: first bidi stream carries the AUTH handshake ----
    let (send, recv) = conn.accept_bi().await?;
    let mut reader = FrameReader::new(recv, None, None);
    reader.decoder_mut().raw = true;

    let auth_frame = match timeout(AUTH_TIMEOUT, reader.read()).await {
        Ok(Ok(Some(f))) if f.ftype == FrameType::Auth => f,
        _ => {
            // Silent drop: no error signature for probes.
            return Ok(());
        }
    };

    let Some((uid, static_key, ap)) = crate::server::auth_from_frame(&st, &auth_frame) else {
        // Failed in-band auth: quietly disappear (stealth).
        return Ok(());
    };

    let session_key = crypto::derive_session_key(&static_key, &ap.salt);
    let cipher = Arc::new(FrameCipher::new(&session_key));
    reader.set_cipher(cipher.clone());

    let stream_counters = CounterGen::stream();
    let dgram_counters = CounterGen::datagram();
    let mut writer = FrameWriter::new(send, cipher.clone(), stream_counters.clone());
    writer.write(FrameType::AuthOk, 0, 0, &[]).await?;
    info!("wt conn authenticated uid={uid}");

    // ---- build connection state ----
    let conn_id = st
        .conn_seq
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let cancel = CancellationToken::new();
    let conn_state = Arc::new(ConnState {
        id: conn_id,
        uid,
        cipher: cipher.clone(),
        stream_counters: stream_counters.clone(),
        rate: RateLimiter::new(st.rate_mbps),
        cancel: cancel.clone(),
        sessions: Default::default(),
        tcp_routes: Default::default(),
        udp_routes: Default::default(),
        max_per_conn: MAX_PER_CONN,
        last_active: std::sync::atomic::AtomicI64::new(crate::server::state::now_millis()),
    });
    st.conns.insert(conn_id, conn_state.clone());

    // ---- control stream writer ----
    let (ctrl_tx, ctrl_rx) = mpsc::channel::<OutFrame>(128);
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

    let sink_ctrl = FrameSink::Chan(ctrl_tx.clone());
    let sink_dgram = FrameSink::Datagram {
        conn: conn.clone(),
        enc: Arc::new(FrameEncoder::new(cipher.clone(), dgram_counters.clone())),
        fallback: ctrl_tx.clone(),
    };

    // ---- control stream reader: UDP + PING ----
    {
        let st2 = st.clone();
        let cs2 = conn_state.clone();
        let sink_dgram2 = sink_dgram.clone();
        let sink_ctrl2 = sink_ctrl.clone();
        tokio::spawn(async move {
            while let Ok(Some(f)) = reader.read().await {
                match f.ftype {
                    FrameType::Ping => {
                        let _ = sink_ctrl2.send(FrameType::Pong, 0, 0, &[]).await;
                    }
                    FrameType::UdpAssociate => {
                        let hooks = Hooks {
                            st: st2.clone(),
                            conn: cs2.clone(),
                            sink: sink_dgram2.clone(),
                        };
                        let res = hooks.udp_associate(f.sid, sink_dgram2.clone()).await;
                        let frame = match res {
                            Ok(()) => OutFrame::new(FrameType::UdpOk, 0, f.sid, Vec::new()),
                            Err(e) => {
                                OutFrame::new(FrameType::OpenErr, 0, f.sid, vec![e.to_code()])
                            }
                        };
                        let _ = sink_ctrl2
                            .send(frame.ftype, frame.flags, frame.sid, &frame.payload)
                            .await;
                    }
                    FrameType::UdpData => {
                        let mut r = crate::proto::addr::Reader::new(&f.payload);
                        if let Ok(dst) = crate::proto::addr::UdpAddr::decode(&mut r) {
                            cs2.touch(f.sid);
                            let hooks = Hooks {
                                st: st2.clone(),
                                conn: cs2.clone(),
                                sink: sink_dgram2.clone(),
                            };
                            hooks.udp_feed(f.sid, dst, r.rest().to_vec()).await;
                        }
                    }
                    FrameType::Close => {
                        cs2.drop_session(f.sid);
                    }
                    _ => {}
                }
            }
            cs2.cancel.cancel();
        });
    }

    // ---- datagram receive loop ----
    {
        let st2 = st.clone();
        let cs2 = conn_state.clone();
        let sink_dgram2 = sink_dgram.clone();
        let cipher2 = cipher.clone();
        let conn2 = conn.clone();
        tokio::spawn(async move {
            let mut dec = FrameDecoder::new(Some(cipher2), Some(ReplayWindow::new()));
            while let Ok(d) = conn2.receive_datagram().await {
                dec.feed(&d);
                loop {
                    match dec.next_frame() {
                        Ok(Some(f)) => {
                            if f.ftype != FrameType::UdpData {
                                continue;
                            }
                            let mut r = crate::proto::addr::Reader::new(&f.payload);
                            if let Ok(dst) = crate::proto::addr::UdpAddr::decode(&mut r) {
                                cs2.touch(f.sid);
                                let hooks = Hooks {
                                    st: st2.clone(),
                                    conn: cs2.clone(),
                                    sink: sink_dgram2.clone(),
                                };
                                hooks.udp_feed(f.sid, dst, r.rest().to_vec()).await;
                            }
                        }
                        Ok(None) => break,
                        // A corrupt datagram must not desync the decoder for
                        // the rest of the connection: drop the buffered bytes
                        // (the replay window itself is kept) and carry on.
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

    // ---- connection death watcher ----
    {
        let cs2 = conn_state.clone();
        let st2 = st.clone();
        let conn3 = conn.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = conn3.closed() => {}
                _ = cs2.cancel.cancelled() => {
                    // Reaper-initiated teardown: cancel alone doesn't end the
                    // QUIC transport (background tasks hold their own clones),
                    // so close it explicitly.
                    conn3.close(wtransport::VarInt::from_u32(0), b"idle conn reaped");
                }
            }
            cs2.cancel.cancel();
            st2.conns.remove(&cs2.id);
        });
    }

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
    let _ = sink_ctrl; // keep alive till here
    Ok(())
}
