//! HTTPS fallback (mode A): one duplex channel that carries the whole frame
//! protocol in both directions, plus the disguise static site.
//!
//! The channel rides either a long-lived POST (`https://`, direct) or a
//! WebSocket (`wss://`, required behind buffering proxies like Cloudflare,
//! which never forward an unfinished request body). Both share the same
//! path, bearer auth and in-band AUTH frame.
//!
//! Plain HTTP (port 80) is a pure front: 301 to HTTPS for everything, with
//! optional Let's Encrypt http-01 challenge support (`--acme-dir`).

use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use axum::body::Body;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{FromRequestParts, Path, Request, State};
use axum::http::header;
use axum::response::Response;
use axum::routing::{any, get};
use axum::Router;
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use tokio::io::AsyncRead;
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::proto::crypto::{AuthPayload, CounterGen};
use crate::proto::frame::{FrameEncoder, FrameReader, FrameType};
use crate::proto::mux::{run_server_mux, FrameSink, OutFrame};
use crate::proto::stream::StreamAsRead;
use crate::server::hub::Hooks;
use crate::server::limit::RateLimiter;
use crate::server::state::{ConnState, ServerState};

pub fn router(st: Arc<ServerState>) -> Router {
    let path = st.path.clone();
    Router::new()
        .route(&path, get(ws_handler).post(api_handler))
        .fallback(any(disguise_handler))
        .with_state(st)
}

async fn disguise_handler() -> Response {
    disguise_response()
}

pub fn disguise_response() -> Response {
    Response::builder()
        .status(200)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::from(crate::server::disguise::DISGUISE_HTML))
        .expect("static response")
}

async fn api_handler(State(st): State<Arc<ServerState>>, req: Request) -> Response {
    let auth = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());

    if !crate::server::bearer_ok(&st, auth) {
        // Auth failure looks like the normal landing page (200 OK HTML).
        return disguise_response();
    }

    let body = req.into_body().into_data_stream();
    let mut reader = FrameReader::new(StreamAsRead::new(body), None, None);
    reader.decoder_mut().raw = true;

    let Some((uid, static_key, ap)) = read_mode_a_auth(&st, &mut reader).await else {
        return disguise_response();
    };

    let (resp_tx, resp_rx) = mpsc::channel::<Bytes>(256);
    spawn_mode_a_channel(st, uid, static_key, ap, reader, resp_tx);

    let stream = ReceiverStream::new(resp_rx).map(Ok::<_, Infallible>);
    Response::builder()
        .status(200)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CACHE_CONTROL, "no-store")
        .header("X-Accel-Buffering", "no")
        .body(Body::from_stream(stream))
        .expect("response")
}

/// WebSocket variant of the same mode-A channel (works through proxies that
/// buffer request bodies, e.g. Cloudflare).
async fn ws_handler(State(st): State<Arc<ServerState>>, req: Request) -> Response {
    let (mut parts, _) = req.into_parts();
    let auth = parts
        .headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());

    if !crate::server::bearer_ok(&st, auth) {
        return disguise_response();
    }

    // Plain GETs (browsers, crawlers) get the disguise page too; only real
    // WS upgrades are accepted here.
    let Ok(upgrade) =
        WebSocketUpgrade::<axum::extract::ws::DefaultOnFailedUpgrade>::from_request_parts(
            &mut parts,
            &(),
        )
        .await
    else {
        return disguise_response();
    };
    upgrade.on_upgrade(move |socket| ws_channel(st, socket))
}

async fn ws_channel(st: Arc<ServerState>, socket: WebSocket) {
    let (mut sink, mut stream) = socket.split();

    // incoming binary messages -> AsyncRead for the frame decoder
    let (in_tx, in_rx) = mpsc::channel::<Bytes>(256);
    tokio::spawn(async move {
        while let Some(Ok(msg)) = stream.next().await {
            match msg {
                Message::Binary(b) => {
                    if in_tx.send(b).await.is_err() {
                        break;
                    }
                }
                Message::Close(_) => break,
                _ => {} // tungstenite answers pings automatically
            }
        }
    });

    let mut reader = FrameReader::new(
        StreamAsRead::new(ReceiverStream::new(in_rx).map(Ok::<_, std::convert::Infallible>)),
        None,
        None,
    );
    reader.decoder_mut().raw = true;

    let Some((uid, static_key, ap)) = read_mode_a_auth(&st, &mut reader).await else {
        // Post-upgrade auth failure: quietly close (stealth).
        return;
    };

    // encoded frames -> WS binary messages
    let (resp_tx, mut resp_rx) = mpsc::channel::<Bytes>(256);
    tokio::spawn(async move {
        while let Some(wire) = resp_rx.recv().await {
            if sink.send(Message::Binary(wire)).await.is_err() {
                break;
            }
        }
        let _ = sink.send(Message::Close(None)).await;
    });
    spawn_mode_a_channel(st, uid, static_key, ap, reader, resp_tx);
}

/// Read and verify the in-band AUTH frame (first frame of the channel,
/// sealed with the user's static key).
async fn read_mode_a_auth<R>(
    st: &Arc<ServerState>,
    reader: &mut FrameReader<R>,
) -> Option<(String, [u8; 32], AuthPayload)>
where
    R: AsyncRead + Unpin,
{
    let auth_frame = match timeout(Duration::from_secs(10), reader.read()).await {
        Ok(Ok(Some(f))) if f.ftype == FrameType::Auth => f,
        _ => {
            warn!("fallback: missing/bad in-band auth");
            return None;
        }
    };
    crate::server::auth_from_frame(st, &auth_frame)
}

/// Establish the connection state and drive the mode-A mux loop; wire bytes
/// for the peer are emitted through `resp_tx`.
fn spawn_mode_a_channel<R>(
    st: Arc<ServerState>,
    uid: String,
    static_key: [u8; 32],
    ap: AuthPayload,
    mut reader: FrameReader<R>,
    resp_tx: mpsc::Sender<Bytes>,
) where
    R: AsyncRead + Unpin + Send + 'static,
{
    let session_key = crate::proto::crypto::derive_session_key(&static_key, &ap.salt);
    let cipher = Arc::new(crate::proto::crypto::FrameCipher::new(&session_key));
    reader.set_cipher(cipher.clone());

    let conn_id = st.conn_seq.fetch_add(1, Ordering::Relaxed);
    let cancel = CancellationToken::new();
    let conn = Arc::new(ConnState {
        id: conn_id,
        uid,
        cipher: cipher.clone(),
        stream_counters: CounterGen::stream(),
        rate: RateLimiter::new(st.rate_mbps),
        cancel: cancel.clone(),
        sessions: Default::default(),
        tcp_routes: Default::default(),
        udp_routes: Default::default(),
        max_per_conn: crate::server::wt::MAX_PER_CONN,
        last_active: std::sync::atomic::AtomicI64::new(crate::server::state::now_millis()),
    });
    st.conns.insert(conn_id, conn.clone());

    let (frame_tx, mut frame_rx) = mpsc::channel::<OutFrame>(256);
    {
        let enc = FrameEncoder::new(cipher.clone(), conn.stream_counters.clone());
        tokio::spawn(async move {
            while let Some(f) = frame_rx.recv().await {
                match enc.encode(f.ftype, f.flags, f.sid, &f.payload) {
                    Ok(wire) => {
                        if resp_tx.send(wire).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });
    }

    tokio::spawn(async move {
        let sink = FrameSink::Chan(frame_tx);
        let hooks = Hooks {
            st: st.clone(),
            conn: conn.clone(),
            sink: sink.clone(),
        };
        run_server_mux(reader, sink, Arc::new(hooks), cancel).await;
        conn.cancel.cancel();
        st.conns.remove(&conn.id);
    });
}

// ---------------------------------------------------------------------------
// Plain HTTP (port 80): pure 301 front + optional ACME http-01
// ---------------------------------------------------------------------------

/// Router for the plaintext listener. Everything is 301-redirected to HTTPS;
/// `/.well-known/acme-challenge/{token}` is served from `acme_dir` when set
/// (certbot http-01). The proxy API is intentionally NOT reachable in
/// plaintext.
pub fn plain_router(acme_dir: Option<PathBuf>) -> Router {
    Router::new()
        .route("/.well-known/acme-challenge/{token}", get(acme_handler))
        .fallback(any(redirect_handler))
        .with_state(acme_dir)
}

async fn redirect_handler(req: Request) -> Response {
    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let path = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    redirect_response(&build_redirect_target(host, path))
}

async fn acme_handler(
    State(acme_dir): State<Option<PathBuf>>,
    Path(token): Path<String>,
    req: Request,
) -> Response {
    if let Some(dir) = acme_dir {
        if is_safe_acme_token(&token) {
            let path = dir.join(&token);
            if let Ok(body) = tokio::fs::read(&path).await {
                return Response::builder()
                    .status(200)
                    .header(header::CONTENT_TYPE, "text/plain")
                    .body(Body::from(body))
                    .expect("acme response");
            }
        }
    }
    // Unknown token / no acme-dir: behave like the rest of port 80.
    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let path = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    redirect_response(&build_redirect_target(host, path))
}

/// Target for the http->https redirect. `host` comes from the Host header
/// (ports preserved when present).
fn build_redirect_target(host: &str, path: &str) -> String {
    let host = host.trim();
    let host_ok = !host.is_empty()
        && host.len() <= 253
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']'));
    let host = if host_ok { host } else { "localhost" };
    let path = if path.starts_with('/') { path } else { "/" };
    format!("https://{host}{path}")
}

fn redirect_response(location: &str) -> Response {
    Response::builder()
        .status(301)
        .header(header::LOCATION, location)
        .header(header::STRICT_TRANSPORT_SECURITY, "max-age=31536000")
        .header(header::CONTENT_LENGTH, "0")
        .body(Body::empty())
        .expect("redirect response")
}

/// Let's Encrypt tokens are base64url: [A-Za-z0-9_-], no dots or slashes —
/// this also blocks path traversal.
fn is_safe_acme_token(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= 255
        && token
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

// ---------------------------------------------------------------------------
// Listeners
// ---------------------------------------------------------------------------

pub async fn run_tls(
    st: Arc<ServerState>,
    addr: SocketAddr,
    cert: PathBuf,
    key: PathBuf,
) -> Result<()> {
    let config = axum_server::tls_rustls::RustlsConfig::from_pem_file(cert, key).await?;
    let app = router(st);
    info!("HTTPS fallback (mode A POST + disguise) listening on tcp://{addr}");
    axum_server::bind_rustls(addr, config)
        .serve(app.into_make_service())
        .await?;
    Ok(())
}

/// Plaintext front: 301 -> HTTPS for everything, optional ACME challenge.
pub async fn run_plain(addr: SocketAddr, acme_dir: Option<PathBuf>) -> Result<()> {
    let app = plain_router(acme_dir);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!("HTTP front (301 -> HTTPS, ACME http-01) listening on tcp://{addr}");
    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redirect_target() {
        assert_eq!(
            build_redirect_target("example.com", "/a/b?c=d"),
            "https://example.com/a/b?c=d"
        );
        // port preserved when the client sent one
        assert_eq!(
            build_redirect_target("example.com:80", "/"),
            "https://example.com:80/"
        );
        assert_eq!(
            build_redirect_target("[::1]:80", "/x"),
            "https://[::1]:80/x"
        );
        // hostile/missing Host falls back to localhost
        assert_eq!(build_redirect_target("", "/"), "https://localhost/");
        assert_eq!(
            build_redirect_target("evil.com\r\nx", "/"),
            "https://localhost/"
        );
        assert_eq!(build_redirect_target("ok.com", ""), "https://ok.com/");
    }

    #[test]
    fn acme_token_safety() {
        assert!(is_safe_acme_token("kF4x9_-abc123"));
        assert!(!is_safe_acme_token("../secret"));
        assert!(!is_safe_acme_token(".."));
        assert!(!is_safe_acme_token("a/b"));
        assert!(!is_safe_acme_token("a.b"));
        assert!(!is_safe_acme_token(""));
        assert!(!is_safe_acme_token(&"x".repeat(256)));
    }
}
