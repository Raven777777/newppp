//! Local HTTP proxy inbound: CONNECT tunneling (primary) plus a minimal
//! absolute-URI GET/POST passthrough for plain HTTP.

use anyhow::{anyhow, Result};
use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{debug, info};

use crate::client::outbound::Outbound;

const MAX_HEAD: usize = 16 * 1024;

/// Minimal error response so clients see a clean failure instead of a
/// connection reset when the outbound cannot be established.
async fn reply_error(sock: &mut tokio::net::TcpStream) {
    let _ = sock
        .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        .await;
}

pub async fn run(bind: String, ob: Outbound) -> Result<()> {
    let listener = TcpListener::bind(&bind).await?;
    info!("HTTP proxy listening on {bind}");
    loop {
        let (sock, peer) = listener.accept().await?;
        let ob = ob.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(sock, ob).await {
                debug!("http proxy conn from {peer} ended: {e:#}");
            }
        });
    }
}

async fn handle(mut sock: tokio::net::TcpStream, ob: Outbound) -> Result<()> {
    let mut buf = BytesMut::new();
    // read until end of request head
    let head_end = loop {
        let mut chunk = [0u8; 4096];
        let n = sock.read(&mut chunk).await?;
        if n == 0 {
            anyhow::bail!("client closed before sending request");
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > MAX_HEAD {
            anyhow::bail!("request head too large");
        }
        if let Some(pos) = find_double_crlf(&buf) {
            break pos;
        }
    };

    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let target = parts.next().unwrap_or_default().to_string();
    let _version = parts.next().unwrap_or_default();

    if method.eq_ignore_ascii_case("CONNECT") {
        let (host, port) = parse_host_port(&target, 443)?;
        let rest = buf.split_off(head_end + 4); // bytes after the head
        let mut remote = match ob.open_tcp(&host, port).await {
            Ok(r) => r,
            Err(e) => {
                reply_error(&mut sock).await;
                return Err(e);
            }
        };
        sock.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        // sock + leftover pipelined bytes form a duplex with the remote
        let mut local = Pipe {
            inner: sock,
            pending: rest,
        };
        tokio::io::copy_bidirectional(&mut local, &mut remote).await?;
        Ok(())
    } else {
        // absolute-URI forward (http://host[:port]/path)
        let hostport = target
            .strip_prefix("http://")
            .ok_or_else(|| anyhow!("only http:// and CONNECT supported"))?;
        let end = hostport.find('/').unwrap_or(hostport.len());
        let (host, port) = parse_host_port(&hostport[..end], 80)?;
        let mut remote = match ob.open_tcp(&host, port).await {
            Ok(r) => r,
            Err(e) => {
                reply_error(&mut sock).await;
                return Err(e);
            }
        };
        remote.write_all(&buf).await?; // forward head (+ any pipelined bytes)
        tokio::io::copy_bidirectional(&mut sock, &mut remote).await?;
        Ok(())
    }
}

/// Duplex wrapper: replays buffered bytes before delegating to the inner
/// stream (both directions).
struct Pipe<S> {
    inner: S,
    pending: BytesMut,
}

impl<S: AsyncRead + Unpin> AsyncRead for Pipe<S> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        out: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if !this.pending.is_empty() {
            let n = this.pending.len().min(out.remaining());
            let b = this.pending.split_to(n);
            out.put_slice(&b);
            return std::task::Poll::Ready(Ok(()));
        }
        std::pin::Pin::new(&mut this.inner).poll_read(cx, out)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Pipe<S> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn parse_host_port(s: &str, default_port: u16) -> Result<(String, u16)> {
    let s = s.trim();
    anyhow::ensure!(!s.is_empty(), "empty target");
    // strip IPv6 brackets
    if let Some(stripped) = s.strip_prefix('[') {
        let end = stripped
            .find(']')
            .ok_or_else(|| anyhow!("bad ipv6 target"))?;
        let host = &stripped[..end];
        let port = stripped[end + 1..]
            .strip_prefix(':')
            .map(|p| p.parse())
            .transpose()?
            .unwrap_or(default_port);
        return Ok((host.to_string(), port));
    }
    match s.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') => Ok((h.to_string(), p.parse()?)),
        _ => Ok((s.to_string(), default_port)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_port() {
        assert_eq!(
            parse_host_port("example.com:8080", 80).unwrap(),
            ("example.com".into(), 8080)
        );
        assert_eq!(
            parse_host_port("example.com", 443).unwrap(),
            ("example.com".into(), 443)
        );
        assert_eq!(
            parse_host_port("[::1]:9090", 80).unwrap(),
            ("::1".into(), 9090)
        );
        assert_eq!(
            parse_host_port("[2001:db8::1]", 443).unwrap(),
            ("2001:db8::1".into(), 443)
        );
    }
}
