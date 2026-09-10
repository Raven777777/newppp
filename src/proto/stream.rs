//! Bridging helpers between message streams and `AsyncRead`.

use bytes::{BufMut, Bytes, BytesMut};

/// AsyncRead adapter over a bytes stream (axum request body, WS message
/// channel, ...). Frames may span multiple stream items; items may contain
/// multiple or partial frames — the frame decoder reassembles.
pub struct StreamAsRead<S> {
    stream: S,
    buf: BytesMut,
    done: bool,
}

impl<S> StreamAsRead<S> {
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            buf: BytesMut::new(),
            done: false,
        }
    }
}

impl<S, E> tokio::io::AsyncRead for StreamAsRead<S>
where
    S: futures_util::Stream<Item = Result<Bytes, E>> + Unpin,
    E: std::fmt::Display,
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
                return std::task::Poll::Ready(Ok(())); // EOF
            }
            match std::pin::Pin::new(&mut this.stream).poll_next(cx) {
                std::task::Poll::Pending => return std::task::Poll::Pending,
                std::task::Poll::Ready(Some(Ok(b))) => this.buf.put(b),
                std::task::Poll::Ready(Some(Err(e))) => {
                    return std::task::Poll::Ready(Err(std::io::Error::other(e.to_string())))
                }
                std::task::Poll::Ready(None) => this.done = true,
            }
        }
    }
}
