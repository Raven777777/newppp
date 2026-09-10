//! Local SOCKS5 inbound (RFC 1928): CONNECT + UDP ASSOCIATE.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};

use crate::client::outbound::Outbound;
use crate::proto::addr::{build_socks5_udp, parse_socks5_udp};

const UDP_IDLE: Duration = Duration::from_secs(300);

pub async fn run(bind: String, ob: Outbound) -> Result<()> {
    let listener = TcpListener::bind(&bind).await?;
    info!("SOCKS5 listening on {bind}");
    loop {
        let (sock, peer) = listener.accept().await?;
        let ob = ob.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(sock, ob).await {
                debug!("socks5 conn from {peer} ended: {e:#}");
            }
        });
    }
}

async fn handle(mut sock: TcpStream, ob: Outbound) -> Result<()> {
    // ---- greeting ----
    let mut h = [0u8; 2];
    sock.read_exact(&mut h).await?;
    if h[0] != 5 {
        anyhow::bail!("not socks5");
    }
    let mut methods = vec![0u8; h[1] as usize];
    sock.read_exact(&mut methods).await?;
    sock.write_all(&[5, 0]).await?; // no auth

    // ---- request ----
    let mut head = [0u8; 3];
    sock.read_exact(&mut head).await?;
    if head[0] != 5 {
        anyhow::bail!("bad socks version");
    }
    let cmd = head[1];
    let target = read_target(&mut sock).await?;

    match cmd {
        1 => connect_cmd(sock, ob, target).await,
        3 => udp_cmd(sock, ob).await,
        _ => {
            reply(&mut sock, 7).await.ok();
            anyhow::bail!("unsupported cmd {cmd}");
        }
    }
}

async fn read_target(sock: &mut TcpStream) -> Result<(String, u16)> {
    let mut atyp = [0u8; 1];
    sock.read_exact(&mut atyp).await?;
    let host = match atyp[0] {
        1 => {
            let mut b = [0u8; 4];
            sock.read_exact(&mut b).await?;
            format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
        }
        3 => {
            let mut l = [0u8; 1];
            sock.read_exact(&mut l).await?;
            let mut d = vec![0u8; l[0] as usize];
            sock.read_exact(&mut d).await?;
            String::from_utf8(d).map_err(|_| anyhow!("bad domain"))?
        }
        4 => {
            let mut b = [0u8; 16];
            sock.read_exact(&mut b).await?;
            std::net::Ipv6Addr::from(b).to_string()
        }
        t => anyhow::bail!("bad atyp {t}"),
    };
    let mut p = [0u8; 2];
    sock.read_exact(&mut p).await?;
    Ok((host, u16::from_be_bytes(p)))
}

async fn reply(sock: &mut TcpStream, code: u8) -> Result<()> {
    sock.write_all(&[5, code, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
    Ok(())
}

async fn connect_cmd(mut sock: TcpStream, ob: Outbound, target: (String, u16)) -> Result<()> {
    match ob.open_tcp(&target.0, target.1).await {
        Ok(mut remote) => {
            reply(&mut sock, 0).await?;
            tokio::io::copy_bidirectional(&mut sock, &mut remote).await?;
            Ok(())
        }
        Err(e) => {
            reply(&mut sock, 1).await.ok();
            Err(e)
        }
    }
}

async fn udp_cmd(mut sock: TcpStream, ob: Outbound) -> Result<()> {
    use std::sync::Mutex as StdMutex;

    // bind relay on the same family as the control connection
    let local = sock.local_addr()?;
    let relay = if local.is_ipv4() {
        UdpSocket::bind("0.0.0.0:0").await?
    } else {
        UdpSocket::bind("[::]:0").await?
    };
    let relay = Arc::new(relay);
    let relay_port = relay.local_addr()?.port();

    let mut pipe = match ob.udp_associate().await {
        Ok(p) => p,
        Err(e) => {
            reply(&mut sock, 1).await.ok();
            return Err(e);
        }
    };

    // reply: BND.ADDR = control-conn local ip, BND.PORT = relay port
    let ip = local.ip();
    let mut rep = vec![5u8, 0, 0, if ip.is_ipv4() { 1 } else { 4 }];
    match ip {
        std::net::IpAddr::V4(v) => rep.extend_from_slice(&v.octets()),
        std::net::IpAddr::V6(v) => rep.extend_from_slice(&v.octets()),
    }
    rep.extend_from_slice(&relay_port.to_be_bytes());
    sock.write_all(&rep).await?;

    let cancel = CancellationToken::new();
    // watch TCP close to end the UDP relay (standard SOCKS5 semantics)
    {
        let c = cancel.clone();
        tokio::spawn(async move {
            let mut s = sock;
            let mut buf = [0u8; 64];
            loop {
                match s.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
            c.cancel();
        });
    }

    let client_addr: Arc<StdMutex<Option<std::net::SocketAddr>>> = Arc::new(StdMutex::new(None));

    // outbound: local client -> remote (records the client endpoint)
    {
        let relay = relay.clone();
        let c = cancel.clone();
        let tx = pipe.outbound.clone();
        let client_addr = client_addr.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                tokio::select! {
                    _ = c.cancelled() => break,
                    r = relay.recv_from(&mut buf) => {
                        match r {
                            Ok((n, from)) => {
                                {
                                    // poisoning can only carry a panic that
                                    // occurred outside the lock scope; the
                                    // stored value stays valid either way
                                    let mut g = client_addr
                                        .lock()
                                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                                    if g.is_none() {
                                        *g = Some(from);
                                    }
                                }
                                if let Ok((dst, payload)) = parse_socks5_udp(&buf[..n]) {
                                    if tx.send((dst, payload)).await.is_err() {
                                        break;
                                    }
                                }
                            }
                            Err(_) => break,
                        }
                    }
                }
            }
        });
    }

    // inbound: remote -> local client, with idle timeout
    let mut last_activity = std::time::Instant::now();
    loop {
        let remaining = UDP_IDLE.saturating_sub(last_activity.elapsed());
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = tokio::time::sleep(remaining) => break, // idle timeout
            r = pipe.inbound.recv() => {
                let Some((src, data)) = r else { break };
                last_activity = std::time::Instant::now();
                let ca = *client_addr
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if let Some(ca) = ca {
                    let _ = relay.send_to(&build_socks5_udp(&src, &data), ca).await;
                }
            }
        }
    }
    debug!("socks5 udp relay closed");
    Ok(())
}
