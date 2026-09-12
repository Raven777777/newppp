//! UDP target/source address encoding (SOCKS5-style but compact).
//!
//! Layout: `type(1) | addr | port(u16 LE)`
//! * type 1: IPv4 (4 bytes)
//! * type 2: IPv6 (16 bytes)
//! * type 3: domain (u8 len + bytes)

use anyhow::{ensure, Result};
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum UdpAddr {
    V4(SocketAddrV4),
    V6(SocketAddrV6),
    Domain(String, u16),
}

impl UdpAddr {
    pub fn encode(&self, out: &mut Vec<u8>) {
        self.encode_with(out, false)
    }

    /// `be_ports = true` writes ports in network byte order (SOCKS5 wire
    /// format); internal frame encoding uses little-endian.
    pub fn encode_with(&self, out: &mut Vec<u8>, be_ports: bool) {
        let put = |out: &mut Vec<u8>, port: u16| {
            if be_ports {
                out.extend_from_slice(&port.to_be_bytes());
            } else {
                out.extend_from_slice(&port.to_le_bytes());
            }
        };
        match self {
            UdpAddr::V4(a) => {
                out.push(1);
                out.extend_from_slice(&a.ip().octets());
                put(out, a.port());
            }
            UdpAddr::V6(a) => {
                out.push(2);
                out.extend_from_slice(&a.ip().octets());
                put(out, a.port());
            }
            UdpAddr::Domain(h, p) => {
                out.push(3);
                out.push(h.len() as u8);
                out.extend_from_slice(h.as_bytes());
                put(out, *p);
            }
        }
    }

    pub fn decode(r: &mut Reader) -> Result<Self> {
        Self::decode_with(r, false)
    }

    pub fn decode_with(r: &mut Reader, be_ports: bool) -> Result<Self> {
        let t = r.read_u8()?;
        let read_port = |r: &mut Reader| -> Result<u16> {
            if be_ports {
                r.read_u16_be()
            } else {
                r.read_u16()
            }
        };
        match t {
            1 => {
                let b = r.read_bytes(4)?;
                let port = read_port(r)?;
                let ip = std::net::Ipv4Addr::new(b[0], b[1], b[2], b[3]);
                Ok(UdpAddr::V4(SocketAddrV4::new(ip, port)))
            }
            2 => {
                let b = r.read_bytes(16)?;
                let port = read_port(r)?;
                let mut oct = [0u8; 16];
                oct.copy_from_slice(b);
                let ip = std::net::Ipv6Addr::from(oct);
                Ok(UdpAddr::V6(SocketAddrV6::new(ip, port, 0, 0)))
            }
            3 => {
                let l = r.read_u8()? as usize;
                let d = r.read_bytes(l)?;
                let port = read_port(r)?;
                Ok(UdpAddr::Domain(String::from_utf8(d.to_vec())?, port))
            }
            _ => anyhow::bail!("bad address type {t}"),
        }
    }

    /// Resolve to a socket address (DNS for domains), 5s timeout.
    pub async fn resolve(&self) -> Result<SocketAddr> {
        match self {
            UdpAddr::V4(a) => Ok(SocketAddr::V4(*a)),
            UdpAddr::V6(a) => Ok(SocketAddr::V6(*a)),
            UdpAddr::Domain(h, p) => {
                let fut = tokio::net::lookup_host((h.as_str(), *p));
                let mut addrs = tokio::time::timeout(std::time::Duration::from_secs(5), fut)
                    .await
                    .map_err(|_| anyhow::anyhow!("resolve timeout"))??;
                addrs
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("no addresses for {h}"))
            }
        }
    }
}

pub struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(b: &'a [u8]) -> Self {
        Self { b, pos: 0 }
    }

    pub fn read_u8(&mut self) -> Result<u8> {
        ensure!(self.pos < self.b.len(), "read past end");
        let v = self.b[self.pos];
        self.pos += 1;
        Ok(v)
    }

    pub fn read_u16(&mut self) -> Result<u16> {
        let b = self.read_bytes(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    pub fn read_u16_be(&mut self) -> Result<u16> {
        let b = self.read_bytes(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    pub fn read_bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        // `len - pos` instead of `pos + n`: no overflow even for huge `n`
        ensure!(self.b.len() - self.pos >= n, "read past end");
        let s = &self.b[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    pub fn rest(&mut self) -> &'a [u8] {
        let s = &self.b[self.pos..];
        self.pos = self.b.len();
        s
    }
}

/// Parse a SOCKS5 UDP request header: RSV(2) FRAG(1) ATYP(1) ADDR PORT.
/// Ports are network byte order (RFC 1928). Fragmented datagrams rejected.
pub fn parse_socks5_udp(packet: &[u8]) -> Result<(UdpAddr, Vec<u8>)> {
    let mut r = Reader::new(packet);
    let _rsv = r.read_u16()?;
    let frag = r.read_u8()?;
    ensure!(frag == 0, "UDP fragmentation not supported");
    let addr = UdpAddr::decode_with(&mut r, true)?;
    Ok((addr, r.rest().to_vec()))
}

/// Build a SOCKS5 UDP reply header for `addr` (network byte order ports).
pub fn build_socks5_udp(addr: &UdpAddr, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(8 + payload.len());
    v.extend_from_slice(&[0, 0, 0]);
    addr.encode_with(&mut v, true);
    v.extend_from_slice(payload);
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addr_roundtrip() {
        for a in [
            UdpAddr::V4(SocketAddrV4::new([8, 8, 8, 8].into(), 53)),
            UdpAddr::Domain("dns.google".into(), 853),
        ] {
            let mut v = Vec::new();
            a.encode(&mut v);
            let mut r = Reader::new(&v);
            let d = UdpAddr::decode(&mut r).unwrap();
            assert_eq!(a, d);
        }
    }

    #[test]
    fn socks5_udp_port_is_big_endian() {
        // RFC 1928: ports in the SOCKS5 UDP header are network byte order.
        let target = UdpAddr::V4(SocketAddrV4::new([1, 2, 3, 4].into(), 0xE450)); // 58448
        let pkt = build_socks5_udp(&target, b"hi");
        // header: RSV(2) FRAG(1) ATYP(1) ADDR(4) PORT(2)
        assert_eq!(&pkt[8..10], &[0xE4, 0x50]);
        let (t2, p2) = parse_socks5_udp(&pkt).unwrap();
        assert_eq!(target, t2);
        assert_eq!(p2, b"hi");
    }

    #[test]
    fn socks5_udp_roundtrip() {
        let target = UdpAddr::V4(SocketAddrV4::new([1, 2, 3, 4].into(), 9999));
        let pkt = build_socks5_udp(&target, b"payload");
        let (t2, p2) = parse_socks5_udp(&pkt).unwrap();
        assert_eq!(target, t2);
        assert_eq!(p2, b"payload");
    }
}
