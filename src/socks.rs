//! SOCKS5 server-side: greeting, CONNECT and UDP ASSOCIATE (no auth).
use anyhow::{anyhow, Result};
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub enum Command {
    Connect(String),
    UdpAssociate,
}

/// Reads the greeting and the request; returns the command. Does not send the
/// final reply — the caller sends it (CONNECT success, or the UDP relay addr).
pub async fn handshake(s: &mut TcpStream) -> Result<Command> {
    let mut head = [0u8; 2];
    s.read_exact(&mut head).await?;
    if head[0] != 0x05 {
        return Err(anyhow!("not SOCKS5"));
    }
    let nmethods = head[1] as usize;
    let mut methods = vec![0u8; nmethods];
    s.read_exact(&mut methods).await?;
    s.write_all(&[0x05, 0x00]).await?; // reply: no authentication

    let mut req = [0u8; 4];
    s.read_exact(&mut req).await?;
    if req[0] != 0x05 {
        return Err(anyhow!("invalid version in request"));
    }
    let host = match req[3] {
        0x01 => {
            let mut a = [0u8; 4];
            s.read_exact(&mut a).await?;
            format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3])
        }
        0x03 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l).await?;
            let mut d = vec![0u8; l[0] as usize];
            s.read_exact(&mut d).await?;
            String::from_utf8_lossy(&d).to_string()
        }
        0x04 => {
            let mut a = [0u8; 16];
            s.read_exact(&mut a).await?;
            let seg: Vec<String> = a
                .chunks(2)
                .map(|c| format!("{:x}", u16::from_be_bytes([c[0], c[1]])))
                .collect();
            format!("[{}]", seg.join(":"))
        }
        _ => return Err(anyhow!("invalid atyp")),
    };
    let mut p = [0u8; 2];
    s.read_exact(&mut p).await?;
    let port = u16::from_be_bytes(p);

    match req[1] {
        0x01 => Ok(Command::Connect(format!("{host}:{port}"))),
        0x03 => Ok(Command::UdpAssociate),
        _ => {
            s.write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
            Err(anyhow!("unsupported command"))
        }
    }
}

/// CONNECT success reply (dummy bind addr).
pub async fn reply_connect(s: &mut TcpStream) -> Result<()> {
    s.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
    Ok(())
}

/// UDP ASSOCIATE success reply carrying the relay socket's address.
pub async fn reply_udp(s: &mut TcpStream, bnd: SocketAddr) -> Result<()> {
    let mut r = vec![0x05, 0x00, 0x00, 0x01];
    match bnd {
        SocketAddr::V4(v4) => {
            r.extend_from_slice(&v4.ip().octets());
            r.extend_from_slice(&v4.port().to_be_bytes());
        }
        SocketAddr::V6(_) => {
            r.extend_from_slice(&[0, 0, 0, 0]);
            r.extend_from_slice(&bnd.port().to_be_bytes());
        }
    }
    s.write_all(&r).await?;
    Ok(())
}

/// Parses a SOCKS5 UDP request header, returning (target "host:port", payload).
pub fn parse_udp_header(buf: &[u8]) -> Option<(String, &[u8])> {
    if buf.len() < 4 || buf[2] != 0 {
        return None; // FRAG must be 0
    }
    let (host, rest) = match buf[3] {
        0x01 => {
            let a = buf.get(4..8)?;
            (format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3]), buf.get(8..)?)
        }
        0x03 => {
            let l = *buf.get(4)? as usize;
            let a = buf.get(5..5 + l)?;
            (String::from_utf8_lossy(a).to_string(), buf.get(5 + l..)?)
        }
        0x04 => {
            let a = buf.get(4..20)?;
            let seg: Vec<String> = a
                .chunks(2)
                .map(|c| format!("{:x}", u16::from_be_bytes([c[0], c[1]])))
                .collect();
            (format!("[{}]", seg.join(":")), buf.get(20..)?)
        }
        _ => return None,
    };
    if rest.len() < 2 {
        return None;
    }
    let port = u16::from_be_bytes([rest[0], rest[1]]);
    Some((format!("{host}:{port}"), &rest[2..]))
}

/// Builds a SOCKS5 UDP reply header for a datagram coming from `peer`.
pub fn build_udp_header(peer: SocketAddr, data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x00, 0x00, 0x00];
    match peer {
        SocketAddr::V4(v4) => {
            out.push(0x01);
            out.extend_from_slice(&v4.ip().octets());
            out.extend_from_slice(&v4.port().to_be_bytes());
        }
        SocketAddr::V6(v6) => {
            out.push(0x04);
            out.extend_from_slice(&v6.ip().octets());
            out.extend_from_slice(&v6.port().to_be_bytes());
        }
    }
    out.extend_from_slice(data);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_udp_header_ipv4() {
        // RSV RSV FRAG ATYP=1 ip=10.0.0.5 port=53 + "hi"
        let buf = [0, 0, 0, 1, 10, 0, 0, 5, 0, 53, b'h', b'i'];
        let (target, payload) = parse_udp_header(&buf).unwrap();
        assert_eq!(target, "10.0.0.5:53");
        assert_eq!(payload, b"hi");
    }

    #[test]
    fn parse_udp_header_rejects_fragmented() {
        let buf = [0, 0, 1, 1, 10, 0, 0, 5, 0, 53];
        assert!(parse_udp_header(&buf).is_none());
    }

    #[test]
    fn build_udp_header_ipv4_shape() {
        let peer: SocketAddr = "192.168.0.9:5353".parse().unwrap();
        let out = build_udp_header(peer, b"x");
        assert_eq!(&out[0..4], &[0, 0, 0, 1]);
        assert_eq!(&out[4..8], &[192, 168, 0, 9]);
        assert_eq!(out.last(), Some(&b'x'));
    }
}
