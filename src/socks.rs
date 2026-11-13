//! Minimal SOCKS5 server-side handshake (CONNECT, no auth).
use anyhow::{anyhow, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub async fn handshake(s: &mut TcpStream) -> Result<String> {
    // greeting
    let mut head = [0u8; 2];
    s.read_exact(&mut head).await?;
    if head[0] != 0x05 {
        return Err(anyhow!("not SOCKS5"));
    }
    let nmethods = head[1] as usize;
    let mut methods = vec![0u8; nmethods];
    s.read_exact(&mut methods).await?;
    // reply: no authentication
    s.write_all(&[0x05, 0x00]).await?;

    // request
    let mut req = [0u8; 4];
    s.read_exact(&mut req).await?;
    if req[0] != 0x05 {
        return Err(anyhow!("invalid version in request"));
    }
    if req[1] != 0x01 {
        // CONNECT only
        s.write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
        return Err(anyhow!("unsupported command"));
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
        _ => return Err(anyhow!("atyp invalid")),
    };
    let mut p = [0u8; 2];
    s.read_exact(&mut p).await?;
    let port = u16::from_be_bytes(p);

    // success (dummy bind addr)
    s.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
    Ok(format!("{host}:{port}"))
}
