//! Tunnel framing protocol.
//! Frame: [id:u32 BE][kind:u8][len:u32 BE][payload:len]
use anyhow::{bail, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const OPEN: u8 = 1;
pub const DATA: u8 = 2;
pub const CLOSE: u8 = 3;
pub const UDP: u8 = 4;

/// Hard cap on a single frame payload (16 MiB) to bound memory on a hostile peer.
const MAX_FRAME: usize = 16 * 1024 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub struct Frame {
    pub id: u32,
    pub kind: u8,
    pub data: Vec<u8>,
}

impl Frame {
    pub fn open(id: u32, target: &str) -> Self {
        Frame { id, kind: OPEN, data: target.as_bytes().to_vec() }
    }
    pub fn data(id: u32, data: Vec<u8>) -> Self {
        Frame { id, kind: DATA, data }
    }
    pub fn close(id: u32) -> Self {
        Frame { id, kind: CLOSE, data: Vec::new() }
    }
    /// A UDP datagram tagged with its peer "host:port".
    pub fn udp(id: u32, addr: &str, data: &[u8]) -> Self {
        let mut payload = (addr.len() as u16).to_be_bytes().to_vec();
        payload.extend_from_slice(addr.as_bytes());
        payload.extend_from_slice(data);
        Frame { id, kind: UDP, data: payload }
    }
}

/// Splits a UDP frame payload into (peer addr, datagram).
pub fn parse_udp(data: &[u8]) -> Option<(String, &[u8])> {
    if data.len() < 2 {
        return None;
    }
    let n = u16::from_be_bytes([data[0], data[1]]) as usize;
    let addr = data.get(2..2 + n)?;
    let payload = data.get(2 + n..)?;
    Some((String::from_utf8_lossy(addr).to_string(), payload))
}

pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<Frame> {
    let mut hdr = [0u8; 9];
    r.read_exact(&mut hdr).await?;
    let id = u32::from_be_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
    let kind = hdr[4];
    let len = u32::from_be_bytes([hdr[5], hdr[6], hdr[7], hdr[8]]) as usize;
    if len > MAX_FRAME {
        bail!("frame too large: {len} bytes");
    }
    let mut data = vec![0u8; len];
    if len > 0 {
        r.read_exact(&mut data).await?;
    }
    Ok(Frame { id, kind, data })
}

pub async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, f: &Frame) -> Result<()> {
    let mut hdr = [0u8; 9];
    hdr[0..4].copy_from_slice(&f.id.to_be_bytes());
    hdr[4] = f.kind;
    hdr[5..9].copy_from_slice(&(f.data.len() as u32).to_be_bytes());
    w.write_all(&hdr).await?;
    if !f.data.is_empty() {
        w.write_all(&f.data).await?;
    }
    w.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[tokio::test]
    async fn roundtrip_data() {
        let f = Frame::data(42, b"hello world".to_vec());
        let mut buf = Vec::new();
        write_frame(&mut buf, &f).await.unwrap();
        let mut cur = Cursor::new(buf);
        let got = read_frame(&mut cur).await.unwrap();
        assert_eq!(got, f);
    }

    #[tokio::test]
    async fn roundtrip_open_and_close() {
        for f in [Frame::open(1, "10.0.0.5:445"), Frame::close(7)] {
            let mut buf = Vec::new();
            write_frame(&mut buf, &f).await.unwrap();
            let mut cur = Cursor::new(buf);
            assert_eq!(read_frame(&mut cur).await.unwrap(), f);
        }
    }

    #[test]
    fn udp_roundtrip() {
        let f = Frame::udp(5, "1.2.3.4:53", b"\x00\x01query");
        let (addr, data) = parse_udp(&f.data).unwrap();
        assert_eq!(addr, "1.2.3.4:53");
        assert_eq!(data, b"\x00\x01query");
    }

    #[test]
    fn parse_udp_rejects_truncated() {
        assert!(parse_udp(&[0x00]).is_none());
        assert!(parse_udp(&[0x00, 0x09, b'a']).is_none()); // claims 9, has 1
    }

    #[tokio::test]
    async fn fuzz_read_frame_no_panic() {
        let mut x: u64 = 0x00C0_FFEE_1234_5678;
        for _ in 0..5000 {
            x ^= x << 13; x ^= x >> 7; x ^= x << 17;
            let len = (x as usize) % 64;
            let mut buf: Vec<u8> = (0..len).map(|i| (x >> (i % 56)) as u8).collect();
            // bound the declared length field so the test stays fast
            if buf.len() >= 9 {
                buf[5] = 0; buf[6] = 0; buf[7] = 0; buf[8] = (x as u8) & 0x1F;
            }
            let mut cur = Cursor::new(buf);
            let _ = read_frame(&mut cur).await;
        }
    }

    #[tokio::test]
    async fn empty_payload_has_no_body() {
        let mut buf = Vec::new();
        write_frame(&mut buf, &Frame::close(3)).await.unwrap();
        assert_eq!(buf.len(), 9); // só header
    }
}
