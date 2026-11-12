//! Tunnel framing protocol.
//! Frame: [id:u32 BE][kind:u8][len:u32 BE][payload:len]
use anyhow::{bail, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const OPEN: u8 = 1;
pub const DATA: u8 = 2;
pub const CLOSE: u8 = 3;

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

    #[tokio::test]
    async fn empty_payload_has_no_body() {
        let mut buf = Vec::new();
        write_frame(&mut buf, &Frame::close(3)).await.unwrap();
        assert_eq!(buf.len(), 9); // só header
    }
}
