//! Protocolo de enquadramento do túnel.
//! Frame: [id:u32 BE][kind:u8][len:u32 BE][payload:len]
use anyhow::Result;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const OPEN: u8 = 1;
pub const DATA: u8 = 2;
pub const CLOSE: u8 = 3;

#[derive(Debug)]
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
