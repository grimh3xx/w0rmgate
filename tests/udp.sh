#!/usr/bin/env bash
# SOCKS5 UDP ASSOCIATE through the tunnel: a datagram must reach a UDP echo
# server and come back intact.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${WORMGATE_BIN:-$ROOT/target/release/w0rmgate}"
[ -x "$BIN" ] || { echo "build first"; exit 2; }
WORK="$(mktemp -d)"; trap 'kill $(jobs -p) 2>/dev/null; rm -rf "$WORK"' EXIT
cat > "$WORK/echo.py" <<'PY'
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(("127.0.0.1",19090))
while True:
    d,a=s.recvfrom(4096); s.sendto(b"ECHO:"+d,a)
PY
python3 "$WORK/echo.py" &
"$BIN" server --control 127.0.0.1:17002 --socks 127.0.0.1:11082 >"$WORK/s" 2>&1 &
"$BIN" agent  --connect 127.0.0.1:17002 >"$WORK/a" 2>&1 &
for _ in $(seq 1 40); do grep -q 'SOCKS5 ready' "$WORK/s" && grep -q 'tunnel established' "$WORK/a" && break; sleep 0.2; done
python3 - <<'PY'
import socket, struct, sys
t=socket.create_connection(("127.0.0.1",11082),timeout=5)
t.sendall(b"\x05\x01\x00"); assert t.recv(2)==b"\x05\x00"
t.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
rep=t.recv(10); assert rep[1]==0
rip=socket.inet_ntoa(rep[4:8]); rport=struct.unpack(">H",rep[8:10])[0]
u=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); u.settimeout(5)
hdr=b"\x00\x00\x00\x01"+socket.inet_aton("127.0.0.1")+struct.pack(">H",19090)
u.sendto(hdr+b"ping",(rip,rport))
data,_=u.recvfrom(4096)
sys.exit(0 if data[10:]==b"ECHO:ping" else 1)
PY
rc=$?
[ $rc -eq 0 ] && echo "udp associate: OK (datagram tunnelled and echoed)" || { echo "udp associate: FAILED"; exit 1; }
