#!/usr/bin/env bash
# Soak test: 60 concurrent requests through the reverse tunnel must all succeed.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${WORMGATE_BIN:-$ROOT/target/release/w0rmgate}"
[ -x "$BIN" ] || { echo "build first"; exit 2; }
WORK="$(mktemp -d)"; trap 'kill $(jobs -p) 2>/dev/null; rm -rf "$WORK"' EXIT
mkdir -p "$WORK/www"; echo SOAKOK > "$WORK/www/m.txt"
( cd "$WORK/www" && python3 -m http.server 18081 --bind 127.0.0.1 >/dev/null 2>&1 ) &
"$BIN" server --control 127.0.0.1:17001 --socks 127.0.0.1:11081 >"$WORK/s" 2>&1 &
"$BIN" agent  --connect 127.0.0.1:17001 >"$WORK/a" 2>&1 &
for _ in $(seq 1 40); do grep -q 'SOCKS5 ready' "$WORK/s" && grep -q 'tunnel established' "$WORK/a" && break; sleep 0.2; done
pids=""
for n in $(seq 1 60); do
  ( curl -s --max-time 10 --socks5-hostname 127.0.0.1:11081 http://127.0.0.1:18081/m.txt > "$WORK/r_$n" ) & pids="$pids $!"
done
for p in $pids; do wait "$p"; done
ok=0; for n in $(seq 1 60); do [ "$(cat "$WORK/r_$n" 2>/dev/null)" = SOAKOK ] && ok=$((ok+1)); done
echo "soak: $ok/60 concurrent requests OK"
[ "$ok" -eq 60 ]
