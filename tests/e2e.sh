#!/usr/bin/env bash
# End-to-end test: operator server + agent + a SOCKS request that must traverse
# the reverse tunnel to a local origin server and come back intact.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${WORMGATE_BIN:-$ROOT/target/release/w0rmgate}"
[ -x "$BIN" ] || { echo "build first: cargo build --release"; exit 2; }

WORK="$(mktemp -d)"; trap 'kill $(jobs -p) 2>/dev/null; rm -rf "$WORK"' EXIT
mkdir -p "$WORK/www"; echo "MARKER123" > "$WORK/www/marker.txt"

( cd "$WORK/www" && python3 -m http.server 18080 --bind 127.0.0.1 >/dev/null 2>&1 ) &
"$BIN" server --control 127.0.0.1:17000 --socks 127.0.0.1:11080 >"$WORK/server.log" 2>&1 &
"$BIN" agent  --connect 127.0.0.1:17000 >"$WORK/agent.log" 2>&1 &

for _ in $(seq 1 40); do
  grep -q 'SOCKS5 ready' "$WORK/server.log" && grep -q 'tunnel established' "$WORK/agent.log" && break
  sleep 0.2
done

fail=0
for n in $(seq 1 8); do
  out="$(curl -s --max-time 8 --socks5-hostname 127.0.0.1:11080 http://127.0.0.1:18080/marker.txt)"
  [ "$out" = "MARKER123" ] || { echo "request $n FAILED ('$out')"; fail=1; }
done
[ $fail -eq 0 ] && echo "e2e OK: 8/8 requests tunnelled" || { echo "e2e FAILED"; exit 1; }
