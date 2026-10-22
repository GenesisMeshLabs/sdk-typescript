#!/usr/bin/env bash
# Record a walkthrough against a fresh local Network Authority, as the session
# transcript its GIF is rendered from. Every line it prints is a command it ran
# ("$ ...") or that command's output; the prefixes only choose colours.
#
#   npm run build
#   PORT=9443 docs/assets/walkthroughs/record.sh governed-rotation > governed-rotation.txt
#   PORT=9443 docs/assets/walkthroughs/record.sh acting-while-the-na-is-down > acting-while-the-na-is-down.txt
#   python render_terminal_gif.py governed-rotation.txt governed-rotation.gif \
#     --title "Genesis Mesh -- Governed Rotation (TypeScript)"
#
# Needs `genesis-mesh` (the core, 1.7 or later) on PATH, Node.js 22.18 or later
# (it runs the examples' TypeScript directly) and curl. The NA runs in a new
# temporary directory, removed at the end.
set -euo pipefail

walkthrough=${1:?usage: record.sh governed-rotation|acting-while-the-na-is-down}
SDK=$(cd "$(dirname "$0")/../../.." && pwd)
PORT=${PORT:-9443}
export GM_NA_URL="http://127.0.0.1:$PORT"
export SDK
WORK=$(mktemp -d)
NA_PID=
cleanup() {
  if [ -n "$NA_PID" ]; then kill "$NA_PID" 2>/dev/null || true; wait "$NA_PID" 2>/dev/null || true; fi
  cd /
  rm -rf "$WORK"
}
trap cleanup EXIT
cd "$WORK"

# Print a command, then run it.
run() { echo "\$ $*"; eval "$@"; }
# Colour the examples' outcome lines.
style() {
  sed -E -e 's/^(ALLOW|verified: true|use [0-9]: under the grant)/!ok \1/' \
         -e 's/^(DENY|verified: false)/!no \1/'
}
na_start() {
  run "genesis-mesh na start --env-file local/na.env > local/na.log 2>&1 &"
  NA_PID=$!
  for _ in $(seq 1 30); do
    curl -sf "$GM_NA_URL/healthz" > /dev/null && break
    sleep 0.5
  done
  run "curl -s $GM_NA_URL/healthz"
  echo
}
na_stop() {
  run 'kill $NA_PID'
  wait "$NA_PID" 2>/dev/null || true
  NA_PID=
  run "curl -s $GM_NA_URL/healthz || echo 'NA unreachable'"
}

echo "==> A local NA (docs.genesismesh.org/sdk/local-network-authority)"
run "mkdir local"
run "genesis-mesh init --config local/genesis-mesh.toml --home local/.genesis-mesh --network-name MY-PROJECT-DEV --na-endpoint $GM_NA_URL --na-port $PORT --env-file local/na.env > local/setup.log 2>&1"
run "genesis-mesh keygen operator --output local/.genesis-mesh/keys/controller --key-id controller --tier standard --env-file local/na.env >> local/setup.log 2>&1"

case "$walkthrough" in
  governed-rotation)
    na_start
    run 'node "$SDK/examples/governed-rotation.ts" local/.genesis-mesh' | style
    ;;
  acting-while-the-na-is-down)
    run "printf 'EVIDENCE_OUT_OF_BAND=on\nEVIDENCE_GRANTS=on\n' >> local/na.env"
    na_start
    run 'node "$SDK/examples/act-while-na-down.ts" setup local/.genesis-mesh' | style
    echo "==> Stop the NA"
    na_stop
    run 'node "$SDK/examples/act-while-na-down.ts" act local/.genesis-mesh' | style
    echo "==> Start the NA again"
    na_start
    run 'node "$SDK/examples/act-while-na-down.ts" sync local/.genesis-mesh' | style
    ;;
  *)
    echo "unknown walkthrough: $walkthrough" >&2
    exit 2
    ;;
esac
