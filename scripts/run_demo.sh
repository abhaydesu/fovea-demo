#!/usr/bin/env bash
# Full bring-up: build services + agent + UI, start the containers, run the agent.
# Needs sudo for the agent (eBPF). Ctrl+C stops the agent and detaches all programs.
set -euo pipefail
cd "$(dirname "$0")/.."

./scripts/check_env.sh

echo "== building demo services, agent and UI"
mkdir -p bin demo/bin
for s in frontend orders inventory; do CGO_ENABLED=0 go build -o demo/bin/$s ./demo/$s; done
go build -o bin/fovea-agent ./cmd/fovea-agent
[ -d ui/node_modules ] || (cd ui && npm install --no-audit --no-fund)
(cd ui && npm run build >/dev/null)

echo "== starting containers (compose project 'demo')"
(cd demo && docker compose -p demo up -d --build)
sleep 2

echo
echo "UI:      http://localhost:9090"
echo "Traffic: ./scripts/traffic.sh   (in another terminal)"
echo
(sleep 2; xdg-open http://localhost:9090 >/dev/null 2>&1 || true) &
exec sudo ./bin/fovea-agent -project demo -ui ui/dist
