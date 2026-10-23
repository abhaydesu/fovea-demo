#!/usr/bin/env bash
# Evaluation for synopsis objective 7: reconstruction accuracy + CPU / latency overhead.
#
#   1. stop the agent (Ctrl+C), containers stay up:   ./scripts/bench.sh baseline [N] [C]
#   2. start the agent (sudo ./bin/fovea-agent ...):  ./scripts/bench.sh agent    [N] [C]
#   3. compare:                                       ./scripts/bench.sh report
#
# Both runs send the same N requests through frontend->orders->inventory.
set -euo pipefail
cd "$(dirname "$0")/.."
N=${2:-2000}; C=${3:-8}
go build -o bin/fovea-load ./cmd/fovea-load
mkdir -p bench
case "${1:-}" in
  baseline)
    if pgrep -x fovea-agent >/dev/null; then echo "stop fovea-agent first (Ctrl+C in its terminal)"; exit 1; fi
    ./bin/fovea-load -n 200 -c "$C" >/dev/null          # warm-up
    ./bin/fovea-load -n "$N" -c "$C" -truth bench/baseline.json ;;
  agent)
    PID=$(pgrep -x fovea-agent | head -1 || true)
    [ -n "$PID" ] || { echo "start fovea-agent first"; exit 1; }
    ./bin/fovea-load -n 200 -c "$C" >/dev/null          # warm-up
    sleep 1
    ./bin/fovea-load -n "$N" -c "$C" -pid "$PID" -truth bench/agent.json
    sleep 2                                              # let the assembler drain
    ./bin/fovea-load -verify bench/agent.json ;;
  report)
    for f in baseline agent; do [ -f bench/$f.json ] || { echo "missing bench/$f.json"; exit 1; }; done
    jq -rn --slurpfile b bench/baseline.json --slurpfile a bench/agent.json '
      def r: . * 100 | round / 100;
      "                     baseline    with Fovea    overhead",
      "throughput (req/s)   \($b[0].rps|r)\t\($a[0].rps|r)\t\((($b[0].rps-$a[0].rps)/$b[0].rps*100)|r)%",
      "latency p50 (ms)     \($b[0].p50_ms|r)\t\($a[0].p50_ms|r)\t+\(($a[0].p50_ms-$b[0].p50_ms)|r) ms",
      "latency p95 (ms)     \($b[0].p95_ms|r)\t\($a[0].p95_ms|r)\t+\(($a[0].p95_ms-$b[0].p95_ms)|r) ms",
      "latency p99 (ms)     \($b[0].p99_ms|r)\t\($a[0].p99_ms|r)\t+\(($a[0].p99_ms-$b[0].p99_ms)|r) ms",
      "agent CPU            -\t\($a[0].agent_cpu_percent_of_one_core|r)% of one core"' ;;
  *) echo "usage: $0 baseline|agent|report [N] [C]"; exit 1 ;;
esac
