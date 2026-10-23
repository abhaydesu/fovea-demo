#!/usr/bin/env bash
# Mix of successful and failing orders against the frontend.
# Usage: traffic.sh [rounds=20] [delay=0.5]
BASE=${BASE:-http://localhost:8080}
N=${1:-20}; D=${2:-0.5}
post() { curl -s -o /dev/null -w "POST /order $1 -> %{http_code}\n" -X POST "$BASE/order" -H 'Content-Type: application/json' -d "$1"; }
for i in $(seq 1 "$N"); do
  post '{"item":"gadget","qty":2}'
  post '{"item":"gizmo","qty":1}'
  curl -s -o /dev/null -w "GET /stock/gadget -> %{http_code}\n" "$BASE/stock/gadget"
  if (( i % 3 == 0 )); then post '{"item":"widget","qty":50}'; fi   # insufficient stock -> 500 -> 502
  if (( i % 7 == 0 )); then post '{"item":"doohickey","qty":1}'; fi # unknown item
  sleep "$D"
done
