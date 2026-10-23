# Fovea: payload-level observability with zero instrumentation

eBPF captures the real HTTP request and JSON response payloads exchanged between services, with no changes to the
services. A Go agent reassembles them into transactions, builds a service map and serves a React UI.
See [docs/design.md](docs/design.md) and [docs/demo-script.md](docs/demo-script.md).

## Run the demo

Needs Linux ≥ 5.8 with BTF and cgroup v2, Go, clang, Docker (+compose), Node/npm. `./scripts/check_env.sh` verifies this.

```bash
./scripts/run_demo.sh          # builds everything, starts 3 containers + the agent (sudo), opens http://localhost:9090
                               # /  = project landing page (live preview + counters), /app.html = live dashboard
./scripts/traffic.sh 20 0.5    # in a second terminal: successes + deterministic failures
```

Stop with Ctrl+C (programs are detached). `cd demo && docker compose -p demo down` removes the containers.

## Features

* Payload capture for `read/write/sendto/recvfrom/readv/writev/sendmsg/recvmsg`, filtered in-kernel to the workload cgroups
* HTTP/1.1 reassembly (split chunks, keep-alive, pipelining, chunked, gzip), request/response pairing, client/server dedup
* Service map (req/s, error rate, p50/p95), inferred call chains with root-cause highlighting
* Network flow layer (TCX packet/byte counters on container veths), joined with transactions by 4-tuple
* Credential/PII redaction (default on), JSONL persistence, agent/collector split, ring-buffer drop counter

## Evaluation (synopsis objective 7)

```bash
./scripts/bench.sh baseline 2000 8   # agent stopped
./scripts/bench.sh agent    2000 8   # agent running: throughput, latency, agent CPU, accuracy vs ground truth
./scripts/bench.sh report            # side-by-side overhead table
```

`fovea-load` sends uniquely numbered orders (10% deliberately failing) and records what the client actually saw;
`-verify` checks Fovea reconstructed each one, byte-exact, with the right status, across all three hops, with no duplicates.

## Tests

`go test ./...` covers event decoding, reassembly edge cases, dedup, redaction, flow merging, call-chain inference, graph stats.

## Layout

```
bpf/                 eBPF programs (C): payload capture + flow counters
cmd/
  fovea-agent/       the agent: loads eBPF, reassembles, serves API + UI
  fovea-load/        numbered load generator + accuracy verifier
internal/
  capture/           eBPF loader, ring-buffer reader
  assemble/          HTTP reassembly, request/response pairing, dedup, store
  identity/          IP / container -> service name
  netflow/           per-connection packet and byte counters
  redact/            credential and PII masking
  graph/             service map, error rates, p50/p95
  trace/             call-chain inference, root cause
  api/               JSON API, SSE stream, static UI
demo/                the three toy services + docker-compose
ui/                  React app: landing page (index.html) and dashboard (app.html)
scripts/             run_demo, traffic, bench, check_env
docs/                design notes, demo script, synopsis
```

## Zero instrumentation check

`grep -rniE "trace|otel|opentelemetry|jaeger|zipkin" demo/*/main.go` returns nothing; the services use only `net/http`.

## API

`GET /api/transactions?limit=&service=&status=` (status: `error`, `5xx`, or a code) · `GET /api/transactions/{id}` (tx + call chain + flow) ·
`GET /api/graph` · `GET /api/flows` · `GET /api/stats` · `GET /api/stream` (SSE) · `POST /api/ingest` (collector mode)
