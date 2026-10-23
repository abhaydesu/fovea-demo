# Demo script (about 5 minutes)

**Setup (before the guide arrives):** `./scripts/run_demo.sh` in terminal 1 (asks for sudo, leaves the agent running).
Open http://localhost:9090 (landing page; "Open live dashboard" goes to /app.html). Terminal 2 is for `./scripts/traffic.sh`.

0. **Landing page (60 s).** Scroll http://localhost:9090: the hero card is a *live* capture from the agent, the
   numbers band is live, the objectives list shows honest status. Then click *Open live dashboard*.
1. **Problem (30 s).** "Hubble/Cilium shows who talked to whom, ports and bytes. It can't show *what was said*.
   When a call fails you still don't know why."
2. **Zero instrumentation (30 s).** Point at the header banner. In terminal 2:
   `grep -rniE "trace|otel|jaeger" demo/*/main.go` → no output. "The three services are plain Go HTTP servers."
3. **Generate traffic (30 s).** `./scripts/traffic.sh 20 0.5`. The service map fills in:
   external → frontend → orders → inventory, with req/s, error %, p95.
4. **The failure (90 s).** On the map, orders → inventory turns red and inventory is tagged *likely origin*;
   the upstream hops turn amber (they only pass the error up). Tick *errors only*, click the 502 `POST /order`.
   Right panel: the request `{"item":"widget","qty":50}` and the response
   `{"error":"insufficient stock","available":3,"requested":50}`. Click the matching `orders → inventory` 500: same body one hop down.
   "Flow metadata would only say 'orders → inventory, 500'. Here we see why."
   Point at the **call chain**: external → frontend → orders → inventory, the inventory call is tagged ROOT CAUSE.
   Point at the **network flow** card: the packet/byte counters of that same TCP connection (the Hubble-style view).
5. **Flows tab (30 s).** Switch to *Network flows*: every connection with packets/bytes/flags. "This is what flow tools
   give you. Fovea links each of these rows to the actual messages."
6. **Numbers (60 s).** Show the output of `./scripts/bench.sh report` and the accuracy block from `bench.sh agent`
   (run them beforehand and keep the terminal open).
7. **How (60 s).** `sudo bpftool prog show | grep tracepoint`: eBPF tracepoints on read/write syscalls, filtered to the
   containers' cgroups in-kernel. Show `docs/design.md` pipeline diagram.
8. **Next (30 s).** Kubernetes `Resolver` + DaemonSet deployment, real Hubble flows instead of our TC counters, TLS via uprobes, HTTP/2/gRPC.

**If something goes wrong:** `curl localhost:9090/api/transactions?limit=3 | jq` shows the agent works even if the UI doesn't;
`docker ps` shows the 3 containers; restart with Ctrl+C then `./scripts/run_demo.sh`.
