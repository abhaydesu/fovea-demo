# Fovea payload-capture slice: design

## Pipeline

```
 containers (plain Go HTTP/1.1)                 host kernel                          userspace (fovea-agent)
 frontend ─▶ orders ─▶ inventory   syscall tracepoints ─▶ BPF ring buffer ─▶ reassemble ─▶ pair ─▶ dedup ─▶ store
                                   (write/sendto/read/                       (per conn,    (req↔resp) (client+server  │
                                    recvfrom)                                 per dir)                  = 1 call)    ▼
                                                                                                  /api/* + SSE + React UI
```

## Capture approach (chosen: syscall tracepoints)

* Entry/exit tracepoint pairs for `write`, `sendto`, `writev`, `sendmsg` (send) and `read`, `recvfrom`, `readv`,
  `recvmsg` (receive). Arguments are stashed at entry; bytes are copied at **exit** using the return value, so the
  captured length is what the kernel actually moved (no over-capture on partial writes).
* `writev/readv/sendmsg/recvmsg`: up to the first 4 iovec segments are copied back-to-back.
* Each event carries ≤ 4 KB of data and is emitted with `bpf_ringbuf_output` as a **variable-length** record built in a
  per-CPU scratch slot, so a 200-byte HTTP request costs ~300 bytes of ring space, not 4 KB.
* Ring overflow is counted in a per-CPU `stats` map and shown in the UI/API (`events_dropped`).
* Kernel 7.x with BTF: CO-RE, `BPF_MAP_TYPE_RINGBUF` (8 MB). Compiled with bpf2go (`go generate ./internal/capture`).
* Why not kprobes on `tcp_sendmsg`: the `iov_iter` layout varies by kernel version; tracepoints are a stable ABI.
* Not covered: `sendfile`/`splice` (zero-copy, no user buffer), `io_uring`, TLS (needs uprobes on the TLS library).

### Socket identity: resolved in-kernel (not the /proc fallback)

`fill_sock()` walks `task->files->fdt->fd[fd]->private_data` as a `struct socket`, validates it
(`sock->sk->sk_socket == sock`, `SOCK_STREAM`, AF_INET/AF_INET6) and reads the local/remote address and ports from
`struct sock`. That removes the /proc race for short-lived connections. Go listens on `[::]`, so sockets are
AF_INET6 with v4-mapped addresses; userspace unmaps them.

### In-kernel filtering

`allowed_cgroups` (hash) holds the cgroup v2 ids (inode of `docker-<id>.scope`) of the compose containers;
`filter_on` toggles it. Userspace refreshes the set every 2 s so new containers are picked up. Host processes (browser,
curl, the agent) are dropped before touching the ring buffer. `--all-processes` disables the filter.

## Network flow layer (`bpf/flows.bpf.c`, `internal/netflow`)

A TCX ingress program on the host side of every container's veth counts packets, bytes and TCP flags per 5-tuple in an
LRU hash map (ingress on the host veth = everything the container sends, so both directions of each conversation are
counted). Userspace pairs the two directions into connection records labelled with service names. This is the metadata
Hubble provides in a Cilium cluster; the payload transaction and its flow are joined by 4-tuple
(`GET /api/transactions/{id}` returns both). The client/server orientation of a flow is a heuristic (lower port = server).

## Reassembly and pairing (`internal/assemble`)

* State per `(tgid, fd, laddr, lport, raddr, rport)`, with one byte buffer per direction.
* Role is inferred from the first bytes: a request line sent → client; a request line received → server.
* `net/http.ReadRequest/ReadResponse` over the buffered bytes; incomplete body ⇒ wait for more chunks; garbage ⇒ drop and resync.
* Requests queue FIFO per connection (HTTP/1.1 has no pipelining here), responses pop the queue ⇒ one *Transaction*.
* Duration: first request byte → last response byte as observed by that side (kernel monotonic clock).
* **Dedup:** the same call is seen at both ends (client's `write`, server's `read`). Canonical key =
  `client ip:port > server ip:port METHOD path`; an observation from the other side within 1 s merges into the
  existing transaction (client-side duration wins, as it includes the network hop). `seen_by` shows which ends saw it.

## Call chains and root cause (`internal/trace`)

No trace ids are injected (that would be instrumentation), so causality is inferred: call C is a child of call P when
P's server is C's client and C lies inside P's time window (smallest enclosing window wins). The deepest failing call
in the chain is flagged as the root cause. Under heavy concurrency on one service a call can be attributed to the wrong
sibling parent; thread/goroutine identity is not used because Go migrates goroutines between threads.

## Privacy

Captured payloads can contain credentials and PII. With `-redact` (default on) `Authorization`, `Cookie`,
`Set-Cookie`, API-key headers and JSON keys matching password/secret/token/api_key/card/cvv/ssn/otp are masked
before anything is stored, streamed or persisted. Bodies with nothing sensitive are stored byte-for-byte unchanged.
gzip-encoded bodies are inflated before display.

## Deployment shape

`fovea-agent -mode all` (default) runs capture + store + API/UI in one process. The synopsis architecture is split
with `-mode agent -collector http://host:9090` on each node (capture, assembly, forwarding in batches) and
`-mode collector` centrally (ingest, store, API/UI, no eBPF). Transaction ids are prefixed with the node name.
`-persist file.jsonl` keeps transactions across restarts.

## Service identity (`internal/identity`)

`Resolver` interface: `ServiceByPID`, `ServiceByIP`, `CgroupIDs`, `Refresh`. The Docker implementation reads
`/proc/<tgid>/cgroup` → container id → compose service label, and maps container IPs → service. Callers outside any
container (curl on the host) resolve to `external`.

**Kubernetes later:** implement `Resolver` against the API server (pod/namespace by cgroup/container id and pod IP);
nothing else changes. **Hubble join later:** key Hubble flows by `(src ip:port, dst ip:port, time)` — the same canonical
tuple the dedup step uses — and attach verdict/policy metadata to the matching Transaction.

## Known limits (honest list)

* HTTP/1.1 plaintext only; no TLS, HTTP/2, gRPC. Chunked bodies are best-effort. Bodies are capped at 64 KB.
* A single syscall moving > 4 KB is truncated to its first 4 KB, so bodies larger than that are incomplete unless the
  application writes them in several calls. Only the first 4 iovec segments are captured.
* Ring buffer overflow drops events (counted, not silent); the affected transaction is then missing or incomplete.
* Client/server dedup and call-chain inference assume a single node (one clock); cross-node joins need the collector
  to dedup by 4-tuple as well.
* Requests from outside the containers (curl on the host) are seen only from the server side.
