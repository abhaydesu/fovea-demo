# Architecture: eBPF Network Monitor

This document details the architectural design, eBPF hook selection, packet processing pipeline, safety considerations, and kernel-to-userspace communication mechanism used in `ebpf-netmon`.

---

## 1. High-Level Architecture Overview

```
                          LINUX KERNEL SPACE
  ===================================================================
         NIC / Driver
              |
         +----+----+
         | Ingress | ---> TC Filter (tc_ingress) ---+
         +----+----+                                 |
              |                                      v
         Linux IP Stack                       [ Packet Event ]
              |                                      |
         +----+----+                                 v
         | Egress  | ---> TC Filter (tc_egress) ---->+--> BPF Ring Buffer
         +----+----+                                          |
  ============================================================|======
                       USERSPACE (C++17)                      |
  ============================================================|======
         NetworkMonitor (monitor.cpp)                         |
              |                                               |
              +<--- ring_buffer__poll() <---------------------+
              |
         Event Parsing & Formatter
              |
         Terminal CLI Table Output (main.cpp)
```

---

## 2. eBPF Hook Selection & Rationale

### Selected Hook: Traffic Control (TC) Classifier (`BPF_PROG_TYPE_SCHED_CLS`)

For monitoring network traffic entering and leaving a network interface, the **Traffic Control (TC)** hook was selected over alternatives like XDP, Socket Filters, or Raw Tracepoints.

### Why TC was selected:
1. **True Bidirectional Support**:
   * **XDP (eXpress Data Path)** runs before the network stack and only hooks into the **ingress** path (`XDP_PASS`, `XDP_TX`, etc.). Capturing egress via XDP is not natively supported without complex forwarding tricks or tc mirrors.
   * **TC** operates at both the **ingress** (`BPF_TC_INGRESS`) and **egress** (`BPF_TC_EGRESS`) processing layers within the kernel networking stack (`sch_clsact`). This allows full bidirectional packet visibility on any network device (e.g. `wlp0s20f3`, `eth0`, `lo`).
2. **Non-Intrusive Observation**:
   * The program returns `TC_ACT_OK` (value `0`), which instructs the kernel queueing discipline to pass the packet along its standard network path without alteration, redirection, or dropping.
3. **Structured Packet Access (`struct __sk_buff`)**:
   * TC programs receive `struct __sk_buff *skb`, which exposes packet bounds (`skb->data`, `skb->data_end`) and total packet length (`skb->len`).
4. **Standard Ecosystem Tooling**:
   * Libbpf provides first-class support for TC attachment through `bpf_tc_hook` and `bpf_tc_attach`, making deployment and teardown straightforward and clean.

### How Ingress and Egress Are Distinguished:
* In `netmon.bpf.c`, two distinct entry points are defined:
  * `SEC("tc") int tc_ingress(struct __sk_buff *skb)`
  * `SEC("tc") int tc_egress(struct __sk_buff *skb)`
* Both functions delegate to a shared inline function `handle_packet(skb, direction)` passing `DIR_INGRESS` (`0`) or `DIR_EGRESS` (`1`).
* The direction field is packed directly into the event record (`struct packet_event`) before being queued into the ring buffer.

### Suitability for Beginner-to-Intermediate Systems Projects:
* Unlike kernel tracepoints (which deal with internal kernel structures that can change across kernel versions), TC operates on standard L2/L3/L4 networking headers (Ethernet, IPv4, TCP, UDP, ICMP).
* It avoids the complexities of kernel tracing, kprobes, or socket state machines, focusing cleanly on packet metadata extraction.

### Known Limitations:
* **Pre-stack drops**: Packets dropped before reaching the TC layer (e.g., rejected at the NIC hardware level or dropped by an earlier XDP filter) will not be observed by TC.
* **Loopback duplication**: On the loopback interface (`lo`), packets sent from a local process to a local port may trigger both egress (when leaving the socket) and ingress (when arriving at the socket).
* **Hardware offload**: On specialized SmartNICs with hardware offload, packets handled entirely on the NIC may bypass kernel software TC hooks unless explicitly directed to the host stack.

---

## 3. Kernel Packet Safety & Verifier Guarantees

The Linux eBPF verifier performs strict static analysis to ensure programs cannot crash the kernel, dereference invalid pointers, or read out-of-bounds memory.

### Boundary Verification Pipeline:
1. **Ethernet Header**:
   ```c
   void *data = (void *)(long)skb->data;
   void *data_end = (void *)(long)skb->data_end;

   struct ethhdr *eth = data;
   if ((void *)(eth + 1) > data_end)
       return TC_ACT_OK;
   ```
2. **IPv4 Ethertype Check & Header Bounds**:
   ```c
   if (eth->h_proto != bpf_htons(ETH_P_IP))
       return TC_ACT_OK;

   struct iphdr *iph = (void *)(eth + 1);
   if ((void *)(iph + 1) > data_end)
       return TC_ACT_OK;

   // Minimum IPv4 header length is 20 bytes (ihl >= 5)
   if (iph->ihl < 5)
       return TC_ACT_OK;

   __u32 ip_hdr_len = iph->ihl * 4;
   void *l4_hdr = (void *)iph + ip_hdr_len;
   if (l4_hdr > data_end)
       return TC_ACT_OK;
   ```
3. **Transport Layer Header Bounds (TCP / UDP / ICMP)**:
   * For TCP: `(void *)(tcph + 1) <= data_end` before accessing `source` and `dest`.
   * For UDP: `(void *)(udph + 1) <= data_end` before accessing `source` and `dest`.
   * For ICMP: `(void *)(icmph + 1) <= data_end`. ICMP packets have no port numbers, so ports are recorded as `0`.
4. **No Loops**: The parsing flow is strictly linear with no loops or backward branches, guaranteeing completion within a bounded number of instructions.

---

## 4. Kernel-to-Userspace Communication: BPF Ring Buffer

We use `BPF_MAP_TYPE_RINGBUF` (introduced in Linux 5.8) rather than the legacy BPF perf buffer.

### Advantages of BPF Ring Buffer:
* **Single Memory Allocation**: Shared across all CPUs, minimizing memory footprint and eliminating per-CPU buffer fragmentation.
* **Variable-Length and In-Order Delivery**: Preserves packet order across events.
* **Zero-Copy Reserving**: `bpf_ringbuf_reserve()` allocates memory directly inside the ring buffer, allowing in-place field initialization followed by an atomic `bpf_ringbuf_submit()`.
* **Low Overhead**: If the buffer is full, `bpf_ringbuf_reserve()` safely returns `NULL`, allowing packet drops without kernel panics.

### Shared Data Contract (`include/netmon.h`):
```c
struct packet_event {
    __u64 timestamp_ns;  // Kernel monotonic timestamp (ns)
    __u32 src_ip;        // IPv4 source address (network byte order)
    __u32 dst_ip;        // IPv4 destination address (network byte order)
    __u16 src_port;      // Source port (network byte order, 0 if ICMP)
    __u16 dst_port;      // Destination port (network byte order, 0 if ICMP)
    __u32 packet_len;    // Total packet size in bytes
    __u8  direction;     // DIR_INGRESS (0) or DIR_EGRESS (1)
    __u8  protocol;      // IPPROTO_TCP, IPPROTO_UDP, IPPROTO_ICMP
    __u8  padding[2];    // 8-byte structure alignment
};
```

---

## 5. Userspace Architecture & Lifecycle

* **CO-RE (Compile Once - Run Everywhere)**: Built against `vmlinux.h` generated directly from `/sys/kernel/btf/vmlinux`, ensuring relocatability across kernel versions.
* **Skeleton Workflow**: `bpftool gen skeleton` generates `netmon.skel.h`, offering type-safe C++ bindings to eBPF maps and programs.
* **Graceful Teardown**: Upon receiving `SIGINT` (Ctrl+C) or `SIGTERM`, the application cleanly:
  1. Stops polling the ring buffer.
  2. Calls `bpf_tc_detach()` for both ingress and egress hooks.
  3. Destroys the `clsact` qdisc (if created by this application).
  4. Destroys the skeleton and unloads the BPF programs from the kernel.

---

## 6. Endpoint Filtering & Runtime Statistics

### Userspace-Side Filtering Rationale
Filtering is performed inside the userspace event loop (`NetworkMonitor::process_event`) rather than in the kernel BPF program:
* **Simplicity & Zero-Overhead BPF**: The eBPF program remains stateless and static. No extra BPF maps (such as hash maps or array configs) are needed to pass filter IP values to the kernel.
* **Accurate Interface Metrics**: Because all packets are submitted to the ring buffer, userspace can track true interface traffic volume (`total_received`, `total_bytes`, `ingress_count`, `egress_count`) while only rendering packets matching the user's filter (`total_displayed`).
* **Bidirectional Matching**: Userspace checks `ntohl(ev->src_ip) == filter_ip || ntohl(ev->dst_ip) == filter_ip`, automatically capturing both outgoing requests and incoming replies for the specified endpoint.

*Kernel-side filtering trade-off*: In extremely high packet rate environments (e.g. 100k+ packets/sec), moving the IP filter into the BPF program (via a BPF array or hash map) would save ring buffer allocations by discarding non-matching packets before `bpf_ringbuf_reserve()`. For desktop/host-level traffic monitoring, userspace filtering provides negligible overhead while retaining full interface observability.

---

## 7. Idempotent TC Qdisc Management & Exclusivity Warning Resolution

### The "Exclusivity flag on, cannot modify" Warning
When `bpf_tc_hook_create()` is called, libbpf constructs a Netlink `RTM_NEWQDISC` message with flags `NLM_F_CREATE | NLM_F_EXCL`.
* If a `clsact` qdisc already exists on the target interface (e.g. created by systemd, NetworkManager, Docker, or another networking component), the Linux kernel rejects the request with `-EEXIST` and attaches an extended acknowledgment (extack) error string:
  ```text
  libbpf: Kernel error message: Exclusivity flag on, cannot modify
  ```
* While harmless to traffic flow, this warning indicates an unnecessary attempt to recreate an existing queueing discipline.

### The Idempotent Solution
`ebpf-netmon` implements a robust idempotent strategy:
1. **Pre-flight Netlink Inspection**:
   Before attempting hook creation, `check_clsact_qdisc_exists()` dumps the interface's qdiscs via Netlink (`RTM_GETQDISC`) to verify if `clsact` is already installed.
2. **Qdisc Reuse without Recreation**:
   - If `clsact` already exists, `bpf_tc_hook_create()` is skipped entirely. We bind our ingress and egress filters directly to the existing qdisc.
   - `hook_created_` is kept `false`, ensuring that on shutdown, `bpf_tc_hook_destroy()` is **never** invoked against a pre-existing qdisc.
   - If `clsact` does not exist, `bpf_tc_hook_create()` is called to create it, and `hook_created_` is set to `true` so it is safely cleaned up on exit.
3. **Filter-Scoped Attachment & Detachment**:
   - When attaching filters, libbpf records the allocated `handle` and `priority`.
   - On shutdown, `bpf_tc_detach()` detaches *only* those specific filters, preserving any other filters that were already configured on the interface.

