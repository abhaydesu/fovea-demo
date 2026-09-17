# ebpf-netmon: Linux eBPF Network Packet Monitor

A lightweight, real-time command-line network packet metadata monitor for Linux built with **eBPF (TC Classifier)**, **libbpf (CO-RE)**, and **C++17**.

> [!NOTE]
> **Scope Notice**: `ebpf-netmon` is a **packet metadata monitor**, not an application-layer (HTTP/HTTPS) inspector or deep packet inspection (DPI) payload parser. It captures L2–L4 network metadata (timestamp, direction, protocol, IP addresses, ports, and packet length) without inspecting payload contents, decrypting TLS, or modifying traffic.

---

## Features

* **Bidirectional Traffic Capture**: Observes both incoming (`IN`) and outgoing (`OUT`) network packets on any selected network interface.
* **Supported Protocols**: Monitors IPv4 traffic for **TCP**, **UDP**, and **ICMP**.
* **Flexible Packet Filtering**:
  * **IPv4 Endpoint Filtering** (`-a`, `--address`): Matches packets where the specified IPv4 address is either the source or destination.
  * **Protocol Filtering** (`-p`, `--proto`): Filter specifically by `tcp`, `udp`, `icmp`, or `all`.
  * **Direction Filtering** (`-d`, `--direction`): Filter strictly by `in` (ingress), `out` (egress), or `both`.
  * **Transport Port Filtering** (`--port`): Filter by L4 port (matches source or destination port for TCP/UDP).
  * **Packet Count Limit** (`-c`, `--count`): Automatically exits after capturing `N` matching packets (ideal for scripting and CI testing).
* **Live Throughput & Session Rates**:
  * Calculates real-time packets per second (PPS) and data rate (B/s, KB/s, MB/s).
  * Displays an active filters breakdown and session summary upon shutdown.
* **Polished Terminal Interface**:
  * Boxed startup banner displaying active interface, filter settings, and live status.
  * ANSI syntax-colored table: direction-coded (green `IN`, orange `OUT`), protocol-coded (blue `TCP`, lavender `UDP`, yellow `ICMP`).
  * Automatic fallback to plain text for non-TTY pipelines or via `--no-color`.
* **Zero-Copy Kernel-to-Userspace Streaming**: Uses modern **BPF Ring Buffer** (`BPF_MAP_TYPE_RINGBUF`) for efficient, low-overhead event streaming.
* **Safe, Idempotent Traffic Control (TC) Integration**:
  * Non-intrusive: returns `TC_ACT_OK` without altering, dropping, or injecting packets.
  * Reuses existing `clsact` qdiscs safely without triggering exclusivity warnings.
  * Detaches only the monitor's own filter rules on exit, leaving unrelated TC filters and shared qdiscs intact.

---

## Output Example

```text
╭──────────────────────────────────────────────────────────────╮
│                         ebpf-netmon                          │
│                 eBPF Network Traffic Monitor                 │
├──────────────────────────────────────────────────────────────┤
│ Interface : eth0  (index 2)                                  │
│ Capture   : INGRESS + EGRESS                                 │
│ Filter Prt: UDP only                                         │
│ Filter IP : 8.8.8.8                                          │
│ Filter Port: 53                                              │
│ TC Qdisc  : Reusing existing clsact                          │
│ TC Filters: pref 5050 handle 1                               │
│ Status    : ● LIVE                                           │
╰──────────────────────────────────────────────────────────────╯

TIME      DIR  PROTO    SOURCE                DESTINATION               SIZE
────────────────────────────────────────────────────────────────────────────
02:04:10  OUT  UDP      10.0.0.15:54210       8.8.8.8:53                78 B
02:04:10  IN   UDP      8.8.8.8:53            10.0.0.15:54210          142 B
02:04:11  OUT  UDP      10.0.0.15:54211       8.8.8.8:53                78 B
02:04:11  IN   UDP      8.8.8.8:53            10.0.0.15:54211          142 B

────────────────────────────────────────────────────────────────────────────
Session Summary
  Duration          : 2.1s
  Packets received  : 18 (8.6 pkts/s)
  Packets displayed : 4 (1.9 pkts/s)
  Ingress           : 9
  Egress            : 9
  Total bytes       : 1.8 KB (876.2 B/s)
  Active filters    : IP=8.8.8.8 | Port=53 | Proto=UDP
  TC Filters        : Detached ingress/egress (pref 5050, handle 1)
  TC Qdisc          : Preserved existing clsact

Clean shutdown completed.
```

---

## Requirements

### Operating System & Kernel
* **Operating System**: Linux with kernel >= 5.8 (compiled with `CONFIG_DEBUG_INFO_BTF=y`).
* **Supported Architectures**: `x86_64`, `aarch64` / `arm64`.
* **Primary Verified Platform**: Ubuntu Linux (22.04 LTS, 24.04 LTS, and newer).
* **Required Privileges**: Root privileges (`sudo`) or Linux capabilities (`CAP_NET_ADMIN`, `CAP_BPF`) to load eBPF programs and attach to TC classifier hooks.

### Required Compilers & Build Tools
* **`clang`** (>= 11) and **`llvm`** (with `llvm-strip`)
* **`cmake`** (>= 3.16) and **`make`** (GNU Make)
* **`g++`** (supporting C++17) or `clang++`
* **`pkg-config`**
* **`bpftool`** (for BPF skeleton generation)
* **`libbpf-dev`** (>= 0.4, tested on libbpf 1.x)
* **Linux kernel headers** matching the running kernel

---

## Installation & Setup

### 1. Clone the Repository
```bash
git clone https://github.com/<username>/ebpf-netmon.git
cd ebpf-netmon
```

### 2. Install Dependencies (Ubuntu / Debian)
```bash
sudo apt update
sudo apt install -y clang llvm libbpf-dev cmake pkg-config bpftool build-essential iproute2 linux-headers-$(uname -r)
```

### 3. Verify Environment Prerequisites
Run the pre-flight dependency checker script to confirm that your kernel, tools, and headers meet all requirements:

```bash
./scripts/check_dependencies.sh
```

---

## Building

Generate build files and compile the project using CMake:

```bash
# 1. Configure out-of-tree build directory
cmake -B build -S .

# 2. Compile eBPF program, generate skeleton, and compile C++ executable
cmake --build build -j"$(nproc)"
```

The compiled binary will be located at `build/netmon`.

---

## Usage

### Command-Line Reference

```text
Usage: netmon [options]

A lightweight Linux eBPF network monitor capturing packet metadata.

Options:
  -i, --interface <iface>       Network interface to monitor (e.g., eth0, wlp0s20f3, lo)
  -a, --address <ipv4>          Filter traffic by IPv4 address (matches source or destination)
  -p, --proto <tcp|udp|icmp>    Filter traffic by protocol (case-insensitive)
  -d, --direction <in|out|both> Filter traffic by direction (in, out, or both; default: both)
      --port <1-65535>          Filter traffic by L4 port (matches source or destination for TCP/UDP)
  -c, --count <N>               Exit after capturing N matching packets
      --no-color                Disable ANSI color output
  -h, --help                    Display this help message and exit
```

### Examples

```bash
# 1. Auto-detect active interface and monitor all traffic
sudo ./build/netmon

# 2. Monitor a specific interface (e.g. WiFi or Ethernet)
sudo ./build/netmon -i wlp0s20f3

# 3. Filter traffic involving a specific IPv4 endpoint (e.g. 8.8.8.8)
sudo ./build/netmon -i wlp0s20f3 -a 8.8.8.8

# 4. Monitor only TCP traffic
sudo ./build/netmon -i wlp0s20f3 -p tcp

# 5. Monitor only outgoing packets
sudo ./build/netmon -i wlp0s20f3 -d out

# 6. Filter by transport port (e.g. HTTPS port 443)
sudo ./build/netmon -i wlp0s20f3 --port 443

# 7. Combined filter: incoming DNS queries and replies on port 53
sudo ./build/netmon -i wlp0s20f3 -p udp --port 53 -d in

# 8. Capture exactly 20 packets and exit automatically
sudo ./build/netmon -i wlp0s20f3 -c 20

# 9. Plain-text mode without ANSI colors (useful for piping or log files)
sudo ./build/netmon -i wlp0s20f3 --no-color > /tmp/traffic.log
```

---

## Architecture Overview

```text
                LINUX KERNEL (eBPF)
       [ Ingress ]                [ Egress ]
            |                          |
   BPF_TC_INGRESS             BPF_TC_EGRESS
   (tc_ingress)               (tc_egress)
            \                          /
             v                        v
        Validate Headers -> Extract L2-L4 Metadata -> bpf_ringbuf_submit()
                                                             |
=============================================================|=============
                USERSPACE APPLICATION (C++17)                |
                                                             v
                      ring_buffer__poll() <------------------+
                               |
               Apply Display Filters (IP, Port, Proto, Dir, Count)
                               |
               Render ANSI / Plain Terminal Output
                               |
               Update Throughput & Session Statistics
```

1. **CLI Configuration**: The application parses user-supplied filter flags (`-a`, `-p`, `-d`, `--port`, `-c`, `--no-color`) and validates input values.
2. **eBPF Attachment**:
   * Inspects active Traffic Control (TC) configuration via Netlink (`RTM_GETQDISC`).
   * Reuses an existing `clsact` qdisc if already present, or creates a new one if absent.
   * Dynamically allocates an unused filter priority (default `5050`) and attaches `tc_ingress` and `tc_egress` classifier programs.
3. **Event Emission**: The kernel programs validate Ethernet, IPv4, TCP, UDP, or ICMP headers, extract metadata into `struct packet_event`, and submit events to a shared BPF ring buffer.
4. **Userspace Processing**: The C++ application polls the ring buffer, calculates session statistics, applies active filters, and formats matching events.
5. **Clean Teardown**: Upon `Ctrl+C` (SIGINT/SIGTERM) or reaching the count limit (`-c`), the monitor detaches strictly its own filters using their specific handle and priority, preserving pre-existing `clsact` qdiscs and unrelated filters.

See [docs/architecture.md](docs/architecture.md) for full architectural documentation.

---

## Testing & Validation

### Automated CLI Test Suite
Run the test script to verify all CLI argument parsing and validation rules:

```bash
./scripts/test_cli.sh
```

### Live Traffic Verification
To verify packet capture with test traffic, open a second terminal:

1. **DNS Query Test**:
   ```bash
   # Terminal 1:
   sudo ./build/netmon -i <interface> -p udp --port 53

   # Terminal 2:
   dig @8.8.8.8 google.com
   ```

2. **ICMP Ping Test**:
   ```bash
   # Terminal 1:
   sudo ./build/netmon -i <interface> -a 8.8.8.8 -p icmp -c 4

   # Terminal 2:
   ping -c 2 8.8.8.8
   ```

3. **Loopback Traffic Test**:
   ```bash
   sudo ./build/netmon -i lo -a 127.0.0.1 -c 6
   ping -c 3 127.0.0.1
   ```

---

## Troubleshooting

### "libbpf: failed to load BPF skeleton" / Permission Denied
Loading eBPF programs and attaching to TC hooks requires root privileges or Linux capabilities (`CAP_NET_ADMIN` and `CAP_BPF`). Ensure you run the program with `sudo ./build/netmon`.

### "Interface not found"
Run `ip -br link` to list the exact names of network interfaces on your system:
```bash
ip -br link
```

### Pre-existing `clsact` Qdisc ("Exclusivity flag on, cannot modify")
`ebpf-netmon` automatically checks via Netlink whether a `clsact` qdisc is already installed on the network interface (e.g. by `systemd-networkd`, `NetworkManager`, or container runtimes). If found, it safely reuses the qdisc without attempting to recreate it, avoiding exclusivity warnings and preserving existing filters.

### How to Inspect TC Configuration Safely
You can inspect active qdiscs and filters using the standard `tc` utility:
```bash
# View active qdiscs on an interface
tc qdisc show dev <interface>

# View active filters on ingress or egress
tc filter show dev <interface> ingress
tc filter show dev <interface> egress
```

### BPF Verifier Rejection
Verify that your kernel is compiled with BTF support (`/sys/kernel/btf/vmlinux` exists). Run `./scripts/check_dependencies.sh` to confirm kernel and toolchain compatibility.

---

## Known Limitations

1. **IPv4 Only**: IPv6 packets are safely bypassed without errors.
2. **Pre-Stack Drops**: Packets dropped by hardware before reaching the OS networking stack or by an earlier XDP hook are not visible to TC.
3. **Loopback Traffic**: On the loopback interface (`lo`), a packet may appear twice (once on egress and once on ingress) as the Linux IP stack loops local socket traffic back into the local input queue.
4. **Non-Payload Inspection**: Packet payload data (such as HTTP URLs, headers, or encrypted TLS bytes) is deliberately not captured or inspected.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on development, code conventions, and submitting pull requests.

---

## Security

See [SECURITY.md](SECURITY.md) for our security policy and instructions on responsible vulnerability disclosure.

---

## License

This project is licensed under the [MIT License](LICENSE).
Kernel eBPF code is licensed as Dual BSD/GPL.
