# ebpf-netmon

A lightweight, real-time command-line network packet monitor for Linux built with **eBPF (Traffic Control)**, **libbpf (CO-RE)**, and **C++17**.

It attaches directly to the Linux kernel network classifier to observe incoming (`IN`) and outgoing (`OUT`) IPv4 packets (TCP, UDP, ICMP) and stream live packet metadata to your terminal with near-zero overhead.

---

## Quick Setup (Run in 3 Steps)

### 1. Clone the Repository
```bash
git clone https://github.com/abhaydesu/fovea-demo.git
cd fovea-demo
```

### 2. Install Prerequisites

**Ubuntu / Debian**:
```bash
sudo apt update
sudo apt install -y clang llvm libbpf-dev cmake pkg-config bpftool build-essential iproute2 linux-headers-$(uname -r)
```

**Arch Linux**:
```bash
sudo pacman -S clang llvm libbpf cmake pkgconf bpf base-devel iproute2 linux-headers
```

*(Optional: Run `./scripts/check_dependencies.sh` to confirm your kernel version and headers are ready).*

### 3. Build & Run
```bash
# Configure and compile
cmake -B build -S .
cmake --build build -j"$(nproc)"

# Run (auto-detects your active network interface)
sudo ./build/netmon
```

Press `Ctrl+C` at any time to cleanly stop the monitor and view the session summary.

---

## Common Examples

```bash
# 1. Run with default interface and see all traffic
sudo ./build/netmon

# 2. Monitor a specific network interface
sudo ./build/netmon -i eth0
# or on Wi-Fi:
sudo ./build/netmon -i wlp0s20f3

# 3. Filter traffic by remote or local IP address
sudo ./build/netmon -a 8.8.8.8

# 4. Filter traffic by port (e.g., DNS on port 53 or HTTPS on port 443)
sudo ./build/netmon --port 53
sudo ./build/netmon --port 443

# 5. Filter by protocol (tcp, udp, or icmp)
sudo ./build/netmon -p tcp
sudo ./build/netmon -p icmp

# 6. Capture incoming traffic only
sudo ./build/netmon -d in

# 7. Capture exactly 10 packets and exit automatically
sudo ./build/netmon -c 10

# 8. Plain-text mode without ANSI colors (great for redirects/logs)
sudo ./build/netmon --no-color > traffic.log
```

---

## Terminal Output Preview

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

Clean shutdown completed.
```

---

## Command-Line Options

```text
Usage: netmon [options]

Options:
  -i, --interface <iface>       Network interface to monitor (auto-detected if omitted)
  -a, --address <ipv4>          Filter by IPv4 address (matches source or destination)
  -p, --proto <tcp|udp|icmp>    Filter by protocol (case-insensitive)
  -d, --direction <in|out|both> Filter by direction (in, out, or both; default: both)
      --port <1-65535>          Filter by L4 port (matches source or destination for TCP/UDP)
  -c, --count <N>               Exit automatically after capturing N matching packets
      --no-color                Disable ANSI color output
  -h, --help                    Display help message and exit
```

---

## How It Works

* **Kernel Space (`bpf/netmon.bpf.c`)**: Hooks into the Linux Traffic Control (TC) subsystem on ingress and egress. For every packet, it parses the Ethernet and IP headers, extracts key metadata (`timestamp`, `direction`, `protocol`, `src_ip`, `dst_ip`, `src_port`, `dst_port`, `packet_length`), and writes it to a high-performance **BPF ring buffer**. It always returns `TC_ACT_OK` without altering or dropping packets.
* **Safe TC Management**: Reuses existing `clsact` qdiscs safely without disrupting other networking tools or VPNs. Automatically detaches only its own filters upon exit.
* **Userspace (`src/`)**: Written in modern C++17. Polls the BPF ring buffer, formats timestamps, computes live throughput rates (PPS and B/s), and prints colored live table entries.

For full design details, see [docs/architecture.md](docs/architecture.md).

---

## Quick Troubleshooting

* **Permission denied / BPF load error**:
  eBPF program loading and TC attachment require root privileges. Always execute with `sudo ./build/netmon`.
* **Cannot find interface**:
  Run `ip -br link` to see available network interfaces on your system.
* **Re-running tests**:
  You can run `./scripts/test_cli.sh` to run the automated CLI test suite.

---

## License

This project is licensed under the [MIT License](LICENSE).
Kernel eBPF code is Dual BSD/GPL.
