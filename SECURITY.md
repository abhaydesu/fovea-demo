# Security Policy

## Supported Versions

Only the latest version of `ebpf-netmon` on the `master` branch receives active security updates and bug fixes.

| Version | Supported          |
| ------- | ------------------ |
| master  | :white_check_mark: |

---

## Security Model & Privileges

* **Passive Observer**: `ebpf-netmon` operates as a passive network traffic observer. It strictly returns `TC_ACT_OK` on both ingress and egress hook points without modifying, dropping, or injecting packets.
* **Metadata Only**: The tool only inspects network headers (Ethernet, IPv4, TCP, UDP, ICMP) to extract metadata (addresses, ports, protocol, timestamps, and packet length). It deliberately does not inspect, parse, or store packet payload data.
* **Privilege Requirements**: Loading eBPF programs into the Linux kernel and attaching to Traffic Control (TC) classifier hooks requires administrative privileges (`CAP_NET_ADMIN` and `CAP_BPF`, typically provided via `sudo`). Users should only run binaries compiled from trusted source code.

---

## Reporting a Vulnerability

If you discover a potential security vulnerability in `ebpf-netmon`:

1. **Do NOT report it via public GitHub issues or public forums.**
2. Report the vulnerability privately by opening a [GitHub Private Security Advisory](https://github.com) or contacting the maintainers directly.
3. Please include:
   * Description of the vulnerability.
   * Steps to reproduce the issue or proof-of-concept code.
   * Kernel version, distribution, and architecture where the issue was observed.
   * Any potential impact or attack vector.

### Response Timeline
* **Acknowledgment**: We aim to acknowledge vulnerability reports within 48 hours.
* **Assessment & Fix**: A patch or mitigation will be developed and verified before any public disclosure.
