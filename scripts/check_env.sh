#!/usr/bin/env bash
# Verifies the machine can run the Fovea demo.
ok=1
need() { if command -v "$1" >/dev/null; then printf "  ok   %-10s %s\n" "$1" "$($1 ${2:---version} 2>&1 | head -1)"; else printf "  MISSING %s\n" "$1"; ok=0; fi; }
echo "kernel: $(uname -r)"
KMAJ=$(uname -r | cut -d. -f1); KMIN=$(uname -r | cut -d. -f2)
if (( KMAJ < 5 || (KMAJ == 5 && KMIN < 8) )); then echo "  FAIL kernel < 5.8 (no BPF ring buffer)"; ok=0; fi
[ -r /sys/kernel/btf/vmlinux ] && echo "  ok   BTF available" || { echo "  FAIL no /sys/kernel/btf/vmlinux"; ok=0; }
[ -d /sys/fs/cgroup/system.slice ] && [ -f /sys/fs/cgroup/cgroup.controllers ] && echo "  ok   cgroup v2" || { echo "  FAIL cgroup v2 required"; ok=0; }
need go version; need clang; need bpftool; need docker; need node; need npm; need curl; need jq
docker compose version >/dev/null 2>&1 && echo "  ok   docker compose" || { echo "  MISSING docker compose"; ok=0; }
docker ps >/dev/null 2>&1 && echo "  ok   docker daemon reachable" || { echo "  FAIL cannot talk to docker (group 'docker' / daemon down)"; ok=0; }
[ -f /usr/include/bpf/bpf_helpers.h ] && echo "  ok   libbpf headers" || { echo "  MISSING libbpf-dev"; ok=0; }
(( ok )) && echo "ENV OK" || { echo "ENV NOT READY"; exit 1; }
