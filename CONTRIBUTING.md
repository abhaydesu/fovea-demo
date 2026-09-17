# Contributing to ebpf-netmon

Thank you for your interest in contributing to `ebpf-netmon`! We welcome bug fixes, documentation improvements, and performance optimizations.

---

## Development Prerequisites

Before building or contributing code, run the dependency checker to verify that your development environment is properly configured:

```bash
./scripts/check_dependencies.sh
```

### Supported Platform
* **Operating System**: Linux with kernel >= 5.8 (compiled with `CONFIG_DEBUG_INFO_BTF=y`).
* **Primary Verified Distribution**: Ubuntu Linux (22.04 LTS, 24.04 LTS, and newer).
* **Compilers & Tools**: Clang (>= 11), LLVM (with `llvm-strip`), CMake (>= 3.16), GCC/G++ (supporting C++17), GNU Make, `pkg-config`, `bpftool`, and `libbpf-dev`.

---

## Build Instructions

`ebpf-netmon` uses CMake for out-of-tree builds:

```bash
# 1. Configure the build directory
cmake -B build -S .

# 2. Compile eBPF program, skeleton headers, and C++ userspace executable
cmake --build build -j"$(nproc)"
```

---

## Testing & Validation

Always run the automated CLI test suite before submitting pull requests:

```bash
./scripts/test_cli.sh
```

### Live Traffic Verification (Requires Root)
To verify live traffic capture without altering existing network state:

```bash
# Terminal 1: Run monitor on active interface with a filter
sudo ./build/netmon -i <interface> -a 8.8.8.8 -c 4

# Terminal 2: Generate test packets
ping -c 2 8.8.8.8
```

Verify that:
1. Both `IN` and `OUT` packets are displayed.
2. Pre-existing Traffic Control (`clsact`) qdiscs and unrelated filters remain intact after graceful exit (`Ctrl+C` or count limit).
3. Session summary displays expected packet counts and throughput.

---

## Coding Standards

### eBPF Kernel Code (`bpf/`)
* Written in strict C (C99).
* Must use CO-RE (Compile Once – Run Everywhere) conventions with `vmlinux.h`.
* Must enforce packet boundary checks before any packet data dereference (`data + offset > data_end`).
* Must remain strictly non-intrusive (`TC_ACT_OK`). Never drop, redirect, or modify packets.
* Must pass the Linux BPF verifier cleanly without unbounded loops or memory safety violations.

### Userspace Application Code (`src/`, `include/`)
* Written in modern C++17.
* Do not introduce heavyweight external dependencies (rely on standard library and `libbpf`).
* Compile cleanly with `-Wall -Wextra -Wpedantic` without warnings.
* All error messages must be actionable and distinguish harmless conditions (e.g. pre-existing `clsact` qdiscs) from genuine failures.

---

## Pull Request Guidelines

1. Ensure the project builds cleanly from a fresh directory:
   ```bash
   rm -rf build && cmake -B build -S . && cmake --build build -j"$(nproc)"
   ```
2. Ensure `./scripts/test_cli.sh` passes completely.
3. Keep commits focused, well-described, and logically separated.
4. Avoid committing build artifacts, generated skeleton headers, or machine-specific configuration files.
