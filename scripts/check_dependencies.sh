#!/usr/bin/env bash
#
# scripts/check_dependencies.sh - Check required tools and kernel features for ebpf-netmon
#
# Safe, non-intrusive pre-flight checker.
# Does NOT install packages or alter system configuration.
#

set -uo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== eBPF Network Monitor - Dependency & Environment Checker ===${NC}\n"

# 0. Distribution Detection
OS_ID="unknown"
OS_NAME="Linux"
OS_VERSION=""
if [ -r /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    OS_ID="${ID:-unknown}"
    OS_NAME="${NAME:-Linux}"
    OS_VERSION="${VERSION_ID:-}"
fi

echo -e "Detected OS: ${OS_NAME} ${OS_VERSION} (${OS_ID})"
if [ "${OS_ID}" != "ubuntu" ] && [ "${OS_ID}" != "debian" ]; then
    echo -e "${YELLOW}[NOTE] Ubuntu is the primary verified distribution for ebpf-netmon.${NC}"
    echo -e "${YELLOW}       Other Linux distributions with kernel >= 5.8 and BTF enabled are compatible,${NC}"
    echo -e "${YELLOW}       but package names may vary.${NC}"
fi
echo ""

MISSING_PKGS=()
ALL_OK=true

check_cmd() {
    local cmd_name="$1"
    local pkg_name="$2"
    if command -v "$cmd_name" >/dev/null 2>&1; then
        local version
        if [ "$cmd_name" = "tc" ]; then
            version=$(tc -V 2>&1 | head -n 1)
        else
            version=$("$cmd_name" --version 2>&1 | head -n 1)
        fi
        echo -e "[ ${GREEN}OK${NC} ] Found ${cmd_name}: ${version}"
    else
        echo -e "[ ${RED}FAIL${NC} ] Missing '${cmd_name}'"
        MISSING_PKGS+=("$pkg_name")
        ALL_OK=false
    fi
}

# 1. Kernel Version & BTF
echo -e "${YELLOW}1. Checking Kernel & BTF support:${NC}"
KERNEL_VER=$(uname -r)
echo -e "   Kernel release: ${KERNEL_VER}"

# Minimum kernel version check (5.8+)
MAJOR_REV=$(echo "${KERNEL_VER}" | cut -d. -f1)
MINOR_REV=$(echo "${KERNEL_VER}" | cut -d. -f2)
if [ "${MAJOR_REV}" -gt 5 ] || { [ "${MAJOR_REV}" -eq 5 ] && [ "${MINOR_REV}" -ge 8 ]; }; then
    echo -e "[ ${GREEN}OK${NC} ] Kernel version ${KERNEL_VER} >= 5.8 (required for BPF ring buffer)"
else
    echo -e "[ ${RED}FAIL${NC} ] Kernel version ${KERNEL_VER} < 5.8. Linux 5.8+ is required for BPF ring buffer support."
    ALL_OK=false
fi

if [ -r /sys/kernel/btf/vmlinux ]; then
    BTF_SIZE=$(wc -c < /sys/kernel/btf/vmlinux)
    echo -e "[ ${GREEN}OK${NC} ] Kernel BTF is enabled (/sys/kernel/btf/vmlinux exists, size: ${BTF_SIZE} bytes)"
else
    echo -e "[ ${RED}FAIL${NC} ] /sys/kernel/btf/vmlinux is missing or unreadable."
    echo -e "         Kernel must be compiled with CONFIG_DEBUG_INFO_BTF=y for CO-RE support."
    ALL_OK=false
fi

# 2. Kernel headers
echo -e "\n${YELLOW}2. Checking Kernel Headers:${NC}"
if [ -d "/lib/modules/${KERNEL_VER}/build" ] || [ -d "/usr/src/linux-headers-${KERNEL_VER}" ]; then
    echo -e "[ ${GREEN}OK${NC} ] Kernel headers found for ${KERNEL_VER}"
else
    echo -e "[ ${RED}FAIL${NC} ] Kernel headers for ${KERNEL_VER} not found"
    MISSING_PKGS+=("linux-headers-${KERNEL_VER}")
    ALL_OK=false
fi

# 3. Build & Compiler Tools
echo -e "\n${YELLOW}3. Checking Compilers & Build Tools:${NC}"
check_cmd "clang" "clang"
check_cmd "llvm-strip" "llvm"
check_cmd "cmake" "cmake"
check_cmd "make" "build-essential"
check_cmd "g++" "build-essential"
check_cmd "pkg-config" "pkg-config"

# 4. BPF Specific Tools & Libraries
echo -e "\n${YELLOW}4. Checking BPF Tools & Libraries:${NC}"
if command -v bpftool >/dev/null 2>&1; then
    BPFTOOL_VER=$(bpftool version 2>&1 | head -n 1)
    echo -e "[ ${GREEN}OK${NC} ] Found bpftool: ${BPFTOOL_VER}"
elif [ -x /usr/sbin/bpftool ]; then
    BPFTOOL_VER=$(/usr/sbin/bpftool version 2>&1 | head -n 1)
    echo -e "[ ${GREEN}OK${NC} ] Found bpftool at /usr/sbin/bpftool: ${BPFTOOL_VER}"
else
    echo -e "[ ${RED}FAIL${NC} ] Missing bpftool (required for generating skeleton headers)"
    MISSING_PKGS+=("bpftool")
    ALL_OK=false
fi

if [ -f /usr/include/bpf/libbpf.h ] || [ -f /usr/local/include/bpf/libbpf.h ]; then
    echo -e "[ ${GREEN}OK${NC} ] libbpf development headers found"
else
    echo -e "[ ${RED}FAIL${NC} ] libbpf development headers missing (/usr/include/bpf/libbpf.h)"
    MISSING_PKGS+=("libbpf-dev")
    ALL_OK=false
fi

# 5. TC (Traffic Control) Tool
echo -e "\n${YELLOW}5. Checking Networking Tools:${NC}"
check_cmd "tc" "iproute2"

# Summary
echo -e "\n${BLUE}===============================================${NC}"
if [ "$ALL_OK" = true ]; then
    echo -e "${GREEN}All required dependencies and kernel features are present!${NC}"
    echo "You can proceed to configure and build the project:"
    echo "  cmake -B build -S ."
    echo "  cmake --build build -j\$(nproc)"
    exit 0
else
    echo -e "${RED}Some required dependencies or kernel prerequisites are missing.${NC}"
    if [ "${#MISSING_PKGS[@]}" -gt 0 ]; then
        # Deduplicate package names
        UNIQUE_PKGS=($(echo "${MISSING_PKGS[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' '))
        if [ "${OS_ID}" = "ubuntu" ] || [ "${OS_ID}" = "debian" ]; then
            echo -e "\nInstall the missing packages on Ubuntu/Debian with:\n"
            echo -e "    ${YELLOW}sudo apt update && sudo apt install -y ${UNIQUE_PKGS[*]}${NC}\n"
        else
            echo -e "\nPlease install the following equivalent packages for your distribution:\n"
            echo -e "    ${YELLOW}${UNIQUE_PKGS[*]}${NC}\n"
        fi
    fi
    exit 1
fi
