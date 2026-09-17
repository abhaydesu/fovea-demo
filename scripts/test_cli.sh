#!/usr/bin/env bash
#
# scripts/test_cli.sh - Non-root automated test suite for ebpf-netmon CLI & validation
#

set -uo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

BIN="./build/netmon"

echo -e "${BLUE}=== ebpf-netmon Automated CLI Test Suite ===${NC}\n"

if [ ! -x "${BIN}" ]; then
    echo -e "${RED}Error: Executable ${BIN} not found.${NC}"
    echo "Please build the project first:"
    echo "  cmake -B build -S ."
    echo "  cmake --build build -j\$(nproc)"
    exit 1
fi

TESTS_PASSED=0
TESTS_TOTAL=0

assert_test() {
    local test_name="$1"
    local cmd="$2"
    local expected_status="$3"
    local expected_pattern="$4"

    ((TESTS_TOTAL++))
    echo -n "Test ${TESTS_TOTAL}: ${test_name}... "

    local output
    local status=0
    output=$(eval "${cmd}" 2>&1) || status=$?

    if [ "${status}" -ne "${expected_status}" ]; then
        echo -e "${RED}FAILED${NC} (expected exit code ${expected_status}, got ${status})"
        echo "Output: ${output}"
        return 1
    fi

    if [ -n "${expected_pattern}" ] && ! echo "${output}" | grep -qE "${expected_pattern}"; then
        echo -e "${RED}FAILED${NC} (output did not match '${expected_pattern}')"
        echo "Output: ${output}"
        return 1
    fi

    echo -e "${GREEN}PASSED${NC}"
    ((TESTS_PASSED++))
    return 0
}

# 1. Help message
assert_test "CLI --help displays usage" \
    "${BIN} --help" \
    0 "Usage: .*netmon \\[options\\]"

# 2. Invalid IPv4
assert_test "Invalid IPv4 address rejected (-a 999.999.999.999)" \
    "${BIN} -a 999.999.999.999" \
    1 "Invalid IPv4 address"

# 3. Invalid protocol
assert_test "Invalid protocol rejected (-p sctp)" \
    "${BIN} -p sctp" \
    1 "Invalid protocol"

# 4. Valid protocol accepted in help/syntax
assert_test "Invalid direction rejected (-d sideways)" \
    "${BIN} -d sideways" \
    1 "Invalid direction"

# 5. Out of range port
assert_test "Out of range port rejected (--port 70000)" \
    "${BIN} --port 70000" \
    1 "outside valid range"

# 6. Invalid packet count
assert_test "Invalid packet count rejected (-c 0)" \
    "${BIN} -c 0" \
    1 "Count .* must be a positive integer"

# 7. Unrecognized option
assert_test "Unrecognized option rejected (--unknown-flag)" \
    "${BIN} --unknown-flag" \
    1 "Unrecognized option"

# 8. Non-root graceful warning & failure
if [ "$(id -u)" -ne 0 ]; then
    assert_test "Non-root execution reports privilege warning" \
        "${BIN} -i lo" \
        1 "Running as non-root user"
fi

echo -e "\n${BLUE}===============================================${NC}"
if [ "${TESTS_PASSED}" -eq "${TESTS_TOTAL}" ]; then
    echo -e "${GREEN}All ${TESTS_TOTAL} tests PASSED!${NC}"
    exit 0
else
    echo -e "${RED}${TESTS_PASSED}/${TESTS_TOTAL} tests passed.${NC}"
    exit 1
fi
