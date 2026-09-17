cmake_minimum_required(VERSION 3.16)
project(ebpf-netmon C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Find required tools
find_program(BPFTOOL_BIN NAMES bpftool PATHS /usr/sbin /usr/bin REQUIRED)
find_program(CLANG_BIN NAMES clang clang-21 clang-20 clang-19 clang-18 REQUIRED)
find_program(LLVM_STRIP_BIN NAMES llvm-strip llvm-strip-21 llvm-strip-20 REQUIRED)

# Find libbpf and dependencies
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBBPF REQUIRED libbpf)

find_package(Threads REQUIRED)

# Determine system architecture for BPF
execute_process(
    COMMAND uname -m
    OUTPUT_VARIABLE SYS_ARCH
    OUTPUT_STRIP_TRAILING_WHITESPACE
)
if(SYS_ARCH STREQUAL "x86_64")
    set(BPF_ARCH "x86")
elseif(SYS_ARCH STREQUAL "aarch64")
    set(BPF_ARCH "arm64")
else()
    set(BPF_ARCH ${SYS_ARCH})
endif()

# 1. Ensure vmlinux.h is available
set(VMLINUX_H ${CMAKE_CURRENT_SOURCE_DIR}/bpf/vmlinux.h)
if(NOT EXISTS ${VMLINUX_H})
    message(STATUS "Generating bpf/vmlinux.h from /sys/kernel/btf/vmlinux...")
    add_custom_command(
        OUTPUT ${VMLINUX_H}
        COMMAND ${BPFTOOL_BIN} btf dump file /sys/kernel/btf/vmlinux format c > ${VMLINUX_H}
        COMMENT "Generating vmlinux.h using bpftool"
    )
endif()

# 2. Compile eBPF program into object file
set(BPF_SRC ${CMAKE_CURRENT_SOURCE_DIR}/bpf/netmon.bpf.c)
set(BPF_OBJ ${CMAKE_CURRENT_BINARY_DIR}/netmon.bpf.o)
set(BPF_SKEL ${CMAKE_CURRENT_BINARY_DIR}/netmon.skel.h)

add_custom_command(
    OUTPUT ${BPF_OBJ}
    COMMAND ${CLANG_BIN} -g -O2 -target bpf
            -D__TARGET_ARCH_${BPF_ARCH}
            -Wall -Wno-missing-declarations
            -I${CMAKE_CURRENT_SOURCE_DIR}/bpf
            -I${CMAKE_CURRENT_SOURCE_DIR}/include
            ${LIBBPF_CFLAGS}
            -c ${BPF_SRC} -o ${BPF_OBJ}
    COMMAND ${LLVM_STRIP_BIN} -g ${BPF_OBJ}
    DEPENDS ${BPF_SRC} ${VMLINUX_H} ${CMAKE_CURRENT_SOURCE_DIR}/include/netmon.h
    COMMENT "Compiling eBPF program netmon.bpf.c to ${BPF_OBJ}"
)

# 3. Generate libbpf skeleton header
add_custom_command(
    OUTPUT ${BPF_SKEL}
    COMMAND ${BPFTOOL_BIN} gen skeleton ${BPF_OBJ} > ${BPF_SKEL}
    DEPENDS ${BPF_OBJ}
    COMMENT "Generating BPF skeleton header ${BPF_SKEL}"
)

# 4. Userspace C++ executable
add_executable(netmon
    src/main.cpp
    src/monitor.cpp
    ${BPF_SKEL}
)

target_include_directories(netmon PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_BINARY_DIR}
    ${LIBBPF_INCLUDE_DIRS}
)

target_compile_options(netmon PRIVATE
    -Wall
    -Wextra
    -Wpedantic
)

target_link_libraries(netmon PRIVATE
    ${LIBBPF_LIBRARIES}
    Threads::Threads
)

install(TARGETS netmon DESTINATION bin)
