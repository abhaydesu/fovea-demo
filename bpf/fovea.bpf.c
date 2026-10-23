// SPDX-License-Identifier: GPL-2.0
// Fovea: capture plaintext TCP payload bytes at the syscall boundary.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#define AF_INET   2
#define AF_INET6  10
#define SOCK_STREAM 1
#define MAX_DATA  4096

#define DIR_SEND 0
#define DIR_RECV 1

struct event {
    __u64 ts_ns;
    __u32 tgid;
    __u32 pid;
    __u32 fd;
    __u32 syscall_len;   // bytes the syscall actually moved (its return value)
    __u32 data_len;      // bytes actually copied into data[]
    __u8  dir;
    __u8  family;
    __u16 lport;         // local port, host order
    __u16 rport;         // remote port, host order
    __u16 pad;
    __u8  laddr[16];     // IPv4 in the first 4 bytes, or full IPv6
    __u8  raddr[16];
    char  comm[16];
    // Only data_len (<= MAX_DATA) bytes are sent to userspace. The array is
    // oversized so the verifier can prove every (offset + length) copy in
    // copy_iov() stays in bounds without relating the two registers.
    __u8  data[MAX_DATA * 3];
};

// Events are built in a per-CPU scratch slot (too big for the 512-byte BPF
// stack) and then emitted as variable-length ring buffer records.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct event);
} scratch SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 8 * 1024 * 1024);
} events SEC(".maps");

// cgroup ids (docker containers) we care about; filled by userspace.
// If the map is empty every process is captured.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, __u8);
} allowed_cgroups SEC(".maps");

// 1 when allowed_cgroups is non-empty (userspace toggles it)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} filter_on SEC(".maps");

// stats[0] = events lost because the ring buffer was full
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

#define STAT_DROPPED 0
#define STAT_SEEN    1

#define KIND_BUF   0   // plain (buf, len)
#define KIND_IOV   1   // iovec array (writev/readv)
#define KIND_MSG   2   // struct user_msghdr (sendmsg/recvmsg)

// Syscall arguments stashed at entry, consumed at exit (when the real length is known).
struct call_args {
    __u64 ptr;      // buffer, iovec array or msghdr
    __u64 cnt;      // iovec count (KIND_IOV)
    __u32 fd;
    __u32 kind;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);
    __type(value, struct call_args);
} active_call SEC(".maps");

static __always_inline void bump(__u32 idx)
{
    __u64 *v = bpf_map_lookup_elem(&stats, &idx);
    if (v)
        (*v)++;
}

// Resolve fd -> struct sock* with validation, fill addresses.
static __always_inline int fill_sock(struct event *e, __u32 fd)
{
    struct task_struct *task = bpf_get_current_task_btf();
    struct files_struct *files = BPF_CORE_READ(task, files);
    struct fdtable *fdt = BPF_CORE_READ(files, fdt);
    if ((int)fd >= BPF_CORE_READ(fdt, max_fds))
        return 0;
    struct file **fds = BPF_CORE_READ(fdt, fd);
    struct file *file = NULL;
    if (bpf_probe_read_kernel(&file, sizeof(file), &fds[fd]) || !file)
        return 0;

    struct socket *sock = (struct socket *)BPF_CORE_READ(file, private_data);
    if (!sock)
        return 0;
    struct sock *sk = NULL;
    if (bpf_probe_read_kernel(&sk, sizeof(sk), &sock->sk) || !sk)
        return 0;
    // validate that private_data really is a struct socket
    struct socket *back = NULL;
    if (bpf_probe_read_kernel(&back, sizeof(back), &sk->sk_socket) || back != sock)
        return 0;

    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    short type = BPF_CORE_READ(sock, type);
    if (type != SOCK_STREAM)
        return 0;

    e->lport = BPF_CORE_READ(sk, __sk_common.skc_num);
    e->rport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
    e->family = family;
    if (family == AF_INET) {
        __u32 s = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        __u32 d = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        __builtin_memcpy(e->laddr, &s, 4);
        __builtin_memcpy(e->raddr, &d, 4);
        return 1;
    }
    if (family == AF_INET6) {
        BPF_CORE_READ_INTO(&e->laddr, sk, __sk_common.skc_v6_rcv_saddr);
        BPF_CORE_READ_INTO(&e->raddr, sk, __sk_common.skc_v6_daddr);
        return 1;
    }
    return 0;
}

static __always_inline int allowed(void)
{
    __u32 zero = 0;
    __u32 *on = bpf_map_lookup_elem(&filter_on, &zero);
    if (!on || !*on)
        return 1;
    __u64 cg = bpf_get_current_cgroup_id();
    return bpf_map_lookup_elem(&allowed_cgroups, &cg) != NULL;
}

#define MAX_IOV 4

// Copy up to MAX_IOV iovec segments back-to-back into e->data. Returns bytes copied.
static __always_inline __u32 copy_iov(struct event *e, const struct iovec *iov, __u64 cnt, __u32 total)
{
    __u32 off = 0;
#pragma unroll
    for (int i = 0; i < MAX_IOV; i++) {
        if (i >= cnt || off >= MAX_DATA || off >= total)
            break;
        struct iovec v;
        if (bpf_probe_read_user(&v, sizeof(v), &iov[i]))
            break;
        __u32 n = v.iov_len;
        if (n > total - off)
            n = total - off;
        if (n > MAX_DATA - off)
            n = MAX_DATA - off;
        off &= (MAX_DATA - 1);   // off <= 4095
        n &= 0x1fff;             // n <= 8191, so off + n < sizeof(e->data)
        if (bpf_probe_read_user(&e->data[off], n, v.iov_base))
            break;
        off += n;
    }
    return off;
}

static __always_inline int emit(const struct call_args *a, __u32 total, __u8 dir)
{
    if (total == 0)
        return 0;
    bump(STAT_SEEN);

    __u32 zero = 0;
    struct event *e = bpf_map_lookup_elem(&scratch, &zero);
    if (!e)
        return 0;

    __builtin_memset(e->laddr, 0, sizeof(e->laddr));
    __builtin_memset(e->raddr, 0, sizeof(e->raddr));
    e->lport = e->rport = e->pad = 0;
    if (!fill_sock(e, a->fd))
        return 0;

    __u32 n = 0;
    if (a->kind == KIND_BUF) {
        n = total > MAX_DATA ? MAX_DATA : total;
        if (bpf_probe_read_user(e->data, n & 0x1fff, (void *)a->ptr))
            return 0;
    } else if (a->kind == KIND_IOV) {
        n = copy_iov(e, (const struct iovec *)a->ptr, a->cnt, total);
    } else {
        struct user_msghdr mh;
        if (bpf_probe_read_user(&mh, sizeof(mh), (void *)a->ptr))
            return 0;
        n = copy_iov(e, mh.msg_iov, mh.msg_iovlen, total);
    }
    if (n == 0)
        return 0;
    if (n > MAX_DATA)
        n = MAX_DATA;

    __u64 id = bpf_get_current_pid_tgid();
    e->ts_ns = bpf_ktime_get_ns();
    e->tgid = id >> 32;
    e->pid = (__u32)id;
    e->fd = a->fd;
    e->syscall_len = total;
    e->data_len = n;
    e->dir = dir;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    __u64 size = __builtin_offsetof(struct event, data) + (n & 0x1fff);
    if (bpf_ringbuf_output(&events, e, size, 0))
        bump(STAT_DROPPED);
    return 0;
}

static __always_inline int enter_call(struct trace_event_raw_sys_enter *ctx, __u32 kind)
{
    if (!allowed())
        return 0;
    __u64 id = bpf_get_current_pid_tgid();
    struct call_args a = { .ptr = ctx->args[1], .fd = (__u32)ctx->args[0], .kind = kind };
    if (kind == KIND_IOV)
        a.cnt = ctx->args[2];
    bpf_map_update_elem(&active_call, &id, &a, BPF_ANY);
    return 0;
}

static __always_inline int exit_call(struct trace_event_raw_sys_exit *ctx, __u8 dir)
{
    __u64 id = bpf_get_current_pid_tgid();
    struct call_args *a = bpf_map_lookup_elem(&active_call, &id);
    if (!a)
        return 0;
    struct call_args local = *a;
    bpf_map_delete_elem(&active_call, &id);
    long ret = ctx->ret;
    if (ret <= 0)
        return 0;
    return emit(&local, (__u32)ret, dir);
}

#define PROG(name, kind, dir_)                                                           \
    SEC("tracepoint/syscalls/sys_enter_" #name)                                          \
    int tp_enter_##name(struct trace_event_raw_sys_enter *ctx) { return enter_call(ctx, kind); } \
    SEC("tracepoint/syscalls/sys_exit_" #name)                                           \
    int tp_exit_##name(struct trace_event_raw_sys_exit *ctx) { return exit_call(ctx, dir_); }

PROG(write,    KIND_BUF, DIR_SEND)
PROG(sendto,   KIND_BUF, DIR_SEND)
PROG(read,     KIND_BUF, DIR_RECV)
PROG(recvfrom, KIND_BUF, DIR_RECV)
PROG(writev,   KIND_IOV, DIR_SEND)
PROG(readv,    KIND_IOV, DIR_RECV)
PROG(sendmsg,  KIND_MSG, DIR_SEND)
PROG(recvmsg,  KIND_MSG, DIR_RECV)

char LICENSE[] SEC("license") = "GPL";
