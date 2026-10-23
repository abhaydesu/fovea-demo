// SPDX-License-Identifier: GPL-2.0
// Fovea network-flow layer: per-connection packet/byte counters taken at the
// container veth (TC ingress = everything a container sends). This is the
// metadata side that Hubble provides in a Cilium cluster; Fovea joins it with
// the payload transactions by 5-tuple.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP 0x0800
#define TCX_NEXT -1

struct flow_key {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;   // host order
    __u16 dport;
    __u8  proto;
    __u8  pad[3];
};

struct flow_val {
    __u64 packets;
    __u64 bytes;
    __u64 first_ns;
    __u64 last_ns;
    __u32 tcp_flags;  // OR of all flags seen (SYN=2 FIN=1 RST=4 ...)
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, struct flow_key);
    __type(value, struct flow_val);
} flows SEC(".maps");

SEC("tc")
int flow_ingress(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end || eth->h_proto != bpf_htons(ETH_P_IP))
        return TCX_NEXT;
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end || ip->ihl < 5)
        return TCX_NEXT;

    struct flow_key k = { .saddr = ip->saddr, .daddr = ip->daddr, .proto = ip->protocol };
    __u32 flags = 0;
    void *l4 = (void *)ip + ip->ihl * 4;
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *t = l4;
        if ((void *)(t + 1) > data_end)
            return TCX_NEXT;
        k.sport = bpf_ntohs(t->source);
        k.dport = bpf_ntohs(t->dest);
        flags = ((__u8 *)t)[13];
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *u = l4;
        if ((void *)(u + 1) > data_end)
            return TCX_NEXT;
        k.sport = bpf_ntohs(u->source);
        k.dport = bpf_ntohs(u->dest);
    }

    __u64 now = bpf_ktime_get_ns();
    struct flow_val *v = bpf_map_lookup_elem(&flows, &k);
    if (v) {
        __sync_fetch_and_add(&v->packets, 1);
        __sync_fetch_and_add(&v->bytes, skb->len);
        v->last_ns = now;
        v->tcp_flags |= flags;
    } else {
        struct flow_val nv = { .packets = 1, .bytes = skb->len, .first_ns = now, .last_ns = now, .tcp_flags = flags };
        bpf_map_update_elem(&flows, &k, &nv, BPF_ANY);
    }
    return TCX_NEXT;
}

char LICENSE[] SEC("license") = "GPL";
