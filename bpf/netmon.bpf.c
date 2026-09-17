#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "netmon.h"

#define ETH_P_IP   0x0800
#define TC_ACT_OK  0

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

static __always_inline int handle_packet(struct __sk_buff *skb, __u8 direction)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // Validate Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    // Filter IPv4 packets only
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    // Validate IPv4 header
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return TC_ACT_OK;

    // Check minimum IPv4 header length (5 * 4 = 20 bytes)
    if (iph->ihl < 5)
        return TC_ACT_OK;

    __u32 ip_hdr_len = iph->ihl * 4;
    void *l4_hdr = (void *)iph + ip_hdr_len;
    if (l4_hdr > data_end)
        return TC_ACT_OK;

    __u8 proto = iph->protocol;
    __u16 src_port = 0;
    __u16 dst_port = 0;

    if (proto == IPPROTO_TCP) {
        struct tcphdr *tcph = l4_hdr;
        if ((void *)(tcph + 1) > data_end)
            return TC_ACT_OK;
        src_port = tcph->source;
        dst_port = tcph->dest;
    } else if (proto == IPPROTO_UDP) {
        struct udphdr *udph = l4_hdr;
        if ((void *)(udph + 1) > data_end)
            return TC_ACT_OK;
        src_port = udph->source;
        dst_port = udph->dest;
    } else if (proto == IPPROTO_ICMP) {
        struct icmphdr *icmph = l4_hdr;
        if ((void *)(icmph + 1) > data_end)
            return TC_ACT_OK;
        src_port = 0;
        dst_port = 0;
    } else {
        // Only monitor TCP, UDP, and ICMP as required
        return TC_ACT_OK;
    }

    // Reserve space in BPF ring buffer
    struct packet_event *event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
    if (!event)
        return TC_ACT_OK;

    event->timestamp_ns = bpf_ktime_get_ns();
    event->src_ip = iph->saddr;
    event->dst_ip = iph->daddr;
    event->src_port = src_port;
    event->dst_port = dst_port;
    event->packet_len = skb->len;
    event->direction = direction;
    event->protocol = proto;
    event->padding[0] = 0;
    event->padding[1] = 0;

    bpf_ringbuf_submit(event, 0);

    return TC_ACT_OK;
}

SEC("tc")
int tc_ingress(struct __sk_buff *skb)
{
    return handle_packet(skb, DIR_INGRESS);
}

SEC("tc")
int tc_egress(struct __sk_buff *skb)
{
    return handle_packet(skb, DIR_EGRESS);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
