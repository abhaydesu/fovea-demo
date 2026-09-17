#ifndef __NETMON_H
#define __NETMON_H

#ifdef __cplusplus
#include <cstdint>
#include <linux/types.h>
extern "C" {
#endif

#define DIR_INGRESS 0
#define DIR_EGRESS  1

#define NETMON_PROTO_ICMP 1
#define NETMON_PROTO_TCP  6
#define NETMON_PROTO_UDP  17

struct packet_event {
    __u64 timestamp_ns;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u32 packet_len;
    __u8  direction;
    __u8  protocol;
    __u8  padding[2];
};

#ifdef __cplusplus
}
#endif

#endif /* __NETMON_H */
