// ZEROMANI (zerokull1) | 0x5A45524F4D414E49ULL
/* ZERO_XDP_TTL_GUARD v1.4.0: Early L3/L4, Industrial (Modbus TCP / EtherCAT), DNS/NTP Amp & L7 SWAR */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef ETH_P_ECAT
#define ETH_P_ECAT 0x88A4
#endif

struct shield_stats {
    __u64 passed;
    __u64 dropped_null_tcp;
    __u64 dropped_l7_smuggling;
    __u64 dropped_tls_splitting;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct shield_stats);
} stats_map SEC(".maps");

SEC("xdp")
int xdp_zero_shield_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    __u32 key = 0;
    struct shield_stats *st = bpf_map_lookup_elem(&stats_map, &key);
    if (!st) return XDP_PASS;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    if (eth->h_proto == bpf_htons(ETH_P_ECAT)) {
        __u8 *ecat = (__u8 *)(eth + 1);
        if ((void *)(ecat + 14) > data_end) {
            __sync_fetch_and_add(&st->dropped_null_tcp, 1);
            return XDP_DROP;
        }
        __u16 hdr = *(__u16 *)ecat;
        __u16 ecat_len = hdr & 0x07FF;
        __u8  ecat_type = (hdr >> 12) & 0x0F;
        if (ecat_type != 0x1 || ecat_len < 12) {
            __sync_fetch_and_add(&st->dropped_null_tcp, 1);
            return XDP_DROP;
        }
        st->passed++;
        return XDP_PASS;
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        st->passed++;
        return XDP_PASS;
    }

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;
    if ((ip->frag_off & __constant_htons(0x3FFF)) != 0) {
        __sync_fetch_and_add(&st->dropped_null_tcp, 1);
        return XDP_DROP;
    }

    __u32 ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < sizeof(struct iphdr)) return XDP_DROP;

    if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + ip_hdr_len;
        if ((void *)(udp + 1) > data_end) return XDP_DROP;
        __u8 *upayload = (__u8 *)(udp + 1);

        if (udp->dest == bpf_htons(123)) {
            if ((void *)(upayload + 48) > data_end) {
                __sync_fetch_and_add(&st->dropped_null_tcp, 1);
                return XDP_DROP;
            }
            if ((*upayload & 0x07) >= 6) {
                __sync_fetch_and_add(&st->dropped_null_tcp, 1);
                return XDP_DROP;
            }
        }

        if (udp->dest == bpf_htons(53)) {
            if ((void *)(upayload + 16) > data_end) {
                __sync_fetch_and_add(&st->dropped_null_tcp, 1);
                return XDP_DROP;
            }
            __u16 flags_le = *(__u16 *)(upayload + 2);
            __u8 qname_len = *(upayload + 12);
            if ((flags_le & 0x0082) != 0 || qname_len > 63) {
                __sync_fetch_and_add(&st->dropped_null_tcp, 1);
                return XDP_DROP;
            }
        }

        st->passed++;
        return XDP_PASS;
    }

    if (ip->protocol != IPPROTO_TCP) {
        st->passed++;
        return XDP_PASS;
    }

    struct tcphdr *tcp = (void *)ip + ip_hdr_len;
    if ((void *)(tcp + 1) > data_end) return XDP_PASS;

    __u8 tcp_flags = *((__u8 *)tcp + 13);
    if (tcp_flags == 0x00) {
        st->dropped_null_tcp++;
        return XDP_DROP;
    }

    __u32 tcp_hdr_len = tcp->doff * 4;
    if (tcp_hdr_len >= sizeof(struct tcphdr)) {
        __u8 *payload = (__u8 *)tcp + tcp_hdr_len;

        if (tcp->dest == bpf_htons(502)) {
            if ((void *)(payload + 8) > data_end) {
                st->dropped_null_tcp++;
                return XDP_DROP;
            }
            __u16 proto_id = *(__u16 *)(payload + 2);
            if (proto_id != 0) {
                st->dropped_null_tcp++;
                return XDP_DROP;
            }
        }

        if ((void *)(payload + 16) <= data_end) {
            __u64 q0 = *(__u64 *)payload;
            __u64 q1 = *(__u64 *)(payload + 8);

            if ((q0 & 0x0000FFFFFFFFFFFFULL) == 0x00002F2054534F50ULL && q1 == 0x0D64656B6E756863ULL) {
                st->dropped_l7_smuggling++;
                return XDP_DROP;
            }

            /* CVE-2026-123007 (NGINX2Root) & CVE-2026-119618: RFC 9113 HTTP/2 Frame Guard */
            if (tcp->dest == bpf_htons(80) || tcp->dest == bpf_htons(8080)) {
                __u32 h2_hdr = bpf_ntohl((__u32)(q0 & 0xFFFFFFFFULL));
                __u32 h2_len = h2_hdr >> 8;
                __u8  h2_typ = (__u8)(h2_hdr & 0xFF);
                __u8  h2_flg = (__u8)((q0 >> 32) & 0xFF);
                if (h2_len > 16384 || ((h2_flg & 0x08) && h2_len == 0 && h2_typ <= 5)) {
                    st->dropped_l7_smuggling++;
                    return XDP_DROP;
                }
            }

            if (tcp->dest == bpf_htons(443)) {
                __u8 rec_type = (__u8)(q0 & 0xFF);
                __u8 maj_ver  = (__u8)((q0 >> 8) & 0xFF);
                __u16 rlen_be = (__u16)((q0 >> 24) & 0xFFFF);
                __u16 rlen    = bpf_ntohs(rlen_be);
                if (rec_type == 0x16 && maj_ver == 0x03 && rlen < 40) {
                    st->dropped_tls_splitting++;
                    return XDP_DROP;
                }
            }
        }
    }

    st->passed++;
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

SEC("xdp_peer")
int xdp_peer_pass(struct xdp_md *ctx) {
    return XDP_PASS;
}
