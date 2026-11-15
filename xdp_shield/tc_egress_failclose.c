#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} fc_stats_map SEC(".maps");

// Индексы карты: 0 = fail_close_flag (0=штатно, 1=авария), 1 = passed_ttl65, 2 = raw_leak_blocked, 3 = fail_close_blocked
SEC("tc")
int tc_egress_failclose_guard(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return TC_ACT_SHOT;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return TC_ACT_OK;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) return TC_ACT_SHOT;

    __u32 k_flag = 0, k_pass = 1, k_raw = 2, k_fc = 3;
    __u64 *flag = bpf_map_lookup_elem(&fc_stats_map, &k_flag);
    __u64 *c_pass = bpf_map_lookup_elem(&fc_stats_map, &k_pass);
    __u64 *c_raw  = bpf_map_lookup_elem(&fc_stats_map, &k_raw);
    __u64 *c_fc   = bpf_map_lookup_elem(&fc_stats_map, &k_fc);
    if (!flag || !c_pass || !c_raw || !c_fc) return TC_ACT_SHOT;

    // 1. Аварийный режим Fail-Close: на провод не выходит НИ ОДИН пакет
    if (*flag != 0ULL) { __sync_fetch_and_add(c_fc, 1ULL); return TC_ACT_SHOT; }

    // 2. Штатный режим: пропускаем только мутированные кадры с меткой ZEROMANI (id == 0x5A45), сырые утечки -> DROP
    if (iph->id != bpf_htons(0x5A45)) { __sync_fetch_and_add(c_raw, 1ULL); return TC_ACT_SHOT; }

    // 3. Демутация и нормализация TTL=65 перед выходом на внешний NIC
    __u16 old_ttl_proto = ((__u16)iph->ttl << 8) | iph->protocol;
    iph->ttl = 65;
    __u16 new_ttl_proto = ((__u16)65 << 8) | iph->protocol;
    bpf_l3_csum_replace(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, check), old_ttl_proto, new_ttl_proto, 2);
    __sync_fetch_and_add(c_pass, 1ULL);
    return TC_ACT_OK;
}
char _license[] SEC("license") = "GPL";
