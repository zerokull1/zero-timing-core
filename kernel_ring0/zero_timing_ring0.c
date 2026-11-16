#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/skbuff.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/atomic.h>
#include <linux/cache.h>
#include <asm/msr.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("zerokull1 (ZEROMANI)");
MODULE_DESCRIPTION("Zero-Timing Core: Monolithic Ring-0 Engine v2.0");

static atomic_t engine_enforce_mode   = ATOMIC_INIT(0);
static atomic_t const_time_window_tsc = ATOMIC_INIT(0);
static u64 epoch_salt                 = 0x9E3779B97F4A7C15ULL;

static atomic64_t stat_rx_pkts       = ATOMIC64_INIT(0);
static atomic64_t stat_clean_pass    = ATOMIC64_INIT(0);
static atomic64_t stat_dropped_pkts  = ATOMIC64_INIT(0);
static atomic64_t stat_smuggling     = ATOMIC64_INIT(0);
static atomic64_t stat_tls_split     = ATOMIC64_INIT(0);
static atomic64_t stat_tls_downgrade = ATOMIC64_INIT(0);
static atomic64_t stat_ttl_anomaly   = ATOMIC64_INIT(0);
static atomic64_t stat_other_blocked = ATOMIC64_INIT(0);
static atomic64_t stat_bot_wl        = ATOMIC64_INIT(0);
static atomic64_t stat_bot_ban       = ATOMIC64_INIT(0);
static atomic64_t stat_total_cycles  = ATOMIC64_INIT(0);

#define FLOW_BUCKETS 4096
struct ring0_flow_slot {
    atomic64_t flow_hash;
    atomic64_t pkt_count;
    atomic64_t byte_count;
    atomic64_t last_tsc;
} ____cacheline_aligned;

static struct ring0_flow_slot flow_table[FLOW_BUCKETS];

static __always_inline u64 hash_5tuple_ring0_hw(u32 saddr, u32 daddr, u16 sport, u16 dport, u8 proto)
{
    u64 lo = ((u64)saddr) | (((u64)daddr) << 32);
    u64 hi = ((u64)sport) | (((u64)dport) << 16) | (((u64)proto) << 32);
    u64 h = epoch_salt ^ lo;
    asm volatile(
        "crc32q %[lo], %[h]\n\t"
        "crc32q %[hi], %[h]\n\t"
        : [h] "+r" (h)
        : [lo] "r" (lo ^ 0x517CC1B727220A95ULL), [hi] "r" (hi ^ 0x2545F4914F6CDD1DULL)
        : "cc"
    );
    return h ^ (h >> 33);
}

static __always_inline void track_flow_ring0_lockfree(u64 fhash, u64 pkt_len, u64 now_tsc)
{
    u32 idx = (u32)(fhash & (FLOW_BUCKETS - 1));
    struct ring0_flow_slot *slot = &flow_table[idx];
    s64 cur = atomic64_read(&slot->flow_hash);
    if ((u64)cur == fhash) {
        atomic64_inc(&slot->pkt_count);
        atomic64_add(pkt_len, &slot->byte_count);
        atomic64_set(&slot->last_tsc, now_tsc);
        return;
    }
    if ((cur == 0 || (now_tsc - (u64)atomic64_read(&slot->last_tsc)) > 3000000000ULL) &&
        atomic64_cmpxchg(&slot->flow_hash, cur, (s64)fhash) == cur) {
        atomic64_set(&slot->pkt_count, 1);
        atomic64_set(&slot->byte_count, pkt_len);
        atomic64_set(&slot->last_tsc, now_tsc);
    }
}

static __always_inline u32 inspect_l7_ring0_asm(const u8 *p, u32 len, u16 dport)
{
    u64 q0, q1, res = 0;
    if (len < 16) return 2;
    q0 = *(const u64 *)p;
    q1 = *(const u64 *)(p + 8);

    if (dport == 443) {
        u64 t0, t1, rlen, ver;
        asm volatile(
            "xor %[res], %[res]\n\t"
            "cmp $0x16, %b[q0]\n\t"
            "jne 1f\n\t"
            "mov %[q0], %[t0]\n\t"
            "shr $24, %[t0]\n\t"
            "movzx %w[t0], %[rlen]\n\t"
            "rol $8, %w[rlen]\n\t"
            "mov $4, %[t1]\n\t"
            "cmp $40, %[rlen]\n\t"
            "cmovbq %[t1], %[res]\n\t"
            "mov %[q0], %[t0]\n\t"
            "shr $40, %[t0]\n\t"
            "cmp $0x01, %b[t0]\n\t"
            "jne 1f\n\t"
            "mov %[q1], %[ver]\n\t"
            "shr $8, %[ver]\n\t"
            "mov $5, %[t1]\n\t"
            "cmp $0x0303, %w[ver]\n\t"
            "cmovneq %[t1], %[res]\n\t"
            "1:\n\t"
            : [res] "=&r" (res), [t0] "=&r" (t0), [t1] "=&r" (t1), [rlen] "=&r" (rlen), [ver] "=&r" (ver)
            : [q0] "q" (q0), [q1] "r" (q1) : "cc"
        );
    } else if (dport == 80) {
        u64 sig_post = 0x20202f2054534f50ULL, sig_chnk = 0x0d64656b6e756863ULL, t1;
        asm volatile(
            "xor %[res], %[res]\n\t"
            "mov $1, %[t1]\n\t"
            "cmp %[sp], %[q0]\n\t"
            "jne 2f\n\t"
            "cmp %[sc], %[q1]\n\t"
            "cmoveq %[t1], %[res]\n\t"
            "2:\n\t"
            : [res] "=&r" (res), [t1] "=&r" (t1)
            : [q0] "r" (q0), [q1] "r" (q1), [sp] "r" (sig_post), [sc] "r" (sig_chnk) : "cc"
        );
    }
    return (u32)res;
}

struct ring0_sentinel_slot {
    u32 src_ip;
    u16 trust_score;
    u8  banned;
    u8  promoted;
    u16 burst_strikes;
    u64 last_tsc;
} ____cacheline_aligned;

static struct ring0_sentinel_slot bot_table[64];
static DEFINE_SPINLOCK(bot_lock);

static bool sentinel_observe_and_check_ban(u32 src_ip, bool is_clean, u64 now_tsc)
{
    unsigned long flags;
    u32 idx = (src_ip * 2654435761U) >> 26;
    struct ring0_sentinel_slot *slot;
    u64 delta;
    bool banned_now;

    spin_lock_irqsave(&bot_lock, flags);
    slot = &bot_table[idx];
    if (slot->src_ip != src_ip) {
        if (slot->banned && (now_tsc - slot->last_tsc) < 3000000000ULL) {
            spin_unlock_irqrestore(&bot_lock, flags);
            return true;
        }
        memset(slot, 0, sizeof(*slot));
        slot->src_ip = src_ip;
        slot->last_tsc = now_tsc;
    }
    delta = now_tsc - slot->last_tsc;
    slot->last_tsc = now_tsc;

    if (is_clean && !slot->banned) {
        if (delta < 50000ULL && ++slot->burst_strikes >= 32) {
            slot->banned = 1; slot->trust_score = 0; atomic64_inc(&stat_bot_ban);
        } else if (delta >= 50000000ULL && ++slot->trust_score >= 16 && !slot->promoted) {
            slot->promoted = 1; atomic64_inc(&stat_bot_wl);
        }
    } else if (!is_clean && !slot->banned) {
        slot->banned = 1; slot->trust_score = 0;
        if (slot->promoted) { slot->promoted = 0; atomic64_dec(&stat_bot_wl); }
        atomic64_inc(&stat_bot_ban);
    }
    banned_now = (slot->banned != 0);
    spin_unlock_irqrestore(&bot_lock, flags);
    return banned_now;
}

static __always_inline void constant_time_pad_ring0(u64 t0)
{
    u64 win = (u64)atomic_read(&const_time_window_tsc), rnd = 0;
    if (!win) return;
    asm volatile("rdrand %0" : "=r" (rnd));
    win += (rnd & 0x3FULL);
    while ((rdtsc() - t0) < win) cpu_relax();
}

static unsigned int zero_nf_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    u64 t0 = rdtsc(), fhash;
    struct iphdr *iph = skb ? ip_hdr(skb) : NULL;
    struct tcphdr *tcph;
    u32 ihl, thl, tot, plen, v;
    u8 buf[64];
    const u8 *p;
    bool ban;

    if (!iph) return NF_ACCEPT;
    atomic64_inc(&stat_rx_pkts);

    if (iph->ttl == 65 || iph->ttl == 129) {
        atomic64_inc(&stat_ttl_anomaly);
        sentinel_observe_and_check_ban(iph->saddr, false, t0);
        atomic64_add(rdtsc() - t0, &stat_total_cycles);
        constant_time_pad_ring0(t0);
        if (atomic_read(&engine_enforce_mode)) { atomic64_inc(&stat_dropped_pkts); return NF_DROP; }
        return NF_ACCEPT;
    }

    if (iph->protocol != IPPROTO_TCP) {
        atomic64_inc(&stat_clean_pass);
        atomic64_add(rdtsc() - t0, &stat_total_cycles);
        constant_time_pad_ring0(t0);
        return NF_ACCEPT;
    }

    ihl = iph->ihl * 4;
    if (ihl < 20 || skb->len < ihl + sizeof(struct tcphdr)) return NF_ACCEPT;
    tcph = (struct tcphdr *)((u8 *)iph + ihl);
    thl = tcph->doff * 4;
    tot = ihl + thl;

    fhash = hash_5tuple_ring0_hw(iph->saddr, iph->daddr, tcph->source, tcph->dest, iph->protocol);
    track_flow_ring0_lockfree(fhash, skb->len, t0);

    if (skb->len <= tot) {
        atomic64_inc(&stat_clean_pass);
        atomic64_add(rdtsc() - t0, &stat_total_cycles);
        constant_time_pad_ring0(t0);
        return NF_ACCEPT;
    }

    plen = skb->len - tot;
    p = skb_header_pointer(skb, tot, plen < 64 ? plen : 64, buf);
    if (!p) return NF_ACCEPT;

    v = inspect_l7_ring0_asm(p, plen, ntohs(tcph->dest));
    ban = sentinel_observe_and_check_ban(iph->saddr, v == 0, t0);

    if (v == 0) atomic64_inc(&stat_clean_pass);
    else if (v == 1) atomic64_inc(&stat_smuggling);
    else if (v == 4) atomic64_inc(&stat_tls_split);
    else if (v == 5) atomic64_inc(&stat_tls_downgrade);
    else atomic64_inc(&stat_other_blocked);

    atomic64_add(rdtsc() - t0, &stat_total_cycles);
    constant_time_pad_ring0(t0);

    if (atomic_read(&engine_enforce_mode) && (v != 0 || ban)) {
        atomic64_inc(&stat_dropped_pkts);
        return NF_DROP;
    }
    return NF_ACCEPT;
}

static struct nf_hook_ops zero_nf_ops = {
    .hook = zero_nf_hook, .pf = NFPROTO_IPV4, .hooknum = NF_INET_PRE_ROUTING, .priority = NF_IP_PRI_FIRST,
};

static int zero_proc_show(struct seq_file *m, void *v)
{
    u64 rx = atomic64_read(&stat_rx_pkts), cyc = atomic64_read(&stat_total_cycles);
    seq_printf(m,
        "ZEROMANI MONOLITHIC RING-0 ENGINE v2.0 (7.3.4-zen)\n"
        "MODE=%s | CONST_WIN=%d | RX=%llu | PASS=%llu | DROP=%llu\n"
        "SMUGGLING=%llu | TLS_SPLIT=%llu | TLS_DOWNGRADE=%llu | TTL_ANOM=%llu | OTHER=%llu\n"
        "BOT_WL=%llu | BOT_BAN=%llu | AVG_CYCLES_PKT=%llu\n",
        atomic_read(&engine_enforce_mode) ? "ENFORCE" : "MONITOR", atomic_read(&const_time_window_tsc),
        rx, (u64)atomic64_read(&stat_clean_pass), (u64)atomic64_read(&stat_dropped_pkts),
        (u64)atomic64_read(&stat_smuggling), (u64)atomic64_read(&stat_tls_split),
        (u64)atomic64_read(&stat_tls_downgrade), (u64)atomic64_read(&stat_ttl_anomaly),
        (u64)atomic64_read(&stat_other_blocked), (u64)atomic64_read(&stat_bot_wl),
        (u64)atomic64_read(&stat_bot_ban), rx > 0 ? (cyc / rx) : 0);
    return 0;
}

static ssize_t zero_proc_write(struct file *f, const char __user *ubuf, size_t cnt, loff_t *ppos)
{
    char cmd[16];
    size_t l = cnt < 15 ? cnt : 15;
    if (copy_from_user(cmd, ubuf, l)) return -EFAULT;
    cmd[l] = 0;
    if (!strncmp(cmd, "enforce", 7)) atomic_set(&engine_enforce_mode, 1);
    else if (!strncmp(cmd, "monitor", 7)) atomic_set(&engine_enforce_mode, 0);
    else if (!strncmp(cmd, "const256", 8)) atomic_set(&const_time_window_tsc, 256);
    else if (!strncmp(cmd, "const0", 6)) atomic_set(&const_time_window_tsc, 0);
    return cnt;
}

static int zero_proc_open(struct inode *i, struct file *f) { return single_open(f, zero_proc_show, NULL); }
static const struct proc_ops zero_proc_ops = {
    .proc_open = zero_proc_open, .proc_read = seq_read, .proc_write = zero_proc_write,
    .proc_lseek = seq_lseek, .proc_release = single_release,
};

static int __init zero_ring0_init(void)
{
    epoch_salt ^= rdtsc();
    proc_create("zero_timing_ring0", 0644, NULL, &zero_proc_ops);
    if (nf_register_net_hook(&init_net, &zero_nf_ops) < 0) {
        remove_proc_entry("zero_timing_ring0", NULL);
        return -EINVAL;
    }
    pr_info("zeromani_ring0: MONOLITHIC RING-0 ENGINE v2.0 LOADED!\n");
    return 0;
}

static void __exit zero_ring0_exit(void)
{
    nf_unregister_net_hook(&init_net, &zero_nf_ops);
    remove_proc_entry("zero_timing_ring0", NULL);
    pr_info("zeromani_ring0: MONOLITHIC RING-0 ENGINE v2.0 UNLOADED.\n");
}

module_init(zero_ring0_init);
module_exit(zero_ring0_exit);
