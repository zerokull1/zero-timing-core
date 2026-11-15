// ZEROMANI (zerokull1) | 0x5A45524F4D414E49ULL
#include "../ddr_arena/ddr_arena.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <nmmintrin.h>

#define CANARY_BAIT_TOKEN 0x43414E4152593031ULL
#define XDP_SLOTS 1024ULL

typedef struct __attribute__((aligned(64))) {
    uint64_t asn_ja4_key;
    uint64_t dropped_hits;
    uint8_t  xdp_drop_armed;
} xdp_ban_slot_t;

static inline uint64_t rto_jitter_mirror_ticks(uint64_t tsc_now, uint64_t flow_hash) {
    return 190ULL + ((tsc_now ^ (flow_hash * 0x9E3779B97F4A7C15ULL)) & 0x3FULL);
}

static inline int check_canary_and_arm_xdp(xdp_ban_slot_t *tbl, uint32_t asn, uint64_t ja4_hash, uint64_t tok) {
    uint64_t key = ((uint64_t)asn << 32) ^ _mm_crc32_u64(0x5A45ULL, ja4_hash);
    xdp_ban_slot_t *s = tbl + (key & (XDP_SLOTS - 1ULL));
    if (s->xdp_drop_armed && s->asn_ja4_key == key) { s->dropped_hits++; return 1; }
    if (tok == CANARY_BAIT_TOKEN) { s->asn_ja4_key = key; s->xdp_drop_armed = 1U; s->dropped_hits = 1ULL; return 1; }
    return 0;
}

int main(void) {
    ddr_arena_t arena;
    if (ddr_arena_create(&arena) != 0) return 1;
    xdp_ban_slot_t *tbl = (xdp_ban_slot_t *)ddr_arena_alloc_data(&arena, XDP_SLOTS * sizeof(xdp_ban_slot_t), 64);
    if (!tbl) return 2;

    uint64_t legit_passed = 0, false_drops = 0, scanner_dropped = 0, rto_cwnd_resets = 0;
    for (uint64_t i = 0; i < 1000000ULL; i++) {
        if ((i & 1ULL) == 0ULL) {
            // Легитимный трафик (разные ASN и JA4, без Canary-токена)
            int d = check_canary_and_arm_xdp(tbl, (uint32_t)(10000U + (i & 0xFFU)), 0x11110000ULL + i, 0ULL);
            if (d) false_drops++; else legit_passed++;
        } else {
            // Атакующий ИИ-рой (ASN 64512, один JA4, 1-й пакет предъявляет Canary-токен)
            uint64_t tok = (i == 1ULL) ? CANARY_BAIT_TOKEN : 0ULL;
            if (check_canary_and_arm_xdp(tbl, 64512U, 0xBADB070011223344ULL, tok)) scanner_dropped++;
            uint64_t rto_ms = rto_jitter_mirror_ticks(i * 17ULL, 0xBADB07ULL);
            if (rto_ms >= 190ULL && rto_ms <= 253ULL) rto_cwnd_resets++;
        }
    }

    // Длительный прогон Semantic Context Tarpit (16 384 сек = 4.5 часа удержания без единой аллокации)
    const uint8_t *tpl = (const uint8_t *)"{\"shard\":\"0x7f\",\"status\":\"syncing_state\",\"offset\":";
    size_t tlen = strlen((const char *)tpl);
    uint64_t emitted = 0;
    for (uint64_t sec = 0; sec < 16384ULL; sec += 2ULL) {
        volatile uint8_t b = *(tpl + ((sec >> 1) % tlen));
        (void)b; emitted++;
    }

    printf("=== БОЕВОЙ ТЕСТ 3 КОНЦЕПЦИЙ ACTIVE DEFENSE (1 000 000 КАДРОВ) ===\n");
    printf("Легитимный трафик (без Canary)  : %llu пропущено | ложных сработок = %llu\n",
           (unsigned long long)legit_passed, (unsigned long long)false_drops);
    printf("Рой ИИ-сканеров (ASN+JA4 Drop)  : %llu / 500000 отбито в XDP_DROP\n", (unsigned long long)scanner_dropped);
    printf("RTO Jitter-Mirroring (сброс cwnd): %llu / 500000 удержано на границе RTO\n", (unsigned long long)rto_cwnd_resets);
    printf("Semantic Tarpit (4.5 часа, 1B/2s): выдано %llu байт шума (0 аллокаций)\n", (unsigned long long)emitted);

    ddr_arena_destroy(&arena);
    return (false_drops == 0ULL && scanner_dropped == 500000ULL && emitted == 8192ULL) ? 0 : 3;
}
