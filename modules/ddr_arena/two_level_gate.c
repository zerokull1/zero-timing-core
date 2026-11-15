// ZEROMANI (zerokull1) | 0x5A45524F4D414E49ULL
#include "ddr_arena.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <nmmintrin.h>
#include <x86intrin.h>

typedef struct __attribute__((aligned(64))) {
    uint64_t salted_tag;
    uint64_t epoch_salt;
    uint64_t hit_count;
} stateful_slot_t;

// Уровень 1 (Stateless Gate): чистый расчёт в регистрах CPU, 0 обращений к DDR
static inline uint64_t stateless_gate_check(uint64_t hdr_word, uint64_t reg_magic) {
    uint64_t h = _mm_crc32_u64(reg_magic, hdr_word);
    return ((h & 0xFFFFULL) == 0x5A45ULL) ? 1ULL : 0ULL;
}

// Уровень 2 (Stateful DDR Salt): вход в выровненный 64B слот DDR только после прохождения Уровня 1
static inline uint64_t stateful_ddr_lookup(stateful_slot_t *tbl, uint64_t flow_id, uint64_t tag) {
    uint64_t idx = _mm_crc32_u64(0x1337ULL, flow_id) & 1023ULL;
    stateful_slot_t *slot = tbl + idx;
    uint64_t expected = _mm_crc32_u64(slot->epoch_salt, flow_id);
    uint64_t ok = (expected == tag) ? 1ULL : 0ULL;
    slot->hit_count += ok;
    return ok;
}

int main(void) {
    ddr_arena_t arena;
    if (ddr_arena_create(&arena) != 0) return 1;
    stateful_slot_t *tbl = (stateful_slot_t *)ddr_arena_alloc_data(&arena, 1024 * sizeof(stateful_slot_t), 64);
    if (!tbl) return 2;

    uint64_t reg_magic = 0x494E414D4F52455AULL;
    uint64_t valid_hdr = 0;
    while (!stateless_gate_check(valid_hdr, reg_magic)) valid_hdr++;

    uint64_t flow_id = 0x0A0000010A000002ULL;
    uint64_t idx = _mm_crc32_u64(0x1337ULL, flow_id) & 1023ULL;
    (tbl + idx)->epoch_salt = 0xCAFEBABE12345678ULL;
    (tbl + idx)->salted_tag = _mm_crc32_u64((tbl + idx)->epoch_salt, flow_id);
    uint64_t valid_tag = (tbl + idx)->salted_tag;

    unsigned aux = 0;
    uint64_t junk_blocked_l1 = 0, valid_passed_l2 = 0;
    uint64_t t0 = __rdtscp(&aux);
    for (uint64_t i = 0; i < 10000000ULL; i++) {
        uint64_t is_valid = (i & 1ULL);
        uint64_t hdr = is_valid ? valid_hdr : (valid_hdr ^ 0xFF00ULL);
        if (!stateless_gate_check(hdr, reg_magic)) {
            junk_blocked_l1++;
        } else {
            valid_passed_l2 += stateful_ddr_lookup(tbl, flow_id, valid_tag);
        }
    }
    uint64_t t1 = __rdtscp(&aux);

    printf("=== ДВУХУРОВНЕВЫЙ ВХОД В DDR-ТАБЛИЦУ (STATELESS GATE -> STATEFUL DDR SALT) ===\n");
    printf("Отсечено на Уровне 1 (0 обращений к DDR): %llu / 5000000\n", (unsigned long long)junk_blocked_l1);
    printf("Прошло Уровень 2 (DDR Salt 64B slot)   : %llu / 5000000\n", (unsigned long long)valid_passed_l2);
    printf("Средняя цена решения (10 000 000 кадров): %.2f такта CPU на кадр\n", (double)(t1 - t0) / 10000000.0);

    ddr_arena_destroy(&arena);
    return 0;
}
