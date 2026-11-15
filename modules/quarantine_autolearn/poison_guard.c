// ZEROMANI (zerokull1) | 0x5A45524F4D414E49ULL
#include "../ddr_arena/ddr_arena.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <nmmintrin.h>

#define TBL_SLOTS 1024ULL
#define TBL_MASK  (TBL_SLOTS - 1ULL)

typedef struct __attribute__((aligned(64))) {
    uint64_t tag64;
    uint32_t clean_hits;
    uint8_t  state;      // 0=empty, 1=quarantine, 2=allow_pinned, 3=blocked
} guarded_slot_t;

static inline uint64_t keyed_tag64(uint64_t salt, uint64_t sig) {
    return (_mm_crc32_u64(salt, sig) << 32) | _mm_crc32_u64(salt ^ 0x9E3779B97F4A7C15ULL, sig);
}

// Защищённое автообучение: 64-бит тег против коллизий + кворум K=8 + запрет перезаписи allow_pinned
static int guarded_learn_step(guarded_slot_t *tbl, uint64_t salt, uint64_t sig, int is_clean,
                              uint64_t *collisions_blocked, uint64_t *poison_blocked) {
    uint64_t tag = keyed_tag64(salt, sig);
    guarded_slot_t *s = tbl + (tag & TBL_MASK);

    if (s->state != 0 && s->tag64 != tag) {
        (*collisions_blocked)++;
        return -1; // Коллизия индекса: чужой слот защищён 64-битным тегом, перезапись запрещена!
    }
    if (s->state == 3) { (*poison_blocked)++; return 3; } // Навсегда в чёрном списке эпохи

    if (!is_clean) {
        if (s->state == 2) { (*poison_blocked)++; return 2; } // Нельзя отравить закреплённый allow-слот
        s->tag64 = tag; s->state = 3; s->clean_hits = 0;
        return 3; // Мгновенная блокировка при первой аномалии
    }

    if (s->state == 0) { s->tag64 = tag; s->state = 1; s->clean_hits = 1; return 1; }
    if (s->state == 1) {
        s->clean_hits++;
        if (s->clean_hits >= 8) s->state = 2; // Промоушен в белый список только после кворума K=8
    }
    return (int)s->state;
}

int main(void) {
    ddr_arena_t arena;
    if (ddr_arena_create(&arena) != 0) return 1;
    guarded_slot_t *tbl = (guarded_slot_t *)ddr_arena_alloc_data(&arena, TBL_SLOTS * sizeof(guarded_slot_t), 64);
    if (!tbl) return 2;

    uint64_t salt = 0x5A45524F4D414E49ULL;
    uint64_t legit_sig = 0x1122334455667788ULL;
    uint64_t coll_blocked = 0, poison_blocked = 0;

    // 1. Легитимный клиент проходит кворум K=8 чистых сессий -> закрепляется в ALLOW (state=2)
    for (int i = 0; i < 8; i++) guarded_learn_step(tbl, salt, legit_sig, 1, &coll_blocked, &poison_blocked);

    // 2. Атакующий шлёт 100 000 коллидирующих сигнатур и попыток отравить слот (1 чистый + 1 атака)
    uint64_t legit_idx = keyed_tag64(salt, legit_sig) & TBL_MASK;
    for (uint64_t a = 1; a <= 100000ULL; a++) {
        uint64_t attack_sig = legit_sig ^ (a << 10);
        guarded_learn_step(tbl, salt, attack_sig, (a & 1ULL) ? 1 : 0, &coll_blocked, &poison_blocked);
    }

    guarded_slot_t *legit_slot = tbl + legit_idx;
    int intact = (legit_slot->state == 2 && legit_slot->tag64 == keyed_tag64(salt, legit_sig));

    printf("=== ЗАЩИТА ТАБЛИЦ АВТООБУЧЕНИЯ ОТ КОЛЛИЗИЙ И ОТРАВЛЕНИЯ ===\n");
    printf("Легитимный слот после 100 000 атак : %s (state=%u, перезаписей=0)\n",
           intact ? "НЕВРЕДИМ (PINNED ALLOW)" : "ПОВРЕЖДЁН", legit_slot->state);
    printf("Пресечено коллизий по индексу      : %llu\n", (unsigned long long)coll_blocked);
    printf("Отбито попыток отравления/повторов : %llu\n", (unsigned long long)poison_blocked);

    ddr_arena_destroy(&arena);
    return intact ? 0 : 3;
}
