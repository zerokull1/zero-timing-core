// ZEROMANI (zerokull1) | 0x5A45524F4D414E49ULL
#include "ddr_arena.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <x86intrin.h>

typedef struct __attribute__((aligned(64))) {
    uint32_t next_seq;
    uint8_t  base_ttl;
    uint8_t  active;
} tcp_flow_guard_t;

// Возврат: 0 = CLEAN PASS, 1 = OVERLAP EVASION DROP, 2 = TTL ANOMALY DROP
/* [МЕТКА 1: КОНТРОЛЬ ПОСЛЕДОВАТЕЛЬНОСТИ TCP SEQ И АНОМАЛИЙ TTL БЕЗ БУФЕРИЗАЦИИ СТРИМА] */
static inline uint32_t inspect_tcp_ttl_guard(tcp_flow_guard_t *f, uint32_t seq, uint32_t len, uint8_t ttl) {
    if (!f->active) {
        if (ttl < 16U) return 2U; // Попытка стартовать сессию с умирающим TTL-приманкой
        f->next_seq = seq + len;
        f->base_ttl = ttl;
        f->active = 1U;
        return 0U;
    }
    uint8_t diff = (ttl > f->base_ttl) ? (ttl - f->base_ttl) : (f->base_ttl - ttl);
    if (ttl < 16U || diff > 4U) return 2U;        // TTL Insertion / скачок маршрута
    if ((int32_t)(seq - f->next_seq) < 0) return 1U; // Перекрывающийся TCP-сегмент (SEQ overlap)
    f->next_seq = seq + len;
    return 0U;
}

int main(void) {
    ddr_arena_t arena;
    if (ddr_arena_create(&arena) != 0) return 1;
    tcp_flow_guard_t *flow = (tcp_flow_guard_t *)ddr_arena_alloc_data(&arena, sizeof(tcp_flow_guard_t), 64);
    if (!flow) { ddr_arena_destroy(&arena); return 2; }

    uint64_t clean_ok = 0, overlap_drops = 0, ttl_drops = 0;
    uint32_t cur_seq = 10000U;
    unsigned aux = 0;
    struct timespec ts0, ts1;
    clock_gettime(CLOCK_MONOTONIC, &ts0);
    uint64_t c0 = __rdtscp(&aux);

    /* [МЕТКА 2: СТРЕСС-ПРОГОН 10 000 000 КАДРОВ (ЧИСТЫЙ ПОТОК + ПЕРЕКРЫТИЕ SEQ + ПОДМЕНА TTL)] */
    for (uint64_t i = 0; i < 10000000ULL; i++) {
        uint64_t mode = i & 3ULL;
        uint32_t seq = cur_seq;
        uint8_t  ttl = 64U;
        if (mode == 1ULL) seq = cur_seq - 32U; // Атака перекрытием SEQ (Overlap Evasion)
        else if (mode == 2ULL) ttl = 4U;       // Атака TTL-приманкой (TTL Insertion)
        else if (mode == 3ULL) ttl = 128U;     // Резкий скачок TTL (подмена источника)

        uint32_t v = inspect_tcp_ttl_guard(flow, seq, 64U, ttl);
        if (v == 0U) { clean_ok++; cur_seq += 64U; }
        else if (v == 1U) overlap_drops++;
        else ttl_drops++;
    }

    uint64_t c1 = __rdtscp(&aux);
    clock_gettime(CLOCK_MONOTONIC, &ts1);
    double sec = (ts1.tv_sec - ts0.tv_sec) + (ts1.tv_nsec - ts0.tv_nsec) * 1e-9;

    printf("=== ТЕСТ №5: АТАКА ПЕРЕКРЫВАЮЩИМИСЯ TCP-СЕГМЕНТАМИ И АНОМАЛЬНЫМ TTL ===\n");
    printf("Чистый монолитный поток (SEQ/TTL OK) : %llu / 2500000\n", (unsigned long long)clean_ok);
    printf("Отбито перекрытий сегментов (Overlap) : %llu / 2500000\n", (unsigned long long)overlap_drops);
    printf("Отбито аномалий TTL (TTL-GUARD Drop)  : %llu / 5000000\n", (unsigned long long)ttl_drops);
    printf("Скорость фильтра (10 000 000 кадров)  : %.2f млн кадров/сек (%.2f такта/кадр)\n",
           10.0 / sec, (double)(c1 - c0) / 10000000.0);

    ddr_arena_destroy(&arena);
    return (clean_ok == 2500000ULL && overlap_drops == 2500000ULL && ttl_drops == 5000000ULL) ? 0 : 3;
}
