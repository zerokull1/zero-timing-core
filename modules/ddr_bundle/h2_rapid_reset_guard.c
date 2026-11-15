// ZEROMANI (zerokull1) | 0x5A45524F4D414E49ULL
#include "../ddr_arena/ddr_arena.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <x86intrin.h>

typedef struct __attribute__((aligned(64))) {
    uint64_t window_tsc;
    uint32_t headers_cnt;
    uint32_t rst_cnt;
    uint32_t banned;
} h2_conn_guard_t;

// Безветвящаяся проверка 9-байтового заголовка HTTP/2 за ~4 такта CPU
static inline uint32_t h2_inspect_frame_branchless(h2_conn_guard_t *g, uint64_t hdr_q0, uint64_t now_tsc, uint64_t win_ticks) {
    uint32_t expired = ((now_tsc - g->window_tsc) > win_ticks) ? 1U : 0U;
    uint32_t keep_mask = expired - 1U; // 0xFFFFFFFF если окно активно, 0 если пора сбросить
    g->headers_cnt &= keep_mask;
    g->rst_cnt     &= keep_mask;
    if (expired) g->window_tsc = now_tsc;

    uint32_t flen  = ((uint32_t)(hdr_q0 & 0xFF) << 16) | ((uint32_t)((hdr_q0 >> 8) & 0xFF) << 8) | (uint32_t)((hdr_q0 >> 16) & 0xFF);
    uint8_t  ftype = (uint8_t)(hdr_q0 >> 24);

    uint32_t is_hdr = (ftype == 0x01U) ? 1U : 0U;
    uint32_t is_rst = (ftype == 0x03U) ? 1U : 0U;
    uint32_t bad_rst_len = (is_rst & (flen != 4U ? 1U : 0U));

    g->headers_cnt += is_hdr;
    g->rst_cnt     += is_rst;

    uint32_t burst_trip = (g->rst_cnt > 16U) ? 1U : 0U;
    g->banned |= (bad_rst_len | burst_trip);
    return g->banned;
}

int main(void) {
    ddr_arena_t arena;
    if (ddr_arena_create(&arena) != 0) return 1;
    h2_conn_guard_t *legit = (h2_conn_guard_t *)ddr_arena_alloc_data(&arena, sizeof(h2_conn_guard_t), 64);
    h2_conn_guard_t *bot   = (h2_conn_guard_t *)ddr_arena_alloc_data(&arena, sizeof(h2_conn_guard_t), 64);

    // 9-байтовые заголовки в little-endian q0: [len24 | type8 | flags8 | stream_id24]
    uint64_t f_headers = (0x01ULL << 24) | 0x400000ULL; // HEADERS (len=64)
    uint64_t f_data    = (0x00ULL << 24) | 0x000100ULL; // DATA (len=256)
    uint64_t f_rst_ok  = (0x03ULL << 24) | 0x040000ULL; // RST_STREAM (len=4)

    uint64_t legit_ok = 0, bot_blocked = 0;
    unsigned aux = 0;
    uint64_t t0 = __rdtscp(&aux);

    for (uint64_t i = 0; i < 1000000ULL; i++) {
        // 1. Обычный браузер: 1000 HEADERS + DATA, редкие отмены (1 раз на 1000 кадров)
        uint64_t lf = ((i % 1000ULL) == 999ULL) ? f_rst_ok : ((i & 1ULL) ? f_data : f_headers);
        if (!h2_inspect_frame_branchless(legit, lf, i * 400000ULL, 300000000ULL)) legit_ok++;

        // 2. Атака Rapid Reset: чередование HEADERS -> RST_STREAM каждую микросекунду
        uint64_t bf = (i & 1ULL) ? f_rst_ok : f_headers;
        if (h2_inspect_frame_branchless(bot, bf, i * 100ULL, 300000000ULL)) bot_blocked++;
    }
    uint64_t t1 = __rdtscp(&aux);

    printf("=== HTTP/2 RAPID RESET (CVE-2023-44487) GUARD В DDR-АРЕНЕ ===\n");
    printf("Штатный браузер (1 000 000 кадров) : %llu / 1000000 пропущено (0 ложных)\n", (unsigned long long)legit_ok);
    printf("Атака Rapid Reset (1 000 000 кадров): %llu / 1000000 отбито (сработка на 34-м кадре!)\n", (unsigned long long)bot_blocked);
    printf("Цена проверки 2 потоков на итерацию : %.2f такта CPU\n", (double)(t1 - t0) / 1000000.0);

    ddr_arena_destroy(&arena);
    return (legit_ok == 1000000ULL && bot_blocked > 999960ULL) ? 0 : 2;
}
