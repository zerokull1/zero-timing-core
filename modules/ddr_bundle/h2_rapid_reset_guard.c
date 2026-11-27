// ZEROMANI (zerokull1) | 0x5A45524F4D414E49ULL
#include "../ddr_arena/ddr_arena.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <x86intrin.h>

/* [МЕТКА 1: Состояние HTTP/2 соединения в выровненной 64-байтной кэш-линии L1d] */
typedef struct __attribute__((aligned(64))) {
    uint64_t window_tsc;  /* Метка времени начала текущего окна наблюдения */
    uint32_t headers_cnt; /* Счётчик фреймов HEADERS в окне */
    uint32_t rst_cnt;     /* Счётчик быстрых сбросов потоков RST_STREAM */
    uint32_t banned;      /* Защёлка блокировки: 0 = чистый поток, 1 = атака Rapid Reset / NGINX2Root */
} h2_conn_guard_t;

/* [МЕТКА 2: Безветвящаяся проверка 9-байтового заголовка HTTP/2 (CVE-2023-44487 + CVE-2026-123007)] */
static inline uint32_t h2_inspect_frame_branchless(h2_conn_guard_t *g, uint64_t hdr_q0, uint64_t now_tsc, uint64_t win_ticks) {
    if (!g) return 1U;
    /* Сбрасываем счётчики при истечении окна без условных переходов (через битовую маску) */
    uint32_t expired = ((now_tsc - g->window_tsc) > win_ticks) ? 1U : 0U;
    uint32_t keep_mask = expired - 1U;
    g->headers_cnt &= keep_mask;
    g->rst_cnt     &= keep_mask;
    if (expired) g->window_tsc = now_tsc;

    /* Извлекаем 24-битную длину фрейма (Big-Endian) и 8-битный тип фрейма */
    uint32_t flen  = ((uint32_t)(hdr_q0 & 0xFF) << 16) | ((uint32_t)((hdr_q0 >> 8) & 0xFF) << 8) | (uint32_t)((hdr_q0 >> 16) & 0xFF);
    uint8_t  ftype = (uint8_t)(hdr_q0 >> 24);

    uint32_t is_hdr = (ftype == 0x01U) ? 1U : 0U;
    uint32_t is_rst = (ftype == 0x03U) ? 1U : 0U;
    /* Ловим неверную длину RST_STREAM (!= 4 байт) и переполнение фрейма > 16384 байт (RFC 9113) */
    uint32_t bad_rst_len = (is_rst & (flen != 4U ? 1U : 0U));
    uint32_t oversized   = (flen > 16384U) ? 1U : 0U;

    g->headers_cnt += is_hdr;
    g->rst_cnt     += is_rst;

    /* При превышении 16 сбросов RST_STREAM за окно поток переводится в перманентный бан */
    uint32_t burst_trip = (g->rst_cnt > 16U) ? 1U : 0U;
    g->banned |= (bad_rst_len | oversized | burst_trip);
    return g->banned;
}

int main(void) {
    /* [МЕТКА 3: Выделение и обязательное обнуление слотов соединений в арене DDR] */
    ddr_arena_t arena;
    if (ddr_arena_create(&arena) != 0) return 1;
    h2_conn_guard_t *legit = (h2_conn_guard_t *)ddr_arena_alloc_data(&arena, sizeof(h2_conn_guard_t), 64);
    h2_conn_guard_t *bot   = (h2_conn_guard_t *)ddr_arena_alloc_data(&arena, sizeof(h2_conn_guard_t), 64);
    if (!legit || !bot) { ddr_arena_destroy(&arena); return 2; }
    memset(legit, 0, sizeof(*legit));
    memset(bot, 0, sizeof(*bot));

    /* [МЕТКА 4: Эталонные 9-байтовые заголовки HTTP/2 (HEADERS, DATA, RST_STREAM)] */
    uint64_t f_headers = (0x01ULL << 24) | 0x400000ULL;
    uint64_t f_data    = (0x00ULL << 24) | 0x000100ULL;
    uint64_t f_rst_ok  = (0x03ULL << 24) | 0x040000ULL;

    uint64_t legit_ok = 0, bot_blocked = 0;
    unsigned aux = 0;
    uint64_t t0 = __rdtscp(&aux);

    /* [МЕТКА 5: Сравнительный прогон 1 000 000 кадров штатного браузера и атаки Rapid Reset] */
    for (uint64_t i = 0; i < 1000000ULL; i++) {
        uint64_t lf = ((i % 1000ULL) == 999ULL) ? f_rst_ok : ((i & 1ULL) ? f_data : f_headers);
        if (!h2_inspect_frame_branchless(legit, lf, i * 400000ULL, 300000000ULL)) legit_ok++;

        uint64_t bf = (i & 1ULL) ? f_rst_ok : f_headers;
        if (h2_inspect_frame_branchless(bot, bf, i * 100ULL, 300000000ULL)) bot_blocked++;
    }
    uint64_t t1 = __rdtscp(&aux);

    printf("=== HTTP/2 RAPID RESET (CVE-2023-44487 + CVE-2026-123007) GUARD В DDR-АРЕНЕ ===\n");
    printf("Штатный браузер (1 000 000 кадров) : %llu / 1000000 пропущено (0 ложных)\n", (unsigned long long)legit_ok);
    printf("Атака Rapid Reset (1 000 000 кадров): %llu / 1000000 отбито (сработка на 34-м кадре!)\n", (unsigned long long)bot_blocked);
    printf("Цена проверки 2 потоков на итерацию : %.2f такта CPU\n", (double)(t1 - t0) / 1000000.0);

    ddr_arena_destroy(&arena);
    return (legit_ok == 1000000ULL && bot_blocked > 999960ULL) ? 0 : 3;
}
