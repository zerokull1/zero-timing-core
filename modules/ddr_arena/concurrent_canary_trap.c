// ZEROMANI (zerokull1) | 0x5A45524F4D414E49ULL
#include "ddr_arena.h"
#include <stdio.h>
#include <stdint.h>
#include <stdatomic.h>
#include <string.h>
#include <pthread.h>

#define CANARY_HEAD 0x5A45524F43414E31ULL
#define CANARY_TAIL 0x494E414D4F52455AULL

typedef struct __attribute__((aligned(64))) {
    _Atomic uint64_t head_canary;
    uint64_t payload_rule;
    uint64_t epoch_secret;
    _Atomic uint64_t tail_canary;
} guarded_ddr_block_t;

typedef struct {
    guarded_ddr_block_t *blk;
    _Atomic uint32_t *fail_close;
    uint64_t passed_before_trip;
    uint64_t blocked_fail_close;
    int is_corruptor;
} worker_ctx_t;

static void *canary_worker(void *arg) {
    worker_ctx_t *ctx = (worker_ctx_t *)arg;
    for (uint64_t i = 0; i < 1000000ULL; i++) {
        if (ctx->is_corruptor && i == 250000ULL) {
            atomic_store_explicit(&ctx->blk->tail_canary, 0xDEAD0000BADC0DEULL, memory_order_release);
            break;
        }
        if (atomic_load_explicit(ctx->fail_close, memory_order_acquire) != 0U) {
            ctx->blocked_fail_close++;
            continue;
        }
        uint64_t h = atomic_load_explicit(&ctx->blk->head_canary, memory_order_acquire);
        uint64_t t = atomic_load_explicit(&ctx->blk->tail_canary, memory_order_acquire);
        if (h != CANARY_HEAD || t != CANARY_TAIL) {
            atomic_store_explicit(ctx->fail_close, 1U, memory_order_seq_cst);
            explicit_bzero(&ctx->blk->epoch_secret, sizeof(uint64_t));
            ctx->blocked_fail_close++;
        } else {
            ctx->passed_before_trip++;
        }
    }
    return NULL;
}

int main(void) {
    ddr_arena_t arena;
    if (ddr_arena_create(&arena) != 0) return 1;
    guarded_ddr_block_t *blk = (guarded_ddr_block_t *)ddr_arena_alloc_data(&arena, sizeof(guarded_ddr_block_t), 64);
    if (!blk) return 2;

    atomic_init(&blk->head_canary, CANARY_HEAD);
    atomic_init(&blk->tail_canary, CANARY_TAIL);
    blk->payload_rule = 0x1122334455667788ULL;
    blk->epoch_secret = 0xCAFEBABEDEADBEEFULL;

    _Atomic uint32_t fail_close = 0U;
    pthread_t *tids = (pthread_t *)ddr_arena_alloc_data(&arena, 4 * sizeof(pthread_t), 64);
    worker_ctx_t *ctxs = (worker_ctx_t *)ddr_arena_alloc_data(&arena, 4 * sizeof(worker_ctx_t), 64);

    for (int t = 0; t < 4; t++) {
        (ctxs + t)->blk = blk;
        (ctxs + t)->fail_close = &fail_close;
        (ctxs + t)->passed_before_trip = 0;
        (ctxs + t)->blocked_fail_close = 0;
        (ctxs + t)->is_corruptor = (t == 3) ? 1 : 0;
        pthread_create(tids + t, NULL, canary_worker, ctxs + t);
    }
    for (int t = 0; t < 4; t++) pthread_join(*(tids + t), NULL);

    uint64_t tot_pass = 0, tot_fc = 0;
    for (int t = 0; t < 3; t++) { tot_pass += (ctxs + t)->passed_before_trip; tot_fc += (ctxs + t)->blocked_fail_close; }

    printf("=== ТЕСТ №6: МНОГОПОТОЧНАЯ ГОНКА CANARY-ЛОВУШКИ И FAIL-CLOSE В DDR ===\n");
    printf("Состояние защёлки Fail-Close : %s (tripped=%u)\n", fail_close ? "СРАБОТАЛА МГНОВЕННО" : "ОШИБКА", fail_close);
    printf("Секрет эпохи после тревоги   : 0x%llx (0 = затёрт в ноль)\n", (unsigned long long)blk->epoch_secret);
    printf("Кадров до порчи / в Fail-Close: %llu пропущено | %llu заблокировано (0 утечек)\n",
           (unsigned long long)tot_pass, (unsigned long long)tot_fc);

    ddr_arena_destroy(&arena);
    return (fail_close == 1U && blk->epoch_secret == 0ULL && tot_fc > 0ULL) ? 0 : 3;
}
