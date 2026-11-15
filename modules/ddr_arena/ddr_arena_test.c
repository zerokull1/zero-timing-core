// ZEROMANI (zerokull1) | 0x5A45524F4D414E49ULL
#include "ddr_arena.h"
#include "hw_pmc_profiler.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <x86intrin.h>

typedef size_t (*asm_mod_fn_t)(const uint8_t *buf, size_t len);

static const uint8_t *soho_code = (const uint8_t[]){
    0x31, 0xc0, 0x48, 0x85, 0xff, 0x74, 0x22, 0x48, 0x83, 0xfe, 0x40, 0x72, 0x1c,
    0x80, 0x7f, 0x36, 0x16, 0x75, 0x16, 0x80, 0x7f, 0x37, 0x03, 0x75, 0x10,
    0x0f, 0xb7, 0x57, 0x30, 0x66, 0xc1, 0xc2, 0x08, 0xb9, 0x01, 0x00, 0x00, 0x00,
    0x45, 0x31, 0xc0, 0x66, 0x81, 0xfa, 0x08, 0x39, 0x41, 0x0f, 0x47, 0xc8, 0x89, 0xc8, 0xc3
};

int main() {
    ddr_arena_t arena;
    if (ddr_arena_create(&arena) != 0) return 1;
    asm_mod_fn_t run_soho = (asm_mod_fn_t)ddr_arena_push_code(&arena, soho_code, 53);
    if (!run_soho || ddr_arena_seal_wx(&arena) != 0) return 2;
    run_soho = (asm_mod_fn_t)(arena.base + (size_t)run_soho);

    uint8_t *pkt = (uint8_t *)ddr_arena_alloc_data(&arena, 128, 64);
    *(pkt + 48) = 0x16; *(pkt + 49) = 0xd0; *(pkt + 54) = 0x16; *(pkt + 55) = 0x03;

    hw_pmc_handle_t pmc_cache, pmc_branch;
    int ok_c = (hw_pmc_open(&pmc_cache, PERF_TYPE_HARDWARE, PERF_COUNT_HW_CACHE_MISSES) == 0);
    int ok_b = (hw_pmc_open(&pmc_branch, PERF_TYPE_HARDWARE, PERF_COUNT_HW_BRANCH_MISSES) == 0);

    unsigned aux; struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    uint64_t cm0 = ok_c ? asm_rdpmc(pmc_cache.pmc_index) : 0;
    uint64_t bm0 = ok_b ? asm_rdpmc(pmc_branch.pmc_index) : 0;
    uint64_t c0 = __rdtscp(&aux), caught = 0;

    for (int i = 0; i < 10000000; i++) caught += run_soho(pkt, 80);

    uint64_t c1 = __rdtscp(&aux);
    uint64_t cm1 = ok_c ? asm_rdpmc(pmc_cache.pmc_index) : 0;
    uint64_t bm1 = ok_b ? asm_rdpmc(pmc_branch.pmc_index) : 0;
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double sec = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) * 1e-9;

    printf("=== DDR-АРЕНА + ВСТРОЕННЫЙ АППАРАТНЫЙ ПРОФАЙЛЕР RDPMC (10 000 000 КАДРОВ) ===\n");
    printf("Скорость в DDR : %.2f млн кадров/сек | %.2f такта/кадр | Поймано: %llu / 10000000\n",
           10.0 / sec, (double)(c1 - c0) / 10000000.0, (unsigned long long)caught);
    printf("Аппаратные PMU : Cache Misses = %llu | Branch Mispredictions = %llu (на 10 млн кадров!)\n",
           ok_c ? (unsigned long long)(cm1 - cm0) : 0ULL, ok_b ? (unsigned long long)(bm1 - bm0) : 0ULL);

    if (ok_c) hw_pmc_close(&pmc_cache);
    if (ok_b) hw_pmc_close(&pmc_branch);
    ddr_arena_destroy(&arena);
    return 0;
}
