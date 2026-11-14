#include "ddr_arena.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <x86intrin.h>

typedef size_t (*asm_mod_fn_t)(const uint8_t *buf, size_t len);

// Чистый машинный код x86_64 ASM: детектор прокси-ботнета SOHO-роутера (Window <= 14600 при TLS 0x16 0x03)
static const uint8_t *soho_code = (const uint8_t[]){
    0x31, 0xc0, 0x48, 0x85, 0xff, 0x74, 0x22, 0x48, 0x83, 0xfe, 0x40, 0x72, 0x1c,
    0x80, 0x7f, 0x36, 0x16, 0x75, 0x16, 0x80, 0x7f, 0x37, 0x03, 0x75, 0x10,
    0x0f, 0xb7, 0x57, 0x30, 0x66, 0xc1, 0xc2, 0x08, 0xb9, 0x01, 0x00, 0x00, 0x00,
    0x45, 0x31, 0xc0, 0x66, 0x81, 0xfa, 0x08, 0x39, 0x41, 0x0f, 0x47, 0xc8, 0x89, 0xc8, 0xc3
};

int main() {
    ddr_arena_t arena;
    if (ddr_arena_create(&arena) != 0) return 1;

    asm_mod_fn_t run_soho = (asm_mod_fn_t)ddr_arena_push_code(&arena, soho_code, 53); if (ddr_arena_seal_wx(&arena) != 0) return 2; run_soho = (asm_mod_fn_t)(arena.base + (size_t)run_soho);
    if (!run_soho) return 2;

    uint8_t *pkt = (uint8_t *)ddr_arena_alloc_data(&arena, 128, 64);
    *(pkt + 48) = 0x16; *(pkt + 49) = 0xd0; // TCP Window = 5840 (роутер-прокси)
    *(pkt + 54) = 0x16; *(pkt + 55) = 0x03; // TLS Handshake

    unsigned aux;
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    uint64_t c0 = __rdtscp(&aux), caught = 0;

    for (int i = 0; i < 10000000; i++) {
        caught += run_soho(pkt, 80);
    }

    uint64_t c1 = __rdtscp(&aux);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double sec = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) * 1e-9;

    printf("=== ЕДИНАЯ DDR-АРЕНА МОДУЛЕЙ (mlock=%d | W^X=%d | HugePage=%d) ===\n",
           arena.locked_in_ram, arena.wx_sealed, arena.is_hugepage);
    printf("Скорость в DDR : 10 000 000 кадров за %.4f сек (%.2f млн кадров/сек | %.2f такта/кадр)\n",
           sec, 10.0 / sec, (double)(c1 - c0) / 10000000.0);
    printf("Поймано атак   : %llu / 10000000 | Очистка DDR при выходе: explicit_bzero\n",
           (unsigned long long)caught);

    ddr_arena_destroy(&arena);
    return 0;
}
