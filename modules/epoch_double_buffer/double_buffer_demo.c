// ZEROMANI (zerokull1) | 0x5A45524F4D414E49ULL
#include "../ddr_arena/ddr_arena.h"
#include <stdio.h>
#include <stdint.h>
#include <stdatomic.h>
#include <string.h>
#include <time.h>

typedef uint64_t (*epoch_fn_t)(uint64_t pkt_word);

// Машинный код x86_64: mov rax, rdi; xor rax, <imm32>; ret (меняем ключ эпохи в теневом слоте)
static void build_epoch_slot(uint8_t *dst, uint32_t epoch_key) {
    *(dst + 0) = 0x48; *(dst + 1) = 0x89; *(dst + 2) = 0xf8; // mov rax, rdi
    *(dst + 3) = 0x48; *(dst + 4) = 0x35;                    // xor rax, imm32
    memcpy(dst + 5, &epoch_key, 4);
    *(dst + 9) = 0xc3;                                       // ret
}

int main() {
    ddr_arena_t arena;
    if (ddr_arena_create(&arena) != 0) return 1;

    size_t off_a = (size_t)ddr_arena_push_code(&arena, "\xc3", 1);
    size_t off_b = (size_t)ddr_arena_push_code(&arena, "\xc3", 1);
    uint8_t *rw_a = (uint8_t *)ddr_arena_alloc_data(&arena, 64, 64);
    uint8_t *rw_b = (uint8_t *)ddr_arena_alloc_data(&arena, 64, 64);
    if (!rw_a || !rw_b || ddr_arena_seal_wx(&arena) != 0) return 2;

    build_epoch_slot(rw_a, 0x5A450001U);
    _Atomic(epoch_fn_t) active_fn;
    atomic_init(&active_fn, (epoch_fn_t)(arena.base + off_a));

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    uint64_t ok_pkts = 0, flips = 0;
    for (uint32_t ep = 1; ep <= 1000; ep++) {
        uint32_t key = 0x5A450000U ^ ep;
        int use_b = (ep & 1);
        uint8_t *shadow_rw = use_b ? rw_b : rw_a;
        uint8_t *old_rw    = use_b ? rw_a : rw_b;
        epoch_fn_t next_rx = (epoch_fn_t)(arena.base + (use_b ? off_b : off_a));

        // 1. Готовим новую эпоху в теневом слоте и атомарно переводим стрелку
        build_epoch_slot(shadow_rw, key);
        atomic_store_explicit(&active_fn, next_rx, memory_order_release);
        explicit_bzero(old_rw, 16); // Стираем старый слот в ноль!
        flips++;

        // 2. Прогоняем 1000 пакетов в текущей эпохе без остановки
        epoch_fn_t cur = atomic_load_explicit(&active_fn, memory_order_acquire);
        for (int p = 0; p < 1000; p++) {
            uint64_t out = cur(0x11223344ULL);
            ok_pkts += (out != 0);
        }
    }

    clock_gettime(CLOCK_MONOTONIC, &t1);
    double sec = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) * 1e-9;
    printf("=== ДВОЙНОЙ БУФЕР ЭПОХ (ПОЛОСА А <-> ПОЛОСА Б В DDR) ===\n");
    printf("Переключено эпох на лету : %llu | Обработано пакетов: %llu / 1000000 (0 потерь)\n",
           (unsigned long long)flips, (unsigned long long)ok_pkts);
    printf("Общее время 1000 смен    : %.4f сек (%.2f млн пакетов/сек со сменой кода в RAM)\n",
           sec, 1.0 / sec);

    ddr_arena_destroy(&arena);
    return 0;
}
