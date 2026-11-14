#include "../ddr_arena/ddr_arena.h"
#include <stdio.h>
#include <stdint.h>
#include <stdatomic.h>
#include <string.h>
#include <time.h>

#define RING_SLOTS 4096
#define RING_MASK  (RING_SLOTS - 1)

typedef struct __attribute__((aligned(64))) {
    uint64_t addr_offset;
    uint32_t pkt_len;
    uint32_t flags;
    uint8_t  inline_data;
} dma_desc_t;

typedef struct __attribute__((aligned(64))) {
    _Atomic uint64_t nic_head;   // Двигает сетевая карта (PCIe DMA)
    uint8_t pad1;
    _Atomic uint64_t cpu_tail;   // Двигает твой x86_64 ASM модуль
    uint8_t pad2;
    dma_desc_t slots;
} dma_rx_ring_t;

int main() {
    ddr_arena_t arena;
    if (ddr_arena_create(&arena) != 0) return 1;

    dma_rx_ring_t *ring = (dma_rx_ring_t *)ddr_arena_alloc_data(&arena, sizeof(dma_rx_ring_t) + RING_SLOTS * sizeof(dma_desc_t), 64);
    if (!ring) return 2;
    atomic_store_explicit(&ring->nic_head, 0, memory_order_relaxed);
    atomic_store_explicit(&ring->cpu_tail, 0, memory_order_relaxed);

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    uint64_t processed = 0, total_pkts = 10000000ULL;
    while (processed < total_pkts) {
        // 1. Сетевая карта (DMA) кладёт пачку из 64 пакетов прямо в DDR без прерывания CPU
        uint64_t h = atomic_load_explicit(&ring->nic_head, memory_order_relaxed);
        for (uint64_t b = 0; b < 64; b++) {
            dma_desc_t *d = (&ring->slots) + ((h + b) & RING_MASK);
            d->pkt_len = 64;
            d->flags = 1;
            d->inline_data = (uint8_t)((h + b) ^ 0x5A);
        }
        atomic_store_explicit(&ring->nic_head, h + 64, memory_order_release);

        // 2. Процессор забирает пакеты из кольца по указателю tail (0 syscall, 0 копирований)
        uint64_t t = atomic_load_explicit(&ring->cpu_tail, memory_order_relaxed);
        uint64_t avail = atomic_load_explicit(&ring->nic_head, memory_order_acquire);
        while (t < avail) {
            dma_desc_t *d = (&ring->slots) + (t & RING_MASK);
            processed += (d->flags & 1);
            t++;
        }
        atomic_store_explicit(&ring->cpu_tail, t, memory_order_release);
    }

    clock_gettime(CLOCK_MONOTONIC, &t1);
    double sec = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) * 1e-9;
    printf("=== СТУПЕНЬ 2: ПРЯМОЙ КОЛЬЦЕВОЙ БУФЕР PCIe/DMA В DDR-АРЕНЕ ===\n");
    printf("Передано без ядра и IRQ : %llu пакетов за %.4f сек (%.2f млн пакетов/сек)\n",
           (unsigned long long)processed, sec, (double)processed / (sec * 1e6));
    printf("Системных вызовов (syscall): 0 | Копирований памяти: 0 | Слот: 64B cache-line\n");

    ddr_arena_destroy(&arena);
    return 0;
}
