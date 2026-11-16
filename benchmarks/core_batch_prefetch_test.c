// ZEROMANI (zerokull1) | 0x5A45524F4D414E49ULL
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/mman.h>
#include <x86intrin.h>

extern uint32_t zero_core_inspect_proto_l7_ports(uint16_t sport, uint16_t dport, const uint8_t *ptr, size_t len);
extern size_t   zero_core_inspect_proto_l7_batch(const uint16_t *sports, const uint16_t *dports,
                                                 const uint8_t *const *ptrs, const size_t *lens,
                                                 uint32_t *verdicts, size_t count);

static uint64_t read_u64_sysfs(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    unsigned long long v = 0;
    if (fscanf(f, "%llu", &v) != 1) v = 0;
    fclose(f);
    return (uint64_t)v;
}

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

int main(void) {
    size_t slots = 262144ULL; // 16 МБ пул пакетов (> 6 МБ L3 кэша)
    uint8_t *pool = mmap(NULL, slots * 64ULL, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (pool == MAP_FAILED) return 1;

    uint16_t *sports = malloc(slots * sizeof(uint16_t));
    uint16_t *dports = malloc(slots * sizeof(uint16_t));
    const uint8_t **ptrs = malloc(slots * sizeof(const uint8_t *));
    size_t *lens = malloc(slots * sizeof(size_t));
    uint32_t *verdicts = malloc(slots * sizeof(uint32_t));
    const uint16_t *plist = (const uint16_t[]){ 443, 502, 53, 123, 445, 22, 4789, 179, 389, 4791 };

    for (size_t i = 0; i < slots; i++) {
        size_t idx = (i * 1315423911ULL) & (slots - 1ULL);
        uint8_t *pkt = pool + idx * 64ULL;
        *(uint64_t *)pkt = 0x2d302e322d485353ULL ^ (uint64_t)(i & 1ULL);
        *(uint64_t *)(pkt + 8) = 0x0000000000000004ULL;
        *(sports + i) = ((i % 7ULL) == 0ULL) ? 123U : 44123U;
        *(dports + i) = *(plist + (i % 10ULL));
        *(ptrs + i)   = pkt;
        *(lens + i)   = 24ULL;
    }

    const char *rapl = "/sys/class/powercap/intel-rapl:0/energy_uj";
    size_t rounds = 40ULL, total = slots * rounds, blk1 = 0, blk2 = 0;
    unsigned aux = 0;

    // 1. Поодиночный вызов ядра (без batch/prefetcht0)
    uint64_t e0 = read_u64_sysfs(rapl), t0 = now_ns(), c0 = __rdtscp(&aux);
    for (size_t r = 0; r < rounds; r++) {
        for (size_t i = 0; i < slots; i++) {
            blk1 += (zero_core_inspect_proto_l7_ports(*(sports + i), *(dports + i), *(ptrs + i), *(lens + i)) != 0U);
        }
    }
    uint64_t c1 = __rdtscp(&aux), t1 = now_ns(), e1 = read_u64_sysfs(rapl);

    // 2. Всеядный батч-конвейер ядра (Batch64 + x86_64 prefetcht0)
    uint64_t e2 = read_u64_sysfs(rapl), t2 = now_ns(), c2 = __rdtscp(&aux);
    for (size_t r = 0; r < rounds; r++) {
        blk2 += zero_core_inspect_proto_l7_batch(sports, dports, ptrs, lens, verdicts, slots);
    }
    uint64_t c3 = __rdtscp(&aux), t3 = now_ns(), e3 = read_u64_sysfs(rapl);

    double s1 = (double)(t1 - t0) / 1e9, s2 = (double)(t3 - t2) / 1e9;
    double w1 = (e1 > e0) ? ((double)(e1 - e0) / 1e6) / s1 : 0.0;
    double w2 = (e3 > e2) ? ((double)(e3 - e2) / 1e6) / s2 : 0.0;

    printf("=== БОЕВОЙ ТЕСТ ВСЕЯДНОГО #![no_std] ЯДРА (10 485 760 КАДРОВ / 9 ПРОТОКОЛОВ) ===\n");
    printf("1. Single-Pkt Core : %.2f Mpps | %.2f такта/кадр | %.2f Вт (блок=%zu)\n",
           ((double)total / 1e6) / s1, (double)(c1 - c0) / (double)total, w1, blk1);
    printf("2. Batch64+Prefetch: %.2f Mpps | %.2f такта/кадр | %.2f Вт (блок=%zu, +%.1f%%)\n",
           ((double)total / 1e6) / s2, (double)(c3 - c2) / (double)total, w2, blk2, ((s1 / s2) - 1.0) * 100.0);

    free(sports); free(dports); free(ptrs); free(lens); free(verdicts);
    munmap(pool, slots * 64ULL);
    return (blk1 == blk2) ? 0 : 2;
}
