// ZEROMANI (zerokull1) | 0x5A45524F4D414E49ULL
#include <sys/mman.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <nmmintrin.h>
#include <xmmintrin.h>
#include <x86intrin.h>

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
    
    
    // Выделяем 16 МБ (262 144 слота по 64 байта — выходим за пределы 6 МБ L3 кэша i5-4590!)
    size_t slots = 262144ULL;
    uint8_t *ring = mmap(NULL, slots * 64ULL, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (!ring) return 2;
    for (size_t i = 0; i < slots; i++) *(uint64_t *)(ring + i * 64ULL) = 0x5A45524F4D414E49ULL ^ (uint64_t)i;

    const char *rapl = "/sys/class/powercap/intel-rapl:0/energy_uj";
    uint64_t total = 100000000ULL, acc = 0;
    unsigned aux = 0;

    // 1. Обычный обход без предвыборки
    uint64_t e0 = read_u64_sysfs(rapl), t0 = now_ns(), c0 = __rdtscp(&aux);
    for (uint64_t i = 0; i < total; i++) {
        size_t idx = (size_t)((i * 1315423911ULL) & (slots - 1ULL));
        acc ^= _mm_crc32_u64(0x1337ULL, *(const uint64_t *)(ring + idx * 64ULL));
    }
    uint64_t c1 = __rdtscp(&aux), t1 = now_ns(), e1 = read_u64_sysfs(rapl);

    // 2. Батчинг по 64 кадра + упреждающий _mm_prefetch(..., _MM_HINT_T0) на +8 шагов вперёд
    uint64_t e2 = read_u64_sysfs(rapl), t2 = now_ns(), c2 = __rdtscp(&aux);
    for (uint64_t b = 0; b < total; b += 64ULL) {
        for (uint64_t k = 0; k < 64ULL; k++) {
            size_t pf_idx = (size_t)(((b + k + 8ULL) * 1315423911ULL) & (slots - 1ULL));
            _mm_prefetch((const char *)(ring + pf_idx * 64ULL), _MM_HINT_T0);
            size_t idx = (size_t)(((b + k) * 1315423911ULL) & (slots - 1ULL));
            acc ^= _mm_crc32_u64(0x1337ULL, *(const uint64_t *)(ring + idx * 64ULL));
        }
    }
    uint64_t c3 = __rdtscp(&aux), t3 = now_ns(), e3 = read_u64_sysfs(rapl);

    double s1 = (double)(t1 - t0) / 1e9, s2 = (double)(t3 - t2) / 1e9;
    double w1 = (e1 > e0) ? ((double)(e1 - e0) / 1e6) / s1 : 0.0;
    double w2 = (e3 > e2) ? ((double)(e3 - e2) / 1e6) / s2 : 0.0;

    printf("=== ЭКСПЕРИМЕНТ №3: БАТЧИНГ 64 + _MM_PREFETCH T0 (16 МБ RING > L3 КЭШ) ===\n");
    printf("1. Без prefetch : %.2f Mpps | %.2f такта/кадр | %.2f Вт (acc=0x%llx)\n",
           100.0 / s1, (double)(c1 - c0) / (double)total, w1, (unsigned long long)(acc & 0xFF));
    printf("2. Batch64 + T0 : %.2f Mpps | %.2f такта/кадр | %.2f Вт (ускорение: +%.1f%%)\n",
           100.0 / s2, (double)(c3 - c2) / (double)total, w2, ((s1 / s2) - 1.0) * 100.0);

    munmap(ring, slots * 64ULL);
    return 0;
}
