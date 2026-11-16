// ZEROMANI (zerokull1) | 0x5A45524F4D414E49ULL
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <x86intrin.h>

extern uint8_t  zero_core_detect_simd_tier(void);
extern uint64_t zero_core_scan_cacheline_64b(const uint8_t *ptr, uint8_t needle);

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
    uint8_t tier = zero_core_detect_simd_tier();
    const char *tname = (tier == 3) ? "AVX-512BW (512-bit ZMM)" :
                        (tier == 2) ? "AVX2 (256-bit YMM)" : "SWAR GPR (64-bit Base)";

    uint8_t *line = aligned_alloc(64, 64);
    for (int i = 0; i < 64; i++) *(line + i) = (uint8_t)(i + 1);
    *(line + 42) = 0xEE;

    const char *rapl = "/sys/class/powercap/intel-rapl:0/energy_uj";
    uint64_t total = 50000000ULL, acc = 0;
    unsigned aux = 0;
    uint64_t e0 = read_u64_sysfs(rapl), t0 = now_ns(), c0 = __rdtscp(&aux);
    for (uint64_t i = 0; i < total; i++) {
        acc ^= zero_core_scan_cacheline_64b(line, 0xEE);
    }
    uint64_t c1 = __rdtscp(&aux), t1 = now_ns(), e1 = read_u64_sysfs(rapl);

    double sec = (double)(t1 - t0) / 1e9;
    double mpps = ((double)total / 1e6) / sec;
    double watts = (e1 > e0) ? ((double)(e1 - e0) / 1e6) / sec : 0.0;

    printf("=== УНИВЕРСАЛЬНЫЙ CPUID-АВТОДИСПЕТЧЕР (50 000 000 КЭШ-ЛИНИЙ ПО 64 Б) ===\n");
    printf("Выбранный конвейер CPUID : Tier %u -> %s\n", tier, tname);
    printf("Скорость / Такты         : %.2f Mpps (%.2f ГБ/с) | %.2f такта / 64B\n",
           mpps, (mpps * 64.0) / 1000.0, (double)(c1 - c0) / (double)total);
    printf("Мощность (Intel RAPL)    : %.2f Вт | %.2f Mpps / Вт (mask=0x%llx)\n",
           watts, (watts > 0.0) ? (mpps / watts) : 0.0, (unsigned long long)(acc & 0xFFFFFFFFFFFFULL));

    free(line);
    return 0;
}
