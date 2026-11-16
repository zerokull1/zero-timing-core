// ZEROMANI (zerokull1) | 0x5A45524F4D414E49ULL
#include "../modules/ddr_arena/ddr_arena.h"
#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <nmmintrin.h>
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
    ddr_arena_t arena;
    if (ddr_arena_create(&arena) != 0) return 1;
    uint64_t *ring = (uint64_t *)ddr_arena_alloc_data(&arena, 65536ULL * sizeof(uint64_t), 64);
    if (!ring) return 2;
    for (size_t i = 0; i < 65536; i++) *(ring + i) = 0x5A45524F4D414E49ULL ^ (uint64_t)i;

    const char *rapl_path = "/sys/class/powercap/intel-rapl:0/energy_uj";
    const char *temp_path = "/sys/class/thermal/thermal_zone0/temp";
    uint64_t temp0 = read_u64_sysfs(temp_path);
    uint64_t e0 = read_u64_sysfs(rapl_path);
    uint64_t t0_ns = now_ns();
    unsigned aux = 0;
    uint64_t c0 = __rdtscp(&aux);

    uint64_t acc = 0, total = 100000000ULL;
    for (uint64_t i = 0; i < total; i++) {
        uint64_t w = *(ring + (i & 65535ULL));
        acc ^= _mm_crc32_u64(0x1337ULL, w);
    }

    uint64_t c1 = __rdtscp(&aux);
    uint64_t t1_ns = now_ns();
    uint64_t e1 = read_u64_sysfs(rapl_path);
    uint64_t temp1 = read_u64_sysfs(temp_path);

    double sec = (double)(t1_ns - t0_ns) / 1e9;
    double mpps = ((double)total / 1e6) / sec;
    double joules = (e1 >= e0) ? ((double)(e1 - e0) / 1e6) : 0.0;
    double watts = (sec > 0.0 && joules > 0.0) ? (joules / sec) : 0.0;
    double mpps_per_watt = (watts > 0.0) ? (mpps / watts) : 0.0;
    double nj_per_pkt = (joules > 0.0) ? ((joules * 1e9) / (double)total) : 0.0;

    printf("=== ТЕПЛОВОЙ ПРОФАЙЛЕР INTEL RAPL (100 000 000 КАДРОВ В DDR-АРЕНЕ) ===\n");
    printf("Скорость / Такты        : %.2f Mpps | %.2f такта/кадр (acc=0x%llx)\n",
           mpps, (double)(c1 - c0) / (double)total, (unsigned long long)(acc & 0xFFFF));
    printf("Энергия / Мощность CPU  : %.3f Дж | %.2f Вт (RAPL Package)\n", joules, watts);
    printf("Холодная эффективность  : %.2f Mpps / Вт | %.3f нДж / пакет\n", mpps_per_watt, nj_per_pkt);
    printf("Температура датчика     : %.1f C -> %.1f C\n", temp0 / 1000.0, temp1 / 1000.0);

    ddr_arena_destroy(&arena);
    return 0;
}
