// ZEROMANI (zerokull1) | 0x5A45524F4D414E49ULL
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <time.h>
#include <sys/mman.h>

extern size_t zero_core_inspect_proto_l7_batch(const uint16_t *sports, const uint16_t *dports,
                                               const uint8_t *const *ptrs, const size_t *lens,
                                               uint32_t *verdicts, size_t count);

typedef struct {
    int core_id;
    size_t slots;
    size_t rounds;
    const uint16_t *sports;
    const uint16_t *dports;
    const uint8_t *const *ptrs;
    const size_t *lens;
    size_t blocked;
} worker_ctx_t;

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

static void *worker_fn(void *arg) {
    worker_ctx_t *w = (worker_ctx_t *)arg;
    cpu_set_t cs;
    CPU_ZERO(&cs);
    CPU_SET(w->core_id, &cs);
    pthread_setaffinity_np(pthread_self(), sizeof(cs), &cs);

    uint32_t *verdicts = malloc(w->slots * sizeof(uint32_t));
    size_t blk = 0;
    for (size_t r = 0; r < w->rounds; r++) {
        blk += zero_core_inspect_proto_l7_batch(w->sports, w->dports, w->ptrs, w->lens, verdicts, w->slots);
    }
    free(verdicts);
    w->blocked = blk;
    return NULL;
}

int main(void) {
    long ncores = sysconf(_SC_NPROCESSORS_ONLN);
    if (ncores < 1) ncores = 1;
    size_t slots = 262144ULL, rounds = 40ULL;

    uint8_t *pool = mmap(NULL, slots * 64ULL, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    uint16_t *sports = malloc(slots * sizeof(uint16_t));
    uint16_t *dports = malloc(slots * sizeof(uint16_t));
    const uint8_t **ptrs = malloc(slots * sizeof(const uint8_t *));
    size_t *lens = malloc(slots * sizeof(size_t));
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

    pthread_t *th = malloc((size_t)ncores * sizeof(pthread_t));
    worker_ctx_t *ctx = malloc((size_t)ncores * sizeof(worker_ctx_t));

    const char *rapl = "/sys/class/powercap/intel-rapl:0/energy_uj";
    const char *temp = "/sys/class/thermal/thermal_zone0/temp";
    uint64_t tp0 = read_u64_sysfs(temp), e0 = read_u64_sysfs(rapl), t0 = now_ns();

    for (long c = 0; c < ncores; c++) {
        *(ctx + c) = (worker_ctx_t){ (int)c, slots, rounds, sports, dports, ptrs, lens, 0 };
        pthread_create(th + c, NULL, worker_fn, ctx + c);
    }
    size_t total_blk = 0;
    for (long c = 0; c < ncores; c++) {
        pthread_join(*(th + c), NULL);
        total_blk += (ctx + c)->blocked;
    }

    uint64_t t1 = now_ns(), e1 = read_u64_sysfs(rapl), tp1 = read_u64_sysfs(temp);
    double sec = (double)(t1 - t0) / 1e9;
    double total_pkts = (double)ncores * (double)slots * (double)rounds;
    double mpps = (total_pkts / 1e6) / sec;
    double watts = (e1 > e0) ? ((double)(e1 - e0) / 1e6) / sec : 0.0;

    printf("=== ЧЕСТНЫЙ ЗАМЕР НА ВСЕХ %ld/%ld ЯДРАХ (%.2f МЛН КАДРОВ / 9 ПРОТОКОЛОВ) ===\n",
           ncores, ncores, total_pkts / 1e6);
    printf("Суммарная скорость чипа  : %.2f Mpps (блок = %zu)\n", mpps, total_blk);
    printf("Мощность пакета (RAPL)   : %.2f Вт | %.2f Mpps / Вт | %.2f нДж / пакет\n",
           watts, (watts > 0.0) ? (mpps / watts) : 0.0, (watts > 0.0) ? ((watts * 1e3) / mpps) : 0.0);
    printf("Температура кристалла    : %.1f C -> %.1f C\n", tp0 / 1000.0, tp1 / 1000.0);

    free(th); free(ctx); free(sports); free(dports); free(ptrs); free(lens);
    munmap(pool, slots * 64ULL);
    return 0;
}
