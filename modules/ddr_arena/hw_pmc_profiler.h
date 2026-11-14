#ifndef ZERO_HW_PMC_PROFILER_H
#define ZERO_HW_PMC_PROFILER_H

#define _GNU_SOURCE
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <linux/perf_event.h>

// Чистый x86_64 ASM: чтение аппаратного счётчика PMU процессора (IA32_PMC0..3 или Fixed PMC) за ~2 такта
static inline uint64_t asm_rdpmc(uint32_t ecx_idx) {
    uint32_t lo = 0, hi = 0;
    __asm__ __volatile__(
        "rdpmc"
        : "=a"(lo), "=d"(hi)
        : "c"(ecx_idx)
    );
    return ((uint64_t)hi << 32) | (uint64_t)lo;
}

typedef struct {
    int fd;
    struct perf_event_mmap_page *pc;
    uint32_t pmc_index;
} hw_pmc_handle_t;

// Активирует CR4.PCE через ядро Linux для прямого Ring-3 доступа к инструкции rdpmc без perf stat
static inline int hw_pmc_open(hw_pmc_handle_t *h, uint32_t type, uint64_t config) {
    if (!h) return -1;
    memset(h, 0, sizeof(*h));
    struct perf_event_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.type = type;
    attr.size = sizeof(attr);
    attr.config = config;
    attr.disabled = 0;
    attr.exclude_kernel = 1;
    attr.exclude_hv = 1;

    h->fd = (int)syscall(SYS_perf_event_open, &attr, 0, -1, -1, 0);
    if (h->fd < 0) return -1;
    h->pc = mmap(NULL, 4096, PROT_READ, MAP_SHARED, h->fd, 0);
    if (h->pc == MAP_FAILED || h->pc->index == 0) {
        close(h->fd); h->fd = -1; return -1;
    }
    h->pmc_index = h->pc->index - 1;
    return 0;
}

static inline void hw_pmc_close(hw_pmc_handle_t *h) {
    if (!h) return;
    if (h->pc && h->pc != MAP_FAILED) munmap(h->pc, 4096);
    if (h->fd >= 0) close(h->fd);
}

#endif
