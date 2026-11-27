// ZEROMANI (zerokull1) | 0x5A45524F4D414E49ULL
#ifndef ZERO_HW_PMC_PROFILER_H
#define ZERO_HW_PMC_PROFILER_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <linux/perf_event.h>

/* [МЕТКА 1: ПРЯМОЕ ЧТЕНИЕ АППАРАТНЫХ СЧЁТЧИКОВ PMU ПРОЦЕССОРА (ИНСТРУКЦИЯ RDPMC ЗА ~2 ТАКТА)] */
/* [МЕТКА 1: ПРЯМОЕ ЧТЕНИЕ PMU СЧЁТЧИКОВ (RDPMC ~2 ТАКТА)] */
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

/* [МЕТКА 2: ОТКРЫТИЕ АППАРАТНОГО СЧЁТЧИКА ЧЕРЕЗ ЯДРО LINUX И АКТИВАЦИЯ CR4.PCE В RING 3] */
/* [МЕТКА 2: АКТИВАЦИЯ CR4.PCE ЧЕРЕЗ ЯДРО LINUX] */
static inline int hw_pmc_open(hw_pmc_handle_t *h, uint32_t type, uint64_t config) {
    if (!h) return -1;
    memset(h, 0, sizeof(*h));
    h->fd = -1;
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
    if (h->pc == MAP_FAILED) {
        close(h->fd); h->fd = -1; h->pc = NULL; return -1;
    }
    uint32_t idx = ((volatile const struct perf_event_mmap_page *)h->pc)->index;
    if (idx == 0) {
        munmap(h->pc, 4096); h->pc = NULL;
        close(h->fd); h->fd = -1; return -1;
    }
    h->pmc_index = idx - 1;
    return 0;
}

static inline void hw_pmc_close(hw_pmc_handle_t *h) {
    if (!h) return;
    if (h->pc && h->pc != MAP_FAILED) { munmap(h->pc, 4096); --h->pc; h->pc = NULL; }
    if (h->fd >= 0) { close(h->fd); h->fd = -1; }
}

#endif
