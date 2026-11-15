#define _GNU_SOURCE
#include "ddr_arena.h"
#include <sys/mman.h>
#include <sys/syscall.h>
#include <linux/memfd.h>
#include <unistd.h>
#include <string.h>

#ifndef MFD_HUGETLB
#define MFD_HUGETLB 0x0004U
#endif
#ifndef MFD_HUGE_2MB
#define MFD_HUGE_2MB (21U << 26)
#endif
#ifndef MPOL_BIND
#define MPOL_BIND 2
#endif
#ifndef MPOL_MF_MOVE
#define MPOL_MF_MOVE (1U << 1)
#endif

static int arena_memfd = -1;
static uint8_t *rw_view = NULL;

static void bind_arena_to_local_numa(void *ptr, size_t len) {
    unsigned int cpu = 0, node = 0;
    if (syscall(__NR_getcpu, &cpu, &node, NULL) == 0) {
        unsigned long nodemask = 1UL << (node & 63U);
        syscall(__NR_mbind, ptr, len, MPOL_BIND, &nodemask, 64UL, MPOL_MF_MOVE);
    }
}

int ddr_arena_create(ddr_arena_t *a) {
    if (!a) return -1;
    memset(a, 0, sizeof(*a));

    /* 1. Пробуем выделить истинную огромную страницу 2 МБ (Zero-TLB-Miss) */
    arena_memfd = memfd_create("zeromani_ddr_arena", MFD_CLOEXEC | MFD_HUGETLB | MFD_HUGE_2MB);
    if (arena_memfd >= 0) {
        a->is_hugepage = 1;
    } else {
        /* 2. Безопасный откат на стандартные 4 КБ страницы, если HugePages не зарезервированы */
        arena_memfd = memfd_create("zeromani_ddr_arena", MFD_CLOEXEC);
        if (arena_memfd < 0) return -1;
        a->is_hugepage = 0;
    }

    if (ftruncate(arena_memfd, DDR_ARENA_SIZE) != 0) {
        close(arena_memfd);
        arena_memfd = -1;
        return -1;
    }

    rw_view = mmap(NULL, DDR_ARENA_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, arena_memfd, 0);
    if (rw_view == MAP_FAILED) {
        close(arena_memfd);
        arena_memfd = -1;
        rw_view = NULL;
        return -1;
    }

    /* Привязываем память к локальному контроллеру DDR текущего сокета (критично для multi-NUMA стоек) */
    bind_arena_to_local_numa(rw_view, DDR_ARENA_SIZE);

    /* Прогреваем все 64-байтные кэш-линии до запечатывания W^X */
    for (size_t off = 0; off < DDR_ARENA_SIZE; off += 64) {
        ((volatile uint8_t *)rw_view)[off] = 0;
    }

    a->base = rw_view;
    a->total_size = DDR_ARENA_SIZE;
    a->code_used = 64;
    if (mlock(rw_view, DDR_ARENA_SIZE) == 0) {
        a->locked_in_ram = 1;
    }
    return 0;
}

void *ddr_arena_push_code(ddr_arena_t *a, const void *machine_code, size_t len) {
    if (!a || !rw_view || a->wx_sealed || !machine_code || len == 0) return NULL;
    size_t off = (a->code_used + 63ULL) & ~63ULL;
    if (off + len > DDR_CODE_SLAB_SIZE) return NULL;
    memcpy(rw_view + off, machine_code, len);
    a->code_used = off + len;
    return (void *)off;
}

int ddr_arena_seal_wx(ddr_arena_t *a) {
    if (!a || arena_memfd < 0) return -1;
    void *rx = mmap(NULL, DDR_CODE_SLAB_SIZE, PROT_READ | PROT_EXEC, MAP_SHARED, arena_memfd, 0);
    if (rx == MAP_FAILED) return -1;
    a->base = (uint8_t *)rx;
    a->wx_sealed = 1;
    return 0;
}

void *ddr_arena_alloc_data(ddr_arena_t *a, size_t len, size_t align) {
    if (!a || !rw_view || len == 0) return NULL;
    size_t mask = (align > 1) ? (align - 1) : 63ULL;
    size_t off = (a->data_used + mask) & ~mask;
    if (off + len > DDR_DATA_SLAB_SIZE) return NULL;
    a->data_used = off + len;
    return rw_view + DDR_DATA_SLAB_OFF + off;
}

void ddr_arena_destroy(ddr_arena_t *a) {
    if (!a) return;
    if (a->wx_sealed && a->base) munmap(a->base, DDR_CODE_SLAB_SIZE);
    if (rw_view) {
        explicit_bzero(rw_view, DDR_ARENA_SIZE);
        if (a->locked_in_ram) munlock(rw_view, DDR_ARENA_SIZE);
        munmap(rw_view, DDR_ARENA_SIZE);
        rw_view = NULL;
    }
    if (arena_memfd >= 0) { close(arena_memfd); arena_memfd = -1; }
    memset(a, 0, sizeof(*a));
}
