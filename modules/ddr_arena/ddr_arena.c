// ZEROMANI (zerokull1) | 0x5A45524F4D414E49ULL
#define _GNU_SOURCE
#include "ddr_arena.h"
#include <sys/mman.h>
#include <sys/syscall.h>
#include <linux/memfd.h>
#include <fcntl.h>
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

/* [МЕТКА 1: ПРИВЯЗКА ПАМЯТИ К ЛОКАЛЬНОМУ КОНТРОЛЛЕРУ DDR ТЕКУЩЕГО СОКЕТА CPU] */
static void bind_arena_to_local_numa(void *ptr, size_t len) {
    unsigned int cpu = 0, node = 0;
    if (syscall(__NR_getcpu, &cpu, &node, NULL) == 0) {
        unsigned long nodemask = 1UL << (node & 63U);
        syscall(__NR_mbind, ptr, len, MPOL_BIND, &nodemask, 64UL, MPOL_MF_MOVE);
    }
}

/* [МЕТКА 2: СОЗДАНИЕ 2-МБ АРЕНЫ DDR С ЗАПЕЧАТЫВАНИЕМ РАЗМЕРА И МИННЫМ ПОЛЕМ UD2] */
int ddr_arena_create(ddr_arena_t *a) {
    if (!a) return -1;
    memset(a, 0, sizeof(*a));
    a->memfd = -1;

    /* Шаг 2.1: Пробуем выделить 2 МБ HugePage с немедленной привязкой страниц (MAP_POPULATE) */
    uint8_t *view = MAP_FAILED;
    int fd = memfd_create("zeromani_ddr_arena",
                          MFD_CLOEXEC | MFD_ALLOW_SEALING | MFD_HUGETLB | MFD_HUGE_2MB);
    if (fd >= 0) {
        if (ftruncate(fd, DDR_ARENA_SIZE) == 0) {
            view = mmap(NULL, DDR_ARENA_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, fd, 0);
        }
        if (view != MAP_FAILED) {
            a->is_hugepage = 1;
        } else {
            close(fd);
            fd = -1;
        }
    }

    /* Шаг 2.2: Если HugePages не зарезервированы в системе — безопасно откатываемся на 4 КБ страницы */
    if (view == MAP_FAILED) {
        fd = memfd_create("zeromani_ddr_arena", MFD_CLOEXEC | MFD_ALLOW_SEALING);
        if (fd < 0) return -1;
        if (ftruncate(fd, DDR_ARENA_SIZE) != 0) { close(fd); return -1; }
        view = mmap(NULL, DDR_ARENA_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, fd, 0);
        if (view == MAP_FAILED) { close(fd); return -1; }
        a->is_hugepage = 0;
    }

    /* Шаг 2.3: Запрещаем ядру и любым процессам менять размер этого файла памяти */
    fcntl(fd, F_ADD_SEALS, F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL);
    bind_arena_to_local_numa(view, DDR_ARENA_SIZE);

    /* Шаг 2.4: Минируем всю кодовую зону (256 КБ) инструкциями UD2 (0x0F 0x0B):
       любой случайный или вражеский прыжок мимо капсул мгновенно вызывает аппаратный SIGILL */
    for (size_t off = 0; off + 1 < DDR_CODE_SLAB_SIZE; off += 2) {
        view[off]     = 0x0F;
        view[off + 1] = 0x0B;
    }

    a->memfd = fd;
    a->base = view;
    a->data_base = view + DDR_DATA_SLAB_OFF;
    a->total_size = DDR_ARENA_SIZE;
    a->code_used = 64; /* Первую кэш-линию (64 Б) оставляем минным полем UD2 */
    if (mlock(view, DDR_ARENA_SIZE) == 0) {
        a->locked_in_ram = 1;
    }
    return 0;
}

/* [МЕТКА 3: ЗАГРУЗКА МАШИННЫХ ОПКОДОВ КАПСУЛЫ С ВЫРАВНИВАНИЕМ ПО 64-БАЙТНОЙ КЭШ-ЛИНИИ L1i] */
void *ddr_arena_push_code(ddr_arena_t *a, const void *machine_code, size_t len) {
    if (!a || !a->base || a->wx_sealed || !machine_code || len == 0) return NULL;
    if (a->code_used > DDR_CODE_SLAB_SIZE - 64) return NULL;
    size_t off = (a->code_used + 63ULL) & ~63ULL;
    if (len > DDR_CODE_SLAB_SIZE - off) return NULL;
    memcpy(a->base + off, machine_code, len);
    a->code_used = off + len;
    return (void *)off;
}

/* [МЕТКА 4: СТРОГОЕ ЗАПЕЧАТЫВАНИЕ W^X — СНИМАЕМ ПРАВО ЗАПИСИ, ОСТАВЛЯЕМ ТОЛЬКО ЧТЕНИЕ И ИСПОЛНЕНИЕ] */
int ddr_arena_seal_wx(ddr_arena_t *a) {
    if (!a || !a->base || a->wx_sealed) return -1;
    if (mprotect(a->base, DDR_CODE_SLAB_SIZE, PROT_READ | PROT_EXEC) != 0) return -1;
    a->wx_sealed = 1;
    return 0;
}

/* [МЕТКА 5: ВЫДЕЛЕНИЕ ВЫРОВНЕННОЙ ПАМЯТИ ПОД ДАННЫЕ (ТАБЛИЦЫ ПОТОКОВ, ПАКЕТЫ, КАНАРЕЙКИ)] */
void *ddr_arena_alloc_data(ddr_arena_t *a, size_t len, size_t align) {
    if (!a || !a->data_base || len == 0) return NULL;
    size_t al = (align >= 1 && (align & (align - 1)) == 0) ? align : 64ULL;
    size_t mask = al - 1ULL;
    if (a->data_used > DDR_DATA_SLAB_SIZE - mask) return NULL;
    size_t off = (a->data_used + mask) & ~mask;
    if (len > DDR_DATA_SLAB_SIZE - off) return NULL;
    a->data_used = off + len;
    return a->data_base + off;
}

/* [МЕТКА 6: БЕЗОПАСНОЕ УНИЧТОЖЕНИЕ АРЕНЫ — ВОЗВРАТ RW, ЗАТИРАНИЕ ДАННЫХ И КОДА В НОЛЬ, ОСВОБОЖДЕНИЕ] */
void ddr_arena_destroy(ddr_arena_t *a) {
    if (!a) return;
    if (a->base) {
        if (a->wx_sealed) {
            mprotect(a->base, DDR_CODE_SLAB_SIZE, PROT_READ | PROT_WRITE);
        }
        if (a->code_used > 0 && a->code_used <= DDR_CODE_SLAB_SIZE) {
            explicit_bzero(a->base, a->code_used);
        }
        if (a->data_used > 0 && a->data_used <= DDR_DATA_SLAB_SIZE && a->data_base) {
            explicit_bzero(a->data_base, a->data_used);
        }
        if (a->locked_in_ram) munlock(a->base, DDR_ARENA_SIZE);
        munmap(a->base, DDR_ARENA_SIZE);
    }
    if (a->memfd >= 0) close(a->memfd);
    memset(a, 0, sizeof(*a));
    a->memfd = -1;
}
