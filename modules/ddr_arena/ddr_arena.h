// ZEROMANI (zerokull1) | 0x5A45524F4D414E49ULL
#ifndef ZERO_DDR_ARENA_H
#define ZERO_DDR_ARENA_H

#include <stdint.h>
#include <stddef.h>

/* [МЕТКА 1: КОНСТАНТЫ РАЗМЕРОВ АРЕНЫ В ПАМЯТИ DDR] */
#define DDR_ARENA_SIZE      (2 * 1024 * 1024) /* Общий размер арены: ровно 2 МБ (одна страница HugePage) */
#define DDR_CODE_SLAB_SIZE  (256 * 1024)      /* Первые 256 КБ отданы под исполняемый машинный код (RX после запечатывания) */
#define DDR_DATA_SLAB_OFF   DDR_CODE_SLAB_SIZE /* Смещение начала области данных от старта арены */
#define DDR_DATA_SLAB_SIZE  (DDR_ARENA_SIZE - DDR_CODE_SLAB_SIZE) /* Остальные 1.75 МБ под таблицы потоков и пакеты (RW) */

/* [МЕТКА 2: ДЕСКРИПТОР ЗАПЕЧАТАННОЙ АРЕНЫ DDR] */
typedef struct {
    uint8_t *base;          /* Базовый виртуальный адрес всей 2-МБ арены */
    uint8_t *data_base;     /* Указатель на область данных (base + 256 КБ) */
    size_t   total_size;    /* Полный размер арены (2 МБ) */
    size_t   code_used;     /* Сколько байт занято загруженными машинными капсулами */
    size_t   data_used;     /* Сколько байт выделено под рабочие данные */
    int      memfd;         /* Дескриптор анонимного файла памяти ядра Linux (memfd) */
    int      is_hugepage;   /* 1 = выделена аппаратная страница 2 МБ (0 промахов TLB), 0 = обычные 4 КБ страницы */
    int      locked_in_ram; /* 1 = память прибита к физической RAM (mlock), сброс в swap невозможен */
    int      wx_sealed;     /* 1 = кодовый участок переведён в W^X (только чтение + исполнение, запись запрещена) */
} ddr_arena_t;

int   ddr_arena_create(ddr_arena_t *a);
void *ddr_arena_push_code(ddr_arena_t *a, const void *machine_code, size_t len);
int   ddr_arena_seal_wx(ddr_arena_t *a);
void *ddr_arena_alloc_data(ddr_arena_t *a, size_t len, size_t align);
void  ddr_arena_destroy(ddr_arena_t *a);

#endif
