// ZEROMANI (zerokull1) | 0x5A45524F4D414E49ULL
#include "../ddr_arena/ddr_arena.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>

typedef struct {
    uint32_t sig;
    uint8_t  payload_byte;
    uint8_t  verdict; // 0 = unknown, 1 = allow, 2 = block
} q_record_t;

int main() {
    ddr_arena_t arena;
    if (ddr_arena_create(&arena) != 0) return 1;

    uint32_t *allow_tbl = (uint32_t *)ddr_arena_alloc_data(&arena, 256 * sizeof(uint32_t), 64);
    uint32_t *block_tbl = (uint32_t *)ddr_arena_alloc_data(&arena, 256 * sizeof(uint32_t), 64);
    q_record_t *uring_log = (q_record_t *)ddr_arena_alloc_data(&arena, 64 * sizeof(q_record_t), 64);

    *(allow_tbl + 0x10) = 0x10;
    *(block_tbl + 0xDE) = 0xDE;

    const uint8_t *traffic = (const uint8_t[]){0x10, 0xDE, 0x77, 0xBA};
    size_t log_cnt = 0, pass1 = 0, drop1 = 0, quar1 = 0;

    // Проход 1: незнакомые сигнатуры 0x77 и 0xBA уходят в карантин и лог io_uring
    for (int i = 0; i < 4; i++) {
        uint8_t s = *(traffic + i);
        if (*(allow_tbl + s) == s) { pass1++; }
        else if (*(block_tbl + s) == s) { drop1++; }
        else {
            quar1++;
            (uring_log + log_cnt)->sig = s;
            (uring_log + log_cnt)->payload_byte = (s == 0x77) ? 0x20 : 0xFF; // 0x20 = норма, 0xFF = сканер
            log_cnt++;
        }
    }

    // Фоновый разбор лога io_uring: безвредное -> в белый список, опасное -> в боевое правило DDR
    for (size_t i = 0; i < log_cnt; i++) {
        uint8_t s = (uint8_t)(uring_log + i)->sig;
        if ((uring_log + i)->payload_byte < 0x80) *(allow_tbl + s) = s;
        else *(block_tbl + s) = s;
    }

    // Проход 2: повторный трафик после автообучения (0 попаданий в карантин!)
    size_t pass2 = 0, drop2 = 0, quar2 = 0;
    for (int i = 0; i < 4; i++) {
        uint8_t s = *(traffic + i);
        if (*(allow_tbl + s) == s) pass2++;
        else if (*(block_tbl + s) == s) drop2++;
        else quar2++;
    }

    printf("=== ШАГ 3: КАРАНТИН -> IO_URING ЛОГ -> АВТООБУЧЕНИЕ В DDR ===\n");
    printf("Проход 1 (холодный) : Пропущено=%zu | Отбито=%zu | В карантин+лог=%zu\n", pass1, drop1, quar1);
    printf("Проход 2 (обученный): Пропущено=%zu | Отбито=%zu | В карантин+лог=%zu\n", pass2, drop2, quar2);

    ddr_arena_destroy(&arena);
    return 0;
}
