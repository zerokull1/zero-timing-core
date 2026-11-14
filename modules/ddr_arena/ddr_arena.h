#ifndef ZERO_DDR_ARENA_H
#define ZERO_DDR_ARENA_H

#include <stdint.h>
#include <stddef.h>

#define DDR_ARENA_SIZE      (2 * 1024 * 1024)
#define DDR_CODE_SLAB_SIZE  (256 * 1024)
#define DDR_DATA_SLAB_OFF   DDR_CODE_SLAB_SIZE
#define DDR_DATA_SLAB_SIZE  (DDR_ARENA_SIZE - DDR_CODE_SLAB_SIZE)

typedef struct {
    uint8_t *base;
    size_t   total_size;
    size_t   code_used;
    size_t   data_used;
    int      is_hugepage;
    int      locked_in_ram;
    int      wx_sealed;
} ddr_arena_t;

int   ddr_arena_create(ddr_arena_t *a);
void *ddr_arena_push_code(ddr_arena_t *a, const void *machine_code, size_t len);
int   ddr_arena_seal_wx(ddr_arena_t *a);
void *ddr_arena_alloc_data(ddr_arena_t *a, size_t len, size_t align);
void  ddr_arena_destroy(ddr_arena_t *a);

#endif
