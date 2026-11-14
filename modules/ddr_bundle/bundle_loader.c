#include "../ddr_arena/ddr_arena.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <nmmintrin.h>

#define ZEROMANI_MAGIC 0x494E414D4F52455AULL

typedef size_t (*bundle_mod_fn_t)(const uint8_t *pkt, size_t len);

typedef struct __attribute__((aligned(64))) {
    uint64_t magic;
    uint32_t mod_count;
    uint32_t code_bytes;
    uint64_t crc64_seal;
    uint64_t off_mod1;
    uint64_t off_mod2;
    uint64_t off_mod3;
} zero_bundle_hdr_t;

// 3 чистых x86_64 ASM модуля (по 16 байт каждый, выровнены в единый пакет без .so на диске):
// Mod1: проверка длины >= 64 | Mod2: проверка маркировки RMM | Mod3: проверка окна SOHO-роутера
static const uint8_t *packed_asm = (const uint8_t[]){
    0x31,0xc0, 0x48,0x83,0xfe,0x40, 0x0f,0x92,0xc0, 0xc3, 0x90,0x90,0x90,0x90,0x90,0x90,
    0x31,0xc0, 0x80,0x3f,0xde,       0x0f,0x94,0xc0, 0xc3, 0x90,0x90,0x90,0x90,0x90,0x90,0x90,
    0x31,0xc0, 0x80,0x7f,0x36,0x16, 0x0f,0x94,0xc0, 0xc3, 0x90,0x90,0x90,0x90,0x90,0x90
};

int main() {
    zero_bundle_hdr_t hdr = { ZEROMANI_MAGIC, 3, 48, 0, 0, 16, 32 };
    uint64_t crc = 0;
    for (size_t i = 0; i < 48; i += 8) crc = _mm_crc32_u64(crc, *(const uint64_t *)(packed_asm + i));
    hdr.crc64_seal = crc;

    ddr_arena_t arena;
    if (ddr_arena_create(&arena) != 0) return 1;

    // Загружаем весь пакет в запечатанную DDR-арену без единого .so файла на диске
    size_t base_off = (size_t)ddr_arena_push_code(&arena, packed_asm, hdr.code_bytes);
    if (!base_off || ddr_arena_seal_wx(&arena) != 0) return 2;

    // Верифицируем целостность уже внутри RX-сегмента DDR аппаратным CRC32C
    uint64_t verify_crc = 0;
    for (size_t i = 0; i < hdr.code_bytes; i += 8)
        verify_crc = _mm_crc32_u64(verify_crc, *(const uint64_t *)(arena.base + base_off + i));

    bundle_mod_fn_t m1 = (bundle_mod_fn_t)(arena.base + base_off + hdr.off_mod1);
    bundle_mod_fn_t m2 = (bundle_mod_fn_t)(arena.base + base_off + hdr.off_mod2);
    bundle_mod_fn_t m3 = (bundle_mod_fn_t)(arena.base + base_off + hdr.off_mod3);

    uint8_t *pkt = (uint8_t *)ddr_arena_alloc_data(&arena, 128, 64);
    *(pkt + 0) = 0xDE; *(pkt + 54) = 0x16;

    size_t alerts = m1(pkt, 80) + m2(pkt, 80) + m3(pkt, 80);
    printf("=== ШАГ 1: МОНОЛИТНЫЙ БЕЗДИСКОВЫЙ ПАКЕТ В DDR-АРЕНЕ (W^X + CRC32C) ===\n");
    printf("Подпись: ZEROMANI | Модулей в пакете: %u (%u байт) | CRC32C в RX-памяти: %s\n",
           hdr.mod_count, hdr.code_bytes, (hdr.magic == ZEROMANI_MAGIC && verify_crc == hdr.crc64_seal) ? "OK" : "FAIL");
    printf("Исполнение цепочки из одной DDR-страницы: сработок = %zu / 3 (0 файлов .so на диске)\n", alerts);

    ddr_arena_destroy(&arena);
    return 0;
}
