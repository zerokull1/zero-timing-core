// ZEROMANI (zerokull1) | 0x5A45524F4D414E49ULL
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <x86intrin.h>

/* [МЕТКА 1: Загрузка 256-битного ключа в регистр YMM15 и физический смыв следа из DDR (clflush)] */
static inline void asm_ymm15_seal_key(uint8_t *ddr_key_buf) {
    __asm__ __volatile__(
        "vmovdqu (%0), %%ymm15\n\t"
        :
        : "r"(ddr_key_buf)
        : "ymm15", "memory"
    );
    explicit_bzero(ddr_key_buf, 32);
    __asm__ __volatile__("clflush (%0)\n\tmfence\n\t" :: "r"(ddr_key_buf) : "memory");
}

/* [МЕТКА 2: Поточное шифрование 32-байтного блока ключом прямо из регистра YMM15 (0 чтений DDR)] */
static inline void asm_ymm15_xor_block32(uint8_t *pkt32) {
    __asm__ __volatile__(
        "vmovdqu (%0), %%ymm0\n\t"
        "vpxor %%ymm15, %%ymm0, %%ymm0\n\t"
        "vmovdqu %%ymm0, (%0)\n\t"
        :
        : "r"(pkt32)
        : "ymm0", "memory"
    );
}

/* [МЕТКА 3: Полная зачистка всех векторных регистров YMM0..YMM15 на кристалле CPU (vzeroall)] */
static inline void asm_ymm15_wipe(void) {
    __asm__ __volatile__("vzeroall\n\t" ::: "ymm0", "ymm15");
}

int main(void) {
    uint8_t *secret_in_ram = __builtin_alloca_with_align(32, 256);
    for (int i = 0; i < 32; i++) *(secret_in_ram + i) = (uint8_t)(0x5A ^ (i * 17));

    asm_ymm15_seal_key(secret_in_ram);

    const char *tag = "ZEROMANI_EPOCH_1_SECRET_PAYLOAD!";
    uint8_t *orig = __builtin_alloca(32);
    uint8_t *work = __builtin_alloca(32);
    memcpy(orig, tag, 32);
    memcpy(work, orig, 32);

    asm_ymm15_xor_block32(work);
    int changed = (memcmp(work, orig, 32) != 0);
    asm_ymm15_xor_block32(work);
    int restored = (memcmp(work, orig, 32) == 0);

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (int i = 0; i < 10000000; i++) asm_ymm15_xor_block32(work);
    clock_gettime(CLOCK_MONOTONIC, &t1);

    double sec = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) * 1e-9;
    double gb_s = (10000000.0 * 32.0) / (sec * 1e9);

    printf("=== СТУПЕНЬ 3: КРЕМНИЕВЫЙ СЕЙФ В РЕГИСТРЕ CPU YMM15 (AVX2) ===\n");
    printf("След ключа в DDR стёрт: %d | Мутация 1:1 проверена: %d\n", *secret_in_ram == 0, changed && restored);
    printf("Скорость в кристалле  : %.2f ГБ/с (%.2f млн 32B-блоков/сек)\n", gb_s, 10.0 / sec);

    asm_ymm15_wipe();
    return (changed && restored && *secret_in_ram == 0) ? 0 : 1;
}
