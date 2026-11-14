#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <x86intrin.h>

// 1. Загружает 256-битный ключ в регистр YMM15 и стирает след в DDR
static inline void asm_ymm15_seal_key(uint8_t *ddr_key_buf) {
    __asm__ __volatile__(
        "vmovdqu (%0), %%ymm15\n\t"
        :
        : "r"(ddr_key_buf)
        : "ymm15", "memory"
    );
    explicit_bzero(ddr_key_buf, 32);
}

// 2. Шифрует/дешифрует 32-байтный блок трафика напрямую ключом из YMM15 (0 обращений за ключом в DDR)
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

// 3. Обнуляет секрет внутри регистра YMM15 при выходе
static inline void asm_ymm15_wipe(void) {
    __asm__ __volatile__("vpxor %%ymm15, %%ymm15, %%ymm15\n\t" ::: "ymm15");
}

int main() {
    uint8_t secret_in_ram[32];
    for (int i = 0; i < 32; i++) secret_in_ram[i] = (uint8_t)(0x5A ^ (i * 17));

    asm_ymm15_seal_key(secret_in_ram);

    uint8_t orig[32] = "ZEROMANI_EPOCH_1_SECRET_PAYLOAD!";
    uint8_t work[32];
    memcpy(work, orig, 32);

    asm_ymm15_xor_block32(work); // Зашифровали ключом из кристалла
    int changed = (memcmp(work, orig, 32) != 0);
    asm_ymm15_xor_block32(work); // Расшифровали обратно тем же регистром YMM15
    int restored = (memcmp(work, orig, 32) == 0);

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (int i = 0; i < 10000000; i++) asm_ymm15_xor_block32(work);
    clock_gettime(CLOCK_MONOTONIC, &t1);

    double sec = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) * 1e-9;
    double gb_s = (10000000.0 * 32.0) / (sec * 1e9);

    printf("=== СТУПЕНЬ 3: КРЕМНИЕВЫЙ СЕЙФ В РЕГИСТРЕ CPU YMM15 (AVX2) ===\n");
    printf("След ключа в DDR стёрт: %d | Мутация 1:1 проверена: %d\n", secret_in_ram[0] == 0, changed && restored);
    printf("Скорость в кристалле  : %.2f ГБ/с (%.2f млн 32B-блоков/сек)\n", gb_s, 10.0 / sec);

    asm_ymm15_wipe();
    return 0;
}
