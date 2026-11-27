// ZEROMANI (zerokull1) | 0x5A45524F4D414E49ULL
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <cpuid.h>
#include <x86intrin.h>

/* [МЕТКА 1: Проверка аппаратной поддержки инструкции CLFLUSHOPT через CPUID Leaf 7] */
static int cpu_has_clflushopt(void) {
    unsigned int eax = 0, ebx = 0, ecx = 0, edx = 0;
    if (__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx)) {
        return (int)((ebx >> 23) & 1U);
    }
    return 0;
}

/* [МЕТКА 2: Нетемпоральное затирание соли прямо в DDR мимо кэшей L1/L2/L3 + сброс кэш-линий] */
static void hw_nt_zero_and_evict(void *ptr, size_t len, int has_opt) {
    /* Обязательная защита от #GP: vmovntdq требует выравнивания адреса и длины по 32 байтам */
    if (!ptr || len == 0 || ((uintptr_t)ptr & 31ULL) != 0 || (len & 31ULL) != 0) return;
    uint8_t *p = (uint8_t *)ptr;
    __asm__ __volatile__("vpxor %%ymm0, %%ymm0, %%ymm0\n\t" ::: "ymm0");
    for (size_t off = 0; off < len; off += 32) {
        __asm__ __volatile__("vmovntdq %%ymm0, (%0)\n\t" :: "r"(p + off) : "memory");
    }
    __asm__ __volatile__("sfence\n\t" ::: "memory");
    for (size_t off = 0; off < len; off += 64) {
        if (has_opt) {
            __asm__ __volatile__(".byte 0x66; clflush (%0)\n\t" :: "r"(p + off) : "memory");
        } else {
            __asm__ __volatile__("clflush (%0)\n\t" :: "r"(p + off) : "memory");
        }
    }
    __asm__ __volatile__("mfence\n\t" ::: "memory");
}

int main(void) {
    /* [МЕТКА 3: Выделение 64B-выровненного буфера в DDR и замер скорости аппаратной инсинерации] */
    uint8_t *salt_ddr = NULL;
    if (posix_memalign((void **)&salt_ddr, 64, 256) != 0 || !salt_ddr) return 1;
    for (size_t i = 0; i < 256; i++) *(salt_ddr + i) = (uint8_t)(0xA5 ^ (i * 13));

    int has_opt = cpu_has_clflushopt();
    unsigned aux = 0;
    uint64_t t0 = __rdtscp(&aux);
    hw_nt_zero_and_evict(salt_ddr, 256, has_opt);
    uint64_t t1 = __rdtscp(&aux);

    uint64_t sum = 0;
    for (size_t i = 0; i < 256; i++) sum |= *(salt_ddr + i);

    printf("=== АППАРАТНЫЙ СБРОС СОЛИ В DDR МИМО КЭША CPU ===\n");
    printf("Инструкция сброса линий : %s (Haswell fallback активен при 0)\n",
           has_opt ? "CLFLUSHOPT (0x66 + clflush)" : "CLFLUSH + MFENCE (Haswell)");
    printf("Non-Temporal запись     : vmovntdq (256-bit мимо L1/L2/L3) + sfence\n");
    printf("Остаток соли в DDR      : %llu (0 = чисто) | Тактов CPU на 256B: %llu\n",
           (unsigned long long)sum, (unsigned long long)(t1 - t0));

    free(salt_ddr);
    return (sum == 0) ? 0 : 2;
}
