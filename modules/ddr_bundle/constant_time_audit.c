// ZEROMANI (zerokull1) | 0x5A45524F4D414E49ULL
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <x86intrin.h>

/* [МЕТКА 1: Эталонное сравнение 32 байт за постоянное время без условных переходов] */
__attribute__((noinline))
static uint8_t ct_memeq32_audit(const uint8_t *a, const uint8_t *b) {
    if (!a || !b) return 0;
    uint8_t diff = 0;
    for (int i = 0; i < 32; i++) {
        uint8_t va = *(a + i);
        uint8_t vb = *(b + i);
        __asm__ __volatile__("" : "+r"(va), "+r"(vb)); /* Запрет компилятору сокращать цикл */
        diff |= (va ^ vb);
    }
    return (diff == 0);
}

/* [МЕТКА 2: Сериализованное чтение тактового счётчика CPU (lfence + rdtscp + lfence)] */
static inline uint64_t rdtscp_serialized(void) {
    unsigned aux = 0;
    _mm_lfence();
    uint64_t t = __rdtscp(&aux);
    _mm_lfence();
    return t;
}

/* [МЕТКА 3: Замер среднего числа тактов по 1 000 000 вызовов с отсевом системных прерываний IRQ] */
static double measure_class_cycles(const uint8_t *ref, const uint8_t *cand, uint64_t iters) {
    uint64_t sum = 0, valid_samples = 0;
    for (uint64_t i = 0; i < iters; i++) {
        uint64_t t0 = rdtscp_serialized();
        volatile uint8_t r = ct_memeq32_audit(ref, cand);
        (void)r;
        uint64_t t1 = rdtscp_serialized();
        uint64_t dt = t1 - t0;
        if (dt < 250ULL) { sum += dt; valid_samples++; }
    }
    return valid_samples ? ((double)sum / (double)valid_samples) : 0.0;
}

int main(void) {
    /* [МЕТКА 4: Сравнение 3 классов: ошибка в 1-м байте, ошибка в 32-м байте и полное совпадение] */
    uint8_t *ref   = __builtin_alloca(32);
    uint8_t *bad0  = __builtin_alloca(32);
    uint8_t *bad31 = __builtin_alloca(32);
    for (int i = 0; i < 32; i++) *(ref + i) = (uint8_t)(0x3C ^ (i * 19));

    memcpy(bad0, ref, 32);  *(bad0 + 0)  ^= 0x01;
    memcpy(bad31, ref, 32); *(bad31 + 31) ^= 0x01;

    measure_class_cycles(ref, bad0, 50000ULL);
    double c_bad0  = measure_class_cycles(ref, bad0,  1000000ULL);
    double c_bad31 = measure_class_cycles(ref, bad31, 1000000ULL);
    double c_match = measure_class_cycles(ref, ref,   1000000ULL);
    double delta = (c_bad31 > c_bad0) ? (c_bad31 - c_bad0) : (c_bad0 - c_bad31);

    printf("=== ТЕСТ №4: CONSTANT-TIME SIDE-CHANNEL АУДИТ (RDTSCP, 3 000 000 ЗАМЕРОВ) ===\n");
    printf("Класс A (ошибка в байте #0)  : %.2f такта CPU\n", c_bad0);
    printf("Класс B (ошибка в байте #31) : %.2f такта CPU\n", c_bad31);
    printf("Класс C (полное совпадение)  : %.2f такта CPU\n", c_match);
    printf("Разница времени |B - A|      : %.3f такта -> %s\n",
           delta, (delta < 1.0) ? "УТЕЧКИ ПО ВРЕМЕНИ НЕТ (CONSTANT-TIME)" : "ОБНАРУЖЕН ПЕРЕКОС");

    return (delta < 1.0) ? 0 : 1;
}
