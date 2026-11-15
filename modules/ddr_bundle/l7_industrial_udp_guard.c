// ZEROMANI (zerokull1) | 0x5A45524F4D414E49ULL
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <x86intrin.h>

__attribute__((noinline))
static uint32_t inspect_proto_branchless(uint16_t dst_port, const uint8_t *p, size_t len) {
    if (len < 8) return 1U;
    uint64_t q0 = 0, q1 = 0;
    memcpy(&q0, p, 8);
    if (len >= 16) memcpy(&q1, p + 8, 8);

    uint32_t drop = 0U, one = 1U;
    if (dst_port == 443U || dst_port == 8080U) {
        uint8_t ftype = (uint8_t)(q0 >> 24);
        uint32_t flen = ((uint32_t)(q0 & 0xFF) << 16) | ((uint32_t)((q0 >> 8) & 0xFF) << 8) | (uint32_t)((q0 >> 16) & 0xFF);
        __asm__ __volatile__("cmpb $0x03, %1\n\tcmovel %2, %0\n\tcmpl $16384, %3\n\tcmoval %2, %0\n\t"
                             : "+r"(drop) : "r"(ftype), "r"(one), "r"(flen) : "cc");
    }
    if (dst_port == 502U) {
        uint16_t proto_id = (uint16_t)(q0 >> 16);
        __asm__ __volatile__("testw %1, %1\n\tcmovnel %2, %0\n\t" : "+r"(drop) : "r"(proto_id), "r"(one) : "cc");
    }
    if (dst_port == 53U) {
        uint8_t flags_hi = (uint8_t)(q0 >> 16);
        uint8_t qname_len = (uint8_t)(q1 >> 32);
        __asm__ __volatile__("testb $0x80, %1\n\tcmovnel %2, %0\n\tcmpb $63, %3\n\tcmoval %2, %0\n\t"
                             : "+r"(drop) : "r"(flags_hi), "r"(one), "r"(qname_len) : "cc");
    }
    if (dst_port == 123U) {
        uint8_t mode = (uint8_t)(q0 & 0x07ULL);
        __asm__ __volatile__("cmpb $6, %1\n\tcmovael %2, %0\n\t" : "+r"(drop) : "r"(mode), "r"(one) : "cc");
    }
    return drop;
}

int main(void) {
    uint8_t *pages = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (pages == MAP_FAILED) return 1;
    if (mprotect(pages + 4096, 4096, PROT_NONE) != 0) return 2;

    const uint16_t *ports = (const uint16_t[]){ 443, 502, 53, 123, 8080 };
    uint64_t blocked = 0, passed = 0;
    unsigned aux = 0;
    uint64_t t0 = __rdtscp(&aux);

    for (uint64_t i = 0; i < 500000ULL; i++) {
        size_t len = (size_t)(i % 33ULL);
        uint8_t *buf = (pages + 4096) - len;
        for (size_t b = 0; b < len; b++) *(buf + b) = (uint8_t)((i * 31ULL + b * 17ULL) & 0xFFULL);
        if (inspect_proto_branchless(*(ports + (i % 5ULL)), buf, len)) blocked++; else passed++;
    }
    uint64_t t1 = __rdtscp(&aux);

    printf("=== PROTOCOL GUARD (HTTP/2, MODBUS, DNS, NTP) + PROT_NONE ФАЗЗЕР ===\n");
    printf("Прогнано впритык к PROT_NONE : 500 000 кадров (0 SIGSEGV / 0 OOB Read)\n");
    printf("Вердикты (Блок / Пропуск)    : %llu / %llu | Средняя цена: %.2f такта/кадр\n",
           (unsigned long long)blocked, (unsigned long long)passed, (double)(t1 - t0) / 500000.0);

    munmap(pages, 8192);
    return 0;
}
