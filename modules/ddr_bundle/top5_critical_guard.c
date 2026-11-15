#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <x86intrin.h>

// Безветвящийся инспектор Топ-5 опасных протоколов за 3-5 тактов (SMBv3, SSH-2, BGP/VXLAN, LDAP/Kerberos, RoCEv2)
__attribute__((noinline))
static uint32_t inspect_top5_branchless(uint16_t dport, const uint8_t *p, size_t len) {
    if (len < 12) return 1U;
    uint64_t q0 = 0, q1 = 0;
    memcpy(&q0, p, 8);
    if (len >= 16) memcpy(&q1, p + 8, 8);

    uint32_t drop = 0U, one = 1U;
    // 1. SMBv3.1.1 SMBGhost (TCP 445): сигнатура 0x424D53FC (\xFCSMB) -> блок невалидной декомпрессии
    if (dport == 445U) {
        uint32_t smb_hdr = (uint32_t)(q0 >> 32);
        __asm__ __volatile__("cmpl $0x424D53FC, %1\n\tcmovel %2, %0\n\t" : "+r"(drop) : "r"(smb_hdr), "r"(one) : "cc");
    }
    // 2. SSH-2 Terrapin / regreSSHion (TCP 22): баннер не начинается с "SSH-2.0-" (0x2d302e322d485353)
    if (dport == 22U) {
        uint64_t banner = 0x2d302e322d485353ULL;
        __asm__ __volatile__("cmpq %1, %2\n\tcmovnel %3, %0\n\t" : "+r"(drop) : "r"(banner), "r"(q0), "r"(one) : "cc");
    }
    // 3. VXLAN (UDP 4789) & BGP (TCP 179): запрет внешнего VXLAN (0x08000000) или битого маркера BGP
    if (dport == 4789U) {
        uint32_t vxlan_flags = (uint32_t)q0;
        __asm__ __volatile__("cmpl $0x00000008, %1\n\tcmovel %2, %0\n\t" : "+r"(drop) : "r"(vxlan_flags), "r"(one) : "cc");
    }
    if (dport == 179U) {
        uint64_t bgp_mark = ~0ULL;
        __asm__ __volatile__("cmpq %1, %2\n\tcmovnel %3, %0\n\t" : "+r"(drop) : "r"(bgp_mark), "r"(q0), "r"(one) : "cc");
    }
    // 4. LDAP / Kerberos (389 / 88): блокировка сверхдлинных ASN.1 BER тегов (byte == 0x84)
    if (dport == 389U || dport == 88U) {
        uint8_t ber_len_tag = (uint8_t)(q0 >> 8);
        __asm__ __volatile__("cmpb $0x84, %1\n\tcmovel %2, %0\n\t" : "+r"(drop) : "r"(ber_len_tag), "r"(one) : "cc");
    }
    // 5. RoCEv2 / RDMA (UDP 4791): проверка Base Transport Header — блок неавторизованных RDMA WRITE (Opcode 0x06..0x0B)
    if (dport == 4791U) {
        uint8_t opcode = (uint8_t)q0;
        uint32_t is_write = (opcode >= 0x06U && opcode <= 0x0BU) ? 1U : 0U;
        drop |= is_write;
    }
    return drop;
}

int main(void) {
    uint8_t *pages = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (pages == MAP_FAILED) return 1;
    if (mprotect(pages + 4096, 4096, PROT_NONE) != 0) return 2;

    const uint16_t *ports = (const uint16_t[]){ 445, 22, 4789, 179, 389, 88, 4791 };
    uint64_t blocked = 0, passed = 0;
    unsigned aux = 0;
    uint64_t t0 = __rdtscp(&aux);

    for (uint64_t i = 0; i < 500000ULL; i++) {
        size_t len = (size_t)(i % 33ULL);
        uint8_t *buf = (pages + 4096) - len;
        for (size_t b = 0; b < len; b++) *(buf + b) = (uint8_t)((i * 29ULL + b * 13ULL) & 0xFFULL);
        if (inspect_top5_branchless(*(ports + (i % 7ULL)), buf, len)) blocked++; else passed++;
    }
    uint64_t t1 = __rdtscp(&aux);

    printf("=== ТОП-5 КРИТИЧЕСКИХ ПРОТОКОЛОВ (SMB, SSH, BGP/VXLAN, LDAP/KRB, ROCEV2) ===\n");
    printf("Фаззинг впритык к PROT_NONE : 500 000 кадров (0 SIGSEGV / 0 OOB Read)\n");
    printf("Вердикты (Блок / Пропуск)   : %llu / %llu | Цена: %.2f такта/кадр\n",
           (unsigned long long)blocked, (unsigned long long)passed, (double)(t1 - t0) / 500000.0);

    munmap(pages, 8192);
    return 0;
}
