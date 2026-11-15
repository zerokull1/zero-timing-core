#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

#define ZEROMANI_MAGIC 0x494E414D4F52455AULL
#define RING_CAP_SLOTS 16

typedef struct __attribute__((aligned(64))) {
    uint64_t magic;
    uint64_t seq;
    uint64_t blocked_attacks;
} telem_slot_t;

int main(void) {
    // 1. Запечатанная телеметрия в DDR (memfd_create + MFD_ALLOW_SEALING + F_SEAL_WRITE|SEAL)
    int mfd = memfd_create("zeromani_sealed_telem", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (mfd < 0) return 1;
    telem_slot_t snap = { ZEROMANI_MAGIC, 1, 98977 };
    if (write(mfd, &snap, sizeof(snap)) != sizeof(snap)) return 2;

    int seals = F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE;
    if (fcntl(mfd, F_ADD_SEALS, seals) != 0) return 3;

    // Проверка атаки: попытка перезаписать запечатанную телеметрию (ядро должно вернуть -1 / EPERM)
    uint64_t poison = 0xDEADDEADDEADDEADULL;
    ssize_t tamper_res = pwrite(mfd, &poison, sizeof(poison), 0);
    int seal_ok = (tamper_res < 0 && errno == EPERM);

    // 2. Кольцевой бортсамописец с защитой от symlink-атак (O_NOFOLLOW) и жёстким лимитом размера
    const char *evil_link = "/tmp/zeromani_symlink_trap.log";
    const char *safe_ring = "/tmp/zeromani_ring_safe.log";
    unlink(evil_link); unlink(safe_ring);
    if (symlink("/etc/passwd", evil_link) != 0) return 4;

    int trap_fd = open(evil_link, O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600);
    int symlink_blocked = (trap_fd < 0 && errno == ELOOP);

    int ring_fd = open(safe_ring, O_RDWR | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (ring_fd < 0) return 5;
    for (uint64_t i = 0; i < 40; i++) {
        telem_slot_t rec = { ZEROMANI_MAGIC, i + 1, 1000 + i };
        off_t slot_off = (off_t)((i % RING_CAP_SLOTS) * sizeof(telem_slot_t));
        if (pwrite(ring_fd, &rec, sizeof(rec), slot_off) != sizeof(rec)) return 6;
    }
    off_t final_sz = lseek(ring_fd, 0, SEEK_END);

    printf("=== ЗАЩИТА №2: SEALED MEMFD + КОЛЬЦЕВОЙ БОРТСАМОПИСЕЦ (O_NOFOLLOW) ===\n");
    printf("Ядерная печать memfd (F_SEAL_WRITE|SEAL) : %s (попытка подмены -> EPERM)\n", seal_ok ? "АКТИВНА" : "ОШИБКА");
    printf("Защита от подмены симлинком (O_NOFOLLOW) : %s (symlink -> ELOOP отбит)\n", symlink_blocked ? "АКТИВНА" : "ОШИБКА");
    printf("Кольцевой бортсамописец (40 записей в 16): размер файла = %lld байт (лимит соблюдён)\n", (long long)final_sz);

    close(ring_fd); close(mfd); unlink(evil_link); unlink(safe_ring);
    return (seal_ok && symlink_blocked && final_sz == RING_CAP_SLOTS * (off_t)sizeof(telem_slot_t)) ? 0 : 7;
}
