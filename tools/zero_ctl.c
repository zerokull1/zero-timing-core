// ZEROMANI (zerokull1) | 0x5A45524F4D414E49ULL | Zero-Dependency Control CLI & SIEM CEF Exporter
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/mman.h>

struct guard_shm {
    uint64_t magic, ticks, temp_c, base_cyc, last_cyc, scrub_events, cryo_status, l1d_bytes, stealth_status;
};

static void print_core3(int cef) {
    int fd = open("/dev/shm/zeromani_core3_guard", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return;
    struct guard_shm *g = mmap(NULL, 4096, PROT_READ, MAP_SHARED, fd, 0);
    close(fd);
    if (g == MAP_FAILED || g->magic != 0x5A45524F434F5233ULL) { if (g != MAP_FAILED) munmap(g, 4096); return; }
    if (cef) printf("CEF:0|ZEROMANI|Core3Supervisor|3.0|100|SiliconGuard|3|rt=%ld000 cs1=%llu cn1=%llu cn2=%llu\n",
                    (long)time(NULL), (unsigned long long)g->temp_c, (unsigned long long)g->base_cyc, (unsigned long long)g->scrub_events);
    else printf("[CORE #3] Temp=%lluC | L1d=%lluB | Base=%llu | Last=%llu | Scrubs=%llu\n",
                (unsigned long long)g->temp_c, (unsigned long long)g->l1d_bytes, (unsigned long long)g->base_cyc, (unsigned long long)g->last_cyc, (unsigned long long)g->scrub_events);
    munmap(g, 4096);
}

int main(int argc, char **argv) {
    int cef = (argc > 1 && strcmp(argv, "cef") == 0);
    if (!cef) printf("=== ZEROMANI UNIFIED CONTROL CONSOLE (73-Vector Hardened) ===\n");
    print_core3(cef);
    return 0;
}
