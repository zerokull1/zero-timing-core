// ZEROMANI (zerokull1) | 0x5A45524F4D414E49ULL
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>

static volatile sig_atomic_t keep_running = 1;
static void on_sigint(int sig) { (void)sig; keep_running = 0; }

static uint64_t read_u64_file(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    unsigned long long v = 0;
    if (fscanf(f, "%llu", &v) != 1) v = 0;
    fclose(f);
    return (uint64_t)v;
}

static int read_cpu_ticks(uint64_t *busy, uint64_t *total, int max_c) {
    FILE *f = fopen("/proc/stat", "r");
    if (!f) return 0;
    char *line = malloc(512);
    int n = 0;
    while (fgets(line, 512, f) && n < max_c) {
        if (strncmp(line, "cpu", 3) == 0 && *(line + 3) >= '0' && *(line + 3) <= '9') {
            unsigned long long u=0, ni=0, sy=0, id=0, io=0, irq=0, sirq=0, st=0;
            if (sscanf(line + 3, "%*d %llu %llu %llu %llu %llu %llu %llu %llu",
                       &u, &ni, &sy, &id, &io, &irq, &sirq, &st) >= 4) {
                uint64_t b = (uint64_t)(u + ni + sy + irq + sirq + st);
                *(busy + n) = b;
                *(total + n) = b + (uint64_t)(id + io);
                n++;
            }
        }
    }
    free(line);
    fclose(f);
    return n;
}

static void read_net_totals(uint64_t *rx_p, uint64_t *tx_p, uint64_t *rx_b, uint64_t *tx_b) {
    *rx_p = *tx_p = *rx_b = *tx_b = 0;
    FILE *f = fopen("/proc/net/dev", "r");
    if (!f) return;
    char *line = malloc(512);
    int row = 0;
    while (fgets(line, 512, f)) {
        if (row++ < 2) continue;
        char *colon = strchr(line, ':');
        if (!colon) continue;
        *colon = '\0';
        char *ifn = line;
        while (*ifn == ' ') ifn++;
        if (strcmp(ifn, "lo") == 0) continue;
        unsigned long long rb=0, rp=0, tb=0, tp=0;
        if (sscanf(colon + 1, "%llu %llu %*u %*u %*u %*u %*u %*u %llu %llu", &rb, &rp, &tb, &tp) == 4) {
            *rx_b += (uint64_t)rb; *rx_p += (uint64_t)rp;
            *tx_b += (uint64_t)tb; *tx_p += (uint64_t)tp;
        }
    }
    free(line);
    fclose(f);
}

static void draw_bar(double pct, int width) {
    int fill = (int)((pct / 100.0) * (double)width + 0.5);
    if (fill < 0) fill = 0;
    if (fill > width) fill = width;
    const char *col = (pct > 75.0) ? "\033[1;31m" : (pct > 30.0) ? "\033[1;33m" : "\033[1;32m";
    printf("%s", col);
    for (int i = 0; i < width; i++) printf("%s", (i < fill) ? "█" : "░");
    printf("\033[0m");
}

int main(int argc, char **argv) {
    int max_ticks = (argc > 1 && strcmp(*(argv + 1), "--demo") == 0) ? 20 : 0;
    signal(SIGINT, on_sigint);

    uint64_t *b0 = calloc(128, sizeof(uint64_t)), *t0 = calloc(128, sizeof(uint64_t));
    uint64_t *b1 = calloc(128, sizeof(uint64_t)), *t1 = calloc(128, sizeof(uint64_t));
    double *prev_pct = calloc(128, sizeof(double));
    char *last_event = calloc(256, 1);
    snprintf(last_event, 256, "Мониторинг запущен (шаг тика 50 мс)");

    int ncores = read_cpu_ticks(b0, t0, 128);
    uint64_t e0 = read_u64_file("/sys/class/powercap/intel-rapl:0/energy_uj");
    uint64_t rp0 = 0, tp0 = 0, rb0 = 0, tb0 = 0;
    read_net_totals(&rp0, &tp0, &rb0, &tb0);

    printf("\033[?25l");
    int tick = 0;
    while (keep_running && (max_ticks == 0 || tick < max_ticks)) {
        usleep(50000); // 50 мс тик (20 Гц)
        tick++;
        read_cpu_ticks(b1, t1, 128);
        uint64_t e1 = read_u64_file("/sys/class/powercap/intel-rapl:0/energy_uj");
        uint64_t temp_mc = read_u64_file("/sys/class/thermal/thermal_zone0/temp");
        uint64_t rp1 = 0, tp1 = 0, rb1 = 0, tb1 = 0;
        read_net_totals(&rp1, &tp1, &rb1, &tb1);

        double watts = (e1 >= e0) ? ((double)(e1 - e0) / 1e6) / 0.05 : 0.0;
        uint64_t drp = (rp1 >= rp0) ? (rp1 - rp0) : 0;
        uint64_t dtp = (tp1 >= tp0) ? (tp1 - tp0) : 0;

        printf("\033[H\033[J");
        printf("\033[1;36m╔══════════════════════════════════════════════════════════════════════╗\033[0m\n");
        printf("\033[1;36m║  ZERO-TIMING LIVE TICK DISPATCHER (20 Гц / 50 мс)  |  Тик #%-8d  ║\033[0m\n", tick);
        printf("\033[1;36m╚══════════════════════════════════════════════════════════════════════╝\033[0m\n");
        printf("  Мощность (RAPL): \033[1;33m%5.2f Вт\033[0m  |  Температура: \033[1;32m%.1f °C\033[0m  |  Ядер: \033[1;37m%d\033[0m\n",
               watts, (double)temp_mc / 1000.0, ncores);
        printf("  Сеть (тик 50мс): RX \033[1;32m+%llu пак/с\033[0m (%.1f КБ/с) | TX \033[1;36m+%llu пак/с\033[0m (%.1f КБ/с)\n\n",
               (unsigned long long)(drp * 20ULL), (double)(rb1 - rb0) * 20.0 / 1024.0,
               (unsigned long long)(dtp * 20ULL), (double)(tb1 - tb0) * 20.0 / 1024.0);

        for (int c = 0; c < ncores; c++) {
            uint64_t dt = *(t1 + c) - *(t0 + c);
            uint64_t db = *(b1 + c) - *(b0 + c);
            double pct = (dt > 0) ? (100.0 * (double)db / (double)dt) : 0.0;
            double delta = pct - *(prev_pct + c);
            printf("  CPU %-2d [", c);
            draw_bar(pct, 28);
            printf("] %5.1f%%  (%+5.1f%%)", pct, delta);
            if (delta > 15.0) {
                printf("  \033[1;31m<-- ВСПЛЕСК В ТИКЕ!\033[0m");
                snprintf(last_event, 256, "[Тик #%d] Скачок CPU %d: %.1f%% -> %.1f%% (%+.1f%%)",
                         tick, c, *(prev_pct + c), pct, delta);
            }
            printf("\n");
            *(prev_pct + c) = pct;
        }
        if ((drp + dtp) > 50ULL) {
            snprintf(last_event, 256, "[Тик #%d] Сетевой всплеск: RX +%llu / TX +%llu пакетов за 50 мс",
                     tick, (unsigned long long)drp, (unsigned long long)dtp);
        }
        printf("\n  \033[1;35mПОСЛЕДНЕЕ СОБЫТИЕ ТИКА:\033[0m %s\n", last_event);
        printf("  (Выход: Ctrl+C | Запуск вживую: sudo ./zero_tick_dispatcher)\n");
        fflush(stdout);

        memcpy(b0, b1, (size_t)ncores * sizeof(uint64_t));
        memcpy(t0, t1, (size_t)ncores * sizeof(uint64_t));
        e0 = e1; rp0 = rp1; tp0 = tp1; rb0 = rb1; tb0 = tb1;
    }
    printf("\033[?25h\n");
    free(b0); free(t0); free(b1); free(t1); free(prev_pct); free(last_event);
    return 0;
}
