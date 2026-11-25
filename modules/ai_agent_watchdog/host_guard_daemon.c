#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <time.h>
#include <poll.h>
#include <sys/inotify.h>

extern int watchdog_freeze_rogue_agents(void);

static void log_alert(const char *msg) {
    const char *home = getenv("HOME");
    if (!home || !*home) return;
    char lp[512];
    int n = snprintf(lp, sizeof(lp), "%s/.zero_host_guard.log", home);
    if (n <= 0 || (size_t)n >= sizeof(lp)) return;
    int lfd = open(lp, O_WRONLY | O_CREAT | O_APPEND | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (lfd >= 0) {
        char line[512];
        int ln = snprintf(line, sizeof(line), "[%ld] ТРЕВОГА ХОСТА: %s\n", (long)time(NULL), msg);
        if (ln > 0) {
            size_t wlen = (size_t)ln < sizeof(line) ? (size_t)ln : (sizeof(line) - 1);
            ssize_t wr = write(lfd, line, wlen);
            (void)wr;
        }
        close(lfd);
    }
}

int main(int argc, char **argv) {
    int fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (fd < 0) return 1;
    for (int i = 1; i < argc; i++) {
        inotify_add_watch(fd, *(argv + i), IN_DELETE | IN_MOVED_FROM | IN_CREATE);
    }
    log_alert("Сторож хоста ZEROMANI v2 (Zero-Alloc, O_NOFOLLOW 0600, exe+cmdline) запущен.");
    struct pollfd pfd = { .fd = fd, .events = POLLIN };
    uint8_t buf[4096] __attribute__((aligned(8)));
    while (poll(&pfd, 1, -1) >= 0) {
        ssize_t len = read(fd, buf, sizeof(buf));
        size_t pos = 0;
        while (len > 0 && pos + sizeof(struct inotify_event) <= (size_t)len) {
            struct inotify_event *ev = (struct inotify_event *)(buf + pos);
            int overflow = (ev->mask & IN_Q_OVERFLOW) != 0;
            int triggered = overflow || (ev->len > 0 && ((ev->mask & (IN_DELETE | IN_MOVED_FROM)) ||
                            strncmp(ev->name, ".cline", 6) == 0 ||
                            strncmp(ev->name, ".cursor", 7) == 0 ||
                            strncmp(ev->name, ".aider", 6) == 0));
            if (triggered) {
                int fz = watchdog_freeze_rogue_agents();
                char msg[256];
                snprintf(msg, sizeof(msg), "Перехвачено '%s' (overflow=%d, заморожено агентов: %d)",
                         overflow ? "IN_Q_OVERFLOW" : ev->name, overflow, fz);
                log_alert(msg);
            }
            pos += sizeof(struct inotify_event) + ev->len;
        }
    }
    close(fd);
    return 0;
}
