#define _GNU_SOURCE
#include "../module_abi.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <dirent.h>
#include <sys/inotify.h>

static int inotify_fd = -1;
static uint64_t blocked_actions = 0;

static int is_rogue_agent_file(const char *name) {
    if (!name) return 0;
    if (strncmp(name, ".cline", 6) == 0) return 1;
    if (strncmp(name, ".cursor", 7) == 0) return 1;
    if (strncmp(name, ".aider", 6) == 0) return 1;
    return 0;
}

static int matches_rogue_signature(const char *s) {
    if (!s || !*s) return 0;
    return (strstr(s, "cline") != NULL) ||
           (strstr(s, "aider") != NULL) ||
           (strstr(s, "auto-approve") != NULL);
}

int watchdog_freeze_rogue_agents(void) {
    DIR *d = opendir("/proc");
    if (!d) return 0;
    int frozen = 0;
    pid_t self_pid = getpid();
    pid_t parent_pid = getppid();
    char path[64];
    char cmd[256];
    char exe_link[256];
    struct dirent *ent;

    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] < '1' || ent->d_name[0] > '9') continue;
        pid_t pid = (pid_t)atoi(ent->d_name);
        if (pid <= 1 || pid == self_pid || pid == parent_pid) continue;

        int hit = 0;
        snprintf(path, sizeof(path), "/proc/%d/exe", pid);
        ssize_t elen = readlink(path, exe_link, sizeof(exe_link) - 1);
        if (elen > 0) {
            exe_link[elen] = '\0';
            if (matches_rogue_signature(exe_link)) hit = 1;
        }

        if (!hit) {
            snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
            int cfd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
            if (cfd >= 0) {
                ssize_t n = read(cfd, cmd, sizeof(cmd) - 1);
                close(cfd);
                if (n > 0) {
                    for (ssize_t i = 0; i < n; i++) if (cmd[i] == '\0') cmd[i] = ' ';
                    cmd[n] = '\0';
                    if (matches_rogue_signature(cmd)) hit = 1;
                }
            }
        }

        if (hit && kill(pid, SIGSTOP) == 0) frozen++;
    }
    closedir(d);
    return frozen;
}

static int wd_init(uint64_t seed) {
    (void)seed;
    inotify_fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    blocked_actions = 0;
    return (inotify_fd >= 0) ? 0 : -1;
}

int watchdog_watch_dir(const char *dir_path) {
    if (inotify_fd < 0) return -1;
    return inotify_add_watch(inotify_fd, dir_path, IN_DELETE | IN_MOVED_FROM | IN_CREATE | IN_MODIFY);
}

size_t watchdog_poll_events(int *out_frozen_pids) {
    if (inotify_fd < 0) return 0;
    uint8_t buf[4096] __attribute__((aligned(8)));
    ssize_t len = read(inotify_fd, buf, sizeof(buf));
    size_t alerts = 0;
    if (len > 0) {
        size_t pos = 0;
        while (pos + sizeof(struct inotify_event) <= (size_t)len) {
            struct inotify_event *ev = (struct inotify_event *)(buf + pos);
            if ((ev->mask & IN_Q_OVERFLOW) != 0) {
                alerts++;
                blocked_actions++;
            } else if (ev->len > 0) {
                if ((ev->mask & (IN_DELETE | IN_MOVED_FROM)) || is_rogue_agent_file(ev->name)) {
                    alerts++;
                    blocked_actions++;
                }
            }
            pos += sizeof(struct inotify_event) + ev->len;
        }
    }
    if (alerts > 0) {
        int fz = watchdog_freeze_rogue_agents();
        if (out_frozen_pids) *out_frozen_pids = fz;
    }
    return alerts;
}

static size_t wd_process_frame(uint8_t *buf, size_t len, size_t max_cap, uint64_t *out_delay_ns) {
    (void)buf; (void)len; (void)max_cap;
    if (out_delay_ns) *out_delay_ns = 0;
    int frozen = 0;
    return watchdog_poll_events(&frozen);
}

static void wd_shutdown(void) {
    if (inotify_fd >= 0) { close(inotify_fd); inotify_fd = -1; }
}

const zero_module_descriptor_t zero_module_entry = {
    .magic = ZEROMANI_MODULE_MAGIC, .abi_version = ZERO_MODULE_ABI_VER, .module_id = 6,
    .name = "ai_agent_process_watchdog", .init = wd_init,
    .process_frame = wd_process_frame, .shutdown = wd_shutdown
};
