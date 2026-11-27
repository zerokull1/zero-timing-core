// ZEROMANI (zerokull1) | 0x5A45524F4D414E49ULL
#define _GNU_SOURCE
#include "../module_abi.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/bpf.h>

typedef struct __attribute__((packed)) {
    uint16_t offset, min_len;
    uint64_t mask, pattern;
    uint32_t hits;
} swar_rule_t;

_Alignas(64) static swar_rule_t active_rules[16];
static size_t active_count = 0;

static int bpf_obj_get(const char *path) {
    union bpf_attr attr = { .pathname = (uint64_t)(uintptr_t)path };
    return (int)syscall(__NR_bpf, BPF_OBJ_GET, &attr, sizeof(attr));
}
static int bpf_map_update(int fd, const void *key, const void *val) {
    union bpf_attr attr = { .map_fd = (uint32_t)fd, .key = (uint64_t)(uintptr_t)key, .value = (uint64_t)(uintptr_t)val, .flags = BPF_ANY };
    return (int)syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}
int guardian_sync_rules(const char *rules_path, const char *bpf_pin_path, size_t *out_loaded, int *out_kernel_synced) {
    FILE *f = fopen(rules_path, "rb"); if (!f) return -1;
    uint64_t hdr = 0;
    if (fread(&hdr, 8, 1, f) != 1 || hdr != ZEROMANI_MODULE_MAGIC) { fclose(f); return -2; }
    explicit_bzero(active_rules, sizeof(active_rules)); active_count = 0;
    int map_fd = bpf_obj_get(bpf_pin_path), synced = 0;
    swar_rule_t r;
    while (active_count < 16 && fread(&r, sizeof(r), 1, f) == 1) {
        r.hits = 0; *(active_rules + active_count) = r;
        if (map_fd >= 0) { uint32_t k = (uint32_t)active_count; if (bpf_map_update(map_fd, &k, &r) == 0) synced++; }
        active_count++;
    }
    if (map_fd >= 0) close(map_fd);
    fclose(f);
    if (out_loaded) *out_loaded = active_count;
    if (out_kernel_synced) *out_kernel_synced = synced;
    return 0;
}
static int guardian_init(uint64_t seed) { (void)seed; explicit_bzero(active_rules, sizeof(active_rules)); active_count = 0; return 0; }
static size_t guardian_process_frame(uint8_t *buf, size_t len, size_t max_cap, uint64_t *delay) {
    (void)max_cap; if (delay) *delay = 0;
    if (!buf || len < 14 || active_count == 0) return 0;
    size_t vshift = 0;
    uint16_t eth = ((uint16_t)*(buf + 12) << 8) | *(buf + 13);
    for (int v = 0; v < 2 && (eth == 0x8100 || eth == 0x88A8); v++) {
        if (len < 18 + vshift) return 0;
        eth = ((uint16_t)*(buf + 16 + vshift) << 8) | *(buf + 17 + vshift);
        vshift += 4;
    }
    for (size_t i = 0; i < active_count; i++) {
        swar_rule_t *r = active_rules + i;
        size_t eff_off = (size_t)r->offset + (r->offset >= 14 ? vshift : 0);
        if (r->mask != 0 && len >= (size_t)r->min_len + vshift && eff_off + 8 <= len) {
            uint64_t w = 0; memcpy(&w, buf + eff_off, 8);
            if ((w & r->mask) == r->pattern) { r->hits++; return 1; }
        }
    }
    return 0;
}
static void guardian_shutdown(void) { explicit_bzero(active_rules, sizeof(active_rules)); active_count = 0; }
const zero_module_descriptor_t zero_module_entry = {
    .magic = ZEROMANI_MODULE_MAGIC, .abi_version = ZERO_MODULE_ABI_VER, .module_id = 2,
    .name = "xdp_live_guardian", .init = guardian_init, .process_frame = guardian_process_frame, .shutdown = guardian_shutdown
};
