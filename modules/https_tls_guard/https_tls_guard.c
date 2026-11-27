// ZEROMANI (zerokull1) | 0x5A45524F4D414E49ULL
#define _DEFAULT_SOURCE
#include "../module_abi.h"
#include "../pkt_cursor.h"
#include <stdio.h>
#include <string.h>

#define MAX_TLS_PROFILES 64
typedef struct __attribute__((packed)) { uint64_t tls_fp; uint32_t sni_hash, seen_hits; } tls_profile_t;
_Alignas(64) static tls_profile_t tls_db[MAX_TLS_PROFILES];
static size_t tls_count = 0;

static inline uint64_t fnv1a_64(const uint8_t *p, size_t n) {
    uint64_t h = 0xCBF29CE484222325ULL;
    for (size_t i = 0; i < n; i++) { h ^= p[i]; h *= 0x100000001B3ULL; }
    return h;
}
static int parse_tls_client_hello(const uint8_t *pay, size_t plen, uint64_t *out_fp, int *out_is_attack) {
    *out_is_attack = 0;
    if (plen < 6 || *(pay + 0) != 0x16) return 0;
    uint16_t rec_ver = ((uint16_t)*(pay + 1) << 8) | *(pay + 2);
    uint16_t rec_len = ((uint16_t)*(pay + 3) << 8) | *(pay + 4);
    if (rec_ver < 0x0303 || rec_len < 40) { *out_is_attack = 1; return 1; }
    if (*(pay + 5) != 0x01) return 0; // ServerHello/Certificate/etc — не блокируем
    if (plen < 44) { *out_is_attack = 1; return 1; }
    uint16_t ch_ver = ((uint16_t)*(pay + 9) << 8) | *(pay + 10);
    if (ch_ver < 0x0303) { *out_is_attack = 1; return 1; }
    size_t sid_len = *(pay + 43);
    size_t cs_off = 44 + sid_len;
    if (cs_off + 2 > plen) {
        *out_fp = ((uint64_t)rec_ver << 48) ^ ((uint64_t)ch_ver << 32) ^ (uint64_t)rec_len;
        return 1;
    }
    size_t inspect_len = (plen > 160) ? 160 : plen;
    *out_fp = fnv1a_64(pay + cs_off, inspect_len - cs_off) ^ ((uint64_t)rec_ver << 48) ^ ((uint64_t)ch_ver << 32);
    return 1;
}
static int tls_init(uint64_t seed) { (void)seed; explicit_bzero(tls_db, sizeof(tls_db)); tls_count = 0; return 0; }
int tls_load_db(const char *path, size_t *out) {
    FILE *f = fopen(path, "rb"); if (!f) { if (out) *out = 0; return -1; }
    uint64_t hdr = 0;
    if (fread(&hdr, 8, 1, f) != 1 || hdr != ZEROMANI_MODULE_MAGIC) { fclose(f); return -2; }
    explicit_bzero(tls_db, sizeof(tls_db)); tls_count = 0;
    tls_profile_t p;
    while (tls_count < MAX_TLS_PROFILES && fread(&p, sizeof(p), 1, f) == 1) tls_db[tls_count++] = p;
    fclose(f); if (out) *out = tls_count; return 0;
}
int tls_save_db(const char *path) {
    FILE *f = fopen(path, "wb"); if (!f) return -1;
    uint64_t hdr = ZEROMANI_MODULE_MAGIC; fwrite(&hdr, 8, 1, f);
    for (size_t i = 0; i < tls_count; i++) fwrite(&tls_db[i], sizeof(tls_profile_t), 1, f);
    fclose(f); return 0;
}
int tls_learn_client(const uint8_t *buf, size_t len) {
    pkt_cursor_t c = parse_pkt_cursor(buf, len);
    if (!c.valid || c.ip_proto != 6 || len <= c.payload_off) return 0;
    uint64_t fp = 0; int bad = 0;
    if (!parse_tls_client_hello(buf + c.payload_off, len - c.payload_off, &fp, &bad) || bad) return 0;
    for (size_t i = 0; i < tls_count; i++) if (tls_db[i].tls_fp == fp) { tls_db[i].seen_hits++; return 0; }
    if (tls_count < MAX_TLS_PROFILES) { tls_db[tls_count++] = (tls_profile_t){fp, (uint32_t)fp, 1}; return 1; }
    return 0;
}
static size_t tls_process_frame(uint8_t *buf, size_t len, size_t max_cap, uint64_t *delay) {
    (void)max_cap; if (delay) *delay = 0;
    pkt_cursor_t c = parse_pkt_cursor(buf, len);
    if (!c.valid || c.ip_proto != 6 || len <= c.payload_off) return 0;
    uint64_t fp = 0; int bad = 0;
    if (!parse_tls_client_hello(buf + c.payload_off, len - c.payload_off, &fp, &bad)) return 0;
    if (bad) return 1;
    if (tls_count == 0) return 0;
    for (size_t i = 0; i < tls_count; i++) if (tls_db[i].tls_fp == fp) return 0;
    return 1;
}
static void tls_shutdown(void) { explicit_bzero(tls_db, sizeof(tls_db)); tls_count = 0; }
const zero_module_descriptor_t zero_module_entry = {
    .magic = ZEROMANI_MODULE_MAGIC, .abi_version = ZERO_MODULE_ABI_VER, .module_id = 7,
    .name = "adaptive_https_tls_guard", .init = tls_init, .process_frame = tls_process_frame, .shutdown = tls_shutdown
};
