// ZEROMANI (zerokull1) | 0x5A45524F4D414E49ULL
#define _DEFAULT_SOURCE
#include "../module_abi.h"
#include "../pkt_cursor.h"
#include <stdio.h>
#include <string.h>

#define MAX_HTTP_SIGS 64
typedef struct __attribute__((packed)) { uint64_t sig_hash; uint32_t kind, hits; } http_sig_t;
_Alignas(64) static http_sig_t http_db[MAX_HTTP_SIGS];
static size_t http_count = 0;

static inline uint64_t fnv1a_64(const uint8_t *p, size_t n) {
    uint64_t h = 0xCBF29CE484222325ULL;
    for (size_t i = 0; i < n; i++) { h ^= p[i]; h *= 0x100000001B3ULL; }
    return h;
}
static inline int has_ci_tok(const uint8_t *b, size_t n, const char *t, size_t tl) {
    if (n < tl) return 0;
    for (size_t i = 0; i + tl <= n; i++) {
        size_t k = 0;
        while (k < tl) {
            uint8_t c1 = b[i + k], c2 = (uint8_t)t[k];
            if (c1 >= 'A' && c1 <= 'Z') c1 |= 0x20;
            if (c2 >= 'A' && c2 <= 'Z') c2 |= 0x20;
            if (c1 != c2) break;
            k++;
        }
        if (k == tl) return 1;
    }
    return 0;
}
static uint32_t classify_http_anomaly(const uint8_t *p, size_t plen) {
    size_t hlen = plen;
    for (size_t i = 0; i + 3 < plen; i++) {
        if (p[i] == '\r' && p[i+1] == '\n' && p[i+2] == '\r' && p[i+3] == '\n') { hlen = i + 4; break; }
    }
    if (has_ci_tok(p, hlen, "content-length:", 15) && has_ci_tok(p, hlen, "transfer-encoding:", 18)) return 1;
    if (has_ci_tok(p, plen, "<script", 7) || has_ci_tok(p, plen, "javascript:", 11)) return 2;
    if (plen > 24 && p[0] == 0x82 && p[1] == 0x82) return 3;
    return 0;
}
static int http_init(uint64_t seed) { (void)seed; explicit_bzero(http_db, sizeof(http_db)); http_count = 0; return 0; }
int http_load_db(const char *path, size_t *out) {
    FILE *f = fopen(path, "rb"); if (!f) { if (out) *out = 0; return -1; }
    uint64_t hdr = 0;
    if (fread(&hdr, 8, 1, f) != 1 || hdr != ZEROMANI_MODULE_MAGIC) { fclose(f); return -2; }
    explicit_bzero(http_db, sizeof(http_db)); http_count = 0;
    http_sig_t s;
    while (http_count < MAX_HTTP_SIGS && fread(&s, sizeof(s), 1, f) == 1) http_db[http_count++] = s;
    fclose(f); if (out) *out = http_count; return 0;
}
int http_save_db(const char *path) {
    FILE *f = fopen(path, "wb"); if (!f) return -1;
    uint64_t hdr = ZEROMANI_MODULE_MAGIC; fwrite(&hdr, 8, 1, f);
    for (size_t i = 0; i < http_count; i++) fwrite(&http_db[i], sizeof(http_sig_t), 1, f);
    fclose(f); return 0;
}
int http_learn_attack(const uint8_t *buf, size_t len) {
    pkt_cursor_t c = parse_pkt_cursor(buf, len);
    if (!c.valid || c.ip_proto != 6 || len <= c.payload_off) return 0;
    const uint8_t *p = buf + c.payload_off; size_t plen = len - c.payload_off;
    uint32_t kind = classify_http_anomaly(p, plen); if (kind == 0) return 0;
    uint64_t sig = fnv1a_64(p, plen);
    for (size_t i = 0; i < http_count; i++) if (http_db[i].sig_hash == sig) return 0;
    if (http_count < MAX_HTTP_SIGS) { http_db[http_count++] = (http_sig_t){sig, kind, 1}; return 1; }
    return 0;
}
static size_t http_process_frame(uint8_t *buf, size_t len, size_t max_cap, uint64_t *delay) {
    (void)max_cap; if (delay) *delay = 0;
    if (http_count == 0) return 0;
    pkt_cursor_t c = parse_pkt_cursor(buf, len);
    if (!c.valid || c.ip_proto != 6 || len <= c.payload_off) return 0;
    uint64_t sig = fnv1a_64(buf + c.payload_off, len - c.payload_off);
    for (size_t i = 0; i < http_count; i++) if (http_db[i].sig_hash == sig) { http_db[i].hits++; return 1; }
    return 0;
}
static void http_shutdown(void) { explicit_bzero(http_db, sizeof(http_db)); http_count = 0; }
const zero_module_descriptor_t zero_module_entry = {
    .magic = ZEROMANI_MODULE_MAGIC, .abi_version = ZERO_MODULE_ABI_VER, .module_id = 4,
    .name = "adaptive_http_table_guard", .init = http_init, .process_frame = http_process_frame, .shutdown = http_shutdown
};
