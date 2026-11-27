// ZEROMANI (zerokull1) | 0x5A45524F4D414E49ULL
#define _DEFAULT_SOURCE
#include "../module_abi.h"
#include "../pkt_cursor.h"
#include <string.h>

static uint64_t egress_key = 0;
static uint64_t pkt_seq_counter = 0;

static inline uint64_t splitmix64(uint64_t *x) {
    uint64_t z = (*x += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}
static size_t apply_wire_cipher(uint8_t *buf, size_t len, uint64_t seq, uint8_t orig_ttl, int is_rx) {
    pkt_cursor_t c = parse_pkt_cursor(buf, len);
    if (!c.valid) return len;
    uint64_t st = egress_key ^ seq;
    uint64_t g0 = splitmix64(&st);
    *(buf + 3) ^= (uint8_t)(g0 & 0xFFU);
    *(buf + 4) ^= (uint8_t)((g0 >> 8) & 0xFFU);
    *(buf + 9) ^= (uint8_t)((g0 >> 16) & 0xFFU);
    *(buf + c.l3_off + 4) ^= (uint8_t)((g0 >> 24) & 0xFFU);
    *(buf + c.l3_off + 5) ^= (uint8_t)((g0 >> 32) & 0xFFU);
    *(buf + c.l3_off + 8) = is_rx ? orig_ttl : (uint8_t)(57U + ((g0 >> 40) & 0x07U));
    size_t pos = c.payload_off;
    while (pos + 8 <= len) {
        uint64_t w = 0, gamma = splitmix64(&st);
        memcpy(&w, buf + pos, 8); w ^= gamma; memcpy(buf + pos, &w, 8);
        pos += 8;
    }
    if (pos < len) {
        uint64_t gamma = splitmix64(&st);
        uint8_t *gb = (uint8_t *)&gamma;
        for (size_t r = 0; pos + r < len; r++) *(buf + pos + r) ^= *(gb + r);
    }
    return len;
}
static int egress_init(uint64_t seed) { egress_key = seed ^ ZEROMANI_MODULE_MAGIC; pkt_seq_counter = 1; return 0; }
static size_t egress_mutate_tx(uint8_t *buf, size_t len, size_t max_cap, uint64_t *delay) {
    (void)max_cap; if (delay) *delay = 0;
    return apply_wire_cipher(buf, len, pkt_seq_counter++, 0, 0);
}
size_t egress_demutate_rx(uint8_t *buf, size_t len, uint64_t seq_num, uint8_t orig_ttl) {
    return apply_wire_cipher(buf, len, seq_num, orig_ttl, 1);
}
static void egress_shutdown(void) { egress_key = 0; pkt_seq_counter = 0; }
const zero_module_descriptor_t zero_module_entry = {
    .magic = ZEROMANI_MODULE_MAGIC, .abi_version = ZERO_MODULE_ABI_VER, .module_id = 9,
    .name = "egress_wire_protocol_mutator", .init = egress_init, .process_frame = egress_mutate_tx, .shutdown = egress_shutdown
};
