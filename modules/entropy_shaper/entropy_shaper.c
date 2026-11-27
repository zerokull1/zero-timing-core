// ZEROMANI (zerokull1) | 0x5A45524F4D414E49ULL
#include "../module_abi.h"
#include <string.h>

static uint64_t shaper_state = 0;

static inline uint64_t splitmix64(uint64_t *x) {
    uint64_t z = (*x += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}
static inline size_t target_bucket(size_t raw_len, uint64_t rnd) {
    size_t b = 1380;
    b = (raw_len <= 1024) ? (1024 + (((rnd >> 12) & 15) * 16)) : b;
    b = (raw_len <= 512)  ? (512  + (((rnd >> 8)  & 15) * 16)) : b;
    b = (raw_len <= 256)  ? (256  + (((rnd >> 4)  & 7)  * 16)) : b;
    b = (raw_len <= 128)  ? (128  + ((rnd & 3) * 16))          : b;
    return b;
}
static int shaper_init(uint64_t seed) { shaper_state = seed ^ ZEROMANI_MODULE_MAGIC; return 0; }
static size_t shaper_process_frame(uint8_t *buf, size_t len, size_t max_cap, uint64_t *out_delay_ns) {
    if (!buf || len == 0 || len > max_cap || len > 0xFFFFU) return len;
    uint64_t rnd = splitmix64(&shaper_state);
    size_t shaped_len = target_bucket(len, rnd);
    if (shaped_len > max_cap) shaped_len = max_cap;
    if (shaped_len < len + 2) {
        shaped_len = len;
    } else {
        uint16_t orig = (uint16_t)len;
        memcpy(buf + len, &orig, 2);
        size_t pos = len + 2;
        while (pos + 8 <= shaped_len) {
            uint64_t noise = splitmix64(&shaper_state);
            memcpy(buf + pos, &noise, 8);
            pos += 8;
        }
        while (pos < shaped_len) {
            *(buf + pos) = (uint8_t)(splitmix64(&shaper_state) & 0xFFU);
            pos++;
        }
    }
    if (out_delay_ns) *out_delay_ns = 15000ULL + ((rnd >> 24) & 0x1FFFFULL);
    return shaped_len;
}
static void shaper_shutdown(void) { shaper_state = 0; }
const zero_module_descriptor_t zero_module_entry = {
    .magic = ZEROMANI_MODULE_MAGIC, .abi_version = ZERO_MODULE_ABI_VER, .module_id = 3,
    .name = "adaptive_entropy_shaper", .init = shaper_init, .process_frame = shaper_process_frame, .shutdown = shaper_shutdown
};
