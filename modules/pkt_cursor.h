// ZEROMANI (zerokull1) | 0x5A45524F4D414E49ULL
#ifndef ZERO_PKT_CURSOR_H
#define ZERO_PKT_CURSOR_H
#include <stdint.h>
#include <stddef.h>
typedef struct { size_t l3_off, l4_off, payload_off; uint8_t ip_proto, valid; } pkt_cursor_t;
static inline pkt_cursor_t parse_pkt_cursor(const uint8_t *b, size_t len) {
    pkt_cursor_t c = {0, 0, 0, 0, 0};
    if (!b || len < 34) return c;
    uint16_t eth = ((uint16_t)*(b + 12) << 8) | *(b + 13);
    size_t off = 14;
    for (int v = 0; v < 2 && (eth == 0x8100 || eth == 0x88A8); v++) {
        if (len < off + 24) return c;
        if (((((uint16_t)*(b + off) << 8) | *(b + off + 1)) & 0x0FFFU) == 0) return c;
        eth = ((uint16_t)*(b + off + 2) << 8) | *(b + off + 3);
        off += 4;
    }
    if (eth != 0x0800 || len < off + 20 || *(b + off) != 0x45) return c;
    uint16_t tot = ((uint16_t)*(b + off + 2) << 8) | *(b + off + 3);
    uint16_t frag = ((uint16_t)*(b + off + 6) << 8) | *(b + off + 7);
    if (tot < 20 || len < off + (size_t)tot || (frag & 0x3FFFU) != 0) return c;
    c.l3_off = off; c.ip_proto = *(b + off + 9); c.l4_off = off + 20;
    if (c.ip_proto == 6 && len >= c.l4_off + 20) {
        size_t doff = ((*(b + c.l4_off + 12) >> 4) & 0x0F) * 4;
        if (doff >= 20 && len >= c.l4_off + doff) { c.payload_off = c.l4_off + doff; c.valid = 1; }
    } else if (c.ip_proto == 17 && len >= c.l4_off + 8) {
        c.payload_off = c.l4_off + 8; c.valid = 1;
    }
    return c;
}
#endif
