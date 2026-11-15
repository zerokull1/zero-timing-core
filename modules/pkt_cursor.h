// ZEROMANI (zerokull1) | 0x5A45524F4D414E49ULL
#ifndef ZERO_PKT_CURSOR_H
#define ZERO_PKT_CURSOR_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    size_t l3_off;
    size_t l4_off;
    size_t payload_off;
    uint8_t ip_proto;
    uint8_t valid;
} pkt_cursor_t;

// Динамический безвыделенный разбор Ethernet (включая 802.1Q VLAN) -> IPv4 (IHL) -> TCP/UDP (Data Offset)
static inline pkt_cursor_t parse_pkt_cursor(const uint8_t *buf, size_t len) {
    pkt_cursor_t c = {0, 0, 0, 0, 0};
    if (!buf || len < 34) return c;

    uint16_t eth = (uint16_t)((*(buf + 12) << 8) | *(buf + 13));
    size_t off = 14;
    if (eth == 0x8100 || eth == 0x88A8) {
        if (len < 38) return c;
        eth = (uint16_t)((*(buf + 16) << 8) | *(buf + 17));
        off = 18;
    }
    if (eth != 0x0800 || len < off + 20) return c;

    uint8_t ihl = (uint8_t)((*(buf + off) & 0x0F) * 4);
    if (ihl < 20 || len < off + ihl) return c;

    c.l3_off = off;
    c.ip_proto = *(buf + off + 9);
    c.l4_off = off + ihl;

    if (c.ip_proto == 6) {
        if (len < c.l4_off + 20) return c;
        uint8_t doff = (uint8_t)(((*(buf + c.l4_off + 12) >> 4) & 0x0F) * 4);
        if (doff < 20 || len < c.l4_off + doff) return c;
        c.payload_off = c.l4_off + doff;
        c.valid = 1;
    } else if (c.ip_proto == 17) {
        if (len < c.l4_off + 8) return c;
        c.payload_off = c.l4_off + 8;
        c.valid = 1;
    }
    return c;
}

#endif
