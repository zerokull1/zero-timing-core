// ZEROMANI (zerokull1) | 0x5A45524F4D414E49ULL
#include "../module_abi.h"
#include <string.h>

static uint64_t tarpit_seed = 0;

static inline uint16_t bswap16(uint16_t v) {
    return (uint16_t)((v << 8) | (v >> 8));
}

static inline uint32_t bswap32(uint32_t v) {
    return ((v & 0xFF000000U) >> 24) |
           ((v & 0x00FF0000U) >> 8)  |
           ((v & 0x0000FF00U) << 8)  |
           ((v & 0x000000FFU) << 24);
}

static uint16_t ipv4_checksum(const uint8_t *hdr) {
    uint32_t sum = 0;
    for (int i = 0; i < 20; i += 2) {
        if (i == 10) continue;
        uint16_t w = (uint16_t)((*(hdr + i) << 8) | *(hdr + i + 1));
        sum += w;
    }
    while (sum >> 16) sum = (sum & 0xFFFFU) + (sum >> 16);
    return (uint16_t)(~sum);
}

static uint16_t tcp_ipv4_checksum(uint32_t src_ip_be, uint32_t dst_ip_be, const uint8_t *tcp_seg, uint16_t tcp_len) {
    uint32_t sum = 0;
    uint32_t s = bswap32(src_ip_be);
    uint32_t d = bswap32(dst_ip_be);
    sum += (s >> 16) + (s & 0xFFFFU);
    sum += (d >> 16) + (d & 0xFFFFU);
    sum += 6U + (uint32_t)tcp_len;

    for (uint16_t i = 0; i + 1 < tcp_len; i += 2) {
        if (i == 16) continue;
        uint16_t w = (uint16_t)((*(tcp_seg + i) << 8) | *(tcp_seg + i + 1));
        sum += w;
    }
    if (tcp_len & 1U) {
        sum += (uint16_t)(*(tcp_seg + tcp_len - 1) << 8);
    }
    while (sum >> 16) sum = (sum & 0xFFFFU) + (sum >> 16);
    return (uint16_t)(~sum);
}

static uint8_t semantic_tarpit_byte(uint32_t seq_num) {
    static const char *bait = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"status\":\"syncing\",\"shard\":\"core-01\",\"token\":\"";
    uint32_t idx = seq_num % 96U;
    return (uint8_t)(*(bait + idx));
}

static int tarpit_init(uint64_t seed) {
    tarpit_seed = seed ^ ZEROMANI_MODULE_MAGIC;
    return 0;
}

// Semantic Context Tarpit (1B/probe, TCP Window=1) + RTO Jitter-Mirroring (180..243 ms)
static size_t tarpit_process_frame(uint8_t *buf, size_t len, size_t max_cap, uint64_t *out_delay_ns) {
    if (!buf || len < 54) return 0;
    if (*(buf + 12) != 0x08 || *(buf + 13) != 0x00 || *(buf + 23) != 6) return 0;

    uint8_t tmp_mac0 = *(buf + 0), tmp_mac1 = *(buf + 1), tmp_mac2 = *(buf + 2);
    uint8_t tmp_mac3 = *(buf + 3), tmp_mac4 = *(buf + 4), tmp_mac5 = *(buf + 5);
    memcpy(buf + 0, buf + 6, 6);
    *(buf + 6) = tmp_mac0; *(buf + 7) = tmp_mac1; *(buf + 8) = tmp_mac2;
    *(buf + 9) = tmp_mac3; *(buf + 10) = tmp_mac4; *(buf + 11) = tmp_mac5;

    uint32_t src_ip = 0, dst_ip = 0;
    memcpy(&src_ip, buf + 26, 4);
    memcpy(&dst_ip, buf + 30, 4);
    memcpy(buf + 26, &dst_ip, 4);
    memcpy(buf + 30, &src_ip, 4);

    uint16_t src_port = 0, dst_port = 0;
    memcpy(&src_port, buf + 34, 2);
    memcpy(&dst_port, buf + 36, 2);
    memcpy(buf + 34, &dst_port, 2);
    memcpy(buf + 36, &src_port, 2);

    uint32_t in_seq = 0, in_ack = 0;
    memcpy(&in_seq, buf + 38, 4);
    memcpy(&in_ack, buf + 42, 4);

    uint32_t host_in_seq = bswap32(in_seq);
    uint32_t host_in_ack = bswap32(in_ack);
    uint32_t ack_num = bswap32(host_in_seq + 1U);
    uint32_t out_seq_host = host_in_ack ? host_in_ack : (uint32_t)(tarpit_seed ^ bswap32(src_ip));
    uint32_t out_seq = bswap32(out_seq_host);

    uint16_t emit_bait = (max_cap >= 55) ? 1U : 0U;
    uint16_t ip_tot_len = (uint16_t)(40U + emit_bait);
    uint16_t tcp_seg_len = (uint16_t)(20U + emit_bait);

    *(buf + 16) = (uint8_t)(ip_tot_len >> 8);
    *(buf + 17) = (uint8_t)(ip_tot_len & 0xFFU);
    *(buf + 22) = 64;
    *(buf + 24) = 0;
    *(buf + 25) = 0;
    uint16_t ip_csum = ipv4_checksum(buf + 14);
    *(buf + 24) = (uint8_t)(ip_csum >> 8);
    *(buf + 25) = (uint8_t)(ip_csum & 0xFFU);

    memcpy(buf + 38, &out_seq, 4);
    memcpy(buf + 42, &ack_num, 4);

    *(buf + 46) = 0x50;
    *(buf + 47) = emit_bait ? 0x18 : 0x10; // PSH+ACK при отдаче 1B или чистый ACK
    *(buf + 48) = 0x00;
    *(buf + 49) = 0x01; // TCP Window = 1 байт (удержание сессии без RST)
    *(buf + 50) = 0x00;
    *(buf + 51) = 0x00;

    if (emit_bait) {
        *(buf + 54) = semantic_tarpit_byte(out_seq_host);
    }

    uint16_t tcp_csum = tcp_ipv4_checksum(dst_ip, src_ip, buf + 34, tcp_seg_len);
    *(buf + 50) = (uint8_t)(tcp_csum >> 8);
    *(buf + 51) = (uint8_t)(tcp_csum & 0xFFU);

    if (out_delay_ns) {
        uint64_t jitter_ms = 180ULL + (((tarpit_seed ^ (uint64_t)src_ip ^ (uint64_t)host_in_seq) & 0x3FULL));
        *out_delay_ns = jitter_ms * 1000000ULL;
    }
    return (size_t)(14U + ip_tot_len);
}

static void tarpit_shutdown(void) {
    tarpit_seed = 0;
}

const zero_module_descriptor_t zero_module_entry = {
    .magic = ZEROMANI_MODULE_MAGIC,
    .abi_version = ZERO_MODULE_ABI_VER,
    .module_id = 1,
    .name = "deception_semantic_rto_tarpit",
    .init = tarpit_init,
    .process_frame = tarpit_process_frame,
    .shutdown = tarpit_shutdown
};
