#ifndef MUTAGEN_COMMON_H
#define MUTAGEN_COMMON_H

#ifdef __BPF__
#include <linux/types.h>
typedef __u64 m_u64;
typedef __u32 m_u32;
#else
#include <stdint.h>
typedef uint64_t m_u64;
typedef uint32_t m_u32;
#endif

struct mutagen_config {
    m_u64 magic; /* ZEROMANI: 0x5A45524F4D414E49ULL */
    m_u32 active;
    m_u32 redirect_ifindex;
    m_u64 seed;
    m_u64 tx_mutated;
    m_u64 rx_restored;
};

#endif
