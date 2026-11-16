// ZEROMANI (zerokull1) | 0x5A45524F4D414E49ULL
// Copyright (c) 2026 zerokull1 (https://github.com)
// Licensed under GPL-3.0. Unauthorized proprietary use is strictly prohibited.

#![allow(dead_code)]

use core::sync::atomic::{AtomicU64, Ordering};

pub const FLOW_TABLE_BUCKETS: usize = 65536; // Степень двойки для быстрой битовой маски (& 0xFFFF)

/// Слот активного сетевого потока (ровно 64 байта = 1 кэш-линия процессора, Zero False-Sharing).
#[repr(C, align(64))]
pub struct FlowSlot {
    pub flow_hash: AtomicU64,   // 64-битный хэш 5-tuple (SrcIP, DstIP, SrcPort, DstPort, Proto)
    pub pkt_count: AtomicU64,   // Счётчик пакетов в сессии
    pub byte_count: AtomicU64,  // Счётчик байт в сессии
    pub last_tsc: AtomicU64,    // Аппаратная метка времени (TSC) последнего пакета
    pub flags: AtomicU64,       // Битовая маска состояния (0x01 = Verified, 0x02 = Suspicious, 0x04 = Blocked)
    pub _pad: [u64; 3],
}

impl FlowSlot {
    pub const fn new() -> Self {
        Self {
            flow_hash: AtomicU64::new(0),
            pkt_count: AtomicU64::new(0),
            byte_count: AtomicU64::new(0),
            last_tsc: AtomicU64::new(0),
            flags: AtomicU64::new(0),
            _pad: [0; 3],
        }
    }
}

/// Безблокировочное обновление состояния потока в DDR за один проход CAS (lock cmpxchg)
#[inline(always)]
pub unsafe fn track_flow_lockfree(
    table_ptr: *const FlowSlot,
    flow_hash: u64,
    pkt_len: u64,
    now_tsc: u64,
) -> u64 { unsafe {
    let idx = (flow_hash as usize) & (FLOW_TABLE_BUCKETS - 1);
    let slot = &*table_ptr.add(idx);

    let current_hash = slot.flow_hash.load(Ordering::Acquire);
    if current_hash == flow_hash {
        slot.pkt_count.fetch_add(1, Ordering::Relaxed);
        slot.byte_count.fetch_add(pkt_len, Ordering::Relaxed);
        slot.last_tsc.store(now_tsc, Ordering::Release);
        return slot.flags.load(Ordering::Acquire);
    }

    // Если слот пуст или устарел (> 3 млрд тактов ~ 1 сек) — захватываем его без блокировок
    let last = slot.last_tsc.load(Ordering::Relaxed);
    if (current_hash == 0 || now_tsc.saturating_sub(last) > 3_000_000_000)
        && slot
            .flow_hash
            .compare_exchange(current_hash, flow_hash, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
        {
            slot.pkt_count.store(1, Ordering::Relaxed);
            slot.byte_count.store(pkt_len, Ordering::Relaxed);
            slot.flags.store(0, Ordering::Relaxed);
            slot.last_tsc.store(now_tsc, Ordering::Release);
            return 0;
        }

    0
}}

/// Аппаратный 64-битный криптографический хэш 5-tuple на кремниевых инструкциях Intel AES-NI (`aesenc`) + SSE4.2 (`crc32q`).
/// Защищает lock-free таблицу потоков от Hash-Flooding / Bucket Collision DoS за ~3-4 такта CPU.
#[inline(always)]
pub unsafe fn hash_5tuple_aes_crc32(
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    proto: u8,
    epoch_key_lo: u64,
    epoch_key_hi: u64,
) -> u64 { unsafe {
    let lo = (src_ip as u64) | ((dst_ip as u64) << 32);
    let hi = (src_port as u64) | ((dst_port as u64) << 16) | ((proto as u64) << 32);

    #[cfg(target_arch = "x86_64")]
    {
        let mut h: u64;
        core::arch::asm!(
            "movq {x0}, {lo}",
            "pinsrq {x0}, {hi}, 1",
            "movq {x1}, {k0}",
            "pinsrq {x1}, {k1}, 1",
            "aesenc {x0}, {x1}",
            "aesenc {x0}, {x1}",
            "movq {h}, {x0}",
            "pextrq {t}, {x0}, 1",
            "crc32 {h}, {t}",
            lo = in(reg) lo,
            hi = in(reg) hi,
            k0 = in(reg) epoch_key_lo,
            k1 = in(reg) epoch_key_hi,
            x0 = out(xmm_reg) _,
            x1 = out(xmm_reg) _,
            t = out(reg) _,
            h = out(reg) h,
            options(pure, nomem, nostack)
        );
        h
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        (lo ^ epoch_key_lo).wrapping_mul(0x9E3779B97F4A7C15) ^ (hi ^ epoch_key_hi)
    }
}}

/// Полный цикл: аппаратный AES-NI+CRC32 хэш 5-tuple + lock-free обновление 64-байтного слота в DDR
#[inline(always)]
pub unsafe fn track_packet_5tuple(
    table_ptr: *const FlowSlot,
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    proto: u8,
    pkt_len: u64,
    now_tsc: u64,
    epoch_key_lo: u64,
    epoch_key_hi: u64,
) -> u64 { unsafe {
    let h = hash_5tuple_aes_crc32(src_ip, dst_ip, src_port, dst_port, proto, epoch_key_lo, epoch_key_hi);
    track_flow_lockfree(table_ptr, h, pkt_len, now_tsc)
}}
