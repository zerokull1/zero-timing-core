// ZEROMANI (zerokull1) | 0x5A45524F4D414E49ULL
// Copyright (c) 2026 zerokull1 (https://github.com)
// Licensed under GPL-3.0. Unauthorized proprietary use is strictly prohibited.

#![no_std]

use core::arch::asm;
use core::sync::atomic::{AtomicU64, Ordering};

static TOTAL_PKTS: AtomicU64 = AtomicU64::new(0);
static DROPPED_L3_L4: AtomicU64 = AtomicU64::new(0);
static DROPPED_L7: AtomicU64 = AtomicU64::new(0);
static LAST_CYCLES: AtomicU64 = AtomicU64::new(0);

// Lock-Free PAWS (TCP Timestamp Replay Guard, RFC 7323) таблица на 4096 слотов
const PAWS_BUCKETS: usize = 4096;
static PAWS_TABLE: [AtomicU64; PAWS_BUCKETS] = [const { AtomicU64::new(0) }; PAWS_BUCKETS];

#[inline(always)]
unsafe fn hash_paws_flow(src_ip: u32, dst_ip: u32, ports_be: u32) -> u64 {
    let lo = (src_ip as u64) | ((dst_ip as u64) << 32);
    let hi = (ports_be as u64) ^ 0x517C_C1B7_2722_0A95u64;
    let mut h: u64 = 0x9E37_79B9_7F4A_7C15u64 ^ lo;
    asm!(
        "crc32 {h}, {lo}",
        "crc32 {h}, {hi}",
        h = inout(reg) h,
        lo = in(reg) lo,
        hi = in(reg) hi,
        options(pure, nomem, nostack)
    );
    h ^ (h >> 33)
}

#[inline(always)]
unsafe fn check_tcp_paws_replay(
    frame_ptr: *const u8,
    frame_len: usize,
    tcp_off: usize,
    tcp_hdr_len: usize,
    tcp_flags: u8,
    src_ip: u32,
    dst_ip: u32,
) -> bool {
    // Стандартная 12-байтная опция TCP Timestamps: NOP(0x01), NOP(0x01), Kind=8(0x08), Len=10(0x0A)
    if tcp_hdr_len < 32 || frame_len < tcp_off + 32 {
        return false;
    }
    let opt_ptr = frame_ptr.add(tcp_off + 20);
    let prefix = core::ptr::read_unaligned(opt_ptr as *const u32);
    if prefix != 0x0A08_0101 {
        return false;
    }
    let tsval = u32::from_be(core::ptr::read_unaligned(opt_ptr.add(4) as *const u32));
    if tsval == 0 {
        return false;
    }

    let ports_be = core::ptr::read_unaligned(frame_ptr.add(tcp_off) as *const u32);
    let h = hash_paws_flow(src_ip, dst_ip, ports_be);
    let idx = (h as usize) & (PAWS_BUCKETS - 1);
    let tag = (h >> 32) as u32;
    let slot = &PAWS_TABLE[idx];
    let prev = slot.load(Ordering::Relaxed);
    let prev_tag = (prev >> 32) as u32;
    let prev_ts = (prev & 0xFFFF_FFFF) as u32;

    let is_syn = (tcp_flags & 0x02) != 0;
    if !is_syn && prev != 0 && prev_tag == tag && prev_ts != 0 {
        // Если TSval отмотан назад (PAWS Wraparound / Replay Attack) -> блокируем!
        if tsval.wrapping_sub(prev_ts) > 0x7FFF_FFFF {
            return true;
        }
    }

    let packed = ((tag as u64) << 32) | (tsval as u64);
    slot.store(packed, Ordering::Relaxed);
    false
}

// Контракт вердиктов C-ABI (синхронизировано с benchmarks/pcap_bench.py):
// 0 = DROP, 1 = PASS, 2 = DECEPTION_TRAP, 3 = MTD_MUTATE
const VERDICT_DROP: u32 = 0;
const VERDICT_PASS: u32 = 1;
const VERDICT_DECEPTION_TRAP: u32 = 2;


#[repr(C)]
pub struct ZeroCiscoStats {
    pub total_inspected: u64,
    pub dropped_l3_l4: u64,
    pub dropped_l7: u64,
    pub last_latency_cycles: u64,
}

#[inline(always)]
unsafe fn rdtsc_start() -> u64 {
    let lo: u32;
    let hi: u32;
    asm!("lfence", "rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack));
    ((hi as u64) << 32) | (lo as u64)
}

#[inline(always)]
unsafe fn rdtscp_end() -> u64 {
    let lo: u32;
    let hi: u32;
    asm!("rdtscp", "lfence", out("eax") lo, out("edx") hi, out("ecx") _, options(nomem, nostack));
    ((hi as u64) << 32) | (lo as u64)
}

#[path = "../src/ttl_guard.rs"]
mod ttl_guard;
use ttl_guard::{GLOBAL_TTL_GUARD, TTL_VERDICT_DROP, TTL_VERDICT_TRAP};

#[no_mangle]
pub extern "C" fn zero_cisco_add_whitelist(net_be: u32, mask_be: u32) -> u32 {
    if GLOBAL_TTL_GUARD.add_whitelist_cidr(net_be, mask_be) { 1 } else { 0 }
}

#[inline(never)]
unsafe fn sync_shm_telemetry(trapped: u64, whitelisted: u64) {
    let path = b"/dev/shm/zero_ring\0";
    let mut fd: isize;
    core::arch::asm!(
        "syscall",
        in("rax") 2usize,
        in("rdi") path.as_ptr(),
        in("rsi") 0x42usize,
        in("rdx") 0o666usize,
        lateout("rax") fd,
        out("rcx") _, out("r11") _,
    );
    if fd >= 0 {
        let mut buf = [0u8; 64];
        buf[0..8].copy_from_slice(&0x5A45524F52494E47u64.to_le_bytes());
        buf[32..40].copy_from_slice(&trapped.to_le_bytes());
        buf[40..48].copy_from_slice(&whitelisted.to_le_bytes());
        let mut written: isize;
        core::arch::asm!(
            "syscall",
            in("rax") 1usize,
            in("rdi") fd as usize,
            in("rsi") buf.as_ptr(),
            in("rdx") 64usize,
            lateout("rax") written,
            out("rcx") _, out("r11") _,
        );
        let _ = written;
        let mut close_ret: isize;
        core::arch::asm!(
            "syscall",
            in("rax") 3usize,
            in("rdi") fd as usize,
            lateout("rax") close_ret,
            out("rcx") _, out("r11") _,
        );
        let _ = close_ret;
    }
}

#[no_mangle]
pub extern "C" fn zero_cisco_init() {
    TOTAL_PKTS.store(0, Ordering::Release);
    DROPPED_L3_L4.store(0, Ordering::Release);
    DROPPED_L7.store(0, Ordering::Release);
}

#[no_mangle]
pub unsafe extern "C" fn zero_cisco_inspect_frame(frame_ptr: *const u8, frame_len: usize) -> u32 {
    if frame_ptr.is_null() || frame_len < 54 {
        return VERDICT_DROP;
    }

    let eth_type = u16::from_be_bytes([*frame_ptr.add(12), *frame_ptr.add(13)]);
    if eth_type != 0x0800 {
        return VERDICT_DROP;
    }

    let ip_ttl = *frame_ptr.add(22);
    let ip_proto = *frame_ptr.add(23);
    let frag_field = u16::from_be_bytes([*frame_ptr.add(20), *frame_ptr.add(21)]);
    let src_ip = u32::from_be_bytes([*frame_ptr.add(26), *frame_ptr.add(27), *frame_ptr.add(28), *frame_ptr.add(29)]);
    let dst_ip = u32::from_be_bytes([*frame_ptr.add(30), *frame_ptr.add(31), *frame_ptr.add(32), *frame_ptr.add(33)]);
    let tcp_flags_peek = if ip_proto == 6 { *frame_ptr.add(47) } else { 0 };
    let ttl_v = GLOBAL_TTL_GUARD.inspect_packet_ipv4(src_ip, dst_ip, ip_ttl, frag_field, tcp_flags_peek, frame_len.saturating_sub(54));
    let chk = GLOBAL_TTL_GUARD.total_checked.load(Ordering::Relaxed);
    if (chk & 0xFF) == 0 {
        sync_shm_telemetry(
            GLOBAL_TTL_GUARD.total_trapped.load(Ordering::Relaxed),
            GLOBAL_TTL_GUARD.total_whitelisted.load(Ordering::Relaxed),
        );
    }
    if ttl_v == TTL_VERDICT_DROP {
        DROPPED_L3_L4.fetch_add(1, Ordering::Relaxed);
        return VERDICT_DROP;
    }
    if ttl_v == TTL_VERDICT_TRAP {
        return VERDICT_DECEPTION_TRAP;
    }

    let t0 = rdtsc_start();
    TOTAL_PKTS.fetch_add(1, Ordering::Relaxed);

    // 1. Проверка IPv4 IHL и минимальной длины кадра
    let ver_ihl = *frame_ptr.add(14);
    let ip_hdr_len = ((ver_ihl & 0x0F) as usize) * 4;
    if ip_hdr_len < 20 || frame_len < 14 + ip_hdr_len + 20 {
        DROPPED_L3_L4.fetch_add(1, Ordering::Relaxed);
        return VERDICT_DROP;
    }

    // 2. Сброс фрагментированных IPv4-пакетов (MF bit 0x2000 или FragOffset != 0)
    if (frag_field & 0x3FFF) != 0 {
        DROPPED_L3_L4.fetch_add(1, Ordering::Relaxed);
        return VERDICT_DROP;
    }

    if ip_proto != 6 {
        let t1 = rdtscp_end();
        LAST_CYCLES.store(t1.saturating_sub(t0), Ordering::Relaxed);
        return VERDICT_PASS;
    }

    // 3. Проверка TCP Data Offset (>= 20 байт) и блокада TCP Null-сегментов (флаги == 0x00)
    let tcp_off = 14 + ip_hdr_len;
    let tcp_hdr_len = (((*frame_ptr.add(tcp_off + 12)) >> 4) as usize) * 4;
    if tcp_hdr_len < 20 || frame_len < tcp_off + tcp_hdr_len {
        DROPPED_L3_L4.fetch_add(1, Ordering::Relaxed);
        return VERDICT_DROP;
    }

    let tcp_flags = *frame_ptr.add(tcp_off + 13);
    // Блокада TCP Null (0x00) и TCP URG Obfuscation (флаг URG 0x20)
    if tcp_flags == 0x00 || (tcp_flags & 0x20) != 0 {
        DROPPED_L3_L4.fetch_add(1, Ordering::Relaxed);
        let t1 = rdtscp_end();
        LAST_CYCLES.store(t1.saturating_sub(t0), Ordering::Relaxed);
        return VERDICT_DROP;
    }

    // 3.5. Проверка монотонности TCP Timestamp (PAWS Replay Guard, RFC 7323)
    if check_tcp_paws_replay(frame_ptr, frame_len, tcp_off, tcp_hdr_len, tcp_flags, src_ip, dst_ip) {
        DROPPED_L3_L4.fetch_add(1, Ordering::Relaxed);
        let t1 = rdtscp_end();
        LAST_CYCLES.store(t1.saturating_sub(t0), Ordering::Relaxed);
        return VERDICT_DECEPTION_TRAP;
    }

    // 4. Анти-микросегментация (1..7B PSH-капли для обхода 64-битного SWAR-окна) и ASM L7 DPI
    let payload_off = tcp_off + tcp_hdr_len;
    let l7_len = frame_len.saturating_sub(payload_off);
    if l7_len > 0 && l7_len < 8 && (tcp_flags & 0x08) != 0 && (tcp_flags & 0x05) == 0 {
        DROPPED_L7.fetch_add(1, Ordering::Relaxed);
        let t1 = rdtscp_end();
        LAST_CYCLES.store(t1.saturating_sub(t0), Ordering::Relaxed);
        return VERDICT_DECEPTION_TRAP;
    }
    if l7_len >= 16 {
        let p = frame_ptr.add(payload_off);
        let q0 = core::ptr::read_unaligned(p as *const u64);
        let q1 = core::ptr::read_unaligned(p.add(8) as *const u64);

        let mut verdict: u64 = VERDICT_PASS as u64;
        let mask5: u64 = 0x0000_00FF_FFFF_FFFF;
        let post_sig: u64 = u64::from_le_bytes(*b"POST /  ") & mask5;
        let te_sig: u64 = u64::from_le_bytes(*b"chunked\r");
        let tls_hdr: u64 = q0 & 0x0000_0000_00FF_FFFF;
        let tls_sig: u64 = 0x0000_0000_0003_0316;
        let rec_len: u16 = u16::from_be(((q0 >> 24) & 0xFFFF) as u16);

        asm!(
            "mov {m0}, {q0}",
            "and {m0}, {mask5}",
            "cmp {m0}, {post}",
            "jne 2f",
            "cmp {q1}, {te}",
            "mov {tmp}, 2",
            "cmove {verd}, {tmp}",
            "2:",
            "cmp {tls_h}, {tls_s}",
            "jne 3f",
            "cmp {rlen:x}, 16384",
            "mov {tmp}, 3",
            "cmova {verd}, {tmp}",
            "3:",
            q0 = in(reg) q0,
            q1 = in(reg) q1,
            mask5 = in(reg) mask5,
            post = in(reg) post_sig,
            te = in(reg) te_sig,
            tls_h = in(reg) tls_hdr,
            tls_s = in(reg) tls_sig,
            rlen = in(reg) rec_len,
            m0 = out(reg) _,
            tmp = out(reg) _,
            verd = inout(reg) verdict,
            options(pure, nomem, nostack)
        );

        if verdict != VERDICT_PASS as u64 {
            DROPPED_L7.fetch_add(1, Ordering::Relaxed);
            let t1 = rdtscp_end();
            LAST_CYCLES.store(t1.saturating_sub(t0), Ordering::Relaxed);
            return verdict as u32;
        }
    }

    let t1 = rdtscp_end();
    LAST_CYCLES.store(t1.saturating_sub(t0), Ordering::Relaxed);
    VERDICT_PASS
}

#[no_mangle]
pub unsafe extern "C" fn zero_cisco_get_stats(out_stats: *mut ZeroCiscoStats) {
    if !out_stats.is_null() {
        (*out_stats).total_inspected = TOTAL_PKTS.load(Ordering::Acquire);
        (*out_stats).dropped_l3_l4 = DROPPED_L3_L4.load(Ordering::Acquire);
        (*out_stats).dropped_l7 = DROPPED_L7.load(Ordering::Acquire);
        (*out_stats).last_latency_cycles = LAST_CYCLES.load(Ordering::Acquire);
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn rust_eh_personality() {}
