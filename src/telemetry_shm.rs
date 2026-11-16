// ZEROMANI (zerokull1) | 0x5A45524F4D414E49ULL
// Copyright (c) 2026 zerokull1 (https://github.com)
// Licensed under GPL-3.0. Unauthorized proprietary use is strictly prohibited.

#![allow(dead_code)]

use core::arch::asm;
use core::sync::atomic::{AtomicU64, Ordering};

pub const TELEMETRY_MAGIC: u64 = 0x5A45524F_54454C45; // "ZEROTELE"

/// 64-байтный блок телеметрии в разделяемой памяти `/dev/shm/zero_telemetry` (Zero-Syscall).
#[repr(C, align(64))]
pub struct ZeroTelemetryShm {
    pub magic: AtomicU64,
    pub rx_packets: AtomicU64,
    pub allowed_packets: AtomicU64,
    pub blocked_smuggling: AtomicU64,
    pub blocked_tls_split: AtomicU64,
    pub bot_whitelisted: AtomicU64,
    pub bot_banned: AtomicU64,
    pub cycles_per_pkt: AtomicU64,
}

impl ZeroTelemetryShm {
    #[inline(always)]
    pub fn publish(
        &self,
        rx: u64,
        allowed: u64,
        smuggling: u64,
        tls_split: u64,
        wl: u64,
        ban: u64,
        cpp: u64,
    ) {
        self.rx_packets.store(rx, Ordering::Relaxed);
        self.allowed_packets.store(allowed, Ordering::Relaxed);
        self.blocked_smuggling.store(smuggling, Ordering::Relaxed);
        self.blocked_tls_split.store(tls_split, Ordering::Relaxed);
        self.bot_whitelisted.store(wl, Ordering::Relaxed);
        self.bot_banned.store(ban, Ordering::Relaxed);
        self.cycles_per_pkt.store(cpp, Ordering::Relaxed);
        self.magic.store(TELEMETRY_MAGIC, Ordering::Release);
    }
}

/// Открывает и маппирует `/dev/shm/zero_telemetry` (64 байта) без единой внешней библиотеки
pub unsafe fn map_telemetry_shm() -> Option<&'static ZeroTelemetryShm> {
    let path = b"/dev/shm/zero_telemetry\0";
    let fd: isize;
    unsafe {
        asm!(
            "syscall",
            in("rax") 2usize, // SYS_OPEN
            in("rdi") path.as_ptr(),
            in("rsi") 0o102usize, // O_RDWR | O_CREAT
            in("rdx") 0o644usize,
            lateout("rax") fd,
            out("rcx") _,
            out("r11") _,
            options(nostack)
        );
    }
    if fd < 0 {
        return None;
    }

    let size = core::mem::size_of::<ZeroTelemetryShm>();
    unsafe {
        asm!(
            "syscall",
            in("rax") 77usize, // SYS_FTRUNCATE
            in("rdi") fd,
            in("rsi") size,
            lateout("rax") _,
            out("rcx") _,
            out("r11") _,
            options(nostack)
        );
    }

    let ptr: *mut ZeroTelemetryShm;
    unsafe {
        asm!(
            "syscall",
            in("rax") 9usize, // SYS_MMAP
            in("rdi") 0usize,
            in("rsi") size,
            in("rdx") 3usize, // PROT_READ | PROT_WRITE
            in("r10") 1usize, // MAP_SHARED
            in("r8") fd,
            in("r9") 0usize,
            lateout("rax") ptr,
            out("rcx") _,
            out("r11") _,
            options(nostack)
        );
        asm!(
            "syscall",
            in("rax") 3usize, // SYS_CLOSE
            in("rdi") fd,
            lateout("rax") _,
            out("rcx") _,
            out("r11") _,
            options(nostack)
        );
    }

    if (ptr as isize) < 0 || ptr.is_null() {
        return None;
    }
    Some(unsafe { &*ptr })
}
