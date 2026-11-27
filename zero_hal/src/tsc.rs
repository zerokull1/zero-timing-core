// ZEROMANI (zerokull1) | 0x5A45524F4D414E49ULL
#![allow(dead_code)]

#[cfg(any(target_arch = "x86_64", target_arch = "s390x", target_arch = "aarch64", target_arch = "riscv64"))]
use core::arch::asm;

#[inline(always)]
pub fn rdtsc_start() -> u64 {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let (low, high): (u32, u32);
        asm!("lfence", "rdtsc", out("eax") low, out("edx") high, options(nomem, nostack, preserves_flags));
        ((high as u64) << 32) | (low as u64)
    }
    #[cfg(target_arch = "s390x")]
    unsafe {
        let mut tod: u64 = 0;
        asm!("bcr 14, 0", "stckf 0({p})", p = in(reg_addr) &mut tod, options(nostack, preserves_flags));
        tod >> 12
    }
    #[cfg(target_arch = "aarch64")]
    unsafe {
        let cnt: u64;
        asm!("isb", "mrs {c}, cntvct_el0", c = out(reg) cnt, options(nomem, nostack, preserves_flags));
        cnt
    }
    #[cfg(target_arch = "riscv64")]
    unsafe {
        let t: u64;
        asm!("rdtime {t}", t = out(reg) t, options(nomem, nostack, preserves_flags));
        t
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "s390x", target_arch = "aarch64", target_arch = "riscv64")))]
    {
        static FALLBACK_CLK: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);
        FALLBACK_CLK.fetch_add(1, core::sync::atomic::Ordering::SeqCst)
    }
}

#[inline(always)]
pub fn rdtsc_end() -> u64 {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let (low, high): (u32, u32);
        asm!("rdtscp", "lfence", out("eax") low, out("edx") high, out("ecx") _, options(nomem, nostack, preserves_flags));
        ((high as u64) << 32) | (low as u64)
    }
    #[cfg(target_arch = "s390x")]
    unsafe {
        let mut tod: u64 = 0;
        asm!("stckf 0({p})", "bcr 14, 0", p = in(reg_addr) &mut tod, options(nostack, preserves_flags));
        tod >> 12
    }
    #[cfg(target_arch = "aarch64")]
    unsafe {
        let cnt: u64;
        asm!("dsb sy", "mrs {c}, cntvct_el0", "isb", c = out(reg) cnt, options(nomem, nostack, preserves_flags));
        cnt
    }
    #[cfg(target_arch = "riscv64")]
    unsafe {
        let t: u64;
        asm!("fence rw, rw", "rdtime {t}", t = out(reg) t, options(nomem, nostack, preserves_flags));
        t
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "s390x", target_arch = "aarch64", target_arch = "riscv64")))]
    {
        rdtsc_start()
    }
}

#[inline(always)]
pub fn measure_cycles<F: FnOnce() -> R, R>(f: F) -> (R, u64) {
    let start = rdtsc_start();
    let res = f();
    (res, rdtsc_end().saturating_sub(start))
}

#[inline(always)]
pub fn constant_time_gate<F: FnOnce() -> R, R>(target_cycles: u64, f: F) -> R {
    let start = rdtsc_start();
    let res = f();
    while rdtsc_end().saturating_sub(start) < target_cycles {
        core::hint::spin_loop();
    }
    res
}

#[inline(always)]
pub fn constant_time_jittered_gate<F: FnOnce() -> R, R>(base_cycles: u64, jitter_mask: u64, f: F) -> R {
    let start = rdtsc_start();
    let result = f();
    let mut x = start ^ 0x9E3779B97F4A7C15;
    x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
    let target = base_cycles.saturating_add(x.wrapping_mul(0x2545F4914F6CDD1D) & jitter_mask);
    while rdtsc_end().saturating_sub(start) < target {
        core::hint::spin_loop();
    }
    result
}

/// 64B-aligned Master CPU Pulse Anchor calibrated at UEFI boot and periodically re-aligned in runtime
/// when server hardware (CPU, DDR, NIC) or link speed changes.
#[repr(C, align(64))]
#[derive(Clone, Copy)]
pub struct HardwarePulseAnchor {
    pub cpu_sig: u32,
    pub target_batch: u32,
    pub base_pulse_tsc: u64,
    pub current_period_tsc: u64,
    pub last_pulse_tsc: u64,
    pub realign_epochs: u64,
    pub _pad: [u64; 3],
}

impl HardwarePulseAnchor {
    #[inline(always)]
    pub const fn new(cpu_sig: u32, base_pulse_tsc: u64, target_batch: u32) -> Self {
        Self {
            cpu_sig,
            target_batch,
            base_pulse_tsc,
            current_period_tsc: base_pulse_tsc,
            last_pulse_tsc: 0,
            realign_epochs: 0,
            _pad: [0; 3],
        }
    }

    /// Periodic lock-free pulse re-alignment (integer shift-only, zero float/div).
    #[inline(always)]
    pub fn periodic_realign(&mut self, cur_cpu_sig: u32, now_tsc: u64, arrived_pkts: u32) -> bool {
        if cur_cpu_sig != self.cpu_sig {
            self.cpu_sig = cur_cpu_sig;
            self.current_period_tsc = self.base_pulse_tsc;
            self.last_pulse_tsc = now_tsc;
            self.realign_epochs = self.realign_epochs.wrapping_add(1);
            return true;
        }
        let dt = now_tsc.wrapping_sub(self.last_pulse_tsc);
        if dt < self.current_period_tsc && arrived_pkts < self.target_batch {
            return false;
        }
        self.last_pulse_tsc = now_tsc;
        self.realign_epochs = self.realign_epochs.wrapping_add(1);
        if arrived_pkts > self.target_batch {
            let next = self.current_period_tsc - (self.current_period_tsc >> 3);
            self.current_period_tsc = if next < 2000 { 2000 } else { next };
        } else if arrived_pkts < (self.target_batch >> 1) {
            let next = self.current_period_tsc + (self.current_period_tsc >> 3);
            self.current_period_tsc = if next > 3_300_000 { 3_300_000 } else { next };
        }
        true
    }

    /// Deterministic Xorshift64* phase jitter (0.15..0.85 ms = 150_000..850_000 ns)
    /// to eliminate bus/network periodic phase locking without FPU.
    #[inline(always)]
    pub fn phase_jitter_ns(entropy: u64) -> u64 {
        let mut x = entropy ^ 0x9E37_79B9_7F4A_7C15;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        150_000 + (x % 700_001)
    }
}
