// ZEROMANI (zerokull1) | 0x5A45524F4D414E49ULL
#[allow(dead_code)]
use core::arch::asm;
use core::arch::x86_64::*;
use core::sync::atomic::{AtomicU8, Ordering};

pub const SIMD_TIER_SWAR: u8   = 1; // 64-bit GPR SWAR (100% x86_64)
pub const SIMD_TIER_AVX2: u8   = 2; // 256-bit YMM (Haswell / Broadwell / Ryzen)
pub const SIMD_TIER_AVX512: u8 = 3; // 512-bit ZMM (Xeon Scalable / EPYC Zen4+)

static DETECTED_TIER: AtomicU8 = AtomicU8::new(0);

#[inline(never)]
unsafe fn cpuid_query(leaf: u32, subleaf: u32) -> (u32, u32, u32, u32) {
    let (mut eax, mut ebx, mut ecx, mut edx): (u32, u32, u32, u32);
    unsafe {
        asm!(
            "push rbx",
            "cpuid",
            "mov {out_ebx:e}, ebx",
            "pop rbx",
            inout("eax") leaf => eax,
            out_ebx = out(reg) ebx,
            inout("ecx") subleaf => ecx,
            out("edx") edx,
            options(nomem, nostack)
        );
    }
    (eax, ebx, ecx, edx)
}

#[inline(never)]
unsafe fn xgetbv0() -> u64 {
    let (lo, hi): (u32, u32);
    unsafe {
        asm!("xgetbv", in("ecx") 0u32, out("eax") lo, out("edx") hi, options(nomem, nostack));
    }
    ((hi as u64) << 32) | (lo as u64)
}

/// Определяет максимальный безопасный SIMD-уровень CPU (CPUID + OSXSAVE + XCR0)
#[no_mangle]
pub extern "C" fn zero_core_detect_simd_tier() -> u8 {
    let cached = DETECTED_TIER.load(Ordering::Acquire);
    if cached != 0 {
        return cached;
    }
    let tier = unsafe {
        let (max_leaf, _, _, _) = cpuid_query(0, 0);
        if max_leaf < 7 {
            SIMD_TIER_SWAR
        } else {
            let (_, _, ecx1, _) = cpuid_query(1, 0);
            let osxsave = (ecx1 & (1 << 27)) != 0;
            let avx_cpu = (ecx1 & (1 << 28)) != 0;
            if !osxsave || !avx_cpu {
                SIMD_TIER_SWAR
            } else {
                let xcr0 = xgetbv0();
                let os_ymm = (xcr0 & 0x06) == 0x06;
                let os_zmm = (xcr0 & 0xE6) == 0xE6;
                let (_, ebx7, _, _) = cpuid_query(7, 0);
                let has_avx2 = (ebx7 & (1 << 5)) != 0;
                let has_avx512bw = (ebx7 & (1 << 16)) != 0 && (ebx7 & (1 << 30)) != 0;
                if os_zmm && has_avx512bw {
                    SIMD_TIER_AVX512
                } else if os_ymm && has_avx2 {
                    SIMD_TIER_AVX2
                } else {
                    SIMD_TIER_SWAR
                }
            }
        }
    };
    DETECTED_TIER.store(tier, Ordering::Release);
    tier
}

#[target_feature(enable = "avx512bw")]
unsafe fn scan_64b_avx512(ptr: *const u8, needle: u8) -> u64 {
    unsafe {
        let v_data = _mm512_loadu_si512(ptr as *const __m512i);
        let v_pat  = _mm512_set1_epi8(needle as i8);
        _mm512_cmpeq_epi8_mask(v_data, v_pat)
    }
}

#[target_feature(enable = "avx2")]
unsafe fn scan_64b_avx2(ptr: *const u8, needle: u8) -> u64 {
    unsafe {
        let v_pat = _mm256_set1_epi8(needle as i8);
        let lo = _mm256_movemask_epi8(_mm256_cmpeq_epi8(_mm256_loadu_si256(ptr as *const __m256i), v_pat)) as u32 as u64;
        let hi = _mm256_movemask_epi8(_mm256_cmpeq_epi8(_mm256_loadu_si256(ptr.add(32) as *const __m256i), v_pat)) as u32 as u64;
        lo | (hi << 32)
    }
}

#[inline(always)]
unsafe fn scan_64b_swar(ptr: *const u8, needle: u8) -> u64 {
    let mut mask: u64 = 0;
    let mut i: usize = 0;
    while i < 64 {
        let hit = unsafe { (*ptr.add(i) == needle) as u64 };
        mask |= hit << i;
        i += 1;
    }
    mask
}

/// Всеядный поиск байта по 64-байтной кэш-линии L1 с автовыбором AVX-512 / AVX2 / SWAR
#[no_mangle]
pub unsafe extern "C" fn zero_core_scan_cacheline_64b(ptr: *const u8, needle: u8) -> u64 {
    if ptr.is_null() {
        return 0;
    }
    let tier = zero_core_detect_simd_tier();
    unsafe {
        match tier {
            SIMD_TIER_AVX512 => scan_64b_avx512(ptr, needle),
            SIMD_TIER_AVX2   => scan_64b_avx2(ptr, needle),
            _                => scan_64b_swar(ptr, needle),
        }
    }
}
