// ZEROMANI (zerokull1) | 0x5A45524F4D414E49ULL
#![allow(dead_code, unused_unsafe)]

#[cfg(any(target_arch = "x86_64", target_arch = "s390x", target_arch = "aarch64"))]
use core::arch::asm;

#[inline(always)]
pub unsafe fn xor_block_256_in_vault(key_256: &[u64; 4], data_256: &mut [u64; 4]) { unsafe {
    #[cfg(target_arch = "x86_64")]
    asm!(
        "vmovdqu ymm15, [{k}]",
        "vmovdqu ymm14, [{d}]",
        "vpxor ymm14, ymm14, ymm15",
        "vmovdqu [{d}], ymm14",
        "vpxor ymm15, ymm15, ymm15",
        "vpxor ymm14, ymm14, ymm14",
        k = in(reg) key_256.as_ptr(),
        d = in(reg) data_256.as_mut_ptr(),
        out("ymm14") _, out("ymm15") _, options(nostack)
    );
    #[cfg(target_arch = "s390x")]
    asm!(
        "vlm 16, 17, 0({k})",
        "vlm 18, 19, 0({d})",
        "vx 18, 18, 16",
        "vx 19, 19, 17",
        "vstm 18, 19, 0({d})",
        "vzero 16", "vzero 17", "vzero 18", "vzero 19",
        k = in(reg_addr) key_256.as_ptr(),
        d = in(reg_addr) data_256.as_mut_ptr(),
        out("v16") _, out("v17") _, out("v18") _, out("v19") _, options(nostack)
    );
    #[cfg(target_arch = "aarch64")]
    asm!(
        "ld1 {{v28.2d, v29.2d}}, [{k}]",
        "ld1 {{v30.2d, v31.2d}}, [{d}]",
        "eor v30.16b, v30.16b, v28.16b",
        "eor v31.16b, v31.16b, v29.16b",
        "st1 {{v30.2d, v31.2d}}, [{d}]",
        "movi v28.2d, #0", "movi v29.2d, #0", "movi v30.2d, #0", "movi v31.2d, #0",
        k = in(reg) key_256.as_ptr(),
        d = in(reg) data_256.as_mut_ptr(),
        out("v28") _, out("v29") _, out("v30") _, out("v31") _, options(nostack)
    );
    #[cfg(not(any(target_arch = "x86_64", target_arch = "s390x", target_arch = "aarch64")))]
    {
        for i in 0..4 {
            let k = core::ptr::read_volatile(&key_256[i]);
            let d = core::ptr::read_volatile(&data_256[i]);
            core::ptr::write_volatile(&mut data_256[i], d ^ k);
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}}

#[inline(always)]
pub unsafe fn seal_key_in_ymm15(key_256: &[u64; 4]) { unsafe {
    #[cfg(target_arch = "x86_64")]
    asm!("vmovdqu ymm15, [{k}]", k = in(reg) key_256.as_ptr(), out("ymm15") _, options(nostack));
    #[cfg(target_arch = "s390x")]
    asm!("vlm 16, 17, 0({k})", k = in(reg_addr) key_256.as_ptr(), out("v16") _, out("v17") _, options(nostack));
    #[cfg(target_arch = "aarch64")]
    asm!("ld1 {{v30.2d, v31.2d}}, [{k}]", k = in(reg) key_256.as_ptr(), out("v30") _, out("v31") _, options(nostack));
    #[cfg(not(any(target_arch = "x86_64", target_arch = "s390x", target_arch = "aarch64")))]
    { let _ = key_256; }
}}

#[inline(always)]
pub unsafe fn read_key_from_ymm15(out_256: &mut [u64; 4]) { unsafe {
    #[cfg(target_arch = "x86_64")]
    asm!("vmovdqu [{o}], ymm15", o = in(reg) out_256.as_mut_ptr(), options(nostack));
    #[cfg(target_arch = "s390x")]
    asm!("vstm 16, 17, 0({o})", o = in(reg_addr) out_256.as_mut_ptr(), options(nostack));
    #[cfg(target_arch = "aarch64")]
    asm!("st1 {{v30.2d, v31.2d}}, [{o}]", o = in(reg) out_256.as_mut_ptr(), options(nostack));
    #[cfg(not(any(target_arch = "x86_64", target_arch = "s390x", target_arch = "aarch64")))]
    { let _ = out_256; }
}}

#[inline(always)]
pub unsafe fn wipe_ymm15() { unsafe {
    #[cfg(target_arch = "x86_64")]
    asm!("vpxor ymm15, ymm15, ymm15", out("ymm15") _, options(nomem, nostack));
    #[cfg(target_arch = "s390x")]
    asm!("vzero 16", "vzero 17", out("v16") _, out("v17") _, options(nomem, nostack));
    #[cfg(target_arch = "aarch64")]
    asm!("movi v30.2d, #0", "movi v31.2d, #0", out("v30") _, out("v31") _, options(nomem, nostack));
}}
