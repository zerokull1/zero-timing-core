// ZEROMANI (zerokull1) | 0x5A45524F4D414E49ULL
#![allow(dead_code)]

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
        k = in(reg) key_256.as_ptr(),
        d = in(reg) data_256.as_mut_ptr(),
        out("v16") _, out("v17") _, out("v18") _, out("v19") _, options(nostack)
    );
}}

#[inline(always)]
pub unsafe fn seal_key_in_ymm15(key_256: &[u64; 4]) { unsafe {
    #[cfg(target_arch = "x86_64")]
    asm!("vmovdqu ymm15, [{k}]", k = in(reg) key_256.as_ptr(), out("ymm15") _, options(nostack));
    #[cfg(target_arch = "s390x")]
    asm!("vlm 16, 17, 0({k})", k = in(reg) key_256.as_ptr(), out("v16") _, out("v17") _, options(nostack));
}}

#[inline(always)]
pub unsafe fn read_key_from_ymm15(out_256: &mut [u64; 4]) { unsafe {
    #[cfg(target_arch = "x86_64")]
    asm!("vmovdqu [{o}], ymm15", o = in(reg) out_256.as_mut_ptr(), options(nostack));
    #[cfg(target_arch = "s390x")]
    asm!("vstm 16, 17, 0({o})", o = in(reg) out_256.as_mut_ptr(), options(nostack));
}}

#[inline(always)]
pub unsafe fn wipe_ymm15() { unsafe {
    #[cfg(target_arch = "x86_64")]
    asm!("vpxor ymm15, ymm15, ymm15", out("ymm15") _, options(nomem, nostack));
    #[cfg(target_arch = "s390x")]
    asm!("vzero 16", "vzero 17", out("v16") _, out("v17") _, options(nomem, nostack));
}}
