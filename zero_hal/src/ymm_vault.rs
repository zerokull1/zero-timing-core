// ZEROMANI (zerokull1) | 0x5A45524F4D414E49ULL
#![allow(dead_code)]
use core::arch::asm;
#[inline(always)]
pub unsafe fn seal_key_in_ymm15(key_256: &[u64; 4]) { unsafe {
#[cfg(target_arch = "x86_64")]
{
asm!(
"vmovdqu ymm15, [{k}]",
k = in(reg) key_256.as_ptr(),
out("ymm15") _,
options(nostack)
);
}
}}
#[inline(always)]
pub unsafe fn read_key_from_ymm15(out_256: &mut [u64; 4]) { unsafe {
#[cfg(target_arch = "x86_64")]
{
asm!(
"vmovdqu [{o}], ymm15",
o = in(reg) out_256.as_mut_ptr(),
options(nostack)
);
}
}}
#[inline(always)]
pub unsafe fn wipe_ymm15() { unsafe {
#[cfg(target_arch = "x86_64")]
{
asm!(
"vpxor ymm15, ymm15, ymm15",
out("ymm15") _,
options(nomem, nostack)
);
}
}}
