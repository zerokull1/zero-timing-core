// ZEROMANI (zerokull1) | 0x5A45524F4D414E49ULL
#![allow(dead_code)]
use core::arch::asm;
pub const ZEROMANI_MAGIC: u64 = 0x5A45524F4D414E49;
pub const SYS_IO_URING_SETUP: u64 = 425;
pub const SYS_IO_URING_ENTER: u64 = 426;
pub const SYS_IO_URING_REGISTER: u64 = 427;
#[repr(C, align(64))]
#[derive(Copy, Clone)]
pub struct UringTelemetrySlot256 {
pub magic: u64,
pub tsc: u64,
pub flow_hash: u64,
pub verdict: u32,
pub core_id: u32,
pub payload_head: [u64; 28],
}
impl UringTelemetrySlot256 {
#[inline(always)]
pub const fn new(tsc: u64, flow_hash: u64, verdict: u32, core_id: u32) -> Self {
Self {
magic: ZEROMANI_MAGIC,
tsc,
flow_hash,
verdict,
core_id,
payload_head: [0u64; 28],
}
}
}
#[inline(always)]
pub unsafe fn sys_io_uring_enter(fd: u32, to_submit: u32, min_complete: u32, flags: u32) -> isize { unsafe {
let ret: isize;
asm!(
"syscall",
in("rax") SYS_IO_URING_ENTER,
in("rdi") fd as u64,
in("rsi") to_submit as u64,
in("rdx") min_complete as u64,
in("r10") flags as u64,
in("r8") 0u64,
in("r9") 8u64,
out("rcx") _, out("r11") _, lateout("rax") ret, options(nostack)
);
ret
}}
