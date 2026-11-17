// ZEROMANI (zerokull1) | 0x5A45524F4D414E49ULL
#![allow(dead_code)]

use core::arch::asm;

#[cfg(target_arch = "x86_64")]
pub mod sysno {
    pub const SYS_CLOSE: u64           = 3;
    pub const SYS_MMAP: u64            = 9;
    pub const SYS_MPROTECT: u64        = 10;
    pub const SYS_MUNMAP: u64          = 11;
    pub const SYS_FCNTL: u64           = 72;
    pub const SYS_FTRUNCATE: u64       = 77;
    pub const SYS_MLOCK: u64           = 149;
    pub const SYS_MBIND: u64           = 237;
    pub const SYS_MEMFD_CREATE: u64    = 319;
    pub const SYS_IO_URING_SETUP: u64  = 425;
    pub const SYS_IO_URING_ENTER: u64  = 426;
    pub const SYS_IO_URING_REG: u64    = 427;
}

#[cfg(target_arch = "s390x")]
pub mod sysno {
    pub const SYS_CLOSE: u64           = 6;
    pub const SYS_FCNTL: u64           = 55;
    pub const SYS_MMAP: u64            = 90;
    pub const SYS_MUNMAP: u64          = 91;
    pub const SYS_FTRUNCATE: u64       = 93;
    pub const SYS_MPROTECT: u64        = 125;
    pub const SYS_MLOCK: u64           = 150;
    pub const SYS_MBIND: u64           = 268;
    pub const SYS_MEMFD_CREATE: u64    = 350;
    pub const SYS_IO_URING_SETUP: u64  = 425;
    pub const SYS_IO_URING_ENTER: u64  = 426;
    pub const SYS_IO_URING_REG: u64    = 427;
}

#[inline(always)]
pub unsafe fn syscall1(nr: u64, a1: u64) -> isize { unsafe {
    let ret: isize;
    #[cfg(target_arch = "x86_64")]
    asm!("syscall", in("rax") nr, in("rdi") a1, out("rcx") _, out("r11") _, lateout("rax") ret, options(nostack));
    #[cfg(target_arch = "s390x")]
    asm!("svc 0", in("r1") nr, in("r2") a1, lateout("r2") ret, options(nostack));
    ret
}}

#[inline(always)]
pub unsafe fn syscall2(nr: u64, a1: u64, a2: u64) -> isize { unsafe {
    let ret: isize;
    #[cfg(target_arch = "x86_64")]
    asm!("syscall", in("rax") nr, in("rdi") a1, in("rsi") a2, out("rcx") _, out("r11") _, lateout("rax") ret, options(nostack));
    #[cfg(target_arch = "s390x")]
    asm!("svc 0", in("r1") nr, in("r2") a1, in("r3") a2, lateout("r2") ret, options(nostack));
    ret
}}

#[inline(always)]
pub unsafe fn syscall3(nr: u64, a1: u64, a2: u64, a3: u64) -> isize { unsafe {
    let ret: isize;
    #[cfg(target_arch = "x86_64")]
    asm!("syscall", in("rax") nr, in("rdi") a1, in("rsi") a2, in("rdx") a3, out("rcx") _, out("r11") _, lateout("rax") ret, options(nostack));
    #[cfg(target_arch = "s390x")]
    asm!("svc 0", in("r1") nr, in("r2") a1, in("r3") a2, in("r4") a3, lateout("r2") ret, options(nostack));
    ret
}}

#[inline(always)]
pub unsafe fn syscall6(nr: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> isize { unsafe {
    let ret: isize;
    #[cfg(target_arch = "x86_64")]
    asm!("syscall", in("rax") nr, in("rdi") a1, in("rsi") a2, in("rdx") a3, in("r10") a4, in("r8") a5, in("r9") a6, out("rcx") _, out("r11") _, lateout("rax") ret, options(nostack));
    #[cfg(target_arch = "s390x")]
    asm!("svc 0", in("r1") nr, in("r2") a1, in("r3") a2, in("r4") a3, in("r5") a4, in("r6") a5, in("r7") a6, lateout("r2") ret, options(nostack));
    ret
}}

#[inline(always)]
pub unsafe fn sys_mmap_anon_or_fd(addr: usize, len: usize, prot: u64, flags: u64, fd: isize, offset: usize) -> isize { unsafe {
    #[cfg(target_arch = "x86_64")]
    { syscall6(sysno::SYS_MMAP, addr as u64, len as u64, prot, flags, fd as u64, offset as u64) }
    #[cfg(target_arch = "s390x")]
    {
        #[repr(C)]
        struct S390Mmap { addr: u64, len: u64, prot: u64, flags: u64, fd: u64, offset: u64 }
        let args = S390Mmap { addr: addr as u64, len: len as u64, prot, flags, fd: fd as u64, offset: offset as u64 };
        syscall1(sysno::SYS_MMAP, (&args as *const S390Mmap) as u64)
    }
}}

#[inline(always)]
pub unsafe fn store_fence() { unsafe {
    #[cfg(target_arch = "x86_64")]
    asm!("sfence", options(nostack, preserves_flags));
    #[cfg(target_arch = "s390x")]
    asm!("bcr 14, 0", options(nostack, preserves_flags));
}}

#[inline(always)]
pub unsafe fn full_fence() { unsafe {
    #[cfg(target_arch = "x86_64")]
    asm!("mfence", options(nostack, preserves_flags));
    #[cfg(target_arch = "s390x")]
    asm!("bcr 15, 0", options(nostack, preserves_flags));
}}
