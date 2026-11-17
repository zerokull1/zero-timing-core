// ZEROMANI (zerokull1) | 0x5A45524F4D414E49ULL
#![allow(dead_code)]

#[cfg(target_arch = "x86_64")]
use core::arch::asm;
use crate::arch::{self, sysno};

const MFD_CLOEXEC: u64       = 0x0001;
const MFD_ALLOW_SEALING: u64 = 0x0002;
const F_ADD_SEALS: u64       = 1033;
const F_SEAL_ALL: u64        = 0x000F;
pub const PROT_NONE: u64     = 0x0;
pub const PROT_READ: u64     = 0x1;
pub const PROT_WRITE: u64    = 0x2;
pub const PROT_EXEC: u64     = 0x4;
const MAP_SHARED: u64        = 0x01;

#[repr(C)]
pub struct SealedDdrArena {
    pub ptr: *mut u8,
    pub len: usize,
    pub fd: i32,
    pub sealed: bool,
}

impl SealedDdrArena {
    pub const fn empty() -> Self {
        Self { ptr: core::ptr::null_mut(), len: 0, fd: -1, sealed: false }
    }

    #[inline(never)]
    pub unsafe fn create_rw(size_bytes: usize) -> Option<Self> { unsafe {
        let aligned_len = (size_bytes + 4095) & !4095;
        let fd = arch::syscall2(sysno::SYS_MEMFD_CREATE, b"zeromani_hal_arena\0".as_ptr() as u64, MFD_CLOEXEC | MFD_ALLOW_SEALING);
        if fd < 0 { return None; }
        if arch::syscall2(sysno::SYS_FTRUNCATE, fd as u64, aligned_len as u64) < 0 {
            let _ = arch::syscall1(sysno::SYS_CLOSE, fd as u64);
            return None;
        }
        let map_ret = arch::sys_mmap_anon_or_fd(0, aligned_len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if map_ret <= 0 || (map_ret as usize) >= 0xFFFF_FFFF_FFFF_0000 {
            let _ = arch::syscall1(sysno::SYS_CLOSE, fd as u64);
            return None;
        }
        let ptr = map_ret as *mut u8;
        let _ = arch::syscall2(sysno::SYS_MLOCK, ptr as u64, aligned_len as u64);
        Some(Self { ptr, len: aligned_len, fd: fd as i32, sealed: false })
    }}

    #[inline(never)]
    pub unsafe fn seal_rx(&mut self) -> bool { unsafe {
        if self.ptr.is_null() || self.fd < 0 { return false; }
        if arch::syscall2(sysno::SYS_MUNMAP, self.ptr as u64, self.len as u64) != 0 {
            return false;
        }
        self.ptr = core::ptr::null_mut();
        if arch::syscall3(sysno::SYS_FCNTL, self.fd as u64, F_ADD_SEALS, F_SEAL_ALL) != 0 {
            return false;
        }
        let rx_ret = arch::sys_mmap_anon_or_fd(0, self.len, PROT_READ | PROT_EXEC, MAP_SHARED, self.fd as isize, 0);
        let _ = arch::syscall1(sysno::SYS_CLOSE, self.fd as u64);
        self.fd = -1;
        if rx_ret <= 0 || (rx_ret as usize) >= 0xFFFF_FFFF_FFFF_0000 {
            return false;
        }
        self.ptr = rx_ret as *mut u8;
        let _ = arch::syscall2(sysno::SYS_MLOCK, self.ptr as u64, self.len as u64);
        self.sealed = true;
        true
    }}

    #[inline(always)]
    pub unsafe fn nt_wipe_64b(dst: *mut u8) { unsafe {
        #[cfg(target_arch = "x86_64")]
        asm!("vpxor ymm0, ymm0, ymm0", "vmovntdq [{p}], ymm0", "vmovntdq [{p} + 32], ymm0", "sfence", "clflush [{p}]", "mfence", p = in(reg) dst, out("ymm0") _, options(nostack));
        #[cfg(not(target_arch = "x86_64"))]
        {
            let mut i = 0usize;
            while i < 64 { core::ptr::write_volatile(dst.add(i), 0u8); i += 1; }
            arch::full_fence();
        }
    }}
}

impl Drop for SealedDdrArena {
    fn drop(&mut self) {
        unsafe {
            if !self.ptr.is_null() && self.len > 0 {
                let _ = arch::syscall2(sysno::SYS_MUNMAP, self.ptr as u64, self.len as u64);
                self.ptr = core::ptr::null_mut();
            }
            if self.fd >= 0 {
                let _ = arch::syscall1(sysno::SYS_CLOSE, self.fd as u64);
                self.fd = -1;
            }
        }
    }
}

#[inline(always)]
pub unsafe fn stream_write_ddr_u64(dst: *mut u64, val: u64) { unsafe {
    #[cfg(target_arch = "x86_64")]
    asm!("movnti [{d}], {v}", "sfence", d = in(reg) dst, v = in(reg) val, options(nostack));
    #[cfg(not(target_arch = "x86_64"))]
    { core::ptr::write_volatile(dst, val); arch::store_fence(); }
}}

#[inline(always)]
pub unsafe fn sterile_read_and_evict_64b(src_ddr: *const u64) -> [u64; 8] { unsafe {
    #[cfg(target_arch = "x86_64")]
    {
        asm!("prefetchnta [{p}]", p = in(reg) src_ddr, options(nostack));
        let line = core::ptr::read_unaligned(src_ddr as *const [u64; 8]);
        asm!("clflush [{p}]", "mfence", p = in(reg) src_ddr, options(nostack));
        line
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let line = core::ptr::read_unaligned(src_ddr as *const [u64; 8]);
        arch::full_fence();
        line
    }
}}
