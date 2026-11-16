// ZEROMANI (zerokull1) | 0x5A45524F4D414E49ULL
#![allow(dead_code)]

use core::arch::asm;

const SYS_MMAP: u64          = 9;
const SYS_MPROTECT: u64      = 10;
const SYS_FCNTL: u64         = 72;
const SYS_FTRUNCATE: u64     = 77;
const SYS_MLOCK: u64         = 149;
const SYS_MEMFD_CREATE: u64  = 319;

const MFD_CLOEXEC: u64       = 0x0001;
const MFD_ALLOW_SEALING: u64 = 0x0002;
const F_ADD_SEALS: u64       = 1033;
const F_SEAL_SEAL: u64       = 0x0001;
const F_SEAL_SHRINK: u64     = 0x0002;
const F_SEAL_GROW: u64       = 0x0004;
const F_SEAL_WRITE: u64      = 0x0008;

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
        let name = b"zeromani_hal_arena\0";
        let fd: isize;
        asm!(
            "syscall",
            in("rax") SYS_MEMFD_CREATE,
            in("rdi") name.as_ptr() as u64,
            in("rsi") MFD_CLOEXEC | MFD_ALLOW_SEALING,
            out("rcx") _, out("r11") _, lateout("rax") fd, options(nostack)
        );
        if fd < 0 { return None; }

        let trunc_ret: isize;
        asm!(
            "syscall",
            in("rax") SYS_FTRUNCATE,
            in("rdi") fd as u64,
            in("rsi") aligned_len,
            out("rcx") _, out("r11") _, lateout("rax") trunc_ret, options(nostack)
        );
        if trunc_ret < 0 { return None; }

        let map_ret: isize;
        asm!(
            "syscall",
            in("rax") SYS_MMAP,
            in("rdi") 0usize,
            in("rsi") aligned_len,
            in("rdx") PROT_READ | PROT_WRITE,
            in("r10") MAP_SHARED,
            in("r8") fd as u64,
            in("r9") 0usize,
            out("rcx") _, out("r11") _, lateout("rax") map_ret, options(nostack)
        );
        if map_ret <= 0 || (map_ret as usize) >= 0xFFFF_FFFF_FFFF_0000 { return None; }

        let ptr = map_ret as *mut u8;
        asm!(
            "syscall",
            in("rax") SYS_MLOCK,
            in("rdi") ptr as u64,
            in("rsi") aligned_len,
            out("rcx") _, out("r11") _, lateout("rax") _, options(nostack)
        );

        Some(Self { ptr, len: aligned_len, fd: fd as i32, sealed: false })
    }}

    #[inline(never)]
    pub unsafe fn seal_rx(&mut self) -> bool { unsafe {
        if self.ptr.is_null() || self.fd < 0 { return false; }
        let mp_ret: isize;
        asm!(
            "syscall",
            in("rax") SYS_MPROTECT,
            in("rdi") self.ptr as u64,
            in("rsi") self.len,
            in("rdx") PROT_READ | PROT_EXEC,
            out("rcx") _, out("r11") _, lateout("rax") mp_ret, options(nostack)
        );
        if mp_ret != 0 { return false; }

        let seals = F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE;
        let fc_ret: isize;
        asm!(
            "syscall",
            in("rax") SYS_FCNTL,
            in("rdi") self.fd as u64,
            in("rsi") F_ADD_SEALS,
            in("rdx") seals,
            out("rcx") _, out("r11") _, lateout("rax") fc_ret, options(nostack)
        );
        self.sealed = fc_ret == 0;
        self.sealed
    }}

    #[inline(always)]
    pub unsafe fn nt_wipe_64b(dst: *mut u8) { unsafe {
        #[cfg(target_arch = "x86_64")]
        {
            asm!(
                "vpxor ymm0, ymm0, ymm0",
                "vmovntdq [{p}], ymm0",
                "vmovntdq [{p} + 32], ymm0",
                "sfence",
                "clflush [{p}]",
                "mfence",
                p = in(reg) dst,
                out("ymm0") _,
                options(nostack)
            );
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            core::ptr::write_bytes(dst, 0, 64);
        }
    }}
}

#[inline(always)]
pub unsafe fn stream_write_ddr_u64(dst: *mut u64, val: u64) { unsafe {
    #[cfg(target_arch = "x86_64")]
    {
        asm!("movnti [{d}], {v}", "sfence", d = in(reg) dst, v = in(reg) val, options(nostack));
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
core::ptr::write_volatile(dst, val);
}
}}
#[inline(always)]
pub unsafe fn sterile_read_and_evict_64b(src_ddr: *const u64) -> [u64; 8] { unsafe {
#[cfg(target_arch = "x86_64")]
{
asm!("prefetchnta [{p}]", p = in(reg) src_ddr, options(nostack));
let line = core::ptr::read_unaligned(src_ddr as *const [u64; 8]);
asm!("clflushopt [{p}]", p = in(reg) src_ddr, options(nostack));
line
}
#[cfg(not(target_arch = "x86_64"))]
{
core::ptr::read_unaligned(src_ddr as *const [u64; 8])
}
}}
