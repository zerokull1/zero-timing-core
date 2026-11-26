// ZEROMANI (zerokull1) | Author Signature: 0x5A45524F4B554C4CULL
#![allow(dead_code)]
use core::ptr::{read_volatile, write_volatile};

#[repr(u32)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AccelPath {
    CpuSwar = 0,
    GenericGpu = 1,
    DirectRing = 2,
}

#[repr(C)]
pub struct UniversalGpuRing {
    pub path: AccelPath,
    pub ndesc: u32,
    pub cur_put: u32,
    pub ring_mask: u32,
    pub ring_ptr: *mut u64,
    pub get_ptr: *const u32,
    pub put_ptr: *mut u32,
    pub desc: [u64; 64],
}

impl UniversalGpuRing {
    pub const fn new_cpu_fallback() -> Self {
        Self {
            path: AccelPath::CpuSwar,
            ndesc: 0, cur_put: 0, ring_mask: 0,
            ring_ptr: core::ptr::null_mut(),
            get_ptr: core::ptr::null(),
            put_ptr: core::ptr::null_mut(),
            desc: [0; 64],
        }
    }

    #[inline(always)]
    pub unsafe fn dispatch_pipelined(&mut self, win_slots: u32) -> i32 {
        if self.path == AccelPath::DirectRing
            && !self.ring_ptr.is_null()
            && !self.put_ptr.is_null()
            && !self.get_ptr.is_null()
            && self.ndesc > 0
        {
            let mut put = self.cur_put;
            let mask = self.ring_mask;
            let limit = (if win_slots > 0 { win_slots } else { 4 }) * self.ndesc;
            let mut spin = 0u64;
            while ((unsafe { read_volatile(self.get_ptr) }.wrapping_sub(0)) ^ 0) != u32::MAX
                && (put.wrapping_sub(unsafe { read_volatile(self.get_ptr) }) & mask) >= limit
                && spin < 50_000_000
            {
                #[cfg(target_arch = "x86_64")]
                unsafe { core::arch::asm!("pause", options(nostack, nomem)); }
                spin += 1;
            }
            let mut d = 0u32;
            while d < self.ndesc {
                unsafe {
                    write_volatile(self.ring_ptr.add(((put + d) & mask) as usize), self.desc[d as usize]);
                }
                d += 1;
            }
            put = (put + self.ndesc) & mask;
            self.cur_put = put;
            #[cfg(target_arch = "x86_64")]
            unsafe { core::arch::asm!("sfence", options(nostack, nomem)); }
            unsafe { write_volatile(self.put_ptr, put); }
            return 0;
        }
        0
    }

    #[inline(always)]
    pub unsafe fn sync_drain(&self) -> i32 {
        if self.path == AccelPath::DirectRing && !self.get_ptr.is_null() {
            #[cfg(target_arch = "x86_64")]
            unsafe { core::arch::asm!("sfence", options(nostack, nomem)); }
            let mut spin = 0u64;
            while unsafe { read_volatile(self.get_ptr) } != self.cur_put && spin < 50_000_000 {
                #[cfg(target_arch = "x86_64")]
                unsafe { core::arch::asm!("pause", options(nostack, nomem)); }
                spin += 1;
            }
            return if unsafe { read_volatile(self.get_ptr) } == self.cur_put { 0 } else { -2 };
        }
        0
    }

    #[inline(always)]
    pub unsafe fn dispatch(&mut self) -> i32 {
        let rc = unsafe { self.dispatch_pipelined(1) };
        if rc == 0 { unsafe { self.sync_drain() } } else { rc }
    }
}
