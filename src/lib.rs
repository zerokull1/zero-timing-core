#![allow(clippy::missing_safety_doc)]
// ZEROMANI (zerokull1) | 0x5A45524F4D414E49ULL
#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

pub extern crate zero_hal;
pub mod tsc;
pub mod l7_shield;
pub mod thin_hypervisor;
pub mod bpf_control;
pub mod af_xdp_engine;
pub mod adaptive_gateway;
pub mod flow_table;
pub mod telemetry_shm;
pub mod topology_placer;
pub mod pulse_barrier;
pub mod work_stealer;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memcpy(dst: *mut core::ffi::c_void, src: *const core::ffi::c_void, count: usize) -> *mut core::ffi::c_void {
    unsafe {
        #[cfg(target_arch = "x86_64")]
        core::arch::asm!(
            "cld",
            "rep movsb",
            inout("rdi") dst => _,
            inout("rsi") src => _,
            inout("rcx") count => _,
            options(nostack)
        );
        #[cfg(not(target_arch = "x86_64"))]
        {
            let (d, s) = (dst as *mut u8, src as *const u8);
            let mut i = 0usize;
            while i < count {
                *d.add(i) = *s.add(i);
                i += 1;
            }
        }
    }
    dst
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memset(dst: *mut core::ffi::c_void, val: i32, count: usize) -> *mut core::ffi::c_void {
    unsafe {
        #[cfg(target_arch = "x86_64")]
        core::arch::asm!(
            "cld",
            "rep stosb",
            inout("rdi") dst => _,
            in("al") val as u8,
            inout("rcx") count => _,
            options(nostack)
        );
        #[cfg(not(target_arch = "x86_64"))]
        {
            let d = dst as *mut u8;
            let mut i = 0usize;
            while i < count {
                *d.add(i) = val as u8;
                i += 1;
            }
        }
    }
    dst
}
