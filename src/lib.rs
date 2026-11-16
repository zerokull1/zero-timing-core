// ZEROMANI (zerokull1) | 0x5A45524F4D414E49ULL
#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

pub mod tsc;
pub mod l7_shield;
pub mod thin_hypervisor;
pub mod bpf_control;
pub mod af_xdp_engine;
pub mod adaptive_gateway;
pub mod flow_table;
pub mod telemetry_shm;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memcpy(dst: *mut core::ffi::c_void, src: *const core::ffi::c_void, count: usize) -> *mut core::ffi::c_void {
    unsafe {
        core::arch::asm!(
            "rep movsb",
            inout("rdi") dst => _,
            inout("rsi") src => _,
            inout("rcx") count => _,
            options(nostack)
        );
    }
    dst
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memset(dst: *mut core::ffi::c_void, val: i32, count: usize) -> *mut core::ffi::c_void {
    unsafe {
        core::arch::asm!(
            "rep stosb",
            inout("rdi") dst => _,
            in("al") val as u8,
            inout("rcx") count => _,
            options(nostack)
        );
    }
    dst
}
