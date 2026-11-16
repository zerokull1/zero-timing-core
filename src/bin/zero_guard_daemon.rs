// ZEROMANI (zerokull1) | 0x5A45524F4D414E49ULL
// Copyright (c) 2026 zerokull1 (https://github.com)
// Licensed under GPL-3.0. Unauthorized proprietary use is strictly prohibited.

#![no_std]
#![no_main]

use core::arch::{asm, naked_asm};
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, Ordering};

static RUNNING: AtomicBool = AtomicBool::new(true);

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

extern "C" fn handle_sig(_sig: i32) {
    RUNNING.store(false, Ordering::SeqCst);
}

#[repr(C)]
struct SigAction {
    sa_handler: extern "C" fn(i32),
    sa_flags: usize,
    sa_restorer: unsafe extern "C" fn(),
    sa_mask: [u64; 16],
}

#[unsafe(naked)]
unsafe extern "C" fn sig_restorer() {
    naked_asm!("mov rax, 15", "syscall"); // SYS_RT_SIGRETURN
}

unsafe fn sys_write(fd: usize, buf: *const u8, len: usize) {
    unsafe {
        asm!("syscall", in("rax") 1usize, in("rdi") fd, in("rsi") buf, in("rdx") len, lateout("rax") _, out("rcx") _, out("r11") _, options(nostack));
    }
}

unsafe fn sys_exit(code: usize) -> ! {
    unsafe {
        asm!("syscall", in("rax") 60usize, in("rdi") code, options(noreturn));
    }
}

unsafe fn read_ifindex_from_sysfs(path_cstr: &[u8]) -> Option<u32> {
    let fd: isize;
    unsafe {
        asm!("syscall", in("rax") 2usize, in("rdi") path_cstr.as_ptr(), in("rsi") 0usize, in("rdx") 0usize, lateout("rax") fd, out("rcx") _, out("r11") _, options(nostack));
    }
    if fd < 0 {
        return None;
    }
    let mut buf = [0u8; 16];
    let n: isize;
    unsafe {
        asm!("syscall", in("rax") 0usize, in("rdi") fd, in("rsi") buf.as_mut_ptr(), in("rdx") buf.len(), lateout("rax") n, out("rcx") _, out("r11") _, options(nostack));
        asm!("syscall", in("rax") 3usize, in("rdi") fd, lateout("rax") _, out("rcx") _, out("r11") _, options(nostack));
    }
    if n <= 0 {
        return None;
    }
    let mut val: u32 = 0;
    for &b in &buf[..(n as usize)] {
        if b >= b'0' && b <= b'9' {
            val = val * 10 + (b - b'0') as u32;
        }
    }
    if val > 0 { Some(val) } else { None }
}

#[no_mangle]
pub extern "C" fn daemon_main() -> ! {
    let sa = SigAction {
        sa_handler: handle_sig,
        sa_flags: 0x04000000, // SA_RESTORER
        sa_restorer: sig_restorer,
        sa_mask: [0; 16],
    };
    unsafe {
        asm!("syscall", in("rax") 13usize, in("rdi") 2usize, in("rsi") &sa, in("rdx") 0usize, in("r10") 8usize, lateout("rax") _, out("rcx") _, out("r11") _, options(nostack)); // SIGINT
        asm!("syscall", in("rax") 13usize, in("rdi") 15usize, in("rsi") &sa, in("rdx") 0usize, in("r10") 8usize, lateout("rax") _, out("rcx") _, out("r11") _, options(nostack)); // SIGTERM
    }

    let ifindex = match unsafe { read_ifindex_from_sysfs(b"/sys/class/net/enp0s20u11/ifindex\0") } {
        Some(idx) => idx,
        None => {
            let msg = b"[ERR] Interface enp0s20u11 not found\n";
            unsafe { sys_write(2, msg.as_ptr(), msg.len()); sys_exit(1); }
        }
    };

    let pipe = match unsafe { zero_core_lib::bpf_control::build_and_load_xdp_pipeline(None) } {
        Ok(p) => p,
        Err(_) => {
            let msg = b"[ERR] Failed to load eBPF XDP into kernel\n";
            unsafe { sys_write(2, msg.as_ptr(), msg.len()); sys_exit(1); }
        }
    };

    let cfg = zero_core_lib::bpf_control::ShieldConfig {
        mode: zero_core_lib::bpf_control::ShieldMode::Monitor as u32,
        block_ttl_65: 1,
        block_ttl_129: 1,
    };
    let _ = unsafe { zero_core_lib::bpf_control::set_shield_mode(pipe.config_map_fd as u32, &cfg) };

    let flags = zero_core_lib::bpf_control::XDP_FLAGS_SKB_MODE;
    if unsafe { zero_core_lib::bpf_control::attach_xdp_to_ifindex(ifindex as i32, pipe.prog_fd, flags) } < 0 {
        let msg = b"[ERR] Failed to attach XDP to enp0s20u11\n";
        unsafe { sys_write(2, msg.as_ptr(), msg.len()); sys_exit(1); }
    }

    let up_msg = b"[ACTIVE] zero_guard_daemon attached to enp0s20u11 (Monitor/Fail-Safe Mode). Press Ctrl+C to detach cleanly.\n";
    unsafe { sys_write(1, up_msg.as_ptr(), up_msg.len()); }

    while RUNNING.load(Ordering::SeqCst) {
        #[repr(C)]
        struct Timespec { tv_sec: i64, tv_nsec: i64 }
        let ts = Timespec { tv_sec: 0, tv_nsec: 100_000_000 }; // 100 ms
        unsafe {
            asm!("syscall", in("rax") 35usize, in("rdi") &ts, in("rsi") 0usize, lateout("rax") _, out("rcx") _, out("r11") _, options(nostack)); // SYS_NANOSLEEP
        }
    }

    unsafe {
        let _ = zero_core_lib::bpf_control::detach_xdp_from_ifindex(ifindex as i32, flags);
        let bye = b"[CLEAN] XDP filter safely detached from enp0s20u11.\n";
        sys_write(1, bye.as_ptr(), bye.len());
        sys_exit(0);
    }
}

#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "C" fn _start() -> ! {
    naked_asm!("and rsp, -16", "call daemon_main");
}
