// ZEROMANI (zerokull1) | 0x5A45524F4D414E49ULL
// Minimal no_std / no_main Live Telemetry Reader (/proc/zero_timing_ring0 & /dev/shm/zero_telemetry)

#![no_std]
#![no_main]

use core::arch::{asm, naked_asm};
use core::panic::PanicInfo;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop { core::hint::spin_loop(); }
}

unsafe fn sys_write(fd: usize, buf: *const u8, len: usize) {
    unsafe {
        asm!("syscall", in("rax") 1usize, in("rdi") fd, in("rsi") buf, in("rdx") len, lateout("rax") _, out("rcx") _, out("r11") _, options(nostack));
    }
}

unsafe fn sys_exit(code: usize) -> ! {
    unsafe { asm!("syscall", in("rax") 60usize, in("rdi") code, options(noreturn)); }
}

unsafe fn print_file(path_cstr: &[u8]) -> bool {
    let fd: isize;
    unsafe {
        asm!("syscall", in("rax") 2usize, in("rdi") path_cstr.as_ptr(), in("rsi") 0usize, in("rdx") 0usize, lateout("rax") fd, out("rcx") _, out("r11") _, options(nostack));
    }
    if fd < 0 { return false; }
    let mut buf = [0u8; 512];
    let n: isize;
    unsafe {
        asm!("syscall", in("rax") 0usize, in("rdi") fd, in("rsi") buf.as_mut_ptr(), in("rdx") buf.len(), lateout("rax") n, out("rcx") _, out("r11") _, options(nostack));
        asm!("syscall", in("rax") 3usize, in("rdi") fd, lateout("rax") _, out("rcx") _, out("r11") _, options(nostack));
    }
    if n > 0 {
        unsafe { sys_write(1, buf.as_ptr(), n as usize); }
        true
    } else {
        false
    }
}

fn push_str(b: &mut [u8], p: &mut usize, s: &[u8]) {
    for &c in s { b[*p] = c; *p += 1; }
}

fn push_u64(b: &mut [u8], p: &mut usize, mut n: u64) {
    let mut d = [0u8; 20];
    let mut l = 0;
    if n == 0 { d.fill(b'0'); l = 1; }
    else { while n > 0 { d[l] = b'0' + (n % 10) as u8; n /= 10; l += 1; } }
    for i in (0..l).rev() { b[*p] = d[i]; *p += 1; }
}

#[no_mangle]
pub extern "C" fn top_main() -> ! {
    let hdr = b"=== ZEROMANI LIVE TELEMETRY (ZERO_TOP) ===\n";
    unsafe { sys_write(1, hdr.as_ptr(), hdr.len()); }

    if !unsafe { print_file(b"/proc/zero_timing_ring0\0") } {
        let off = b"[RING-0] /proc/zero_timing_ring0 not loaded (run: sudo modprobe zero_timing_ring0)\n";
        unsafe { sys_write(1, off.as_ptr(), off.len()); }
    }

    if let Some(shm) = unsafe { zero_core_lib::telemetry_shm::map_telemetry_shm() } {
        use core::sync::atomic::Ordering;
        if shm.magic.load(Ordering::Acquire) == zero_core_lib::telemetry_shm::TELEMETRY_MAGIC {
            let mut line = [b' '; 180];
            let mut pos = 0;
            push_str(&mut line, &mut pos, b"[AF_XDP SHM] RX=");
            push_u64(&mut line, &mut pos, shm.rx_packets.load(Ordering::Relaxed));
            push_str(&mut line, &mut pos, b" | ALLOWED=");
            push_u64(&mut line, &mut pos, shm.allowed_packets.load(Ordering::Relaxed));
            push_str(&mut line, &mut pos, b" | SMUGGLING=");
            push_u64(&mut line, &mut pos, shm.blocked_smuggling.load(Ordering::Relaxed));
            push_str(&mut line, &mut pos, b" | TLS_SPLIT=");
            push_u64(&mut line, &mut pos, shm.blocked_tls_split.load(Ordering::Relaxed));
            push_str(&mut line, &mut pos, b" | BOT_WL=");
            push_u64(&mut line, &mut pos, shm.bot_whitelisted.load(Ordering::Relaxed));
            push_str(&mut line, &mut pos, b" | BOT_BAN=");
            push_u64(&mut line, &mut pos, shm.bot_banned.load(Ordering::Relaxed));
            push_str(&mut line, &mut pos, b" | cycles/pkt=");
            push_u64(&mut line, &mut pos, shm.cycles_per_pkt.load(Ordering::Relaxed));
            push_str(&mut line, &mut pos, b"\n");
            unsafe { sys_write(1, line.as_ptr(), pos); }
        }
    }

    unsafe { sys_exit(0); }
}

#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "C" fn _start() -> ! {
    naked_asm!("and rsp, -16", "call top_main");
}
