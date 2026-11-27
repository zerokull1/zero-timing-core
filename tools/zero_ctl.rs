// ZEROMANI (zerokull1) | 0x5A45524F4D414E49ULL
// Copyright (c) 2026 zerokull1 (https://github.com)
// Licensed under GPL-3.0. Unauthorized proprietary use is strictly prohibited.

#![no_std]
#![no_main]
#![deny(unsafe_op_in_unsafe_fn)]

use core::arch::asm;
use core::mem::{size_of, MaybeUninit};
use core::panic::PanicInfo;
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{compiler_fence, Ordering};

/* [МЕТКА 1: Номера системных вызовов ядра Linux x86_64 и команд eBPF] */
const SYS_WRITE: usize = 1;
const SYS_MMAP: usize = 9;
const SYS_EXIT: usize = 60;
const SYS_EPOLL_WAIT: usize = 232;
const SYS_EPOLL_CTL: usize = 233;
const SYS_EPOLL_CREATE1: usize = 291;
const SYS_BPF: usize = 321;

const BPF_MAP_LOOKUP_ELEM: usize = 1;
const BPF_MAP_UPDATE_ELEM: usize = 2;
const BPF_MAP_DELETE_ELEM: usize = 3;
const BPF_OBJ_GET: usize = 7;

/* [МЕТКА 2: Пути к закреплённым (pinned) в /sys/fs/bpf/ картам XDP-щита] */
const PATH_WHITELIST: &[u8] = b"/sys/fs/bpf/zero_shield/whitelist_v4\0";
const PATH_BLACKLIST: &[u8] = b"/sys/fs/bpf/zero_shield/blacklist_v4\0";
const PATH_CONFIG: &[u8] = b"/sys/fs/bpf/zero_shield/config_map\0";
const PATH_STATS: &[u8] = b"/sys/fs/bpf/zero_shield/stats_map\0";
const PATH_RING: &[u8] = b"/sys/fs/bpf/zero_shield/events_ring\0";
const RING_SIZE: usize = 4096 * 16;

#[repr(C)]
struct BpfMapElemAttr { map_fd: u32, _pad: u32, key: u64, value: u64, flags: u64 }

#[repr(C)]
struct BpfObjAttr { pathname: u64, bpf_fd: u32, file_flags: u32 }

#[repr(C)]
#[derive(Copy, Clone)]
struct ShieldConfig { mode: u32, block_ttl_65: u32, block_ttl_129: u32, pps_limit: u32 }

#[repr(C)]
#[derive(Copy, Clone)]
struct DataRec { rx_packets: u64, dropped_packets: u64, whitelisted_packets: u64 }

#[repr(C)]
#[derive(Copy, Clone)]
struct AlertEvent { timestamp_ns: u64, src_ip: u32, reason: u32 }

#[repr(C, packed)]
#[derive(Copy, Clone)]
struct EpollEvent { events: u32, data: u64 }

#[no_mangle]
pub unsafe extern "C" fn memset(s: *mut core::ffi::c_void, c: i32, n: usize) -> *mut core::ffi::c_void {
    let mut i = 0;
    unsafe { while i < n { write_volatile((s as *mut u8).add(i), c as u8); i += 1; } }
    s
}

#[no_mangle]
pub unsafe extern "C" fn strlen(s: *const i8) -> usize {
    let mut len = 0;
    unsafe { while read_volatile((s as *const u8).add(len)) != 0 { len += 1; } }
    len
}

#[inline(always)]
unsafe fn syscall3(num: usize, a1: usize, a2: usize, a3: usize) -> isize {
    let ret: isize;
    compiler_fence(Ordering::SeqCst);
    unsafe {
        asm!("syscall", in("rax") num, in("rdi") a1, in("rsi") a2, in("rdx") a3,
             lateout("rax") ret, lateout("rcx") _, lateout("r11") _, options(nostack));
    }
    ret
}

#[inline(always)]
unsafe fn syscall4(num: usize, a1: usize, a2: usize, a3: usize, a4: usize) -> isize {
    let ret: isize;
    compiler_fence(Ordering::SeqCst);
    unsafe {
        asm!("syscall", in("rax") num, in("rdi") a1, in("rsi") a2, in("rdx") a3, in("r10") a4,
             lateout("rax") ret, lateout("rcx") _, lateout("r11") _, options(nostack));
    }
    ret
}

#[inline(always)]
unsafe fn sys_mmap(len: usize, prot: usize, flags: usize, fd: usize, off: usize) -> isize {
    let ret: isize;
    unsafe {
        asm!("syscall", in("rax") SYS_MMAP, in("rdi") 0usize, in("rsi") len, in("rdx") prot,
             in("r10") flags, in("r8") fd, in("r9") off,
             lateout("rax") ret, lateout("rcx") _, lateout("r11") _, options(nostack));
    }
    ret
}

#[inline(always)]
unsafe fn sys_write(fd: usize, buf: &[u8]) {
    unsafe { let _ = syscall3(SYS_WRITE, fd, buf.as_ptr() as usize, buf.len()); }
}

#[inline(always)]
unsafe fn sys_exit(code: usize) -> ! {
    unsafe { asm!("syscall", in("rax") SYS_EXIT, in("rdi") code, options(noreturn)); }
}

/* [МЕТКА 3: Безопасное получение дескриптора BPF-карты через write_volatile (защита от DSE)] */
unsafe fn bpf_obj_get(path: &[u8]) -> isize {
    let mut attr = MaybeUninit::<BpfObjAttr>::uninit();
    unsafe {
        write_volatile(attr.as_mut_ptr(), BpfObjAttr {
            pathname: path.as_ptr() as u64,
            bpf_fd: 0,
            file_flags: 0,
        });
        syscall3(SYS_BPF, BPF_OBJ_GET, attr.as_ptr() as usize, size_of::<BpfObjAttr>())
    }
}

unsafe fn bpf_elem_op(op: usize, map_fd: u32, key_ptr: u64, val_ptr: u64) -> isize {
    let mut attr = MaybeUninit::<BpfMapElemAttr>::uninit();
    unsafe {
        write_volatile(attr.as_mut_ptr(), BpfMapElemAttr {
            map_fd,
            _pad: 0,
            key: key_ptr,
            value: val_ptr,
            flags: 0,
        });
        syscall3(SYS_BPF, op, attr.as_ptr() as usize, size_of::<BpfMapElemAttr>())
    }
}

unsafe fn cstr_to_slice<'a>(ptr: *const u8) -> &'a [u8] {
    unsafe { core::slice::from_raw_parts(ptr, strlen(ptr as *const i8)) }
}

fn parse_u32(s: &[u8]) -> Option<u32> {
    if s.is_empty() { return None; }
    let mut acc: u64 = 0;
    for &b in s {
        if b < b'0' || b > b'9' { return None; }
        acc = acc * 10 + (b - b'0') as u64;
        if acc > u32::MAX as u64 { return None; }
    }
    Some(acc as u32)
}

fn parse_ipv4_be(s: &[u8]) -> Option<u32> {
    let mut octets = [0u8, 0u8, 0u8, 0u8];
    let mut idx = 0usize;
    let mut acc: u16 = 0;
    let mut has_digit = false;
    for &b in s {
        if b >= b'0' && b <= b'9' {
            acc = acc * 10 + (b - b'0') as u16;
            if acc > 255 { return None; }
            has_digit = true;
        } else if b == b'.' {
            if !has_digit || idx >= 3 { return None; }
            unsafe { *octets.as_mut_ptr().add(idx) = acc as u8; }
            idx += 1;
            acc = 0;
            has_digit = false;
        } else { return None; }
    }
    if !has_digit || idx != 3 { return None; }
    unsafe { *octets.as_mut_ptr().add(3) = acc as u8; }
    Some(u32::from_ne_bytes(octets))
}

unsafe fn write_u64(mut n: u64) {
    let mut buf = MaybeUninit::<[u8; 20]>::zeroed();
    if n == 0 { unsafe { sys_write(1, b"0"); } return; }
    let ptr = buf.as_mut_ptr() as *mut u8;
    let mut i = 20usize;
    while n > 0 {
        i -= 1;
        unsafe { *ptr.add(i) = b'0' + (n % 10) as u8; }
        n /= 10;
    }
    unsafe { sys_write(1, core::slice::from_raw_parts(ptr.add(i), 20 - i)); }
}

unsafe fn write_ipv4_be(ip_be: u32) {
    let b = ip_be.to_ne_bytes();
    let p = b.as_ptr();
    unsafe {
        write_u64(*p as u64); sys_write(1, b".");
        write_u64(*p.add(1) as u64); sys_write(1, b".");
        write_u64(*p.add(2) as u64); sys_write(1, b".");
        write_u64(*p.add(3) as u64);
    }
}

/* [МЕТКА 4: Zero-Syscall чтение кольцевого буфера событий BPF_MAP_TYPE_RINGBUF через epoll_wait] */
unsafe fn run_watch() -> ! {
    unsafe {
        let fd = bpf_obj_get(PATH_RING);
        if fd < 0 { sys_write(2, b"[ERR] Cannot open events_ring\n"); sys_exit(1); }

        let cons_raw = sys_mmap(4096, 3, 1, fd as usize, 0);
        let prod_raw = sys_mmap(4096 + 2 * RING_SIZE, 1, 1, fd as usize, 4096);
        if cons_raw < 0 || prod_raw < 0 {
            sys_write(2, b"[ERR] mmap events_ring failed\n");
            sys_exit(1);
        }
        let cons_ptr = cons_raw as *mut u64;
        let prod_ptr = prod_raw as *const u8;

        let epfd = syscall3(SYS_EPOLL_CREATE1, 0, 0, 0);
        if epfd < 0 { sys_write(2, b"[ERR] epoll_create1 failed\n"); sys_exit(1); }

        let mut ev = MaybeUninit::<EpollEvent>::uninit();
        write_volatile(ev.as_mut_ptr(), EpollEvent { events: 1, data: fd as u64 });
        if syscall4(SYS_EPOLL_CTL, epfd as usize, 1, fd as usize, ev.as_ptr() as usize) < 0 {
            sys_write(2, b"[ERR] epoll_ctl failed\n");
            sys_exit(1);
        }

        sys_write(1, b"[OK] no_std Rust Sentinel sleeping on epoll_wait (0% CPU)...\n");
        let mask = (RING_SIZE - 1) as u64;
        let mut out_ev = MaybeUninit::<EpollEvent>::zeroed();

        loop {
            let _ = syscall4(SYS_EPOLL_WAIT, epfd as usize, out_ev.as_mut_ptr() as usize, 1, usize::MAX);
            let mut cons = read_volatile(cons_ptr);
            let prod = read_volatile(prod_ptr as *const u64);
            while cons < prod {
                let off = 4096 + ((cons & mask) as usize);
                let rec_len = read_volatile(prod_ptr.add(off) as *const u32);
                if (rec_len & (1 << 31)) != 0 { break; }
                let aligned = ((rec_len + 7) & !7) as u64;
                if off + 8 + (aligned as usize) > 4096 + 2 * RING_SIZE { break; }
                if (rec_len & (1 << 30)) == 0 {
                    let alert = read_volatile(prod_ptr.add(off + 8) as *const AlertEvent);
                    sys_write(1, b"[ALERT] SRC="); write_ipv4_be(alert.src_ip);
                    match alert.reason {
                        2 => sys_write(1, b" | RATE_FLOOD\n"),
                        3 => sys_write(1, b" | TCP_SCAN\n"),
                        _ => sys_write(1, b" | TTL_ANOMALY\n"),
                    }
                }
                cons += 8 + aligned;
                write_volatile(cons_ptr, cons);
            }
        }
    }
}

fn print_usage() {
    unsafe {
        sys_write(1, b"Usage:\n  zero-ctl stats\n  zero-ctl watch\n  zero-ctl allow <IPv4>\n  zero-ctl deny <IPv4>\n  zero-ctl ban <IPv4>\n  zero-ctl unban <IPv4>\n  zero-ctl limit <pps>\n  zero-ctl mode <fail-open|monitor|enforce>\n");
    }
}

#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "C" fn _start() -> ! {
    core::arch::naked_asm!("mov rdi, rsp", "and rsp, -16", "jmp {entry}", entry = sym rust_main);
}

/* [МЕТКА 5: Точка входа CLI-диспетчера управления картами XDP без stdlib] */
unsafe extern "C" fn rust_main(stack_ptr: *const usize) -> ! {
    unsafe {
        let argc = *stack_ptr;
        let argv = stack_ptr.add(1) as *const *const u8;
        if argc < 2 { print_usage(); sys_exit(1); }
        let cmd = cstr_to_slice(*argv.add(1));

        if cmd == b"watch" { run_watch(); }
        if cmd == b"stats" {
            let fd = bpf_obj_get(PATH_STATS);
            if fd < 0 { sys_write(2, b"[ERR] Cannot open stats_map\n"); sys_exit(1); }
            let mut key: u32 = 0;
            let mut per_cpu = MaybeUninit::<[DataRec; 128]>::zeroed();
            let ptr = per_cpu.as_mut_ptr() as *mut DataRec;
            let _ = bpf_elem_op(BPF_MAP_LOOKUP_ELEM, fd as u32, &mut key as *mut u32 as u64, ptr as u64);
            let (mut rx, mut drop, mut wl) = (0u64, 0u64, 0u64);
            let mut i = 0usize;
            while i < 128 {
                let rec = *ptr.add(i);
                rx = rx.wrapping_add(rec.rx_packets);
                drop = drop.wrapping_add(rec.dropped_packets);
                wl = wl.wrapping_add(rec.whitelisted_packets);
                i += 1;
            }
            sys_write(1, b"RX        : "); write_u64(rx);
            sys_write(1, b"\nDROP      : "); write_u64(drop);
            sys_write(1, b"\nWHITELIST : "); write_u64(wl);
            sys_write(1, b"\n");
            sys_exit(0);
        }

        if argc < 3 { print_usage(); sys_exit(1); }
        let arg = cstr_to_slice(*argv.add(2));

        if cmd == b"allow" || cmd == b"deny" || cmd == b"ban" || cmd == b"unban" {
            let is_black = cmd == b"ban" || cmd == b"unban";
            let is_add = cmd == b"allow" || cmd == b"ban";
            let ip_be = match parse_ipv4_be(arg) { Some(v) => v, None => { sys_write(2, b"[ERR] Invalid IPv4\n"); sys_exit(1); } };
            let fd = bpf_obj_get(if is_black { PATH_BLACKLIST } else { PATH_WHITELIST });
            if fd < 0 { sys_write(2, b"[ERR] Cannot open BPF map\n"); sys_exit(1); }
            let mut val: u8 = 1;
            let mut k_ip = ip_be;
            let op = if is_add { BPF_MAP_UPDATE_ELEM } else { BPF_MAP_DELETE_ELEM };
            if bpf_elem_op(op, fd as u32, &mut k_ip as *mut u32 as u64, if is_add { &mut val as *mut u8 as u64 } else { 0 }) == 0 {
                sys_write(1, b"[OK] List updated\n"); sys_exit(0);
            }
            sys_write(2, b"[ERR] BPF update failed\n"); sys_exit(1);
        } else if cmd == b"mode" || cmd == b"limit" {
            let fd = bpf_obj_get(PATH_CONFIG);
            if fd < 0 { sys_write(2, b"[ERR] Cannot open config_map\n"); sys_exit(1); }
            let mut key: u32 = 0;
            let mut cfg = ShieldConfig { mode: 2, block_ttl_65: 1, block_ttl_129: 1, pps_limit: 0 };
            let _ = bpf_elem_op(BPF_MAP_LOOKUP_ELEM, fd as u32, &mut key as *mut u32 as u64, &mut cfg as *mut ShieldConfig as u64);
            if cmd == b"mode" {
                cfg.mode = if arg == b"fail-open" { 0 } else if arg == b"monitor" { 1 } else if arg == b"enforce" { 2 } else { print_usage(); sys_exit(1); };
            } else {
                cfg.pps_limit = match parse_u32(arg) { Some(v) => v, None => { sys_write(2, b"[ERR] Invalid PPS\n"); sys_exit(1); } };
            }
            if bpf_elem_op(BPF_MAP_UPDATE_ELEM, fd as u32, &mut key as *mut u32 as u64, &mut cfg as *mut ShieldConfig as u64) == 0 {
                sys_write(1, b"[OK] Config updated\n"); sys_exit(0);
            }
            sys_write(2, b"[ERR] Config update failed\n"); sys_exit(1);
        } else {
            print_usage();
            sys_exit(1);
        }
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! { unsafe { sys_exit(1) } }
