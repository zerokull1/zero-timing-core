// ZEROMANI (zerokull1) | 0x5A45524F4D414E49ULL
#![allow(dead_code)]
use core::arch::asm;
use core::sync::atomic::AtomicU64;
use zero_hal::arch::sysno::{SYS_CLOSE, SYS_MMAP, SYS_MUNMAP};
#[cfg(target_arch = "x86_64")] const SYS_READ: usize = 0;
#[cfg(target_arch = "x86_64")] const SYS_OPENAT: usize = 257;
#[cfg(not(target_arch = "x86_64"))] const SYS_READ: usize = 63;
#[cfg(not(target_arch = "x86_64"))] const SYS_OPENAT: usize = 56;
const SYS_SCHED_SETAFFINITY: usize = 203;
const SYS_SCHED_GETAFFINITY: usize = 204;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CoreEntry { pub cpu_id: u32, pub numa_node: u32 }

#[repr(C)]
#[derive(Clone, Copy)]
pub struct HardwareProfile { pub total_cores: usize, pub numa_nodes: usize, pub worker_cores: usize, pub hot_core_id: usize, pub cache_line: usize, pub has_128b_lock: bool, pub has_avx2: bool }

#[repr(C, align(64))]
pub struct ImpulseSlot { pub pulse_seq: AtomicU64, pub payload_hash: AtomicU64, pub worker_cpu_id: u32, pub numa_node: u32, pub target_hot_idx: u32, pub ttl_phase: u32, pub _pad: [u64; 3] }

pub unsafe fn sys_mmap_anon(bytes: usize) -> *mut u8 {
    let ret: isize;
    unsafe { asm!("syscall", inlateout("rax") SYS_MMAP as isize => ret, in("rdi") 0usize, in("rsi") bytes, in("rdx") 3usize, in("r10") 0x22usize, in("r8") -1isize, in("r9") 0usize, lateout("rcx") _, lateout("r11") _, options(nostack)); }
    if ret < 0 { core::ptr::null_mut() } else { ret as *mut u8 }
}
pub unsafe fn sys_munmap_anon(ptr: *mut u8, bytes: usize) {
    if ptr.is_null() { return; }
    unsafe { asm!("syscall", inlateout("rax") SYS_MUNMAP as isize => _, in("rdi") ptr as usize, in("rsi") bytes, lateout("rcx") _, lateout("r11") _, options(nostack)); }
}
unsafe fn read_cpu_numa_node(cpu: u32) -> u32 {
    let mut p = [0u8; 64];
    let pfx = b"/sys/devices/system/cpu/cpu";
    p[..pfx.len()].copy_from_slice(pfx);
    let mut pos = pfx.len();
    let mut d = [0u8; 12]; let mut k = 0; let mut v = cpu;
    if v == 0 { unsafe { *d.as_mut_ptr() = b'0'; } k = 1; }
    while v > 0 { unsafe { *d.as_mut_ptr().add(k) = b'0' + (v % 10) as u8; } v /= 10; k += 1; }
    while k > 0 { k -= 1; unsafe { *p.as_mut_ptr().add(pos) = *d.as_ptr().add(k); } pos += 1; }
    let sfx = b"/topology/physical_package_id\0";
    p[pos..pos + sfx.len()].copy_from_slice(sfx);
    let fd: isize;
    unsafe {
        asm!("syscall", inlateout("rax") SYS_OPENAT as isize => fd, in("rdi") -100isize, in("rsi") p.as_ptr(), in("rdx") 0usize, in("r10") 0usize, lateout("rcx") _, lateout("r11") _, options(nostack));
    }
    if fd < 0 { return 0; }
    let mut buf = [0u8; 16]; let n: isize;
    unsafe {
        asm!("syscall", inlateout("rax") SYS_READ as isize => n, in("rdi") fd as usize, in("rsi") buf.as_mut_ptr(), in("rdx") 15usize, lateout("rcx") _, lateout("r11") _, options(nostack));
        asm!("syscall", inlateout("rax") SYS_CLOSE as isize => _, in("rdi") fd as usize, lateout("rcx") _, lateout("r11") _, options(nostack));
    }
    let mut res = 0u32;
    let mut i = 0isize;
    while i < n {
        let c = unsafe { *buf.as_ptr().add(i as usize) };
        if c >= b'0' && c <= b'9' { res = res * 10 + (c - b'0') as u32; } else { break; }
        i += 1;
    }
    res
}

pub unsafe fn discover_hardware_and_place(out_entries: *mut *mut CoreEntry) -> HardwareProfile {
    let cl_def = if cfg!(target_arch = "s390x") { 256 } else { 64 };
    let mut prof = HardwareProfile { total_cores: 1, numa_nodes: 1, worker_cores: 1, hot_core_id: 0, cache_line: cl_def, has_128b_lock: true, has_avx2: false };
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let mut ebx1: u32; let mut ecx1: u32; let mut ebx7: u32;
        asm!("push rbx", "mov eax, 1", "cpuid", "mov {b:e}, ebx", "pop rbx", out("eax") _, b = out(reg) ebx1, out("ecx") ecx1, out("edx") _, options(nomem, nostack));
        asm!("push rbx", "mov eax, 7", "xor ecx, ecx", "cpuid", "mov {b:e}, ebx", "pop rbx", out("eax") _, b = out(reg) ebx7, out("ecx") _, out("edx") _, options(nomem, nostack));
        let cl = ((ebx1 >> 8) & 0xFF) as usize * 8;
        if cl >= 32 { prof.cache_line = cl; }
        prof.has_128b_lock = (ecx1 & (1 << 13)) != 0;
        prof.has_avx2 = (ebx7 & (1 << 5)) != 0;
    }
    let mut mask_bytes: usize = 128;
    loop {
        let mask = unsafe { sys_mmap_anon(mask_bytes) };
        if mask.is_null() { return prof; }
        let ret: isize;
        unsafe { asm!("syscall", inlateout("rax") SYS_SCHED_GETAFFINITY as isize => ret, in("rdi") 0usize, in("rsi") mask_bytes, in("rdx") mask as usize, lateout("rcx") _, lateout("r11") _, options(nostack)); }
        if ret >= 0 {
            let valid = ret as usize;
            let mut cnt = 0usize;
            for b in 0..valid { cnt += unsafe { *mask.add(b) }.count_ones() as usize; }
            if cnt > 0 {
                prof.total_cores = cnt;
                let entries = unsafe { sys_mmap_anon((cnt * core::mem::size_of::<CoreEntry>() + 4095) & !4095) as *mut CoreEntry };
                let mut idx = 0usize; let mut max_numa = 0u32;
                for b in 0..valid {
                    let mut byte = unsafe { *mask.add(b) };
                    while byte != 0 {
                        let cpu = (b * 8 + byte.trailing_zeros() as usize) as u32;
                        let numa = unsafe { read_cpu_numa_node(cpu) };
                        if numa > max_numa { max_numa = numa; }
                        if !entries.is_null() && idx < cnt { unsafe { *entries.add(idx) = CoreEntry { cpu_id: cpu, numa_node: numa }; } }
                        prof.hot_core_id = cpu as usize;
                        idx += 1; byte &= byte - 1;
                    }
                }
                if !out_entries.is_null() { unsafe { *out_entries = entries; } }
                prof.numa_nodes = (max_numa + 1) as usize;
                prof.worker_cores = if cnt > 1 { cnt - 1 } else { 1 };
            }
            unsafe { sys_munmap_anon(mask, mask_bytes); }
            break;
        }
        unsafe { sys_munmap_anon(mask, mask_bytes); }
        mask_bytes *= 2;
        if mask_bytes > 1024 * 1024 { break; }
    }
    prof
}

pub unsafe fn pin_current_thread_to_core(cpu_id: usize) -> bool {
    let mask_bytes = ((cpu_id / 8 + 72) & !63).max(128);
    let mask = unsafe { sys_mmap_anon(mask_bytes) };
    if mask.is_null() { return false; }
    unsafe {
        *mask.add(cpu_id / 8) = 1u8 << (cpu_id % 8);
        let ret: isize;
        asm!("syscall", inlateout("rax") SYS_SCHED_SETAFFINITY as isize => ret, in("rdi") 0usize, in("rsi") mask_bytes, in("rdx") mask as usize, lateout("rcx") _, lateout("r11") _, options(nostack));
        sys_munmap_anon(mask, mask_bytes);
        ret == 0
    }
}
