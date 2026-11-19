// ZEROMANI (zerokull1) | 0x5A45524F4D414E49ULL
#![allow(dead_code)]
use core::arch::asm;
use core::sync::atomic::AtomicU64;

const SYS_MMAP: usize = 9;
const SYS_MUNMAP: usize = 11;
const SYS_SCHED_SETAFFINITY: usize = 203;
const SYS_SCHED_GETAFFINITY: usize = 204;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct HardwareProfile {
    pub total_cores: usize,
    pub worker_cores: usize,
    pub hot_core_id: usize,
    pub cache_line: usize,
    pub has_128b_lock: bool,
    pub has_avx2: bool,
}

#[repr(C, align(64))]
pub struct ImpulseSlot {
    pub pulse_seq: AtomicU64,
    pub payload_hash: AtomicU64,
    pub worker_cpu_id: u32,
    pub ttl_phase: u32,
    pub _pad: [u64; 5],
}

pub unsafe fn sys_mmap_anon(bytes: usize) -> *mut u8 {
    let ret: isize;
    unsafe {
        asm!("syscall", inlateout("rax") SYS_MMAP as isize => ret,
             in("rdi") 0usize, in("rsi") bytes, in("rdx") 3usize,
             in("r10") 0x22usize, in("r8") -1isize, in("r9") 0usize,
             lateout("rcx") _, lateout("r11") _, options(nostack));
    }
    if ret < 0 { core::ptr::null_mut() } else { ret as *mut u8 }
}

pub unsafe fn sys_munmap_anon(ptr: *mut u8, bytes: usize) {
    if ptr.is_null() { return; }
    unsafe {
        asm!("syscall", inlateout("rax") SYS_MUNMAP as isize => _,
             in("rdi") ptr as usize, in("rsi") bytes,
             lateout("rcx") _, lateout("r11") _, options(nostack));
    }
}

pub unsafe fn discover_hardware_and_place(out_cpu_ids: *mut *mut u32) -> HardwareProfile {
    let mut prof = HardwareProfile { total_cores: 1, worker_cores: 1, hot_core_id: 0, cache_line: 64, has_128b_lock: false, has_avx2: false };
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
        unsafe {
            asm!("syscall", inlateout("rax") SYS_SCHED_GETAFFINITY as isize => ret,
                 in("rdi") 0usize, in("rsi") mask_bytes, in("rdx") mask as usize,
                 lateout("rcx") _, lateout("r11") _, options(nostack));
        }
        if ret >= 0 {
            let valid = ret as usize;
            let mut cnt = 0usize;
            for b in 0..valid { cnt += unsafe { *mask.add(b) }.count_ones() as usize; }
            if cnt > 0 {
                prof.total_cores = cnt;
                let ids = unsafe { sys_mmap_anon((cnt * 4 + 4095) & !4095) as *mut u32 };
                let mut idx = 0usize;
                for b in 0..valid {
                    let mut byte = unsafe { *mask.add(b) };
                    while byte != 0 {
                        let cpu = (b * 8 + byte.trailing_zeros() as usize) as u32;
                        if !ids.is_null() && idx < cnt { unsafe { *ids.add(idx) = cpu; } }
                        prof.hot_core_id = cpu as usize;
                        idx += 1; byte &= byte - 1;
                    }
                }
                if !out_cpu_ids.is_null() { unsafe { *out_cpu_ids = ids; } }
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
        asm!("syscall", inlateout("rax") SYS_SCHED_SETAFFINITY as isize => ret,
             in("rdi") 0usize, in("rsi") mask_bytes, in("rdx") mask as usize,
             lateout("rcx") _, lateout("r11") _, options(nostack));
        sys_munmap_anon(mask, mask_bytes);
        ret == 0
    }
}
