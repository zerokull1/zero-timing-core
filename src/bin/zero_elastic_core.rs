#![no_std]
#![no_main]
// ZEROMANI (zerokull1) | 0x5A45524F4D414E49ULL
use core::arch::{asm, global_asm};
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use zero_core_lib::pulse_barrier::{seal_and_verify_monolith_wx, SealedHotPerimeter};
use zero_core_lib::topology_placer::{discover_hardware_and_place, pin_current_thread_to_core, sys_mmap_anon, ImpulseSlot};
use zero_core_lib::work_stealer::{pop_or_steal_batch, CoreWorkDeque};

static MONOLITH_20CAPS: &[u8] = include_bytes!("../../build_core_bundle/zeromani_20caps.bin");
static OMNI_MCODE_50B: &[u8] = include_bytes!("../../build_core_bundle/omni_mcode.bin");
static MILLICODE_VM: &[u8] = include_bytes!("../../build_core_bundle/millicode_vm.bin");

static BARRIER_READY: AtomicU32 = AtomicU32::new(0);
static WORKERS_DONE: AtomicU32 = AtomicU32::new(0);
static TOTAL_STOLEN: AtomicU64 = AtomicU64::new(0);
static G_DEQUES: AtomicU64 = AtomicU64::new(0);
static G_NWORKERS: AtomicU64 = AtomicU64::new(0);

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! { loop {} }
#[unsafe(no_mangle)]
pub extern "C" fn rust_eh_personality() {}

global_asm!(
    ".globl _start", "_start:", "and rsp, -16", "call elastic_core_main", "mov rdi, rax", "mov eax, 60", "syscall",
    ".globl spawn_raw_worker", "spawn_raw_worker:", "sub rsi, 16", "mov [rsi], rdx", "mov [rsi + 8], rcx",
    "mov rax, 56", "syscall", "test rax, rax", "jnz 1f", "pop rax", "pop rdi", "call rax", "mov rdi, rax", "mov eax, 60", "syscall", "1: ret"
);
unsafe extern "C" { fn spawn_raw_worker(flags: usize, stack_top: *mut u8, entry: extern "C" fn(*mut ImpulseSlot) -> usize, arg: *mut ImpulseSlot) -> isize; }

extern "C" fn worker_core_entry(slot: *mut ImpulseSlot) -> usize {
    unsafe {
        let s = &mut *slot;
        let my_idx = s.ttl_phase as usize;
        pin_current_thread_to_core(s.worker_cpu_id as usize);
        while BARRIER_READY.load(Ordering::Acquire) == 0 { asm!("pause", options(nomem, nostack)); }
        let deques = G_DEQUES.load(Ordering::Acquire) as *mut CoreWorkDeque;
        let nw = G_NWORKERS.load(Ordering::Acquire) as usize;
        let mut local_seq = 0u64;
        while let Some((b_start, b_end)) = pop_or_steal_batch(deques, nw, my_idx, 256) {
            for id in b_start..b_end {
                if my_idx == 0 { for _ in 0..80 { asm!("pause", options(nomem, nostack)); } } // Имитация IRQ-перекоса на CPU #0
                local_seq += 1;
                s.ttl_phase = 65;
                s.payload_hash.store(id ^ (s.worker_cpu_id as u64 * 0x5A45524F), Ordering::Relaxed);
                s.pulse_seq.store(local_seq, Ordering::Release);
                while s.pulse_seq.load(Ordering::Acquire) != 0 { asm!("pause", options(nomem, nostack)); }
            }
        }
        TOTAL_STOLEN.fetch_add((*deques.add(my_idx)).stolen_by_me, Ordering::Relaxed);
        WORKERS_DONE.fetch_add(1, Ordering::Release);
    }
    0
}

#[target_feature(enable = "avx2,sse4.2")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn elastic_core_main() -> usize {
    unsafe {
        let mut cpu_ids: *mut u32 = core::ptr::null_mut();
        let hw = discover_hardware_and_place(&mut cpu_ids);
        pin_current_thread_to_core(hw.hot_core_id);
        let wx = seal_and_verify_monolith_wx(MONOLITH_20CAPS, MILLICODE_VM, OMNI_MCODE_50B);
        let perim = match SealedHotPerimeter::arm() { Some(p) if !wx.is_null() => p, _ => return 98 };
        let key: [u64; 4] = [0x5A45524F4D414E49, 0x1122334455667788, 0xCAFEBABEDEADBEEF, 0x0F1E2D3C4B5A6978];
        core::ptr::copy_nonoverlapping(key.as_ptr() as *const u8, perim.hot_page, 32);
        asm!("vmovdqu ymm15, [{p}]", "vpxor ymm0, ymm0, ymm0", "vmovntdq [{p}], ymm0", "sfence", "clflush [{p}]", "mfence", p = in(reg) perim.hot_page, out("ymm0") _, out("ymm15") _, options(nostack));

        let nw = hw.worker_cores;
        let slots = sys_mmap_anon((nw * core::mem::size_of::<ImpulseSlot>() + 4095) & !4095) as *mut ImpulseSlot;
        let deques = sys_mmap_anon((nw * core::mem::size_of::<CoreWorkDeque>() + 4095) & !4095) as *mut CoreWorkDeque;
        G_DEQUES.store(deques as u64, Ordering::Release); G_NWORKERS.store(nw as u64, Ordering::Release);

        let mut w_idx = 0usize;
        for i in 0..hw.total_cores {
            let cid = *cpu_ids.add(i) as usize;
            if (hw.total_cores > 1 && cid == hw.hot_core_id) || w_idx >= nw { continue; }
            let sl = slots.add(w_idx); (*sl).worker_cpu_id = cid as u32; (*sl).ttl_phase = w_idx as u32;
            (*deques.add(w_idx)).init(cid as u32, 0, (w_idx as u64) * 200_000, ((w_idx + 1) as u64) * 200_000);
            spawn_raw_worker(0x00010F00, sys_mmap_anon(16384).add(16384), worker_core_entry, sl);
            w_idx += 1;
        }
        let t0: u64; { let lo: u32; let hi: u32; asm!("lfence", "rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack)); t0 = ((hi as u64) << 32) | (lo as u64); }
        BARRIER_READY.store(1, Ordering::Release);
        let mut seen = [0u64; 1024]; let mut total = 0u64;
        while WORKERS_DONE.load(Ordering::Acquire) < nw as u32 {
            for w in 0..nw {
                let sl = &mut *slots.add(w);
                if sl.pulse_seq.load(Ordering::Acquire) != 0 {
                    let exp = seen[w & 1023] + 1;
                    if perim.verify_impulse_and_mirage(sl, exp, (exp & 0xFF) == 0) == 0xFF { perim.disarm_and_wipe(); return 99; }
                    seen[w & 1023] = exp; total += 1; sl.pulse_seq.store(0, Ordering::Release);
                }
            }
        }
        let t1: u64; { let lo: u32; let hi: u32; asm!("rdtscp", "lfence", out("eax") lo, out("edx") hi, out("ecx") _, options(nomem, nostack)); t1 = ((hi as u64) << 32) | (lo as u64); }
        perim.disarm_and_wipe();
        fn put_u64(b: &mut [u8], p: &mut usize, mut v: u64) { let mut d = [0u8; 20]; let mut k = 0; if v == 0 { unsafe { *d.as_mut_ptr() = b'0'; } k = 1; } while v > 0 { d[k] = b'0' + (v % 10) as u8; v /= 10; k += 1; } while k > 0 { k -= 1; b[*p] = d[k]; *p += 1; } }
        fn put_s(b: &mut [u8], p: &mut usize, s: &[u8]) { b[*p..*p+s.len()].copy_from_slice(s); *p += s.len(); }
        let mut buf = [0u8; 128]; let mut pos = 0;
        put_s(&mut buf, &mut pos, b"[WORK-STEALING] PULSES="); put_u64(&mut buf, &mut pos, total);
        put_s(&mut buf, &mut pos, b" | STOLEN_FROM_BUSY_CPU="); put_u64(&mut buf, &mut pos, TOTAL_STOLEN.load(Ordering::Relaxed));
        put_s(&mut buf, &mut pos, b" | CYCLES/PULSE="); put_u64(&mut buf, &mut pos, t1.saturating_sub(t0) / total.max(1));
        put_s(&mut buf, &mut pos, b"\n");
        asm!("syscall", in("rax") 1usize, in("rdi") 1usize, in("rsi") buf.as_ptr(), in("rdx") pos, lateout("rcx") _, lateout("r11") _, options(nostack));
    }
    0
}
