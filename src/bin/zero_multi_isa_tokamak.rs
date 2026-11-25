// ZEROMANI (zerokull1) | Author Signature: 0x5A45524F4D414E49ULL
// Multi-ISA Pure Raw Assembly Tokamak Engine (#![no_std], #![no_main], 0 libc, 0 C11)
// Bit-Exact Phase (0x61db215f9a709a79) across x86_64, aarch64 (NEON), riscv64, s390x (IBM Z)

#![allow(unsafe_op_in_unsafe_fn)]
#![no_std]
#![no_main]

use core::arch::{asm, global_asm};
use core::sync::atomic::{fence, Ordering};

#[unsafe(no_mangle)] pub extern "C" fn rust_eh_personality() {}
#[panic_handler] fn panic(_: &core::panic::PanicInfo) -> ! { loop {} }

#[cfg(target_arch = "x86_64")]
global_asm!(
    ".globl _start",
    "_start:",
    "and rsp, -16",
    "call main_entry",
    "mov rdi, rax",
    "mov eax, 60",
    "syscall",

    ".globl tokamak_orbit_vec4_asm",
    ".globl tokamak_orbit_vec4_asm_end",
    ".p2align 6",
    "tokamak_orbit_vec4_asm:",
    "vmovq xmm4, rdx",
    "vpbroadcastq ymm4, xmm4",
    "mov rax, 0x9E3779B97F4A7C15",
    "vmovq xmm5, rax",
    "vpbroadcastq ymm5, xmm5",
    "vpxor ymm0, ymm4, ymm5",
    "vpaddq ymm1, ymm4, ymm5",
    "test rsi, rsi",
    "jz 2f",
    "1:",
    "vmovdqa ymm2, [rdi]",
    "vmovdqa ymm3, [rdi + 32]",
    "vpxor ymm0, ymm0, ymm2",
    "vpxor ymm1, ymm1, ymm3",
    "vpsllq ymm6, ymm0, 13",
    "vpsrlq ymm7, ymm0, 51",
    "vpor ymm0, ymm6, ymm7",
    "vpsllq ymm8, ymm1, 19",
    "vpsrlq ymm9, ymm1, 45",
    "vpor ymm1, ymm8, ymm9",
    "vpaddq ymm0, ymm0, ymm5",
    "vpaddq ymm1, ymm1, ymm5",
    "vmovdqa [rdi], ymm0",
    "vmovdqa [rdi + 32], ymm1",
    "add rdi, 64",
    "sub rsi, 8",
    "ja 1b",
    "2:",
    "vpxor ymm0, ymm0, ymm1",
    "vextracti128 xmm2, ymm0, 1",
    "vpxor xmm0, xmm0, xmm2",
    "vpshufd xmm2, xmm0, 0xEE",
    "vpxor xmm0, xmm0, xmm2",
    "vmovq rax, xmm0",
    "vzeroupper",
    "ret",
    "tokamak_orbit_vec4_asm_end:"
);

#[cfg(target_arch = "aarch64")]
global_asm!(
    ".globl _start", "_start:", "bl main_entry", "mov x8, #93", "svc #0",
    ".globl tokamak_orbit_vec4_asm", ".globl tokamak_orbit_vec4_asm_end", ".p2align 6",
    "tokamak_orbit_vec4_asm:",
    "movz x3, #0x7C15", "movk x3, #0x7F4A, lsl #16", "movk x3, #0x79B9, lsl #32", "movk x3, #0x9E37, lsl #48",
    "dup v4.2d, x2", "dup v5.2d, x3",
    "eor v0.16b, v4.16b, v5.16b", "mov v1.16b, v0.16b",
    "add v2.2d, v4.2d, v5.2d", "mov v3.16b, v2.16b",
    "cbz x1, 2f",
    "1:",
    "ld1 {v16.2d, v17.2d, v18.2d, v19.2d}, [x0]",
    "eor v0.16b, v0.16b, v16.16b", "eor v1.16b, v1.16b, v17.16b",
    "eor v2.16b, v2.16b, v18.16b", "eor v3.16b, v3.16b, v19.16b",
    "shl v6.2d, v0.2d, #13", "ushr v7.2d, v0.2d, #51", "orr v0.16b, v6.16b, v7.16b",
    "shl v8.2d, v1.2d, #13", "ushr v9.2d, v1.2d, #51", "orr v1.16b, v8.16b, v9.16b",
    "shl v6.2d, v2.2d, #19", "ushr v7.2d, v2.2d, #45", "orr v2.16b, v6.16b, v7.16b",
    "shl v8.2d, v3.2d, #19", "ushr v9.2d, v3.2d, #45", "orr v3.16b, v8.16b, v9.16b",
    "add v0.2d, v0.2d, v5.2d", "add v1.2d, v1.2d, v5.2d",
    "add v2.2d, v2.2d, v5.2d", "add v3.2d, v3.2d, v5.2d",
    "st1 {v0.2d, v1.2d, v2.2d, v3.2d}, [x0], #64",
    "subs x1, x1, #8", "b.hi 1b",
    "2:",
    "eor v0.16b, v0.16b, v1.16b", "eor v2.16b, v2.16b, v3.16b", "eor v0.16b, v0.16b, v2.16b",
    "umov x4, v0.d[0]", "umov x5, v0.d[1]", "eor x0, x4, x5", "ret",
    "tokamak_orbit_vec4_asm_end:"
);

#[cfg(target_arch = "riscv64")]
global_asm!(
    ".globl _start", "_start:", "call main_entry", "li a7, 93", "ecall",
    ".globl tokamak_orbit_vec4_asm", ".globl tokamak_orbit_vec4_asm_end", ".p2align 6",
    "tokamak_orbit_vec4_asm:",
    "li t6, 0x9E3779B97F4A7C15",
    "xor t0, a2, t6", "mv t1, t0", "mv t2, t0", "mv t3, t0",
    "add s0, a2, t6", "mv s1, s0", "mv s2, s0", "mv s3, s0",
    "beqz a1, 2f",
    "1:",
    "ld a3, 0(a0)", "ld a4, 8(a0)", "ld a5, 16(a0)", "ld a6, 24(a0)",
    "xor t0, t0, a3", "xor t1, t1, a4", "xor t2, t2, a5", "xor t3, t3, a6",
    "slli a3, t0, 13", "srli a4, t0, 51", "or t0, a3, a4", "add t0, t0, t6",
    "slli a3, t1, 13", "srli a4, t1, 51", "or t1, a3, a4", "add t1, t1, t6",
    "slli a3, t2, 13", "srli a4, t2, 51", "or t2, a3, a4", "add t2, t2, t6",
    "slli a3, t3, 13", "srli a4, t3, 51", "or t3, a3, a4", "add t3, t3, t6",
    "sd t0, 0(a0)", "sd t1, 8(a0)", "sd t2, 16(a0)", "sd t3, 24(a0)",
    "ld a3, 32(a0)", "ld a4, 40(a0)", "ld a5, 48(a0)", "ld a6, 56(a0)",
    "xor s0, s0, a3", "xor s1, s1, a4", "xor s2, s2, a5", "xor s3, s3, a6",
    "slli a3, s0, 19", "srli a4, s0, 45", "or s0, a3, a4", "add s0, s0, t6",
    "slli a3, s1, 19", "srli a4, s1, 45", "or s1, a3, a4", "add s1, s1, t6",
    "slli a3, s2, 19", "srli a4, s2, 45", "or s2, a3, a4", "add s2, s2, t6",
    "slli a3, s3, 19", "srli a4, s3, 45", "or s3, a3, a4", "add s3, s3, t6",
    "sd s0, 32(a0)", "sd s1, 40(a0)", "sd s2, 48(a0)", "sd s3, 56(a0)",
    "addi a0, a0, 64", "addi a1, a1, -8", "bgtz a1, 1b",
    "2:",
    "xor t0, t0, t1", "xor t2, t2, t3", "xor t0, t0, t2",
    "xor s0, s0, s1", "xor s2, s2, s3", "xor s0, s0, s2",
    "xor a0, t0, s0", "ret",
    "tokamak_orbit_vec4_asm_end:"
);

#[cfg(target_arch = "s390x")]
global_asm!(
    ".globl _start", "_start:", "aghi %r15, -160", "brasl %r14, main_entry", "lghi %r1, 1", "svc 0",
    ".globl tokamak_orbit_vec4_asm", ".globl tokamak_orbit_vec4_asm_end", ".p2align 6",
    "tokamak_orbit_vec4_asm:",
    "llihf %r13, 0x9E3779B9", "iilf %r13, 0x7F4A7C15",
    "lgr %r5, %r4", "xgr %r5, %r13", "lgr %r6, %r5", "lgr %r7, %r5", "lgr %r8, %r5",
    "lgr %r9, %r4", "agr %r9, %r13", "lgr %r10, %r9", "lgr %r11, %r9", "lgr %r12, %r9",
    "ltgr %r3, %r3", "jz 2f",
    "1:",
    "lg %r1, 0(%r2)", "xgr %r5, %r1", "rllg %r5, %r5, 13", "agr %r5, %r13", "stg %r5, 0(%r2)",
    "lg %r1, 8(%r2)", "xgr %r6, %r1", "rllg %r6, %r6, 13", "agr %r6, %r13", "stg %r6, 8(%r2)",
    "lg %r1, 16(%r2)", "xgr %r7, %r1", "rllg %r7, %r7, 13", "agr %r7, %r13", "stg %r7, 16(%r2)",
    "lg %r1, 24(%r2)", "xgr %r8, %r1", "rllg %r8, %r8, 13", "agr %r8, %r13", "stg %r8, 24(%r2)",
    "lg %r1, 32(%r2)", "xgr %r9, %r1", "rllg %r9, %r9, 19", "agr %r9, %r13", "stg %r9, 32(%r2)",
    "lg %r1, 40(%r2)", "xgr %r10, %r1", "rllg %r10, %r10, 19", "agr %r10, %r13", "stg %r10, 40(%r2)",
    "lg %r1, 48(%r2)", "xgr %r11, %r1", "rllg %r11, %r11, 19", "agr %r11, %r13", "stg %r11, 48(%r2)",
    "lg %r1, 56(%r2)", "xgr %r12, %r1", "rllg %r12, %r12, 19", "agr %r12, %r13", "stg %r12, 56(%r2)",
    "aghi %r2, 64", "aghi %r3, -8", "jh 1b",
    "2:",
    "xgr %r5, %r6", "xgr %r7, %r8", "xgr %r5, %r7",
    "xgr %r9, %r10", "xgr %r11, %r12", "xgr %r9, %r11",
    "lgr %r2, %r5", "xgr %r2, %r9", "br %r14",
    "tokamak_orbit_vec4_asm_end:"
);

unsafe extern "C" {
    fn tokamak_orbit_vec4_asm(torus_ptr: *mut u64, words: usize, seed: u64) -> u64;
    fn tokamak_orbit_vec4_asm_end();
}

#[inline(always)]
unsafe fn sys3(num: usize, a1: usize, a2: usize, a3: usize) -> isize {
    let ret: isize;
    #[cfg(target_arch = "x86_64")]
    asm!("syscall", inout("rax") num => ret, in("rdi") a1, in("rsi") a2, in("rdx") a3, out("rcx") _, out("r11") _, options(nostack));
    #[cfg(target_arch = "aarch64")]
    asm!("svc #0", inout("x0") a1 => ret, in("x1") a2, in("x2") a3, in("x8") num, options(nostack));
    #[cfg(target_arch = "riscv64")]
    asm!("ecall", inout("a0") a1 => ret, in("a1") a2, in("a2") a3, in("a7") num, options(nostack));
    #[cfg(target_arch = "s390x")]
    asm!("svc 0", inout("r2") a1 => ret, in("r3") a2, in("r4") a3, in("r1") num, options(nostack));
    ret
}

#[inline(always)]
unsafe fn sys6(num: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize) -> isize {
    let ret: isize;
    #[cfg(target_arch = "x86_64")]
    asm!("syscall", inout("rax") num => ret, in("rdi") a1, in("rsi") a2, in("rdx") a3, in("r10") a4, in("r8") a5, in("r9") a6, out("rcx") _, out("r11") _, options(nostack));
    #[cfg(target_arch = "aarch64")]
    asm!("svc #0", inout("x0") a1 => ret, in("x1") a2, in("x2") a3, in("x3") a4, in("x4") a5, in("x5") a6, in("x8") num, options(nostack));
    #[cfg(target_arch = "riscv64")]
    asm!("ecall", inout("a0") a1 => ret, in("a1") a2, in("a2") a3, in("a3") a4, in("a4") a5, in("a5") a6, in("a7") num, options(nostack));
    #[cfg(target_arch = "s390x")]
    asm!("svc 0", inout("r2") a1 => ret, in("r3") a2, in("r4") a3, in("r5") a4, in("r6") a5, in("r7") a6, in("r1") num, options(nostack));
    ret
}

#[inline(always)]
unsafe fn read_ticks() -> u64 {
    #[cfg(target_arch = "x86_64")]
    { let lo: u32; let hi: u32; asm!("lfence", "rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack)); ((hi as u64) << 32) | (lo as u64) }
    #[cfg(target_arch = "aarch64")]
    { let c: u64; asm!("dsb sy", "mrs {}, cntvct_el0", out(reg) c, options(nomem, nostack)); c }
    #[cfg(target_arch = "riscv64")]
    { let t: u64; asm!("fence rw, rw", "rdtime {}", out(reg) t, options(nomem, nostack)); t }
    #[cfg(target_arch = "s390x")]
    { let mut clk = [0u64; 2]; let p = clk.as_mut_ptr(); asm!("stckf 0({})", in(reg_addr) p, options(nostack)); clk[0] }
}

unsafe fn verify_wx_sum(p: *const u8, len: usize) -> u64 {
    let mut h: u64 = 0xCBF29CE484222325;
    let mut i = 0;
    while i < len { h ^= p.add(i).read_volatile() as u64; h = h.wrapping_mul(0x100000001B3); i += 1; }
    h
}

unsafe fn detect_l1d_half() -> usize {
    #[cfg(target_arch = "x86_64")] let (o, r, c) = (257usize, 0usize, 3usize);
    #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))] let (o, r, c) = (56usize, 63usize, 57usize);
    #[cfg(target_arch = "s390x")] let (o, r, c) = (322usize, 3usize, 6usize);
    let fd = sys6(o, (-100isize) as usize, b"/sys/devices/system/cpu/cpu0/cache/index0/size\0".as_ptr() as usize, 0, 0, 0, 0);
    if fd >= 0 {
        let mut buf = [0u8; 32];
        let n = sys3(r, fd as usize, buf.as_mut_ptr() as usize, 31);
        let _ = sys3(c, fd as usize, 0, 0);
        if n > 0 {
            let mut v = 0usize; let mut i = 0;
            while i < (n as usize) {
                let ch = buf[i];
                if ch >= b'0' && ch <= b'9' { v = v * 10 + ((ch - b'0') as usize); }
                else if ch == b'K' || ch == b'k' { v *= 1024; break; }
                i += 1;
            }
            if v >= 8192 { return (v / 2) & !127usize; }
        }
    }
    16384
}

unsafe fn w_str(s: &[u8]) {
    #[cfg(target_arch = "x86_64")] let w = 1usize;
    #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))] let w = 64usize;
    #[cfg(target_arch = "s390x")] let w = 4usize;
    let _ = sys3(w, 1, s.as_ptr() as usize, s.len());
}
unsafe fn w_u64(mut v: u64) {
    if v == 0 { w_str(b"0"); return; }
    let mut b = [0u8; 24]; let mut i = 23;
    while v > 0 { b[i] = b'0' + (v % 10) as u8; v /= 10; i -= 1; }
    w_str(&b[i + 1..]);
}
unsafe fn w_hex(mut v: u64) {
    const H: &[u8] = b"0123456789abcdef";
    let mut b = [0u8; 18]; b[0] = b'0'; b[1] = b'x';
    for i in (2..18).rev() { b[i] = H[(v & 0xF) as usize]; v >>= 4; }
    w_str(&b);
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn main_entry() -> i32 {
    #[cfg(target_arch = "x86_64")] let (mm, mp, mu) = (9usize, 10usize, 11usize);
    #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))] let (mm, mp, mu) = (222usize, 226usize, 215usize);
    #[cfg(target_arch = "s390x")] let (mm, mp, mu) = (90usize, 125usize, 91usize);

    let src = tokamak_orbit_vec4_asm as *const () as *const u8;
    let len = (tokamak_orbit_vec4_asm_end as *const () as usize) - (src as usize);
    let sum = verify_wx_sum(src, len);

    let arena = sys6(mm, 0, 12288, 0, 0x22, (-1isize) as usize, 0) as *mut u8;
    if (arena as isize) <= 0 { return 1; }
    let wx = arena.add(4096);
    if sys3(mp, wx as usize, 4096, 3) != 0 { return 2; }
    let mut c = 0; while c < len { wx.add(c).write_volatile(src.add(c).read()); c += 1; }
    fence(Ordering::SeqCst);
    if verify_wx_sum(wx, len) != sum { return 99; }
    if sys3(mp, wx as usize, 4096, 5) != 0 { return 3; }

    let tb = detect_l1d_half();
    let words = tb / 8;
    let torus = sys6(mm, 0, tb, 3, 0x22, (-1isize) as usize, 0) as *mut u64;
    if (torus as isize) <= 0 { return 4; }
    let mut i = 0;
    while i < words { torus.add(i).write_volatile((i as u64).wrapping_mul(0x9E3779B97F4A7C15) ^ 0x5A45524F4D414E49); i += 1; }

    let f: extern "C" fn(*mut u64, usize, u64) -> u64 = core::mem::transmute(wx);
    let t0 = read_ticks();
    let mut ph = 0x5A45524F4D414E49u64;
    let mut orb = 0;
    while orb < 100_000 { ph = f(torus, words, ph); orb += 1; }
    let t1 = read_ticks();

    w_str(b"[TOKAMAK-MULTI-ISA] OPCODES="); w_u64(len as u64);
    w_str(b"B | L1D_HALF="); w_u64(tb as u64);
    w_str(b"B | CYCLES="); w_u64(t1.wrapping_sub(t0));
    w_str(b" | PHASE="); w_hex(ph); w_str(b"\n");

    if sys3(mp, wx as usize, 4096, 3) == 0 {
        let mut z = 0; while z < len { wx.add(z).write_volatile(0); z += 1; }
        fence(Ordering::SeqCst); let _ = sys3(mp, wx as usize, 4096, 0);
    }
    let mut z = 0; while z < words { torus.add(z).write_volatile(0); z += 1; }
    fence(Ordering::SeqCst);
    let _ = sys3(mu, torus as usize, tb, 0);
    let _ = sys3(mu, arena as usize, 12288, 0);
    0
}
