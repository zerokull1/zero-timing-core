#![no_std]
#![no_main]
// ZEROMANI (zerokull1) | Author Signature: 0x5A45524F4D414E49ULL | Pure #![no_std] Rust + x86_64 ASM Engine

use core::arch::{asm, global_asm};
use zero_hal::{ddr_arena, tsc, ymm_vault};

#[unsafe(no_mangle)]
pub extern "C" fn rust_eh_personality() {}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

global_asm!(
    ".globl _start",
    "_start:",
    "and rsp, -16",
    "call pure_asm_main",
    "mov rdi, rax",
    "mov eax, 60",
    "syscall",

    ".section .text.pure_asm_engine, \"ax\", @progbits",
    // rdi = pkt_ptr, rsi = pkt_len, rdx = l1d_arena (0..2047 JA4 table, 2048..2079 pulse state),
    // rcx = ttl_in, r8 = scan_flag (0 = clean, 1 = port scan)
    ".globl pure_asm_inspect_and_mirage",
    ".type pure_asm_inspect_and_mirage, @function",
    "pure_asm_inspect_and_mirage:",
    "cmp rsi, 16",
    "jb 9f",
    "cmp rdi, 0x10000",
    "jb 9f",
    "cmp rdx, 0x10000",
    "jb 9f",

    // 1. Branchless TTL-Guard & L7 Signature Check (TLS Downgrade 0x160301 / 0x160302)
    "xor r9d, r9d",
    "mov r10d, 1",
    "cmp cl, 65",
    "cmove r9d, r10d",
    "cmp cl, 129",
    "cmove r9d, r10d",
    "mov eax, dword ptr [rdi]",
    "and eax, 0x00FFFFFF",
    "cmp eax, 0x00010316",
    "cmove r9d, r10d",
    "cmp eax, 0x00020316",
    "cmove r9d, r10d",

    // 2. Self-Learning JA4-SentinelBot (SSE4.2 CRC32C + 64-slot L1d Reputation + Anti-Eviction)
    "mov eax, 0x5A45524F",
    "mov r11, qword ptr [rdi]",
    "crc32 rax, r11",
    "mov r11, qword ptr [rdi + 8]",
    "crc32 rax, r11",
    "mov esi, eax",
    "and eax, 0x3F",
    "shl eax, 5",
    "lea r11, [rdx + rax]",
    "push rdx",
    "rdtsc",
    "shl rdx, 32",
    "or rax, rdx",
    "pop rdx",
    "mov r10, rax",
    "cmp dword ptr [r11], esi",
    "je 2f",
    "cmp dword ptr [r11 + 4], 2",
    "jne 1f",
    "mov rax, r10",
    "sub rax, qword ptr [r11 + 8]",
    "mov rcx, 3300000000",
    "cmp rax, rcx",
    "jb 4f",
    "1:",
    "mov dword ptr [r11], esi",
    "mov dword ptr [r11 + 4], 0",
    "mov qword ptr [r11 + 8], 0",
    "mov dword ptr [r11 + 16], 0",
    "2:",
    "test r9d, r9d",
    "jz 3f",
    "mov dword ptr [r11 + 4], 2",
    "mov dword ptr [r11 + 16], 0",
    "mov qword ptr [r11 + 8], r10",
    "mov r9d, 2",
    "jmp 5f",
    "3:",
    "mov eax, dword ptr [r11 + 4]",
    "cmp eax, 2",
    "jne 31f",
    "mov r9d, 2",
    "jmp 5f",
    "31:",
    "mov rax, r10",
    "sub rax, qword ptr [r11 + 8]",
    "cmp rax, 50000",
    "jb 4f",
    "mov qword ptr [r11 + 8], r10",
    "mov ecx, dword ptr [r11 + 16]",
    "inc ecx",
    "mov dword ptr [r11 + 16], ecx",
    "cmp ecx, 8",
    "jb 4f",
    "mov dword ptr [r11 + 4], 1",
    "4:",
    "mov r9d, dword ptr [r11 + 4]",

    // 3. Pulse-Triggered 3-Phase TTL Mirage (only when scan_flag r8 != 0; otherwise 0x00 pass)
    "5:",
    "test r8d, r8d",
    "jz 8f",
    "lea r11, [rdx + 2048]",
    "mov ecx, dword ptr [r11]",
    "inc dword ptr [r11 + 16]",
    "mov qword ptr [r11 + 8], r10",
    "test ecx, ecx",
    "jnz 6f",
    "mov dword ptr [r11], 1",
    "mov eax, 65",
    "shl rax, 8",
    "or eax, r9d",
    "ret",
    "6:",
    "cmp ecx, 1",
    "jne 7f",
    "mov dword ptr [r11], 2",
    "mov eax, r10d",
    "imul rax, rax, 54",
    "shr rax, 32",
    "add eax, 65",
    "shl rax, 8",
    "or eax, r9d",
    "ret",
    "7:",
    "mov dword ptr [r11], 0",
    "8:",
    "mov eax, r9d",
    "ret",
    "9:",
    "xor eax, eax",
    "ret",
);

unsafe extern "sysv64" {
    fn pure_asm_inspect_and_mirage(
        pkt: *const u8,
        len: usize,
        l1d_arena: *mut u8,
        ttl_in: u32,
        scan_flag: u32,
    ) -> u32;
}

#[inline(never)]
unsafe fn write_str(s: &[u8]) {
    let ptr = s.as_ptr() as usize;
    let len = s.len();
    unsafe {
        asm!(
            "syscall",
            inout("rax") 1isize => _,
            in("rdi") 1usize,
            in("rsi") ptr,
            in("rdx") len,
            out("rcx") _,
            out("r11") _,
            options(nostack, preserves_flags)
        );
    }
}

unsafe fn write_num(mut v: u64) {
    let mut buf = [0u8; 24];
    let mut i = 23;
    if v == 0 {
        buf[i] = b'0';
        i -= 1;
    }
    while v > 0 {
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
        i -= 1;
    }
    unsafe {
        write_str(&buf[i + 1..24]);
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pure_asm_main() -> i32 {
    unsafe {
        // 1. Allocate 3-page DDR arena with PROT_NONE guard pages on both sides
        let mut raw_ptr: usize;
        asm!(
            "syscall",
            inout("rax") 9isize => raw_ptr,
            in("rdi") 0usize,
            in("rsi") 12288usize,
            in("rdx") 3usize,
            in("r10") 0x22usize,
            in("r8") (-1isize) as usize,
            in("r9") 0usize,
            out("rcx") _,
            out("r11") _,
            options(nostack)
        );
        let base = raw_ptr as *mut u8;
        asm!("syscall", in("rax") 10isize, in("rdi") base as usize, in("rsi") 4096usize, in("rdx") 0usize, out("rcx") _, out("r11") _, options(nostack));
        asm!("syscall", in("rax") 10isize, in("rdi") base.add(8192) as usize, in("rsi") 4096usize, in("rdx") 0usize, out("rcx") _, out("r11") _, options(nostack));

        let arena = base.add(4096);
        { let mut off = 0usize; while off < 4096 { ddr_arena::SealedDdrArena::nt_wipe_64b(arena.add(off)); off += 64; } }

        // 2. Seal 256-bit epoch key in YMM15 with zero DDR footprint
        #[repr(align(64))]
        struct Key64([u64; 8]);
        let mut key = Key64([0x5A45_524F_4D41_4E49u64, 0x1337_CAFE_BABE_0001, 0xDEAD_BEEF_9988_7766, 0x0102_0304_0506_0708, 0, 0, 0, 0]);
        let k4: &[u64; 4] = &*(key.0.as_ptr() as *const [u64; 4]);
        ymm_vault::seal_key_in_ymm15(k4);
        ddr_arena::SealedDdrArena::nt_wipe_64b(key.0.as_mut_ptr() as *mut u8);

        // 3. Verify JA4-SentinelBot learning on 8 clean TLS 1.3 sessions
        let hello = b"\x16\x03\x03\x00\x40\x01\x00\x00\x3c\x03\x03\x5a\x45\x52\x4f\x01";
        let mut res = 0u32;
        let mut s = 0u32;
        while s < 8 {
            let t_wait = tsc::rdtsc_start() + 60_000;
            while tsc::rdtsc_end() < t_wait {}
            res = pure_asm_inspect_and_mirage(hello.as_ptr(), hello.len(), arena, 64, 0);
            s += 1;
        }
        let ja4_trust = res & 0xFF;
        if ja4_trust != 1 {
            return 21;
        }

        // 4. Verify 3-Phase Pulse TTL Mirage on Port Scan (65 -> 65..118 -> 0x00)
        let m1 = (pure_asm_inspect_and_mirage(hello.as_ptr(), hello.len(), arena, 64, 1) >> 8) & 0xFF;
        let m2 = (pure_asm_inspect_and_mirage(hello.as_ptr(), hello.len(), arena, 64, 1) >> 8) & 0xFF;
        let m3 = (pure_asm_inspect_and_mirage(hello.as_ptr(), hello.len(), arena, 64, 1) >> 8) & 0xFF;
        if m1 != 65 || m2 < 65 || m2 > 118 || m3 != 0 {
            return 22;
        }

        // 5. RDTSCP Benchmark over 1,000,000 frames
        let t0 = tsc::rdtsc_start();
        let mut i = 0u64;
        while i < 1_000_000 {
            let _ = pure_asm_inspect_and_mirage(hello.as_ptr(), hello.len(), arena, 64, 0);
            i += 1;
        }
        let t1 = tsc::rdtsc_end();

        ymm_vault::wipe_ymm15();
        { let mut off = 0usize; while off < 4096 { ddr_arena::SealedDdrArena::nt_wipe_64b(arena.add(off)); off += 64; } }

        write_str(b"[ZERO-PURE-RUST-ASM] YMM15+PROT_NONE+JA4_BOT(TRUST=");
        write_num(ja4_trust as u64);
        write_str(b")+MIRAGE(");
        write_num(m1 as u64);
        write_str(b"->");
        write_num(m2 as u64);
        write_str(b"->");
        write_num(m3 as u64);
        write_str(b") | 1M PKTS CYCLES/PKT=");
        write_num((t1 - t0) / 1_000_000);
        write_str(b"\n");
        0
    }
}
