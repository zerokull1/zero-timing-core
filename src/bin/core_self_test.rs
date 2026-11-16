// ZEROMANI (zerokull1) | 0x5A45524F4D414E49ULL
#![no_std]
#![no_main]

use core::arch::{asm, naked_asm};
use core::panic::PanicInfo;
use zero_core_lib::l7_shield::{inspect_l7_payload_asm, L7Verdict};
use zero_core_lib::thin_hypervisor::{
    classify_vmexit_branchless, EptPageTable, HypervisorBackend, VmExitVerdict, EPT_PERM_XO,
};

#[inline(always)]
unsafe fn sys_write(fd: usize, buf: *const u8, len: usize) {
    unsafe {
        asm!(
            "syscall",
            in("rax") 1usize,
            in("rdi") fd,
            in("rsi") buf,
            in("rdx") len,
            out("rcx") _,
            out("r11") _,
            options(nostack)
        );
    }
}

#[inline(always)]
unsafe fn sys_exit(code: usize) -> ! {
    unsafe {
        asm!(
            "syscall",
            in("rax") 60usize,
            in("rdi") code,
            options(noreturn, nostack)
        );
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    let msg = b"[FAIL] PANIC in no_std cargo test!\n";
    unsafe {
        sys_write(2, msg.as_ptr(), msg.len());
        sys_exit(1);
    }
}

fn check(cond: bool, err_msg: &[u8]) {
    if !cond {
        unsafe {
            sys_write(2, err_msg.as_ptr(), err_msg.len());
            sys_exit(1);
        }
    }
}

#[no_mangle]
pub extern "C" fn test_main() -> ! {
    // 1. Валидный TLS 1.3 ClientHello -> CleanPass
    let mut valid_tls13 = [0xAAu8; 64];
    valid_tls13[0..11].copy_from_slice(&[
        0x16, 0x03, 0x03, 0x00, 0x3B, 0x01, 0x00, 0x00, 0x37, 0x03, 0x03,
    ]);
    let v_ok = unsafe { inspect_l7_payload_asm(valid_tls13.as_ptr(), valid_tls13.len(), 443) };
    check(v_ok == L7Verdict::CleanPass, b"[FAIL] valid TLS 1.3 rejected\n");

    // 2. 128-битный TLS ClientHello Downgrade (TLS 1.0 и SSL 3.0) -> BlockedTlsDowngrade
    let mut downgrade_tls = [0xAAu8; 64];
    downgrade_tls[0..11].copy_from_slice(&[
        0x16, 0x03, 0x03, 0x00, 0x3B, 0x01, 0x00, 0x00, 0x37, 0x03, 0x01,
    ]);
    let v_10 = unsafe { inspect_l7_payload_asm(downgrade_tls.as_ptr(), downgrade_tls.len(), 443) };
    check(v_10 == L7Verdict::BlockedTlsDowngrade, b"[FAIL] TLS 1.0 downgrade missed\n");

    downgrade_tls[10] = 0x00;
    let v_30 = unsafe { inspect_l7_payload_asm(downgrade_tls.as_ptr(), downgrade_tls.len(), 443) };
    check(v_30 == L7Verdict::BlockedTlsDowngrade, b"[FAIL] SSL 3.0 downgrade missed\n");

    // 3. TLS Record Splitting (< 40B) + HTTP Smuggling
    let mut split_pkt = [0x11u8; 32];
    split_pkt[0..6].copy_from_slice(&[0x16, 0x03, 0x03, 0x00, 0x05, 0x01]);
    let v_split = unsafe { inspect_l7_payload_asm(split_pkt.as_ptr(), split_pkt.len(), 443) };
    check(v_split == L7Verdict::BlockedTlsRecordSplitting, b"[FAIL] TLS record splitting missed\n");

    let smuggle = *b"POST /  chunked\r";
    let v_http = unsafe { inspect_l7_payload_asm(smuggle.as_ptr(), smuggle.len(), 80) };
    check(v_http == L7Verdict::BlockedHttpSmuggling, b"[FAIL] HTTP smuggling missed\n");

    // 4. SMP Ring -1 VM-Exit классификатор + EPT Execute-Only
    check(
        classify_vmexit_branchless(HypervisorBackend::IntelVtxEpt, 48) == VmExitVerdict::SecurityViolationTrap,
        b"[FAIL] EPT violation trap mismatch\n",
    );
    check(
        classify_vmexit_branchless(HypervisorBackend::IntelVtxEpt, 3) == VmExitVerdict::SipiApicSync,
        b"[FAIL] INIT VM-exit mismatch\n",
    );
    check(
        classify_vmexit_branchless(HypervisorBackend::IntelVtxEpt, 4) == VmExitVerdict::SipiApicSync,
        b"[FAIL] SIPI VM-exit mismatch\n",
    );
    check(
        classify_vmexit_branchless(HypervisorBackend::AmdSvmNpt, 0x400) == VmExitVerdict::SecurityViolationTrap,
        b"[FAIL] AMD NPT violation mismatch\n",
    );

    let mut ept = EptPageTable::new();
    ept.map_execute_only_4k(0, 0x0020_0000);
    check((ept.entries[0] & 0x7) == (EPT_PERM_XO & 0x7), b"[FAIL] EPT XO bits mismatch\n");

    let ok_msg = b"[OK] cargo test (no_std / no_main): 128-bit TLS Downgrade, L7 ASM, SMP VM-Exit & EPT XO VERIFIED!\n";
    unsafe {
        sys_write(1, ok_msg.as_ptr(), ok_msg.len());
        sys_exit(0);
    }
}

#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "C" fn _start() -> ! {
    naked_asm!("and rsp, -16", "call test_main");
}
