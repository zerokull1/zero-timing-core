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
pub extern "C" fn test_main(argc: usize, argv: *const *const u8) -> ! {
    let mut rx_ifindex: u32 = 1;
    if argc > 1 {
        let mut p = unsafe { *argv.add(1) };
        let mut v: u32 = 0;
        while unsafe { *p } != 0 {
            let b = unsafe { *p };
            if b >= b'0' && b <= b'9' { v = v * 10 + (b - b'0') as u32; }
            p = unsafe { p.add(1) };
        }
        if v > 0 { rx_ifindex = v; }
    }
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

    // 5. Real Linux Kernel eBPF/XDP Verifier & Netlink NIC Attach Check
    let mut vlog = [0u8; 4096];
    match unsafe { zero_core_lib::bpf_control::build_and_load_xdp_pipeline(Some(&mut vlog)) } {
        Ok(pipe) => {
            let cfg = zero_core_lib::bpf_control::ShieldConfig {
                mode: zero_core_lib::bpf_control::ShieldMode::Enforce as u32,
                block_ttl_65: 1,
                block_ttl_129: 1,
            };
            let rc_cfg = unsafe { zero_core_lib::bpf_control::set_shield_mode(pipe.config_map_fd as u32, &cfg) };
            check(rc_cfg == 0, b"[FAIL] XDP config map update failed\n");
            let rc_wl = unsafe { zero_core_lib::bpf_control::whitelist_add_ipv4(pipe.whitelist_map_fd as u32, 0x0100007f) };
            check(rc_wl == 0, b"[FAIL] XDP whitelist map update failed\n");
            let rc_att = unsafe {
                zero_core_lib::bpf_control::attach_xdp_to_ifindex(
                    1,
                    pipe.prog_fd,
                    zero_core_lib::bpf_control::XDP_FLAGS_SKB_MODE,
                )
            };
            check(rc_att > 0, b"[FAIL] XDP Netlink attach failed\n");
            let _ = unsafe {
                zero_core_lib::bpf_control::detach_xdp_from_ifindex(
                    1,
                    zero_core_lib::bpf_control::XDP_FLAGS_SKB_MODE,
                )
            };
            let bypass_res = unsafe {
                zero_core_lib::af_xdp_engine::run_full_kernel_bypass_pipeline(
                    1,
                    zero_core_lib::bpf_control::ShieldMode::Monitor,
                )
            };
            check(bypass_res.is_ok(), b"[FAIL] Full XDP->XSKMAP->AF_XDP pipeline failed\n");
            let b_ok = b"[OK] FULL E2E PIPELINE (eBPF XDP -> XSKMAP -> AF_XDP UMEM -> L7 ASM) VERIFIED!\n";
            unsafe { sys_write(1, b_ok.as_ptr(), b_ok.len()); }

            if argc > 1 { match unsafe { zero_core_lib::af_xdp_engine::benchmark_live_xdp_burst(rx_ifindex, 2000) } {
                Err(_) => { check(false, b"[FAIL] benchmark_live_xdp_burst failed\n"); }
                Ok(st) => {
                    fn put_s(b: &mut [u8], p: &mut usize, s: &[u8]) { for &c in s { b[*p] = c; *p += 1; } }
                    fn put_u(b: &mut [u8], p: &mut usize, mut n: u64) {
                        let mut d = [0u8; 20]; let mut l = 0;
                        if n == 0 { d[0] = b'0'; l = 1; } else { while n > 0 { d[l] = b'0' + (n % 10) as u8; n /= 10; l += 1; } }
                        for i in (0..l).rev() { b[*p] = d[i]; *p += 1; }
                    }
                    let mut line = [b' '; 160]; let mut pos = 0;
                    put_s(&mut line, &mut pos, b"[BENCH] PKTS="); put_u(&mut line, &mut pos, st.total_pkts as u64);
                    put_s(&mut line, &mut pos, b" | ALLOWED="); put_u(&mut line, &mut pos, st.allowed as u64);
                    put_s(&mut line, &mut pos, b" | SMUGGLING="); put_u(&mut line, &mut pos, st.blocked_smuggling as u64);
                    put_s(&mut line, &mut pos, b" | TLS_SPLIT="); put_u(&mut line, &mut pos, st.blocked_tls_split as u64);
                    put_s(&mut line, &mut pos, b" | OTHER="); put_u(&mut line, &mut pos, st.blocked_other as u64);
                    put_s(&mut line, &mut pos, b" | BOT_WL="); put_u(&mut line, &mut pos, st.bot_whitelisted as u64);
                    put_s(&mut line, &mut pos, b" | BOT_BAN="); put_u(&mut line, &mut pos, st.bot_banned as u64);
                    let cpp = if st.total_pkts > 0 { st.total_cycles / (st.total_pkts as u64) } else { 0 };
                    put_s(&mut line, &mut pos, b" | cycles/pkt="); put_u(&mut line, &mut pos, cpp);
                    put_s(&mut line, &mut pos, b"\n");
                    unsafe { sys_write(1, line.as_ptr(), pos); }
                }
            } }
            let xdp_ok = b"[OK] REAL KERNEL eBPF/XDP VERIFIER & NETLINK ATTACH VERIFIED!\n";
            unsafe { sys_write(1, xdp_ok.as_ptr(), xdp_ok.len()); }
        }
        Err(e) => {
            if e == -1 || e == -13 {
                let skip = b"[SKIP] Kernel eBPF/XDP test requires CAP_BPF (run with sudo)\n";
                unsafe { sys_write(1, skip.as_ptr(), skip.len()); }
            } else {
                let end = vlog.iter().position(|&b| b == 0).unwrap_or(vlog.len());
                unsafe {
                    sys_write(2, b"[XDP VERIFIER LOG]\n".as_ptr(), 20);
                    sys_write(2, vlog.as_ptr(), end);
                    sys_write(2, b"\n".as_ptr(), 1);
                }
                check(false, b"[FAIL] Kernel eBPF verifier rejected XDP bytecode\n");
            }
        }
    }


    if !zero_core_lib::l7_shield::inspect_php_proto_vector_swar(b"GET /core/install.php HTTP/1.1\r\n\r\n")
        || !zero_core_lib::l7_shield::inspect_php_proto_vector_swar(b"Cookie: s=O:8:\"stdClass\":0:{}")
        || !zero_core_lib::l7_shield::inspect_php_proto_vector_swar(b"GET /?q=O%3A8%3A\"T\"&f=phar://a.jpg HTTP/1.1\r\n\r\n")
        || zero_core_lib::l7_shield::inspect_php_proto_vector_swar(b"POST /api/v1/items HTTP/1.1\r\n\r\n{\"id\":1}")
    {
        zero_core_lib::l7_shield::inspect_php_proto_vector_swar(b"");
        panic!("PHP/CMS SWAR test failed");
    }
    let ok_msg = b"[OK] cargo test (no_std / no_main): 128-bit TLS Downgrade, L7 ASM, SMP VM-Exit & EPT XO VERIFIED!\n";
    unsafe {
        sys_write(1, ok_msg.as_ptr(), ok_msg.len());
        sys_exit(0);
    }
}

#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "C" fn _start() -> ! {
    naked_asm!("mov rdi, [rsp]", "lea rsi, [rsp + 8]", "and rsp, -16", "call test_main");
}
