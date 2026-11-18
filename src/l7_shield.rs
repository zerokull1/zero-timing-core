#![allow(dead_code)]
// ZEROMANI (zerokull1) | 0x5A45524F4D414E49ULL

use core::arch::asm;

#[derive(Copy, Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum L7Verdict {
    CleanPass = 0,
    BlockedHttpSmuggling = 1,
    BlockedInvalidTlsRecord = 2,
    BlockedNullPayload = 3,
    BlockedTlsRecordSplitting = 4,
    BlockedTlsDowngrade = 5,
}

const SIG_POST_SPACE: u64 = u64::from_le_bytes(*b"POST /  ");
const MASK_5_BYTES: u64   = 0x0000_00FF_FFFF_FFFF;
const SIG_TE_CHUNKED: u64 = u64::from_le_bytes(*b"chunked\r");

#[inline(always)]
pub unsafe fn inspect_l7_payload_asm(payload: *const u8, len: usize, dst_port: u16) -> L7Verdict { unsafe {
    if len < 16 || payload.is_null() {
        return L7Verdict::BlockedNullPayload;
    }

    #[cfg(target_arch = "x86_64")]
    {
        let verdict_code: u64;
        if dst_port == 443 {
            asm!(
                "mov {q0}, qword ptr [{ptr}]",
                "mov {q1}, qword ptr [{ptr} + 8]",
                "xor {res:e}, {res:e}",
                "cmp {q0:l}, 0x16",
                "sete {t2:l}",
                "mov {t0}, {q0}",
                "shr {t0}, 40",
                "cmp {t0:l}, 0x01",
                "sete {t1:l}",
                "and {t1:l}, {t2:l}",
                "mov {t0}, {q1}",
                "shr {t0}, 8",
                "cmp {t0:x}, 0x0303",
                "setne {t0:l}",
                "and {t1:l}, {t0:l}",
                "mov {t0:e}, 5",
                "test {t1:l}, {t1:l}",
                "cmovnz {res:e}, {t0:e}",
                "mov {t0}, {q0}",
                "shr {t0}, 24",
                "rol {t0:x}, 8",
                "cmp {t0:x}, 40",
                "setb {t1:l}",
                "and {t1:l}, {t2:l}",
                "mov {t0:e}, 4",
                "test {t1:l}, {t1:l}",
                "cmovnz {res:e}, {t0:e}",
                "mov {t0:e}, 2",
                "mov {t1}, {q0}",
                "shr {t1}, 8",
                "cmp {t1:l}, 0x03",
                "cmovne {res:e}, {t0:e}",
                "sub {q0:l}, 0x16",
                "cmp {q0:l}, 1",
                "cmova {res:e}, {t0:e}",
                ptr = in(reg) payload,
                q0 = out(reg) _, q1 = out(reg) _, t0 = out(reg) _, t1 = out(reg) _, t2 = out(reg) _,
                res = out(reg) verdict_code,
                options(readonly, nostack, pure)
            );
        } else {
            asm!(
                "mov {q0}, qword ptr [{ptr}]",
                "mov {q1}, qword ptr [{ptr} + 8]",
                "and {q0}, {mask}",
                "xor {res:e}, {res:e}",
                "mov {bad:e}, 1",
                "cmp {q0}, {sig0}",
                "cmovne {bad:e}, {res:e}",
                "cmp {q1}, {sig1}",
                "cmove {res:e}, {bad:e}",
                ptr = in(reg) payload,
                mask = in(reg) MASK_5_BYTES,
                sig0 = in(reg) (SIG_POST_SPACE & MASK_5_BYTES),
                sig1 = in(reg) SIG_TE_CHUNKED,
                q0 = out(reg) _, q1 = out(reg) _, bad = out(reg) _,
                res = out(reg) verdict_code,
                options(readonly, nostack, pure)
            );
        }
        return match verdict_code as u8 {
            0 => L7Verdict::CleanPass,
            1 => L7Verdict::BlockedHttpSmuggling,
            2 => L7Verdict::BlockedInvalidTlsRecord,
            4 => L7Verdict::BlockedTlsRecordSplitting,
            5 => L7Verdict::BlockedTlsDowngrade,
            _ => L7Verdict::BlockedNullPayload,
        };
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        let b = core::slice::from_raw_parts(payload, 16);
        if dst_port == 443 {
            let rec_type = b[0];
            let major_ver = b[1];
            let rec_len = u16::from_be_bytes([b[3], b[4]]);
            let hs_type = b[5];
            let legacy_ver = u16::from_be_bytes([b[9], b[10]]);
            if major_ver != 0x03 || (rec_type != 0x16 && rec_type != 0x17) {
                return L7Verdict::BlockedInvalidTlsRecord;
            }
            if rec_type == 0x16 && rec_len < 40 {
                return L7Verdict::BlockedTlsRecordSplitting;
            }
            if rec_type == 0x16 && hs_type == 0x01 && legacy_ver != 0x0303 {
                return L7Verdict::BlockedTlsDowngrade;
            }
            L7Verdict::CleanPass
        } else {
            let is_post = &b[0..5] == b"POST ";
            let is_chunked = &b[8..16] == b"chunked\r";
            if is_post && is_chunked { L7Verdict::BlockedHttpSmuggling } else { L7Verdict::CleanPass }
        }
    }
}}

pub fn benchmark_l7_swar() -> (u64, u8) {
    let tls_hello: [u8; 16] = [
        0x16, 0x03, 0x03, 0x00, 0xF4, 0x01, 0x00, 0x00,
        0xF0, 0x03, 0x03, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE
    ];
    let smuggle_pkt: [u8; 16] = *b"POST /  chunked\r";
    let t0 = crate::tsc::rdtsc_start();
    let v_tls = unsafe { inspect_l7_payload_asm(tls_hello.as_ptr(), tls_hello.len(), 443) };
    let v_atk = unsafe { inspect_l7_payload_asm(smuggle_pkt.as_ptr(), smuggle_pkt.len(), 80) };
    let t1 = crate::tsc::rdtsc_end();
    (t1.saturating_sub(t0), ((v_tls as u8) << 4) | (v_atk as u8))
}

#[inline(always)]
pub unsafe fn inspect_quic_l7_asm(payload_ptr: *const u8, len: usize) -> u64 { unsafe {
    if len < 16 || payload_ptr.is_null() { return 0; }
    let b = core::slice::from_raw_parts(payload_ptr, 16);
    let first_byte = b[0];
    if (first_byte & 0x80) == 0 { return 0; }

    let version = u32::from_be_bytes([b[1], b[2], b[3], b[4]]);
    let dcid_len = b[5] as u32;
    let pkt_type = ((first_byte >> 4) & 0x03) as u32;
    let pkt_len = len as u32;

    #[cfg(target_arch = "x86_64")]
    {
        let mut verdict: u64 = 0;
        asm!(
            "cmp {ver:e}, 1", "sete {v1:l}",
            "cmp {ver:e}, 0x6b3343cf", "sete {v2:l}",
            "test {ver:e}, {ver:e}", "sete {vn:l}",
            "or {v1:l}, {v2:l}", "or {v1:l}, {vn:l}",
            "test {v1:l}, {v1:l}", "mov {tmp}, 4", "cmovz {verd}, {tmp}",
            "cmp {dcid:e}, 20", "cmova {verd}, {tmp}",
            "cmp {ptype:e}, {v2:e}", "sete {is_init:l}",
            "cmp {plen:e}, 1200", "setb {is_short:l}",
            "and {is_init:l}, {is_short:l}",
            "test {is_init:l}, {is_init:l}", "cmovnz {verd}, {tmp}",
            ver = in(reg) version, dcid = in(reg) dcid_len, ptype = in(reg) pkt_type, plen = in(reg) pkt_len,
            v1 = out(reg) _, v2 = out(reg) _, vn = out(reg) _, is_init = out(reg) _, is_short = out(reg) _, tmp = out(reg) _,
            verd = inout(reg) verdict,
            options(pure, nomem, nostack)
        );
        verdict
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        let valid_ver = (version == 1) | (version == 0x6b3343cf) | (version == 0);
        let is_v2 = (version == 0x6b3343cf) as u32;
        let short_init = (pkt_type == is_v2) & (pkt_len < 1200);
        if !valid_ver || dcid_len > 20 || short_init { 4 } else { 0 }
    }
}}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub unsafe fn cpu_supports_avx512bw() -> bool { unsafe {
    let ecx1: u32;
    asm!("push rbx", "mov eax, 1", "cpuid", "pop rbx", out("ecx") ecx1, out("eax") _, out("edx") _, options(nomem, nostack));
    if (ecx1 & (1 << 27)) == 0 { return false; }
    let xcr0_lo: u32;
    asm!("xor ecx, ecx", "xgetbv", out("eax") xcr0_lo, out("edx") _, out("ecx") _, options(nomem, nostack));
    if (xcr0_lo & 0xE6) != 0xE6 { return false; }
    let ebx7: u32;
    asm!("push rbx", "mov eax, 7", "xor ecx, ecx", "cpuid", "mov {o:e}, ebx", "pop rbx", o = out(reg) ebx7, out("eax") _, out("ecx") _, out("edx") _, options(nomem, nostack));
    (ebx7 & ((1 << 16) | (1 << 30))) == ((1 << 16) | (1 << 30))
}}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f,avx512bw")]
#[inline]
pub unsafe fn scan_cacheline_byte_avx512(ptr: *const u8, needle: u8) -> u64 { unsafe {
    let mask64: u64;
    let needle_broadcast: u32 = (needle as u32) * 0x0101_0101;
    asm!(
        "vmovd {xmm_tmp}, {ndl:e}",
        "vpbroadcastd zmm1, {xmm_tmp}",
        "vmovdqu64 zmm0, zmmword ptr [{p}]",
        "vpcmpeqb k1, zmm0, zmm1",
        "kmovq {out_mask}, k1",
        "vzeroupper",
        p = in(reg) ptr, ndl = in(reg) needle_broadcast,
        xmm_tmp = out(xmm_reg) _, out_mask = out(reg) mask64,
        out("zmm0") _, out("zmm1") _, out("k1") _, options(nostack)
    );
    mask64
}}

#[inline(always)]
pub unsafe fn inspect_l7_payload_adaptive(payload: *const u8, len: usize, dst_port: u16) -> L7Verdict { unsafe {
    #[cfg(target_arch = "x86_64")]
    if dst_port == 80 && len >= 64 && !payload.is_null() && cpu_supports_avx512bw() {
        let q0 = (payload as *const u64).read_unaligned();
        if (q0 & MASK_5_BYTES) == (SIG_POST_SPACE & MASK_5_BYTES) {
            let max_scan = if len > 256 { 256 } else { len };
            let mut base = 0usize;
            while base + 64 <= max_scan {
                let mut hits = scan_cacheline_byte_avx512(payload.add(base), b'c');
                while hits != 0 {
                    let idx = base + (hits.trailing_zeros() as usize);
                    if idx + 8 <= max_scan {
                        let cand = (payload.add(idx) as *const u64).read_unaligned();
                        if cand == SIG_TE_CHUNKED {
                            return L7Verdict::BlockedHttpSmuggling;
                        }
                    }
                    hits &= hits - 1;
                }
                base += 56;
            }
            return L7Verdict::CleanPass;
        }
    }
    inspect_l7_payload_asm(payload, len, dst_port)
}}

pub const VERDICT_MODBUS_BLOCK: u64   = 0x10;
pub const VERDICT_ETHERCAT_BLOCK: u64 = 0x11;
pub const VERDICT_DNS_BLOCK: u64      = 0x12;
pub const VERDICT_NTP_BLOCK: u64      = 0x13;

#[inline(always)]
pub unsafe fn inspect_modbus_tcp_asm(payload: *const u8, len: usize) -> u64 { unsafe {
    if len < 8 || payload.is_null() { return VERDICT_MODBUS_BLOCK; }
    let allowed_fc_mask: u64 = (1u64 << 0x01) | (1u64 << 0x02) | (1u64 << 0x03) | (1u64 << 0x04)

        | (1u64 << 0x05) | (1u64 << 0x06) | (1u64 << 0x0F) | (1u64 << 0x10)
        | (1u64 << 0x14) | (1u64 << 0x15) | (1u64 << 0x16) | (1u64 << 0x17);

    #[cfg(target_arch = "x86_64")]
    {
        let q0 = core::ptr::read_unaligned(payload as *const u64);
        let pkt_len = len as u32;
        let mut verdict: u64 = 0;
        asm!(
            "mov {t0}, {q0}", "shr {t0}, 16", "test {t0:x}, {t0:x}", "mov {bad}, 0x10", "cmovnz {verd}, {bad}",
            "mov {t0}, {q0}", "shr {t0}, 32", "rol {t0:x}, 8", "movzx {t1:e}, {t0:x}",
            "cmp {t1:e}, 2", "cmovb {verd}, {bad}",
            "cmp {t1:e}, 254", "cmova {verd}, {bad}",
            "add {t1:e}, 6", "cmp {t1:e}, {plen:e}", "cmova {verd}, {bad}",
            "mov {t0}, {q0}", "shr {t0}, 56", "cmp {t0:e}, 63", "cmova {verd}, {bad}",
            "bt {fmask}, {t0}", "cmovnc {verd}, {bad}",
            q0 = in(reg) q0, plen = in(reg) pkt_len, fmask = in(reg) allowed_fc_mask,
            t0 = out(reg) _, t1 = out(reg) _, bad = out(reg) _, verd = inout(reg) verdict,
            options(pure, nomem, nostack)
        );
        verdict
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        let b = core::slice::from_raw_parts(payload, 8);
        let proto_id = u16::from_be_bytes([b, b]);
        let mbap_len = u16::from_be_bytes([b, b]) as usize;
        let fc = b;
        let bad = proto_id != 0 || mbap_len < 2 || mbap_len > 254 || (mbap_len + 6) > len || fc > 63 || ((allowed_fc_mask >> fc) & 1) == 0;
        if bad { VERDICT_MODBUS_BLOCK } else { 0 }
    }
}}

#[inline(always)]
pub unsafe fn inspect_ethercat_asm(payload: *const u8, len: usize) -> u64 { unsafe {
    if len < 14 || payload.is_null() { return VERDICT_ETHERCAT_BLOCK; }

    #[cfg(target_arch = "x86_64")]
    {
        let q0 = core::ptr::read_unaligned(payload as *const u64);
        let pkt_len = len as u32;
        let mut verdict: u64 = 0;
        asm!(
            "mov {bad}, 0x11",
            "mov {t0:e}, {q0:e}", "shr {t0:e}, 12", "and {t0:e}, 0x0F", "cmp {t0:e}, 1", "cmovne {verd}, {bad}",
            "mov {t0:e}, {q0:e}", "and {t0:e}, 0x07FF", "cmp {t0:e}, 12", "cmovb {verd}, {bad}",
            "add {t0:e}, 2", "cmp {t0:e}, {plen:e}", "cmova {verd}, {bad}",
            q0 = in(reg) q0, plen = in(reg) pkt_len, t0 = out(reg) _, bad = out(reg) _, verd = inout(reg) verdict,
            options(pure, nomem, nostack)
        );
        verdict
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        let b = core::slice::from_raw_parts(payload, 2);
        let hdr = u16::from_le_bytes([b, b]);
        let etype = (hdr >> 12) & 0x0F;
        let elen = (hdr & 0x07FF) as usize;
        if etype != 1 || elen < 12 || (elen + 2) > len { VERDICT_ETHERCAT_BLOCK } else { 0 }
    }
}}

#[inline(always)]
pub unsafe fn inspect_dns_guard_asm(payload: *const u8, len: usize) -> u64 { unsafe {
    if len < 16 || payload.is_null() { return VERDICT_DNS_BLOCK; }

    #[cfg(target_arch = "x86_64")]
    {
        let q0 = core::ptr::read_unaligned(payload as *const u64);
        let q1 = core::ptr::read_unaligned(payload.add(8) as *const u64);
        let mut verdict: u64 = 0;
        asm!(
            "mov {bad}, 0x12",
            "mov {t0}, {q0}", "shr {t0}, 16", "test {t0:x}, 0x0082", "cmovnz {verd}, {bad}",
            "mov {t0}, {q1}", "shr {t0}, 32", "cmp {t0:l}, 63", "cmova {verd}, {bad}",
            q0 = in(reg) q0, q1 = in(reg) q1, t0 = out(reg) _, bad = out(reg) _, verd = inout(reg) verdict,
            options(pure, nomem, nostack)
        );
        verdict
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        let b = core::slice::from_raw_parts(payload, 13);
        let flags_le = u16::from_le_bytes([b, b]);
        let qname_len = b;
        if (flags_le & 0x0082) != 0 || qname_len > 63 { VERDICT_DNS_BLOCK } else { 0 }
    }
}}

#[inline(always)]
pub unsafe fn inspect_ntp_guard_asm(payload: *const u8, len: usize) -> u64 { unsafe {
    if len < 48 || payload.is_null() { return VERDICT_NTP_BLOCK; }

    #[cfg(target_arch = "x86_64")]
    {
        let q0 = core::ptr::read_unaligned(payload as *const u64);
        let mut verdict: u64 = 0;
        asm!(
            "mov {bad}, 0x13",
            "mov {t0:e}, {q0:e}", "and {t0:e}, 0x07", "cmp {t0:e}, 6", "cmovae {verd}, {bad}",
            q0 = in(reg) q0, t0 = out(reg) _, bad = out(reg) _, verd = inout(reg) verdict,
            options(pure, nomem, nostack)
        );
        verdict
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        let mode = (*payload) & 0x07;
        if mode >= 6 { VERDICT_NTP_BLOCK } else { 0 }
    }
}}

pub const VERDICT_RMM_SOHO_BLOCK: u64 = 0x14;

#[inline(always)]
pub unsafe fn inspect_rmm_soho_window_asm(payload: *const u8, len: usize, tcp_window: u16) -> u64 { unsafe {
    if len == 0 || payload.is_null() {
        return 0;
    }
    if len < 6 {
        return if tcp_window < 64 { VERDICT_RMM_SOHO_BLOCK } else { 0 };
    }

    #[cfg(target_arch = "x86_64")]
    {
        let q0 = core::ptr::read_unaligned(payload as *const u64);
        let win = tcp_window as u32;
        let mut verdict: u64 = 0;
        asm!(
            "mov {bad}, 0x14",
            "cmp {win:e}, 64",
            "cmovb {verd}, {bad}",
            "cmp {q0:l}, 0x16",
            "sete {t0:l}",
            "mov {t1}, {q0}",
            "shr {t1}, 8",
            "cmp {t1:l}, 0x03",
            "sete {t2:l}",
            "and {t0:l}, {t2:l}",
            "mov {t1}, {q0}",
            "shr {t1}, 40",
            "cmp {t1:l}, 0x01",
            "sete {t2:l}",
            "and {t0:l}, {t2:l}",
            "cmp {win:e}, 4096",
            "setb {t2:l}",
            "and {t0:l}, {t2:l}",
            "test {t0:l}, {t0:l}",
            "cmovnz {verd}, {bad}",
            q0 = in(reg) q0,
            win = in(reg) win,
            t0 = out(reg) _,
            t1 = out(reg) _,
            t2 = out(reg) _,
            bad = out(reg) _,
            verd = inout(reg) verdict,
            options(pure, nomem, nostack)
        );
        verdict
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        let b = core::slice::from_raw_parts(payload, 6);
        let is_tls_hello = b[0] == 0x16 && b[1] == 0x03 && b[5] == 0x01;
        if tcp_window < 64 || (is_tls_hello && tcp_window < 4096) {
            VERDICT_RMM_SOHO_BLOCK
        } else {
            0
        }
    }
}}


/// Безветвящаяся проверка отсутствия IPv4 Options (IHL == 5) против CVE-2026-98432 (~2 такта).
#[inline(always)]
pub fn verify_ipv4_no_options_asm(ver_ihl: u8) -> u32 {
    let verdict: u32;
    unsafe {
        core::arch::asm!(
            "and {tmp:e}, 0x0F",
            "cmp {tmp:e}, 5",
            "setne {out}",
            "movzx {verdict:e}, {out}",
            tmp = inout(reg) (ver_ihl as u32) => _,
            out = out(reg_byte) _,
            verdict = out(reg) verdict,
            options(pure, nomem, nostack)
        );
    }
    verdict
}
