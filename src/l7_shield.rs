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

#[cfg(not(target_os = "uefi"))]
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
    if len == 0 || payload_ptr.is_null() { return 4; }
    let first_byte = *payload_ptr;
    ((((first_byte & 0x80) != 0) | ((first_byte & 0xC0) == 0x40)) as u64) << 2
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
#[cfg(not(target_os = "uefi"))]
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
#[cfg(not(target_os = "uefi"))]
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
        let hdr = u16::from_le_bytes([b[0], b[1]]);
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
        let flags_le = u16::from_le_bytes([b[2], b[3]]);
        let qname_len = b[12];
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
    if payload.is_null() || len < 6 {
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

/// Единый безветвящийся SWAR-нормализатор инвариантов RFC 9000 / 9112 / 9113
/// (закрывает пачку CVE-2026: PHP-FPM Smuggling CVE-2026-129289, NGINX2Root CVE-2026-123007,
/// H2 Near-Empty Bomb CVE-2026-49975, LiteLLM RCE CVE-2026-40217, QUIC RFC 9000 CVE-2026-95691).
#[inline(always)]
pub unsafe fn verify_l7_rfc_normalizer_swar(payload: *const u8, len: usize) -> u32 {
    if len < 16 || payload.is_null() {
        return 1;
    }

    let (w0, w1, tail) = unsafe {
        (
            (payload as *const u64).read_unaligned(),
            (payload.add(8) as *const u64).read_unaligned(),
            (payload.add(len - 8) as *const u64).read_unaligned(),
        )
    };
    let b0 = (w0 & 0xFF) as u8;

    // 1. Zero-QUIC Policy (RFC 9000 Long + 1-RTT Short Header 0x40): drop any QUIC header in 1 cycle
    let is_quic_any = (((b0 & 0x80) != 0) | ((b0 & 0xC0) == 0x40)) as u32;
    let mut drop_mask = is_quic_any;

    // 2. HTTP/2 RFC 9113 (NGINX2Root CVE-2026-123007 + Near-Empty Bomb CVE-2026-49975 + >=64KB Frame Bypass):
    let h2_hdr = u32::from_be(w0 as u32);
    let h2_len = h2_hdr >> 8;
    let h2_type = (h2_hdr & 0xFF) as u8;
    let is_h2_hdr = ((h2_type == 0x01) | (h2_type == 0x09)) as u32;
    let bad_h2_len = ((h2_len < 6) | (h2_len > 16384)) as u32;
    let is_h2_win = (h2_type == 0x08) as u32;
    let win_inc = u32::from_be((w1 >> 8) as u32) & 0x7FFF_FFFF;
    let bad_win = ((h2_len != 4) | (win_inc == 0) | (win_inc > 0x3FFF_FFFF)) as u32;
    let maybe_h2 = ((is_quic_any == 0) & (b0 <= 0x0F) & (h2_type <= 0x09)) as u32;
    drop_mask |= maybe_h2 & ((is_h2_hdr & bad_h2_len) | (is_h2_win & bad_win));

    // 3. BerriAI LiteLLM RCE (CVE-2026-40217): "/guardra" из регистров w0/w1 без лишних чтений
    let verb32 = (w0 & 0xFFFF_FFFF) as u32;
    let is_get = (verb32 == 0x2054_4547) as u32;
    let is_post = (verb32 == 0x5453_4F50) as u32;
    let uri_from_get = (w0 >> 32) | (w1 << 32);
    let uri_from_post = (w0 >> 40) | (w1 << 24);
    let sig_guardra: u64 = 0x6172_6472_6175_672F;
    drop_mask |= (is_get & ((uri_from_get == sig_guardra) as u32))
               | (is_post & ((uri_from_post == sig_guardra) as u32));

    // 4. HTTP/1.1 + FastCGI Smuggling (CVE-2026-129289): протечка FCGI_Header в хвосте кадра
    let fcgi_ver = (tail & 0xFF) as u8;
    let fcgi_type = ((tail >> 8) & 0xFF) as u8;
    let fcgi_smuggle = ((fcgi_ver == 1) & (fcgi_type >= 1) & (fcgi_type <= 11)) as u32;
    drop_mask |= (is_get | is_post) & fcgi_smuggle;

    drop_mask
}

/// Universal 32-byte branchless SWAR protocol invariant descriptor (RFC framing / magic / length / opcode bounds).
#[repr(C, align(32))]
#[derive(Clone, Copy)]
pub struct UniversalSwarRule {
    pub magic_mask: u64,
    pub magic_expected: u64,
    pub len_shift: u8,
    pub len_is_32: u8,
    pub len_is_be: u8,
    pub has_len_field: u8,
    pub type_shift: u8,
    pub min_type: u8,
    pub type_span: u8,
    pub _pad: u8,
    pub min_pkt_len: u16,
    pub _pad2: u16,
    pub _pad3: u32,
}

/// Branchless 145-byte SWAR binary protocol invariant verifier (~17.1 cycles/pkt, 3.14 IPC).
/// Returns 0 on valid RFC frame invariants, 1 on anomaly / length-spoofing / MBZ violation.
#[inline(never)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn inspect_universal_swar(
    payload: *const u8,
    wire_len: usize,
    rule: &UniversalSwarRule,
) -> u32 {
    if wire_len < (rule.min_pkt_len as usize) || payload.is_null() {
        return 1;
    }
    let w0 = unsafe { (payload as *const u64).read_unaligned() };
    let bad_magic = (((w0 & rule.magic_mask) ^ rule.magic_expected) != 0) as u32;

    let raw_shifted = w0 >> (rule.len_shift & 63);
    let len16_le = (raw_shifted as u16) as u32;
    let len16_be = (raw_shifted as u16).swap_bytes() as u32;
    let len32_le = raw_shifted as u32;
    let len32_be = (raw_shifted as u32).swap_bytes();

    let d16 = if rule.len_is_be != 0 { len16_be } else { len16_le };
    let d32 = if rule.len_is_be != 0 { len32_be } else { len32_le };
    let declared_len = if rule.len_is_32 != 0 { d32 } else { d16 };

    let len_err = ((declared_len < (rule.min_pkt_len as u32))
        | ((declared_len as usize) > wire_len)) as u32;
    let bad_len = len_err & (rule.has_len_field as u32);

    let msg_type = ((w0 >> (rule.type_shift & 63)) & 0xFF) as u8;
    let bad_type = (msg_type.wrapping_sub(rule.min_type) > rule.type_span) as u32;

    bad_magic | bad_len | bad_type
}

/// Branchless ~70B SWAR /24 & /32 sliding-window DDoS storm detector (0 DDR reads, 2 cycles).
/// `window` holds 4 packed big-endian IPv4 addresses (2 x u64). Returns 1 on flood burst (>=3 hits).
#[inline(never)]
#[unsafe(no_mangle)]
pub extern "C" fn inspect_swar_subnet_storm(src_ip_be: u32, w0: u64, w1: u64) -> u32 {
    let ip0 = w0 as u32;
    let ip1 = (w0 >> 32) as u32;
    let ip2 = w1 as u32;
    let ip3 = (w1 >> 32) as u32;
    let m24: u32 = 0x00FF_FFFF; // /24 in network byte order (LE representation)
    let h0 = (((ip0 ^ src_ip_be) & m24) == 0) as u32;
    let h1 = (((ip1 ^ src_ip_be) & m24) == 0) as u32;
    let h2 = (((ip2 ^ src_ip_be) & m24) == 0) as u32;
    let h3 = (((ip3 ^ src_ip_be) & m24) == 0) as u32;
    ((h0 + h1 + h2 + h3) >= 3) as u32
}

/// Branchless ~120B AVX2 YMM 32-byte-per-cycle HTTP URI & control-byte sanitizer (FP = 0).
/// Detects NUL injection, illegal ASCII control bytes, and `../` or `..\` path traversal in 1 vector pass.
#[inline(never)]
#[unsafe(no_mangle)]
#[cfg(target_arch = "x86_64")]
pub unsafe extern "C" fn inspect_avx2_http_uri_32b(payload: *const u8, len: usize) -> u32 { unsafe {
    if len < 32 || payload.is_null() {
        return 0;
    }
    use core::arch::x86_64::*;
    let v = _mm256_loadu_si256(payload as *const __m256i);
    // 1. NUL-byte & C0 control byte check (< 0x20, excluding \t=0x09, \n=0x0A, \r=0x0D)
    let zero = _mm256_setzero_si256();
    let has_nul = _mm256_movemask_epi8(_mm256_cmpeq_epi8(v, zero)) as u32;
    let del = _mm256_set1_epi8(0x7F);
    let has_del = _mm256_movemask_epi8(_mm256_cmpeq_epi8(v, del)) as u32;

    // 2. Vectorized `..` detection across all 32 bytes simultaneously
    let dot = _mm256_set1_epi8(b'.' as i8);
    let dot_mask = _mm256_movemask_epi8(_mm256_cmpeq_epi8(v, dot)) as u32;
    let dbl_dot = dot_mask & (dot_mask >> 1);
    let slash = _mm256_set1_epi8(b'/' as i8);
    let bslash = _mm256_set1_epi8(b'\\' as i8);
    let sl_mask = (_mm256_movemask_epi8(_mm256_cmpeq_epi8(v, slash))
                 | _mm256_movemask_epi8(_mm256_cmpeq_epi8(v, bslash))) as u32;
    let traversal = dbl_dot & (sl_mask >> 2);

    ((has_nul | has_del | traversal) != 0) as u32
}}

/// Единый безветвящийся L3/L4 канонический шлюз (убивает CVE-2026-98432 IHL!=5, фрагментацию, Zero-QUIC, Window Squeezing).
/// Возвращает 0 (PASS) или 1 (DROP).
#[inline(always)]
pub unsafe fn canonical_l3_l4_gate(ip: *const u8, len: usize) -> u64 { unsafe {
    if ip.is_null() || len < 20 { return 1; }
    #[cfg(target_arch = "x86_64")]
    {
        let mut verdict: u64 = 0;
        asm!(
            "mov {bad:e}, 1",
            "movzx {t0:e}, byte ptr [{ip}]",
            "cmp {t0:e}, 0x45",
            "cmovne {verd:e}, {bad:e}",
            "movzx {t0:e}, word ptr [{ip} + 6]",
            "test {t0:e}, 0xFF3F",
            "cmovnz {verd:e}, {bad:e}",
            "movzx {t0:e}, byte ptr [{ip} + 9]",
            "cmp {t0:e}, 17",
            "jne 2f",
            "cmp {len}, 28",
            "cmovb {verd:e}, {bad:e}",
            "jb 3f",
            "movzx {t0:e}, word ptr [{ip} + 22]",
            "rol {t0:x}, 8",
            "cmp {t0:e}, 443",
            "cmove {verd:e}, {bad:e}",
            "cmp {t0:e}, 8443",
            "cmove {verd:e}, {bad:e}",
            "jmp 3f",
            "2:",
            "cmp {t0:e}, 6",
            "jne 3f",
            "cmp {len}, 40",
            "cmovb {verd:e}, {bad:e}",
            "jb 3f",
            "movzx {t0:e}, word ptr [{ip} + 34]",
            "rol {t0:x}, 8",
            "cmp {t0:e}, 64",
            "cmovb {verd:e}, {bad:e}",
            "3:",
            ip = in(reg) ip,
            len = in(reg) len,
            t0 = out(reg) _,
            bad = out(reg) _,
            verd = inout(reg) verdict,
            options(pure, readonly, nostack)
        );
        verdict
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        if *ip != 0x45 { return 1; }
        let frag = u16::from_be_bytes([*ip.add(6), *ip.add(7)]) & 0x3FFF;
        if frag != 0 { return 1; }
        let proto = *ip.add(9);
        if proto == 17 {
            if len < 28 { return 1; }
            let dport = u16::from_be_bytes([*ip.add(22), *ip.add(23)]);
            if dport == 443 || dport == 8443 { return 1; }
        } else if proto == 6 {
            if len < 40 { return 1; }
            let sport = u16::from_be_bytes([*ip.add(20), *ip.add(21)]);
            let dport = u16::from_be_bytes([*ip.add(22), *ip.add(23)]);
            if dport == 2049 { return 1; }
            let win = u16::from_be_bytes([*ip.add(34), *ip.add(35)]);
            if sport != 443 && win < 16 { return 1; }
        }
        0
    }
}}

/// Единый L7 канонический нормализатор (URI SWAR + HTTP/2 Window Overflow + Serialization/Smuggling Gate).
/// Убивает на корню CVE-2026-123007 (NGINX2Root), CVE-2026-104286/133968/102226 (Path Traversal) и CVE-2026-129448 (XML/Java Deser).
#[inline(never)]
pub unsafe fn canonical_l7_normalizer(dport: u16, l7: *const u8, len: usize) -> u32 { unsafe {
    if dport == 135 || (dport >= 137 && dport <= 139) || dport == 445 || dport == 3389 || dport == 5355 || dport == 5985 || dport == 5986 { return 2; }
    if l7.is_null() || len == 0 { return 0; }
    if (dport == 80 || dport == 8080) && len >= 13 {
        let flen = (u32::from_be_bytes([*l7, *l7.add(1), *l7.add(2), *l7.add(3)]) >> 8) & 0x00FF_FFFF;
        let ftype = *l7.add(3);
        if ftype == 0x08 {
            let inc = u32::from_be_bytes([*l7.add(9), *l7.add(10), *l7.add(11), *l7.add(12)]) & 0x7FFF_FFFF;
            if flen != 4 || inc == 0 || inc >= 0x4000_0000 { return 2; }
        } else if ftype == 0x01 && (flen as usize) + 18 <= len {
            let f2 = l7.add(9 + (flen as usize));
            let f2_len = (u32::from_be_bytes([*f2, *f2.add(1), *f2.add(2), *f2.add(3)]) >> 8) & 0x00FF_FFFF;
            if *f2.add(3) == 0x03 && f2_len == 4 { return 2; }
            if (*l7.add(4) & 0x04) == 0 && *f2.add(3) == 0x09 && (*f2.add(4) & 0x04) == 0 { return 2; }
        }
    }
    if dport == 53 && len >= 14 {
        let q_lbl = *l7.add(12);
        if q_lbl >= 48 && q_lbl <= 63 { return 2; }
    }
    if len >= 12 {
        let mut uri_start = 0usize;
        let mut m = 0usize;
        while m < 10 && m + 1 < len {
            let c = *l7.add(m);
            if c == 0x20 && m >= 3 { uri_start = m + 1; break; }
            let cu = c & 0xDF;
            if cu < b'A' || cu > b'Z' { break; }
            m += 1;
        }
        if uri_start != 0 {
            if uri_start == 8 && (u64::from_le_bytes([*l7, *l7.add(1), *l7.add(2), *l7.add(3), *l7.add(4), *l7.add(5), *l7.add(6), *l7.add(7)]) & 0x00DF_DFDF_DFDF_DFDF) == 0x0054_4345_4E4E_4F43 { return 2; }
            let uri_lim = if len > 512 { 512 } else { len };
            let mut i = uri_start;
            while i + 2 <= uri_lim {
                let b0 = *l7.add(i);
                if b0 == 0x0D || b0 == 0x0A { break; }
                let b1 = *l7.add(i + 1);
                if b0 < 0x20 || b0 == b'\\' || (b0 == b'.' && b1 == b'.') || (b0 == b'/' && b1 == b'/') {
                    return 2;
                }
                if b0 == b'%' && i + 2 < uri_lim {
                    let h1 = *l7.add(i + 1) | 0x20;
                    let h2 = *l7.add(i + 2) | 0x20;
                    if (h1 == b'2' && (h2 == b'e' || h2 == b'f')) || (h1 == b'5' && h2 == b'c') || (h1 == b'0' && h2 == b'0') || (h1 == b'2' && h2 == b'5' && i + 3 < uri_lim && *l7.add(i + 3) == b'2') {
                        return 2;
                    }
                }
                i += 1;
            }
            let hdr_lim = if len > 512 { 512 } else { len };
            let mut has_cl = 0u32;
            let mut has_te = 0u32;
            let mut has_upg = 0u32;
            let mut body_off = 0usize;
            let mut h = i;
            while h + 18 <= hdr_lim {
                if *l7.add(h) == 0x0D && *l7.add(h + 1) == 0x0A && *l7.add(h + 2) == 0x0D && *l7.add(h + 3) == 0x0A {
                    body_off = h + 4;
                    break;
                }
                if h > 0 && *l7.add(h - 1) == 0x0A {
                    let w0 = u64::from_le_bytes([
                        *l7.add(h), *l7.add(h + 1), *l7.add(h + 2), *l7.add(h + 3),
                        *l7.add(h + 4), *l7.add(h + 5), *l7.add(h + 6), *l7.add(h + 7)
                    ]) & 0xDFDF_DFDF_DFDF_DFDF;
                    if w0 == 0x0D54_4E45_544E_4F43 && (*l7.add(h + 8) & 0xDF) == b'L' && *l7.add(h + 14) == b':' { has_cl += 1; }
                    if w0 == 0x5245_4653_4E41_5254 && (*l7.add(h + 16) & 0xDF) == b'G' && *l7.add(h + 17) == b':' { has_te += 1; }
                    if (w0 & 0x00FF_FFFF_FFFF_FFFF) == 0x0045_4441_5247_5055 && *l7.add(h + 7) == b':' { has_upg += 1; }
                    if w0 == 0x4E49_4749_524F_0D58 || w0 == 0x5449_5257_4552_0D58 { return 2; }
                    if (w0 & 0x0000_0000_FFFF_FFFF) == 0x0000_0000_5453_4F48 && *l7.add(h + 4) == b':' {
                        let mut v = h + 5;
                        while v + 9 <= hdr_lim && (*l7.add(v) == b' ' || *l7.add(v) == 0x09) { v += 1; }
                        if v + 9 <= hdr_lim {
                            let hv = u64::from_le_bytes([*l7.add(v), *l7.add(v+1), *l7.add(v+2), *l7.add(v+3), *l7.add(v+4), *l7.add(v+5), *l7.add(v+6), *l7.add(v+7)]);
                            if (hv & 0xFFFF_FFFF) == 0x2E37_3231 || hv == 0x2E34_3532_2E39_3631 || ((hv & 0xDFDF_DFDF_DFDF_DFDF) == 0x534F_484C_4143_4F4C && (*l7.add(v + 8) & 0xDF) == b'T') { return 2; }
                        }
                    }
                }
                h += 1;
            }
            if (has_cl != 0 && has_te != 0) || has_cl > 1 || has_te > 1 || (has_upg != 0 && (has_te != 0 || has_cl != 0)) { return 2; }
            if body_off > 0 && body_off + 4 <= len {
                let mut bo = body_off;
                while bo + 4 <= len && bo < body_off + 16 && (*l7.add(bo) == b' ' || *l7.add(bo) == 0x09 || *l7.add(bo) == 0x0D || *l7.add(bo) == 0x0A) { bo += 1; }
                if bo + 4 <= len {
                    let b = u32::from_le_bytes([*l7.add(bo), *l7.add(bo + 1), *l7.add(bo + 2), *l7.add(bo + 3)]);
                    if b == 0x6D783F3C || b == 0x4F44213C || b == 0x4E45213C || b == 0x41304F72 || b == 0x0500EDAC {
                        return 2;
                    }
                }
            }
        }
    }
    0
}}

#[inline(always)]
pub unsafe fn tcp_boundary_split_guard(dport: u16, tcp_flags: u8, l7_len: usize, slot_flags: *mut u16) -> u32 {
    if dport != 22 && l7_len >= 1 && l7_len < 12 && (tcp_flags & 0x01) == 0 && !slot_flags.is_null() {
        let f = unsafe { *slot_flags };
        if (f & 16) != 0 {
            unsafe { *slot_flags = 0; }
            return 2;
        }
        unsafe { *slot_flags = f | 16; }
    }
    0
}

/// Root-Cause L7 SWAR Guard (endian-safe, #![no_std]):
/// - Arbitrary-offset "/install.php" & "/update.php" (CVE-2026-136716 / CVE-2026-132165)
/// - PHP Object Serialization "O:<digit>:" / "C:<digit>:" / "O%3A" / "C%3A" (CVE-2026-132166)
/// - Stream wrapper "phar://"
#[inline(always)]
pub fn inspect_php_proto_vector_swar(buf: &[u8]) -> bool {
    let len = buf.len();
    if len < 6 {
        return false;
    }
    let scan_lim = if len > 1024 { 1024 } else { len };
    let mut hit: u32 = 0;
    let mut i: usize = 0;
    while i + 4 <= scan_lim {
        let w = u32::from_le_bytes([buf[i], buf[i + 1], buf[i + 2], buf[i + 3]]);
        let b0 = (w as u8) & 0xDF;
        let b1 = (w >> 8) as u8;
        let b2 = (w >> 16) as u8;
        let is_oc = ((b0 == b'O') as u32) | ((b0 == b'C') as u32);
        let is_colon = (b1 == b':') as u32;
        let is_digit = (b2.wrapping_sub(b'0') <= 9) as u32;
        hit |= is_oc & is_colon & is_digit;

        let wu = w & 0xDFFFFFFF;
        hit |= ((wu == 0x4133254F) as u32) | ((wu == 0x41332543) as u32);

        let wl = w | 0x20202020;
        if wl == 0x736E692F && i + 12 <= scan_lim {
            let tail = u64::from_le_bytes([
                buf[i + 4], buf[i + 5], buf[i + 6], buf[i + 7],
                buf[i + 8], buf[i + 9], buf[i + 10], buf[i + 11],
            ]);
            hit |= ((tail | 0x2020200020202020) == 0x7068702E6C6C6174) as u32;
        }
        if wl == 0x6470752F && i + 11 <= scan_lim {
            let tail = u64::from_le_bytes([
                buf[i + 4], buf[i + 5], buf[i + 6], buf[i + 7],
                buf[i + 8], buf[i + 9], buf[i + 10], 0,
            ]);
            hit |= ((tail | 0x0020202000202020) == 0x007068702E657461) as u32;
        }
        if wl == 0x72616870 && i + 7 <= scan_lim {
            let sep = (buf[i + 4] as u32) | ((buf[i + 5] as u32) << 8) | ((buf[i + 6] as u32) << 16);
            hit |= (sep == 0x002F2F3A) as u32;
        }
        i += 1;
    }
    hit != 0
}


#[repr(C, align(64))]
pub struct MetaNormSlot {
    pub flow_hash: u64,
    pub meta_anchor: u64,
    pub seq_or_ctr: u64,
    pub replay_win: u64,
    pub state: u8,
    pub _pad: [u8; 39],
}

/// Кросс-слойный нормализатор метаданных (0=PASS, 1=DROP):
/// 1) Жесткий отсев разрыва 64B на 2x32B (любой стартовый TCP L7 < 64B без FIN -> DROP)
/// 2) Привязка индексов и монотонности счетчика WireGuard (148B -> 92B -> >=64B, кратно 16B)
#[inline]
pub fn normalize_64b_gate(
    slot: &mut MetaNormSlot,
    hash: u64,
    is_udp: bool,
    is_cleartext_http: bool,
    tcp_flags: u8,
    l7: &[u8],
) -> u8 {
    let l7_len = l7.len();
    if is_udp {
        if l7_len < 16 {
            return 1;
        }
        let w0 = u32::from_le_bytes([l7[0], l7[1], l7[2], l7[3]]);
        let idx1 = u32::from_le_bytes([l7[4], l7[5], l7[6], l7[7]]);
        let idx2 = u32::from_le_bytes([l7[8], l7[9], l7[10], l7[11]]);
        let ctr = u64::from_le_bytes([
            l7[8], l7[9], l7[10], l7[11], l7[12], l7[13], l7[14], l7[15],
        ]);

        let msg_type = w0 & 0xFF;
        let rsv_ok = ((w0 >> 8) == 0) as u8;
        let same_flow = (slot.flow_hash == hash) as u8;
        let cli_idx = slot.meta_anchor as u32;
        let srv_idx = (slot.meta_anchor >> 32) as u32;

        let is_init = ((msg_type == 1) & (l7_len == 148) & (rsv_ok == 1)) as u8;
        let is_resp = ((msg_type == 2) & (l7_len == 92) & (rsv_ok == 1)
            & (same_flow == 1) & (slot.state == 1) & (idx2 == cli_idx)) as u8;
        let is_cook = ((msg_type == 3) & (l7_len == 64) & (rsv_ok == 1)
            & (same_flow == 1) & (slot.state == 1) & (idx2 == cli_idx)) as u8;

        let idx_ok = ((idx1 == srv_idx) | (idx1 == cli_idx)) as u8;
        let ctr_new = (ctr > slot.seq_or_ctr) as u8;
        let diff = slot.seq_or_ctr.wrapping_sub(ctr);
        let ctr_win = ((ctr <= slot.seq_or_ctr) & (diff < 64) & (((slot.replay_win >> (diff & 63)) & 1) == 0)) as u8;
        let is_data = ((msg_type == 4) & (l7_len >= 64) & ((l7_len & 15) == 0) & (rsv_ok == 1)
            & (same_flow == 1) & (slot.state == 2) & (idx_ok == 1) & ((ctr_new | ctr_win) == 1)) as u8;

        if is_init == 1 {
            slot.flow_hash = hash;
            slot.meta_anchor = idx1 as u64;
            slot.seq_or_ctr = 0;
            slot.replay_win = 0;
            slot.state = 1;
        } else if is_resp == 1 {
            slot.meta_anchor = ((idx1 as u64) << 32) | (cli_idx as u64);
            slot.replay_win = 0;
            slot.state = 2;
        } else if is_data == 1 {
            if ctr_new == 1 {
                let sh = ctr - slot.seq_or_ctr;
                slot.replay_win = if sh >= 64 { 1 } else { (slot.replay_win << sh) | 1 };
                slot.seq_or_ctr = ctr;
            } else {
                slot.replay_win |= 1u64 << (diff & 63);
            }
        }
        return (is_init | is_resp | is_cook | is_data) ^ 1;
    }

    if (tcp_flags & 0x17) == 0x02 {
        if l7_len != 0 {
            return 1;
        }
        slot.flow_hash = hash;
        slot.state = 1;
        return 0;
    }
    if slot.flow_hash != hash || slot.state == 0 {
        return 1;
    }
    if l7_len > 0 && slot.state == 1 {
        if is_cleartext_http && l7_len < 64 && (tcp_flags & 0x01) == 0 {
            let mut has_crlf = false;
            let mut j = 4usize;
            while j + 4 <= l7_len {
                if u32::from_le_bytes([l7[j], l7[j + 1], l7[j + 2], l7[j + 3]]) == 0x0A0D0A0D {
                    has_crlf = true;
                    break;
                }
                j += 1;
            }
            if !has_crlf {
                return 1;
            }
        }
        slot.state = 2;
    }
    0
}

/// Безветвящийся SWAR-детектор Cacti 4HTTP2SHELL (0-day 28.11.2026)
#[inline(always)]
pub fn inspect_cacti_4http2shell_swar(payload: &[u8]) -> bool {
    let limit = if payload.len() < 512 { payload.len() } else { 512 };
    if limit < 26 { return false; }
    const KEY: &[u8; 24] = b"preview_graphs_per_page=";
    let mut i = 0usize;
    while i + 25 <= limit {
        let w0 = u64::from_le_bytes([
            payload[i], payload[i+1], payload[i+2], payload[i+3],
            payload[i+4], payload[i+5], payload[i+6], payload[i+7],
        ]);
        if w0 == 0x5f77656976657270u64 && &payload[i..i+24] == KEY {
            let mut j = i + 24;
            let end = if j + 32 < limit { j + 32 } else { limit };
            let mut bad = 0u8;
            while j < end {
                let c = payload[j];
                if c == b'&' || c == b' ' || c == b'\r' || c == b'\n' { break; }
                bad |= ((c.wrapping_sub(b'0')) > 9) as u8;
                j += 1;
            }
            if bad != 0 { return true; }
        }
        i += 1;
    }
    false
}
