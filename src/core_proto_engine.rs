// ZEROMANI (zerokull1) | 0x5A45524F4D414E49ULL
#[allow(dead_code)]
use core::arch::asm;
use core::ptr::read_unaligned;

#[repr(C)]
#[derive(Copy, Clone)]
struct ProtoRule {
    port: u16,
    op: u8,     // 0=none, 1=eq_drop, 2=ne_drop, 3=gt_drop, 4=ge_drop, 5=h2, 6=dns, 7=roce
    shift: u8,
    _pad: u32,
    mask: u64,
    val: u64,
}

const EMPTY_RULE: ProtoRule = ProtoRule { port: 0, op: 0, shift: 0, _pad: 0, mask: 0, val: 0 };

// Таблица O(1) Perfect Hash ((port * 0xDAA66D13) >> 27) & 31 — 0 коллизий для всех 12 портов
const fn build_proto_table() -> [ProtoRule; 32] {
    let mut t = [EMPTY_RULE; 32];
    let items: [(u16, u8, u8, u64, u64); 12] = [
        (443,  5, 0,  0,                  0),                    // HTTP/2 Rapid Reset / Len > 16384
        (8080, 5, 0,  0,                  0),                    // HTTP/2 Alt
        (502,  2, 16, 0xFFFF,             0),                    // Modbus TCP Protocol ID != 0
        (53,   6, 0,  0,                  0),                    // DNS Reflection / Tunneling
        (123,  4, 0,  0x07,               6),                    // NTP Mode >= 6
        (445,  1, 32, 0xFFFF_FFFF,        0x424D_53FC),          // SMBv3.1.1 SMBGhost (\xFCSMB)
        (22,   2, 0,  0xFFFF_FFFF_FFFF_FFFF, 0x2d30_2e32_2d48_5353), // SSH-2.0- banner
        (4789, 1, 0,  0xFFFF_FFFF,        0x0000_0008),          // VXLAN external encap
        (179,  2, 0,  0xFFFF_FFFF_FFFF_FFFF, !0u64),             // BGP 8B marker != 0xFF..FF
        (389,  1, 8,  0xFF,               0x84),                 // LDAP ASN.1 BER 0x84
        (88,   1, 8,  0xFF,               0x84),                 // Kerberos ASN.1 BER 0x84
        (4791, 7, 0,  0xFF,               0),                    // RoCEv2 RDMA WRITE (0x06..0x0B)
    ];
    let mut i = 0;
    while i < items.len() {
        let (p, op, sh, m, v) = items[i];
        let slot = ((p as u32).wrapping_mul(0xDAA66D13) >> 27) as usize & 31;
        if t[slot].op != 0 {
            panic!("Perfect hash collision");
        }
        t[slot] = ProtoRule { port: p, op, shift: sh, _pad: 0, mask: m, val: v };
        i += 1;
    }
    t
}

static PROTO_TABLE: [ProtoRule; 32] = build_proto_table();

#[no_mangle]
pub unsafe extern "C" fn zero_core_inspect_proto_l7(dport: u16, ptr: *const u8, len: usize) -> u32 {
    unsafe { zero_core_inspect_proto_l7_ports(0, dport, ptr, len) }
}

#[no_mangle]
pub unsafe extern "C" fn zero_core_inspect_proto_l7_ports(sport: u16, dport: u16, ptr: *const u8, len: usize) -> u32 {
    if len < 12 || ptr.is_null() {
        return 1;
    }
    unsafe {
        let q0: u64 = read_unaligned(ptr as *const u64);
        let q1: u64 = if len >= 16 { read_unaligned(ptr.add(8) as *const u64) } else { 0 };
        let mut drop: u32 = 0;

        // O(1) проверка source port (53 / 123 Amplification) без ветвлений
        let sp_dns = (sport == 53) as u32;
        let sp_ntp = (sport == 123) as u32;
        let dns_amp = ((((q0 >> 16) as u8) & 0x80) != 0 || u16::from_be((q0 >> 48) as u16) > 8) as u32;
        let ntp_amp = (((q0 & 0x07) as u8) >= 6) as u32;
        drop |= (sp_dns & dns_amp) | (sp_ntp & ntp_amp);

        // O(1) Perfect-Hash выбор правила по dport (без таблицы переходов match dport)
        let slot = ((dport as u32).wrapping_mul(0xDAA66D13) >> 27) as usize & 31;
        let r = *PROTO_TABLE.as_ptr().add(slot);
        let port_hit = (r.port == dport) as u32;

        let extracted = (q0 >> (r.shift & 63)) & r.mask;
        let rule_trip = match r.op {
            1 => (extracted == r.val) as u32,
            2 => (extracted != r.val) as u32,
            4 => (extracted >= r.val) as u32,
            5 => {
                let ftype = (q0 >> 24) as u8;
                let flen = (((q0 & 0xFF) as u32) << 16) | ((((q0 >> 8) & 0xFF) as u32) << 8) | (((q0 >> 16) & 0xFF) as u32);
                (ftype == 0x03 || flen > 16384) as u32
            }
            6 => {
                let flags_hi = (q0 >> 16) as u8;
                let qname_len = (q1 >> 32) as u8;
                ((flags_hi & 0x80) != 0 || qname_len > 63) as u32
            }
            7 => {
                let op = (q0 & 0xFF) as u8;
                (op >= 0x06 && op <= 0x0B) as u32
            }
            _ => 0,
        };
        drop | (port_hit & rule_trip)
    }
}

/// Всеядный батч-инспектор (пачки до 64 кадров + x86_64 prefetcht0)
#[no_mangle]
pub unsafe extern "C" fn zero_core_inspect_proto_l7_batch(
    sports: *const u16,
    dports: *const u16,
    ptrs: *const *const u8,
    lens: *const usize,
    verdicts: *mut u32,
    count: usize,
) -> usize {
    if count == 0 || dports.is_null() || ptrs.is_null() || lens.is_null() || verdicts.is_null() {
        return 0;
    }
    unsafe {
        let mut blocked: usize = 0;
        let mut base: usize = 0;
        while base < count {
            let chunk = if count - base > 64 { 64 } else { count - base };
            let mut i: usize = 0;
            while i < chunk {
                let cur = base + i;
                let pf_idx = if i + 4 < chunk { cur + 4 } else { cur };
                let pf_ptr = *ptrs.add(pf_idx);
                if !pf_ptr.is_null() {
                    asm!("prefetcht0 [{}]", in(reg) pf_ptr, options(readonly, nostack, preserves_flags));
                }
                let sp = if sports.is_null() { 0 } else { *sports.add(cur) };
                let v = zero_core_inspect_proto_l7_ports(sp, *dports.add(cur), *ptrs.add(cur), *lens.add(cur));
                *verdicts.add(cur) = v;
                blocked += (v != 0) as usize;
                i += 1;
            }
            base += chunk;
        }
        blocked
    }
}
