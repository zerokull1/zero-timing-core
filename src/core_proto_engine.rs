// ZEROMANI (zerokull1) | 0x5A45524F4D414E49ULL
#[allow(dead_code)]
use core::arch::asm;
use core::ptr::read_unaligned;

/// Единый безветвящийся инспектор 9 протоколов в #![no_std] ядре (HTTP/2, Modbus, DNS, NTP, SMBv3, SSH-2, BGP/VXLAN, LDAP/KRB, RoCEv2)
#[no_mangle]
pub unsafe extern "C" fn zero_core_inspect_proto_l7(dport: u16, ptr: *const u8, len: usize) -> u32 {
    if len < 12 || ptr.is_null() {
        return 1;
    }
    unsafe {
        let q0: u64 = read_unaligned(ptr as *const u64);
        let q1: u64 = if len >= 16 { read_unaligned(ptr.add(8) as *const u64) } else { 0 };
        let mut drop: u32 = 0;
        let one: u32 = 1;

        match dport {
            443 | 8080 => {
                let ftype = (q0 >> 24) as u8;
                let flen = (((q0 & 0xFF) as u32) << 16) | ((((q0 >> 8) & 0xFF) as u32) << 8) | (((q0 >> 16) & 0xFF) as u32);
                asm!("cmp {ft}, 0x03\n\tcmove {d:e}, {one:e}\n\tcmp {fl:e}, 16384\n\tcmova {d:e}, {one:e}",
                     d = inout(reg) drop, ft = in(reg_byte) ftype, fl = in(reg) flen, one = in(reg) one, options(pure, nomem, nostack));
            }
            502 => {
                let proto_id = (q0 >> 16) as u16;
                asm!("test {pid:x}, {pid:x}\n\tcmovne {d:e}, {one:e}",
                     d = inout(reg) drop, pid = in(reg) proto_id, one = in(reg) one, options(pure, nomem, nostack));
            }
            53 => {
                let flags_hi = (q0 >> 16) as u8;
                let qname_len = (q1 >> 32) as u8;
                asm!("test {fh}, 0x80\n\tcmovne {d:e}, {one:e}\n\tcmp {ql}, 63\n\tcmova {d:e}, {one:e}",
                     d = inout(reg) drop, fh = in(reg_byte) flags_hi, ql = in(reg_byte) qname_len, one = in(reg) one, options(pure, nomem, nostack));
            }
            123 => {
                let mode = (q0 & 0x07) as u8;
                asm!("cmp {m}, 6\n\tcmovae {d:e}, {one:e}",
                     d = inout(reg) drop, m = in(reg_byte) mode, one = in(reg) one, options(pure, nomem, nostack));
            }
            445 => {
                let smb_hdr = (q0 >> 32) as u32;
                asm!("cmp {s:e}, 0x424D53FC\n\tcmove {d:e}, {one:e}",
                     d = inout(reg) drop, s = in(reg) smb_hdr, one = in(reg) one, options(pure, nomem, nostack));
            }
            22 => {
                let banner: u64 = 0x2d302e322d485353;
                asm!("cmp {q}, {b}\n\tcmovne {d:e}, {one:e}",
                     d = inout(reg) drop, b = in(reg) banner, q = in(reg) q0, one = in(reg) one, options(pure, nomem, nostack));
            }
            4789 => {
                let vx = q0 as u32;
                asm!("cmp {v:e}, 0x00000008\n\tcmove {d:e}, {one:e}",
                     d = inout(reg) drop, v = in(reg) vx, one = in(reg) one, options(pure, nomem, nostack));
            }
            179 => {
                let bgp_mark: u64 = !0u64;
                asm!("cmp {q}, {m}\n\tcmovne {d:e}, {one:e}",
                     d = inout(reg) drop, m = in(reg) bgp_mark, q = in(reg) q0, one = in(reg) one, options(pure, nomem, nostack));
            }
            389 | 88 => {
                let ber = (q0 >> 8) as u8;
                asm!("cmp {b}, 0x84\n\tcmove {d:e}, {one:e}",
                     d = inout(reg) drop, b = in(reg_byte) ber, one = in(reg) one, options(pure, nomem, nostack));
            }
            4791 => {
                let op = q0 as u8;
                drop |= (op >= 0x06 && op <= 0x0B) as u32;
            }
            _ => {}
        }
        drop
    }
}
