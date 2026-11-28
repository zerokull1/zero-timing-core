#![allow(clippy::missing_safety_doc)]
// ZEROMANI (zerokull1) | 0x5A45524F4D414E49ULL
#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

pub extern crate zero_hal;
pub mod tsc;
pub mod l7_shield;
pub mod thin_hypervisor;
pub mod bpf_control;
pub mod af_xdp_engine;
pub mod adaptive_gateway;
pub mod flow_table;
pub mod telemetry_shm;
pub mod topology_placer;
pub mod pulse_barrier;
pub mod work_stealer;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memcpy(dst: *mut core::ffi::c_void, src: *const core::ffi::c_void, count: usize) -> *mut core::ffi::c_void {
    unsafe {
        #[cfg(target_arch = "x86_64")]
        core::arch::asm!(
            "cld",
            "rep movsb",
            inout("rdi") dst => _,
            inout("rsi") src => _,
            inout("rcx") count => _,
            options(nostack)
        );
        #[cfg(not(target_arch = "x86_64"))]
        {
            let (d, s) = (dst as *mut u8, src as *const u8);
            let mut i = 0usize;
            while i < count {
                *d.add(i) = *s.add(i);
                i += 1;
            }
        }
    }
    dst
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memset(dst: *mut core::ffi::c_void, val: i32, count: usize) -> *mut core::ffi::c_void {
    unsafe {
        #[cfg(target_arch = "x86_64")]
        core::arch::asm!(
            "cld",
            "rep stosb",
            inout("rdi") dst => _,
            in("al") val as u8,
            inout("rcx") count => _,
            options(nostack)
        );
        #[cfg(not(target_arch = "x86_64"))]
        {
            let d = dst as *mut u8;
            let mut i = 0usize;
            while i < count {
                *d.add(i) = val as u8;
                i += 1;
            }
        }
    }
    dst
}

#[repr(C, align(64))]
pub struct ZeroTransitState {
    pub flow_slot: l7_shield::MetaNormSlot,
    pub rx_total: u64,
    pub passed: u64,
    pub dropped: u64,
    pub banned: u64,
}

impl ZeroTransitState {
    pub const fn new() -> Self {
        Self {
            flow_slot: l7_shield::MetaNormSlot {
                flow_hash: 0, meta_anchor: 0, seq_or_ctr: 0,
                replay_win: 0, state: 0, _pad: [0; 39],
            },
            rx_total: 0, passed: 0, dropped: 0, banned: 0,
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn zero_bare_metal_transit_step(
    state: *mut ZeroTransitState,
    frame: *const u8,
    frame_len: usize,
) -> u32 {
    unsafe {
        if state.is_null() || frame.is_null() || frame_len < 34 { return 1; }
        let st = &mut *state;
        st.rx_total = st.rx_total.wrapping_add(1);
        let mut off = 12usize;
        let mut etype = u16::from_be_bytes([*frame.add(off), *frame.add(off + 1)]);
        off += 2;
        let mut vdepth = 0u8;
        while etype == 0x8100 || etype == 0x88A8 {
            vdepth += 1;
            if vdepth > 2 || off + 4 > frame_len { st.dropped += 1; return 1; }
            let tci = u16::from_be_bytes([*frame.add(off), *frame.add(off + 1)]);
            if (tci & 0x0FFF) == 0 { st.dropped += 1; return 1; }
            etype = u16::from_be_bytes([*frame.add(off + 2), *frame.add(off + 3)]);
            off += 4;
        }
        if etype == 0x88B5 { st.passed += 1; return 0; }
        if etype != 0x0800 || off + 20 > frame_len { st.dropped += 1; return 1; }
        let ip = frame.add(off);
        let ip_len = frame_len - off;
        if l7_shield::canonical_l3_l4_gate(ip, ip_len) != 0 { st.dropped += 1; return 1; }
        if *ip.add(9) != 6 { st.passed += 1; return 0; }
        let doff = ((*ip.add(32) >> 4) as usize) * 4;
        if doff < 20 || 20 + doff > ip_len { st.dropped += 1; return 1; }
        let dport = u16::from_be_bytes([*ip.add(22), *ip.add(23)]);
        let l7_ptr = ip.add(20 + doff);
        let l7_len = ip_len - 20 - doff;
        let l7_s = core::slice::from_raw_parts(l7_ptr, l7_len);
        if l7_shield::canonical_l7_normalizer(dport, l7_ptr, l7_len) != 0
            || l7_shield::inspect_php_proto_vector_swar(l7_s)
            || l7_shield::inspect_cacti_4http2shell_swar(l7_s)
        {
            st.banned += 1;
            return 2;
        }
        st.passed += 1;
        0
    }
}
