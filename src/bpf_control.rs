// ZEROMANI (zerokull1) | 0x5A45524F4D414E49ULL
// Copyright (c) 2026 zerokull1 (https://github.com)
// Licensed under GPL-3.0. Unauthorized proprietary use is strictly prohibited.

//! Zero-dependency `no_std` Linux eBPF/XDP bytecode generator, verifier loader (`BPF_PROG_LOAD`),
//! map manager (`BPF_MAP_CREATE` / `XSKMAP`), and raw Netlink (`IFLA_XDP`) NIC attacher.

#![allow(dead_code)]

use core::arch::asm;

const SYS_SOCKET: usize = 41;
const SYS_SENDTO: usize = 44;
const SYS_CLOSE: usize = 3;
const SYS_BPF: usize = 321;

const BPF_MAP_CREATE: usize = 0;
const BPF_MAP_UPDATE_ELEM: usize = 2;
const BPF_MAP_DELETE_ELEM: usize = 3;
const BPF_PROG_LOAD: usize = 5;
const BPF_OBJ_GET: usize = 7;

const BPF_MAP_TYPE_HASH: u32 = 1;
const BPF_MAP_TYPE_ARRAY: u32 = 2;
const BPF_MAP_TYPE_XSKMAP: u32 = 17;

const BPF_PROG_TYPE_XDP: u32 = 6;

// XDP verdict codes
pub const XDP_ABORTED: i32 = 0;
pub const XDP_DROP: i32 = 1;
pub const XDP_PASS: i32 = 2;
pub const XDP_TX: i32 = 3;
pub const XDP_REDIRECT: i32 = 4;

// eBPF instruction classes & opcodes
const BPF_LD: u8 = 0x00;
const BPF_LDX: u8 = 0x01;
const BPF_ST: u8 = 0x02;
const BPF_STX: u8 = 0x03;
const BPF_ALU: u8 = 0x04;
const BPF_JMP: u8 = 0x05;
const BPF_ALU64: u8 = 0x07;

const BPF_W: u8 = 0x00;
const BPF_H: u8 = 0x08;
const BPF_B: u8 = 0x10;
const BPF_DW: u8 = 0x18;
const BPF_IMM: u8 = 0x00;
const BPF_MEM: u8 = 0x60;

const BPF_ADD: u8 = 0x00;
const BPF_MOV: u8 = 0xb0;
const BPF_JEQ: u8 = 0x10;
const BPF_JGT: u8 = 0x20;
const BPF_JNE: u8 = 0x50;
const BPF_CALL: u8 = 0x80;
const BPF_EXIT: u8 = 0x90;
const BPF_K: u8 = 0x00;
const BPF_X: u8 = 0x08;

// BPF helper IDs
const BPF_FUNC_MAP_LOOKUP_ELEM: i32 = 1;
const BPF_FUNC_REDIRECT_MAP: i32 = 51;

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct BpfInsn {
    pub code: u8,
    pub regs: u8, // dst_reg:4 | src_reg:4
    pub off: i16,
    pub imm: i32,
}

impl BpfInsn {
    #[inline(always)]
    pub const fn new(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> Self {
        Self { code, regs: (src << 4) | (dst & 0x0f), off, imm }
    }
    #[inline(always)]
    pub const fn mov64_imm(dst: u8, imm: i32) -> Self { Self::new(BPF_ALU64 | BPF_MOV | BPF_K, dst, 0, 0, imm) }
    #[inline(always)]
    pub const fn mov64_reg(dst: u8, src: u8) -> Self { Self::new(BPF_ALU64 | BPF_MOV | BPF_X, dst, src, 0, 0) }
    #[inline(always)]
    pub const fn add64_imm(dst: u8, imm: i32) -> Self { Self::new(BPF_ALU64 | BPF_ADD | BPF_K, dst, 0, 0, imm) }
    #[inline(always)]
    pub const fn ldx_mem(size: u8, dst: u8, src: u8, off: i16) -> Self { Self::new(BPF_LDX | size | BPF_MEM, dst, src, off, 0) }
    #[inline(always)]
    pub const fn stx_mem(size: u8, dst: u8, src: u8, off: i16) -> Self { Self::new(BPF_STX | size | BPF_MEM, dst, src, off, 0) }
    #[inline(always)]
    pub const fn st_mem(size: u8, dst: u8, off: i16, imm: i32) -> Self { Self::new(BPF_ST | size | BPF_MEM, dst, 0, off, imm) }
    #[inline(always)]
    pub const fn jmp_imm(op: u8, dst: u8, imm: i32, off: i16) -> Self { Self::new(BPF_JMP | op | BPF_K, dst, 0, off, imm) }
    #[inline(always)]
    pub const fn jmp_reg(op: u8, dst: u8, src: u8, off: i16) -> Self { Self::new(BPF_JMP | op | BPF_X, dst, src, off, 0) }
    #[inline(always)]
    pub const fn call(func_id: i32) -> Self { Self::new(BPF_JMP | BPF_CALL, 0, 0, 0, func_id) }
    #[inline(always)]
    pub const fn exit() -> Self { Self::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0) }

    /// Двухслотовая 64-битная загрузка файлового дескриптора карты (`BPF_PSEUDO_MAP_FD = 1`)
    #[inline(always)]
    pub const fn ld_map_fd(dst: u8, map_fd: i32) -> [Self; 2] {
        [
            Self::new(BPF_LD | BPF_DW | BPF_IMM, dst, 1, 0, map_fd),
            Self::new(0, 0, 0, 0, 0),
        ]
    }
}

#[repr(u32)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ShieldMode {
    FailOpen = 0, // BYPASS
    Monitor = 1,  // SHIELD (AF_XDP redirect)
    Enforce = 2,  // TARPIT / XDP_DROP
}

#[repr(C)]
pub struct ShieldConfig {
    pub mode: u32,
    pub block_ttl_65: u32,
    pub block_ttl_129: u32,
}

#[repr(C)]
struct BpfMapCreateAttr {
    map_type: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    map_flags: u32,
}

#[repr(C)]
struct BpfProgLoadAttr {
    prog_type: u32,
    insn_cnt: u32,
    insns: u64,
    license: u64,
    log_level: u32,
    log_size: u32,
    log_buf: u64,
    kern_version: u32,
    prog_flags: u32,
    prog_name: [u8; 16],
}

#[repr(C)]
struct BpfMapElemAttr {
    map_fd: u32,
    _pad: u32,
    key: u64,
    value: u64,
    flags: u64,
}

#[repr(C)]
struct BpfObjAttr {
    pathname: u64,
    bpf_fd: u32,
    file_flags: u32,
}

pub struct XdpKernelPipeline {
    pub prog_fd: i32,
    pub config_map_fd: i32,
    pub whitelist_map_fd: i32,
    pub xsk_map_fd: i32,
}

#[inline(always)]
unsafe fn sys_bpf(cmd: usize, attr: *const u8, size: usize) -> isize {
    let ret: isize;
    unsafe {
        asm!(
            "syscall",
            in("rax") SYS_BPF,
            in("rdi") cmd,
            in("rsi") attr,
            in("rdx") size,
            lateout("rax") ret,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack)
        );
    }
    ret
}

pub unsafe fn bpf_map_create(map_type: u32, key_size: u32, value_size: u32, max_entries: u32) -> isize {
    let attr = BpfMapCreateAttr { map_type, key_size, value_size, max_entries, map_flags: 0 };
    unsafe { sys_bpf(BPF_MAP_CREATE, &attr as *const _ as *const u8, core::mem::size_of::<BpfMapCreateAttr>()) }
}

pub unsafe fn bpf_obj_get(pinned_path_cstr: &[u8]) -> isize {
    let attr = BpfObjAttr { pathname: pinned_path_cstr.as_ptr() as u64, bpf_fd: 0, file_flags: 0 };
    unsafe { sys_bpf(BPF_OBJ_GET, &attr as *const _ as *const u8, core::mem::size_of::<BpfObjAttr>()) }
}

pub unsafe fn whitelist_add_ipv4(map_fd: u32, ipv4_be: u32) -> isize {
    let allow: u8 = 1;
    let attr = BpfMapElemAttr {
        map_fd, _pad: 0, key: &ipv4_be as *const u32 as u64, value: &allow as *const u8 as u64, flags: 0,
    };
    unsafe { sys_bpf(BPF_MAP_UPDATE_ELEM, &attr as *const _ as *const u8, core::mem::size_of::<BpfMapElemAttr>()) }
}

pub unsafe fn whitelist_del_ipv4(map_fd: u32, ipv4_be: u32) -> isize {
    let attr = BpfMapElemAttr { map_fd, _pad: 0, key: &ipv4_be as *const u32 as u64, value: 0, flags: 0 };
    unsafe { sys_bpf(BPF_MAP_DELETE_ELEM, &attr as *const _ as *const u8, core::mem::size_of::<BpfMapElemAttr>()) }
}

pub unsafe fn set_shield_mode(config_map_fd: u32, cfg: &ShieldConfig) -> isize {
    let key: u32 = 0;
    let attr = BpfMapElemAttr {
        map_fd: config_map_fd, _pad: 0, key: &key as *const u32 as u64, value: cfg as *const ShieldConfig as u64, flags: 0,
    };
    unsafe { sys_bpf(BPF_MAP_UPDATE_ELEM, &attr as *const _ as *const u8, core::mem::size_of::<BpfMapElemAttr>()) }
}

/// Компилирует и загружает eBPF-программу в верификатор ядра Linux (`BPF_PROG_TYPE_XDP`)
pub unsafe fn build_and_load_xdp_pipeline(
    log_buf: Option<&mut [u8]>,
) -> Result<XdpKernelPipeline, isize> {
    let cfg_fd = unsafe { bpf_map_create(BPF_MAP_TYPE_ARRAY, 4, core::mem::size_of::<ShieldConfig>() as u32, 1) };
    if cfg_fd < 0 { return Err(cfg_fd); }

    let wl_fd = unsafe { bpf_map_create(BPF_MAP_TYPE_HASH, 4, 1, 65536) };
    if wl_fd < 0 { return Err(wl_fd); }

    let xsk_fd = unsafe { bpf_map_create(BPF_MAP_TYPE_XSKMAP, 4, 4, 64) };
    if xsk_fd < 0 { return Err(xsk_fd); }

    let cfg_ld = BpfInsn::ld_map_fd(1, cfg_fd as i32);
    let wl_ld = BpfInsn::ld_map_fd(1, wl_fd as i32);
    let xsk_ld = BpfInsn::ld_map_fd(1, xsk_fd as i32);

    // 39 инструкций eBPF: проверка границ Ethernet+IPv4, whitelist, XDP_DROP в ENFORCE и XSKMAP redirect в SHIELD
    let insns: [BpfInsn; 39] = [
        /* 0  */ BpfInsn::mov64_reg(6, 1),                          // r6 = ctx (struct xdp_md *)
        /* 1  */ BpfInsn::ldx_mem(BPF_W, 2, 6, 0),                  // r2 = ctx->data
        /* 2  */ BpfInsn::ldx_mem(BPF_W, 3, 6, 4),                  // r3 = ctx->data_end
        /* 3  */ BpfInsn::ldx_mem(BPF_W, 7, 6, 16),                 // r7 = ctx->rx_queue_index
        /* 4  */ BpfInsn::mov64_reg(4, 2),                          // r4 = data
        /* 5  */ BpfInsn::add64_imm(4, 34),                         // r4 = data + 14 (Eth) + 20 (IPv4)
        /* 6  */ BpfInsn::jmp_reg(BPF_JGT, 4, 3, 27),               // if r4 > data_end -> goto 34 (PASS)
        /* 7  */ BpfInsn::ldx_mem(BPF_H, 5, 2, 12),                 // r5 = eth->h_proto (BE)
        /* 8  */ BpfInsn::jmp_imm(BPF_JNE, 5, 0x0008, 25),          // if != ETH_P_IP -> goto 34 (PASS)
        /* 9  */ BpfInsn::ldx_mem(BPF_W, 5, 2, 26),                 // r5 = ip->saddr
        /* 10 */ BpfInsn::stx_mem(BPF_W, 10, 5, -8),                // *(u32 *)(fp - 8) = saddr
        /* 11 */ BpfInsn::ldx_mem(BPF_B, 8, 2, 22),                 // r8 = ip->ttl
        /* 12 */ BpfInsn::st_mem(BPF_W, 10, -4, 0),                 // *(u32 *)(fp - 4) = 0
        /* 13 */ cfg_ld[0],                                         // r1 = config_map_fd (lo)
        /* 14 */ cfg_ld[1],                                         //                    (hi)
        /* 15 */ BpfInsn::mov64_reg(2, 10),                         // r2 = fp
        /* 16 */ BpfInsn::add64_imm(2, -4),                         // r2 = fp - 4
        /* 17 */ BpfInsn::call(BPF_FUNC_MAP_LOOKUP_ELEM),           // r0 = lookup(config_map, &0)
        /* 18 */ BpfInsn::jmp_imm(BPF_JEQ, 0, 0, 15),               // if r0 == NULL -> goto 34 (PASS)
        /* 19 */ BpfInsn::ldx_mem(BPF_W, 9, 0, 0),                  // r9 = cfg->mode
        /* 20 */ BpfInsn::jmp_imm(BPF_JEQ, 9, 0, 13),               // if mode == BYPASS (0) -> goto 34 (PASS)
        /* 21 */ wl_ld[0],                                          // r1 = whitelist_map_fd (lo)
        /* 22 */ wl_ld[1],                                          //                       (hi)
        /* 23 */ BpfInsn::mov64_reg(2, 10),                         // r2 = fp
        /* 24 */ BpfInsn::add64_imm(2, -8),                         // r2 = fp - 8 (&saddr)
        /* 25 */ BpfInsn::call(BPF_FUNC_MAP_LOOKUP_ELEM),           // r0 = lookup(whitelist_map, &saddr)
        /* 26 */ BpfInsn::jmp_imm(BPF_JNE, 0, 0, 7),                // if r0 != NULL -> goto 34 (PASS)
        /* 27 */ BpfInsn::jmp_imm(BPF_JNE, 9, 2, 2),                // if mode != ENFORCE (2) -> goto 30 (AF_XDP)
        /* 28 */ BpfInsn::jmp_imm(BPF_JGT, 8, 128, 7),              // if ttl > 128 -> goto 36 (DROP)
        /* 29 */ BpfInsn::jmp_imm(BPF_JEQ, 0, 0, 0),                // nop -> 30
        /* 30 */ xsk_ld[0],                                         // r1 = xsk_map_fd (lo)
        /* 31 */ xsk_ld[1],                                         //                 (hi)
        /* 32 */ BpfInsn::mov64_reg(2, 7),                          // r2 = rx_queue_index
        /* 33 */ BpfInsn::mov64_imm(3, XDP_PASS),                   // r3 = flags (fallback XDP_PASS)
        /* 34 */ BpfInsn::call(BPF_FUNC_REDIRECT_MAP),              // return bpf_redirect_map(xsk_map, q, XDP_PASS)
        /* 35 */ BpfInsn::exit(),
        /* 36 */ BpfInsn::mov64_imm(0, XDP_DROP),                   // r0 = XDP_DROP
        /* 37 */ BpfInsn::exit(),
        /* 38 */ BpfInsn::mov64_imm(0, XDP_PASS),                   // r0 = XDP_PASS (fallback)
    ];

    // Корректируем метку PASS (индекс 38 + exit = добавим exit на 39)
    let mut prog = [BpfInsn::exit(); 40];
    prog[..39].copy_from_slice(&insns);
    prog[6] = BpfInsn::jmp_reg(BPF_JGT, 4, 3, 31);        // -> 38 (PASS)
    prog[8] = BpfInsn::jmp_imm(BPF_JNE, 5, 0x0008, 29);     // -> 38 (PASS)
    prog[18] = BpfInsn::jmp_imm(BPF_JEQ, 0, 0, 19);         // -> 38 (PASS)
    prog[20] = BpfInsn::jmp_imm(BPF_JEQ, 9, 0, 17);         // -> 38 (PASS)
    prog[26] = BpfInsn::jmp_imm(BPF_JNE, 0, 0, 11);         // -> 38 (PASS)
    prog[39] = BpfInsn::exit();

    let license = b"GPL\0";
    let mut name = [0u8; 16];
    name[..13].copy_from_slice(b"zeromani_xdp\0");

    let (log_level, log_size, log_ptr) = match log_buf {
        Some(buf) => (1u32, buf.len() as u32, buf.as_mut_ptr() as u64),
        None => (0u32, 0u32, 0u64),
    };

    let attr = BpfProgLoadAttr {
        prog_type: BPF_PROG_TYPE_XDP,
        insn_cnt: prog.len() as u32,
        insns: prog.as_ptr() as u64,
        license: license.as_ptr() as u64,
        log_level,
        log_size,
        log_buf: log_ptr,
        kern_version: 0,
        prog_flags: 0,
        prog_name: name,
    };

    let prog_fd = unsafe {
        sys_bpf(BPF_PROG_LOAD, &attr as *const _ as *const u8, core::mem::size_of::<BpfProgLoadAttr>())
    };
    if prog_fd < 0 {
        return Err(prog_fd);
    }

    Ok(XdpKernelPipeline {
        prog_fd: prog_fd as i32,
        config_map_fd: cfg_fd as i32,
        whitelist_map_fd: wl_fd as i32,
        xsk_map_fd: xsk_fd as i32,
    })
}

const AF_NETLINK: usize = 16;
const SOCK_RAW: usize = 3;
const NETLINK_ROUTE: usize = 0;

const RTM_SETLINK: u16 = 19;
const NLM_F_REQUEST: u16 = 0x0001;
const NLM_F_ACK: u16 = 0x0004;

const IFLA_XDP: u16 = 43;
const NLA_F_NESTED: u16 = 1 << 15;
const IFLA_XDP_FD: u16 = 1;
const IFLA_XDP_FLAGS: u16 = 3;

pub const XDP_FLAGS_UPDATE_IF_NOEXIST: u32 = 1 << 0;
pub const XDP_FLAGS_SKB_MODE: u32 = 1 << 1;
pub const XDP_FLAGS_DRV_MODE: u32 = 1 << 2;

#[repr(C)]
struct SockaddrNl {
    nl_family: u16,
    nl_pad: u16,
    nl_pid: u32,
    nl_groups: u32,
}

#[repr(C)]
struct NlMsgHdr {
    nlmsg_len: u32,
    nlmsg_type: u16,
    nlmsg_flags: u16,
    nlmsg_seq: u32,
    nlmsg_pid: u32,
}

#[repr(C)]
struct IfInfoMsg {
    ifi_family: u8,
    _pad: u8,
    ifi_type: u16,
    ifi_index: i32,
    ifi_flags: u32,
    ifi_change: u32,
}

#[repr(C)]
struct NlAttr {
    nla_len: u16,
    nla_type: u16,
}

/// Привязывает загруженную XDP-программу (`prog_fd`) к сетевому интерфейсу (`ifindex`) через Netlink
pub unsafe fn attach_xdp_to_ifindex(ifindex: i32, prog_fd: i32, xdp_flags: u32) -> isize {
    let sock: isize;
    unsafe {
        asm!(
            "syscall",
            in("rax") SYS_SOCKET,
            in("rdi") AF_NETLINK,
            in("rsi") SOCK_RAW,
            in("rdx") NETLINK_ROUTE,
            lateout("rax") sock,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack)
        );
    }
    if sock < 0 {
        return sock;
    }

    #[repr(C)]
    struct XdpLinkReq {
        nlh: NlMsgHdr,
        ifi: IfInfoMsg,
        nested_xdp: NlAttr,
        attr_fd: NlAttr,
        fd_val: i32,
        attr_flags: NlAttr,
        flags_val: u32,
    }

    let total_len = core::mem::size_of::<XdpLinkReq>() as u32;
    let nested_len = (core::mem::size_of::<NlAttr>() * 3 + 8) as u16;
    let req = XdpLinkReq {
        nlh: NlMsgHdr {
            nlmsg_len: total_len,
            nlmsg_type: RTM_SETLINK,
            nlmsg_flags: NLM_F_REQUEST | NLM_F_ACK,
            nlmsg_seq: 1,
            nlmsg_pid: 0,
        },
        ifi: IfInfoMsg {
            ifi_family: 0,
            _pad: 0,
            ifi_type: 0,
            ifi_index: ifindex,
            ifi_flags: 0,
            ifi_change: 0,
        },
        nested_xdp: NlAttr { nla_len: nested_len, nla_type: IFLA_XDP | NLA_F_NESTED },
        attr_fd: NlAttr { nla_len: 8, nla_type: IFLA_XDP_FD },
        fd_val: prog_fd,
        attr_flags: NlAttr { nla_len: 8, nla_type: IFLA_XDP_FLAGS },
        flags_val: xdp_flags,
    };

    let dst = SockaddrNl { nl_family: AF_NETLINK as u16, nl_pad: 0, nl_pid: 0, nl_groups: 0 };
    let sent: isize;
    unsafe {
        asm!(
            "syscall",
            in("rax") SYS_SENDTO,
            in("rdi") sock,
            in("rsi") &req as *const _ as *const u8,
            in("rdx") total_len as usize,
            in("r10") 0usize,
            in("r8") &dst as *const _ as *const u8,
            in("r9") core::mem::size_of::<SockaddrNl>(),
            lateout("rax") sent,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack)
        );
        asm!(
            "syscall",
            in("rax") SYS_CLOSE,
            in("rdi") sock,
            lateout("rax") _,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack)
        );
    }
    sent
}

/// Отключает XDP-фильтр от сетевого интерфейса
pub unsafe fn detach_xdp_from_ifindex(ifindex: i32, xdp_flags: u32) -> isize {
    unsafe { attach_xdp_to_ifindex(ifindex, -1, xdp_flags) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memset(dst: *mut core::ffi::c_void, val: i32, count: usize) -> *mut core::ffi::c_void {
    unsafe {
        asm!(
            "rep stosb",
            inout("rdi") dst => _,
            inout("rcx") count => _,
            in("al") val as u8,
            options(nostack)
        );
    }
    dst
}

/// Загружает минимальную 2-инструкционную XDP-заглушку (`XDP_PASS`) для активации нативного NAPI драйвера veth
pub unsafe fn load_xdp_peer_pass() -> Result<i32, isize> {
    let insns: [BpfInsn; 2] = [
        BpfInsn::mov64_imm(0, XDP_PASS),
        BpfInsn::exit(),
    ];
    let license = b"GPL\0";
    let mut name = [0u8; 16];
    name[..13].copy_from_slice(b"zeromani_peer");
    let attr = BpfProgLoadAttr {
        prog_type: BPF_PROG_TYPE_XDP,
        insn_cnt: insns.len() as u32,
        insns: insns.as_ptr() as u64,
        license: license.as_ptr() as u64,
        log_level: 0,
        log_size: 0,
        log_buf: 0,
        kern_version: 0,
        prog_flags: 0,
        prog_name: name,
    };
    let fd = unsafe { sys_bpf(BPF_PROG_LOAD, &attr as *const _ as *const u8, core::mem::size_of::<BpfProgLoadAttr>()) };
    if fd < 0 { Err(fd) } else { Ok(fd as i32) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memcpy(dst: *mut core::ffi::c_void, src: *const core::ffi::c_void, count: usize) -> *mut core::ffi::c_void {
    unsafe {
        asm!(
            "rep movsb",
            inout("rdi") dst => _,
            inout("rsi") src => _,
            inout("rcx") count => _,
            options(nostack)
        );
    }
    dst
}
