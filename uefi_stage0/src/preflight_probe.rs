#![allow(dead_code)]
use core::arch::asm;

#[repr(C)]
pub struct PreflightReport {
    pub cpu_brand: [u8; 48],
    pub apic_id: u32,
    pub has_avx2: bool,
    pub has_intel_cat: bool,
    pub l3_cat_mask0: u64,
    pub vmx_unlocked: bool,
    pub ept_supported: bool,
    pub found_x520_da2: bool,
    pub found_tesla_p40: bool,
    pub p40_above_4g_ok: bool,
    pub cycles_per_frame: u64,
}

#[inline(always)]
unsafe fn outb(port: u16, val: u8) {
    asm!("out dx, al", in("dx") port, in("al") val, options(nomem, nostack, preserves_flags));
}

#[inline(always)]
unsafe fn inb(port: u16) -> u8 {
    let val: u8;
    asm!("in al, dx", out("al") val, in("dx") port, options(nomem, nostack, preserves_flags));
    val
}

pub unsafe fn com1_write_bytes(bytes: &[u8]) {
    for &b in bytes {
        while (inb(0x3FD) & 0x20) == 0 {}
        outb(0x3F8, b);
    }
}

pub unsafe fn com1_write_hex64(val: u64) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut buf = [0u8; 18];
    buf[0] = b'0';
    buf[1] = b'x';
    for i in 0..16 {
        let shift = (15 - i) * 4;
        buf[2 + i] = HEX[((val >> shift) & 0xF) as usize];
    }
    com1_write_bytes(&buf);
}

#[inline(always)]
unsafe fn cpuid(leaf: u32, subleaf: u32) -> (u32, u32, u32, u32) {
    let (eax, ebx, ecx, edx): (u32, u32, u32, u32);
    asm!(
        "push rbx",
        "cpuid",
        "mov {0:e}, ebx",
        "pop rbx",
        out(reg) ebx,
        inout("eax") leaf => eax,
        inout("ecx") subleaf => ecx,
        lateout("edx") edx,
        options(nomem, nostack)
    );
    (eax, ebx, ecx, edx)
}

#[inline(always)]
unsafe fn rdmsr(msr: u32) -> u64 {
    let (lo, hi): (u32, u32);
    asm!(
        "rdmsr",
        in("ecx") msr,
        out("eax") lo,
        out("edx") hi,
        options(nomem, nostack, preserves_flags)
    );
    ((hi as u64) << 32) | (lo as u64)
}

#[inline(always)]
unsafe fn rdtsc_ordered() -> u64 {
    let (lo, hi): (u32, u32);
    asm!(
        "lfence",
        "rdtsc",
        out("eax") lo,
        out("edx") hi,
        options(nomem, nostack)
    );
    ((hi as u64) << 32) | (lo as u64)
}

#[inline(always)]
unsafe fn pci_read32(bus: u8, dev: u8, func: u8, offset: u8) -> u32 {
    let addr: u32 = 0x8000_0000
        | ((bus as u32) << 16)
        | ((dev as u32) << 11)
        | ((func as u32) << 8)
        | ((offset as u32) & 0xFC);
    let val: u32;
    asm!(
        "out dx, eax",
        "mov dx, 0xCFC",
        "in eax, dx",
        in("dx") 0xCF8u16,
        in("eax") addr,
        lateout("eax") val,
        options(nomem, nostack, preserves_flags)
    );
    val
}

pub unsafe fn run_baremetal_preflight() -> PreflightReport {
    let mut rep = PreflightReport {
        cpu_brand: [0u8; 48],
        apic_id: 0,
        has_avx2: false,
        has_intel_cat: false,
        l3_cat_mask0: 0,
        vmx_unlocked: false,
        ept_supported: false,
        found_x520_da2: false,
        found_tesla_p40: false,
        p40_above_4g_ok: false,
        cycles_per_frame: 0,
    };

    for i in 0..3u32 {
        let (a, b, c, d) = cpuid(0x8000_0002 + i, 0);
        let base = (i as usize) * 16;
        rep.cpu_brand[base..base + 4].copy_from_slice(&a.to_le_bytes());
        rep.cpu_brand[base + 4..base + 8].copy_from_slice(&b.to_le_bytes());
        rep.cpu_brand[base + 8..base + 12].copy_from_slice(&c.to_le_bytes());
        rep.cpu_brand[base + 12..base + 16].copy_from_slice(&d.to_le_bytes());
    }

    let (_, ebx1, ecx1, _) = cpuid(1, 0);
    rep.apic_id = (ebx1 >> 24) & 0xFF;
    let (_, ebx7, _, _) = cpuid(7, 0);
    rep.has_avx2 = (ebx7 & (1 << 5)) != 0;

    let (max_leaf, _, _, _) = cpuid(0, 0);
    if max_leaf >= 0x10 {
        let (_, ebx10, _, _) = cpuid(0x10, 0);
        if (ebx10 & (1 << 1)) != 0 {
            rep.has_intel_cat = true;
            rep.l3_cat_mask0 = rdmsr(0xC90);
        }
    }

    if (ecx1 & (1 << 5)) != 0 {
        let feat_ctrl = rdmsr(0x3A);
        rep.vmx_unlocked = (feat_ctrl & 0x5) == 0x5 || (feat_ctrl & 0x1) == 0;
        if rep.vmx_unlocked {
            let proc2 = rdmsr(0x48B);
            rep.ept_supported = (proc2 & (1u64 << 33)) != 0;
        }
    }

    for bus in 0..=255u8 {
        for dev in 0..32u8 {
            let id0 = pci_read32(bus, dev, 0, 0x00);
            if id0 == 0xFFFF_FFFF {
                continue;
            }
            let hdr = (pci_read32(bus, dev, 0, 0x0C) >> 16) & 0xFF;
            let max_func = if (hdr & 0x80) != 0 { 8 } else { 1 };
            for func in 0..max_func {
                let vid_did = pci_read32(bus, dev, func, 0x00);
                let vid = (vid_did & 0xFFFF) as u16;
                let did = (vid_did >> 16) as u16;

                if vid == 0x8086 && did == 0x10FB {
                    rep.found_x520_da2 = true;
                }
                if vid == 0x10DE && did == 0x1B38 {
                    rep.found_tesla_p40 = true;
                    let bar1_lo = pci_read32(bus, dev, func, 0x14);
                    let bar1_hi = pci_read32(bus, dev, func, 0x18);
                    let is_64bit = ((bar1_lo >> 1) & 0x3) == 0x2;
                    rep.p40_above_4g_ok = is_64bit && (bar1_hi != 0 || (bar1_lo & 0xFFFF_FFF0) != 0);
                }
            }
        }
    }

    let mut acc: u64 = 0x5A45_524F_4D41_4E49;
    let t0 = rdtsc_ordered();
    for i in 0..1_000_000u64 {
        asm!(
            "crc32 {acc}, {val}",
            "xor {acc}, 0x1337",
            acc = inout(reg) acc,
            val = in(reg) i,
            options(nomem, nostack)
        );
    }
    let t1 = rdtsc_ordered();
    core::hint::black_box(acc);
    rep.cycles_per_frame = (t1.saturating_sub(t0)) / 1_000_000;

    rep
}

pub unsafe fn print_preflight_com1(rep: &PreflightReport) {
    com1_write_bytes(b"\r\n[ZTM-PREFLIGHT] CPU: ");
    com1_write_bytes(&rep.cpu_brand);
    com1_write_bytes(b"\r\n[ZTM-PREFLIGHT] AVX2=");
    com1_write_bytes(if rep.has_avx2 { b"OK" } else { b"NO" });
    com1_write_bytes(b" | CAT=");
    com1_write_bytes(if rep.has_intel_cat { b"OK" } else { b"NO" });
    com1_write_bytes(b" | L3_MASK0=");
    com1_write_hex64(rep.l3_cat_mask0);
    com1_write_bytes(b"\r\n[ZTM-PREFLIGHT] VMX=");
    com1_write_bytes(if rep.vmx_unlocked { b"OK" } else { b"LOCKED" });
    com1_write_bytes(b" | EPT_XO=");
    com1_write_bytes(if rep.ept_supported { b"OK" } else { b"NO" });
    com1_write_bytes(b"\r\n[ZTM-PREFLIGHT] X520-DA2=");
    com1_write_bytes(if rep.found_x520_da2 { b"FOUND" } else { b"MISSING" });
    com1_write_bytes(b" | TESLA_P40=");
    com1_write_bytes(if rep.found_tesla_p40 { b"FOUND" } else { b"MISSING" });
    com1_write_bytes(b" | ABOVE_4G=");
    com1_write_bytes(if rep.p40_above_4g_ok { b"OK" } else { b"FAIL" });
    com1_write_bytes(b"\r\n[ZTM-PREFLIGHT] L1_CYCLES_PER_FRAME=");
    com1_write_hex64(rep.cycles_per_frame);
    com1_write_bytes(b"\r\n");
}
