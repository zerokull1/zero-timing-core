// ZEROMANI (zerokull1) | 0x5A45524F4D414E49ULL
#![allow(dead_code)]

use crate::arch::{self, sysno};

const PROT_RW: u64          = 0x3;
const MAP_PRIV_ANON: u64    = 0x22;
const MAP_LOCKED: u64       = 0x2000;
const MAP_HUGETLB: u64      = 0x40000;
const MAP_HUGE_2MB: u64     = 21 << 26;
const MPOL_BIND: u64        = 2;
const MPOL_MF_MOVE: u64     = 1 << 1;

#[inline(always)]
unsafe fn raw_sys_mmap(len: usize, flags: u64) -> isize { unsafe {
    arch::sys_mmap_anon_or_fd(0, len, PROT_RW, flags, -1, 0)
}}

#[inline(always)]
pub unsafe fn bind_memory_to_numa_node(ptr: *mut u8, len: usize, numa_node: u32) -> bool { unsafe {
    let nodemask: u64 = 1u64 << (numa_node & 63);
    arch::syscall6(sysno::SYS_MBIND, ptr as u64, len as u64, MPOL_BIND, (&nodemask as *const u64) as u64, 64, MPOL_MF_MOVE) == 0
}}

#[inline(always)]
pub unsafe fn prefault_ddr_cachelines(ptr: *mut u8, len: usize) { unsafe {
    if ptr.is_null() || len == 0 { return; }
    let mut offset = 0usize;
    while offset < len {
        core::ptr::write_volatile(ptr.add(offset), 0u8);
        offset += 64;
    }
    arch::full_fence();
}}

#[inline(always)]
pub unsafe fn alloc_huge_numa_ring(size_bytes: usize, numa_node: u32) -> (*mut u8, bool) { unsafe {
    let aligned_len = (size_bytes + 0x1F_FFFF) & !0x1F_FFFF;
    let huge_ptr = raw_sys_mmap(aligned_len, MAP_PRIV_ANON | MAP_HUGETLB | MAP_HUGE_2MB);
    if huge_ptr > 0 && (huge_ptr as usize) < 0xFFFF_FFFF_FFFF_0000 {
        let p = huge_ptr as *mut u8;
        let _ = bind_memory_to_numa_node(p, aligned_len, numa_node);
        prefault_ddr_cachelines(p, aligned_len);
        return (p, true);
    }
    let std_ptr = raw_sys_mmap(aligned_len, MAP_PRIV_ANON | MAP_LOCKED);
    if std_ptr > 0 && (std_ptr as usize) < 0xFFFF_FFFF_FFFF_0000 {
        let p = std_ptr as *mut u8;
        let _ = bind_memory_to_numa_node(p, aligned_len, numa_node);
        prefault_ddr_cachelines(p, aligned_len);
        return (p, false);
    }
    (core::ptr::null_mut(), false)
}}

#[inline(always)]
pub unsafe fn free_huge_numa_ring(ptr: *mut u8, size_bytes: usize) -> bool { unsafe {
    if ptr.is_null() || size_bytes == 0 { return false; }
    let aligned_len = (size_bytes + 0x1F_FFFF) & !0x1F_FFFF;
    arch::syscall2(sysno::SYS_MUNMAP, ptr as u64, aligned_len as u64) == 0
}}
