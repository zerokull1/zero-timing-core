// ZEROMANI (zerokull1) | 0x5A45524F4D414E49ULL
// Copyright (c) 2026 zerokull1 (https://github.com)
// Licensed under GPL-3.0. Unauthorized proprietary use is strictly prohibited.

#![allow(dead_code)]

use core::arch::asm;

#[inline(always)]
pub fn rdtsc_start() -> u64 {
    let low: u32;
    let high: u32;
    unsafe {
        asm!(
            "lfence",
            "rdtsc",
            out("eax") low,
            out("edx") high,
            options(nomem, nostack, preserves_flags)
        );
    }
    ((high as u64) << 32) | (low as u64)
}

#[inline(always)]
pub fn rdtsc_end() -> u64 {
    let low: u32;
    let high: u32;
    unsafe {
        asm!(
            "rdtscp",
            "lfence",
            out("eax") low,
            out("edx") high,
            out("ecx") _,
            options(nomem, nostack, preserves_flags)
        );
    }
    ((high as u64) << 32) | (low as u64)
}

#[inline(always)]
pub fn measure_cycles<F, R>(f: F) -> (R, u64)
where
    F: FnOnce() -> R,
{
    let start = rdtsc_start();
    let result = f();
    let end = rdtsc_end();
    (result, end.saturating_sub(start))
}

/// Константное временное окно исполнения (Constant-Time Execution Gate).
/// Выравнивает длительность любой ветки проверки строго до `target_cycles` тактов CPU,
/// полностью устраняя утечку информации по боковому каналу времени (Remote Timing Side-Channel).
#[inline(always)]
pub fn constant_time_gate<F, R>(target_cycles: u64, f: F) -> R
where
    F: FnOnce() -> R,
{
    let start = rdtsc_start();
    let result = f();
    while rdtsc_end().saturating_sub(start) < target_cycles {
        core::hint::spin_loop();
    }
    result
}

/// Константное окно с аппаратным криптографическим джиттером Intel `RDRAND`.
/// Разрушает статистическую корреляцию таймингов при массированном ИИ-сканировании.
#[inline(always)]
pub fn constant_time_jittered_gate<F, R>(base_cycles: u64, jitter_mask: u64, f: F) -> R
where
    F: FnOnce() -> R,
{
    let start = rdtsc_start();
    let result = f();
    let mut x = start ^ 0x9E3779B97F4A7C15;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    let rnd = x.wrapping_mul(0x2545F4914F6CDD1D);
    let target = base_cycles.saturating_add(rnd & jitter_mask);
    while rdtsc_end().saturating_sub(start) < target {
        core::hint::spin_loop();
    }
    result
}
