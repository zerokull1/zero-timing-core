// ZEROMANI (zerokull1) | 0x5A45524F4D414E49ULL
// Copyright (c) 2026 zerokull1 (https://github.com)
// Licensed under GPL-3.0. Unauthorized proprietary use is strictly prohibited.

#![allow(dead_code)]

use core::arch::asm;

/// Состояние автономного адаптивного шлюза (выровнено по кэш-линии 64 байта)
#[repr(C, align(64))]
pub struct AdaptiveDdosGateway {
    /// Текущий порог энтропии Шеннона в формате Q16.16 (по умолчанию 3.50 бита = 229376)
    pub entropy_threshold_q16: u32,
    /// Базовый порог для быстрого возврата после спада атаки
    pub base_threshold_q16: u32,
    /// Счётчик адаптированных (заблокированных) аномальных потоков
    pub mitigated_flows: u64,
    /// Режим жёсткой блокировки (0 = штатный, 1 = карантин)
    pub lockdown_level: u32,
    pub _pad: [u32; 9],
}

impl AdaptiveDdosGateway {
    #[inline(always)]
    pub const fn new() -> Self {
        Self {
            entropy_threshold_q16: 229_376, // 3.50 bits (Q16.16)
            base_threshold_q16: 229_376,
            mitigated_flows: 0,
            lockdown_level: 0,
            _pad: [0; 9],
        }
    }

    /// Безветвящийся ассемблерный вердикт шлюза (cmova) на основе спектральной энтропии потока:
    /// Возвращает: 0 = PASS, 1 = QUARANTINE (подозрительный всплеск), 2 = HARD DROP (атака)
    #[inline(always)]
    pub unsafe fn evaluate_flow_asm(&mut self, flow_entropy_q16: u32, packet_score: u32) -> u32 { unsafe {
        let mut verdict: u32 = 0;
        let thresh = self.entropy_threshold_q16;
        let hard_thresh = thresh.wrapping_add(32_768); // +0.50 бита сверх порога -> мгновенный DROP

        #[cfg(target_arch = "x86_64")]
        asm!(
            "mov {v:e}, 0",
            "mov {q:e}, 1",
            "mov {d:e}, 2",
            "cmp {ent:e}, {t1:e}",
            "cmova {v:e}, {q:e}",
            "cmp {ent:e}, {t2:e}",
            "cmova {v:e}, {d:e}",
            ent = in(reg) flow_entropy_q16,
            t1 = in(reg) thresh,
            t2 = in(reg) hard_thresh,
            v = out(reg) verdict,
            q = out(reg) _,
            d = out(reg) _,
            options(pure, nomem, nostack)
        );

        #[cfg(not(target_arch = "x86_64"))]
        {
            if flow_entropy_q16 > hard_thresh {
                verdict = 2;
            } else if flow_entropy_q16 > thresh {
                verdict = 1;
            }
        }

        // Адаптивная подстройка порога без ветвлений: при атаке порог затягивается ниже, в покое плавно отпускает
        let is_attack = (verdict != 0) as u32;
        self.mitigated_flows = self.mitigated_flows.wrapping_add(is_attack as u64);
        self.lockdown_level = is_attack;

        let tightened = self.entropy_threshold_q16.saturating_sub(512);
        let relaxed = self.entropy_threshold_q16.saturating_add(128).min(self.base_threshold_q16);
        self.entropy_threshold_q16 = if is_attack != 0 {
            tightened.max(163_840) // Не ниже 2.50 бита
        } else {
            relaxed
        };

        let _ = packet_score;
        verdict
    }}
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct SentinelSlot {
    pub src_ip_be: u32,
    pub trust_score: u16,
    pub banned: u8,
    pub promoted: u8,
    pub burst_strikes: u16,
    pub _pad: u16,
    pub last_tsc: u64,
}

/// Автономный обучаемый сторожевой бот с защитой от отравления обучения (Anti-Poisoning),
/// защитой от вытеснения бана (Anti-Eviction) и контролем частоты всплесков (Burst Rate-Limit).
#[repr(C, align(64))]
pub struct OnlineSentinelBot {
    pub slots: [SentinelSlot; 64],
    pub learned_whitelisted: u32,
    pub learned_banned: u32,
    pub poison_attempts_blocked: u32,
    pub enforce_triggered: u32,
}

impl OnlineSentinelBot {
    pub const fn new() -> Self {
        Self {
            slots: [SentinelSlot {
                src_ip_be: 0,
                trust_score: 0,
                banned: 0,
                promoted: 0,
                burst_strikes: 0,
                _pad: 0,
                last_tsc: 0,
            }; 64],
            learned_whitelisted: 0,
            learned_banned: 0,
            poison_attempts_blocked: 0,
            enforce_triggered: 0,
        }
    }

    #[inline(always)]
    pub unsafe fn observe_and_act(
        &mut self,
        src_ip_be: u32,
        is_clean: bool,
        now_tsc: u64,
        whitelist_map_fd: u32,
        config_map_fd: u32,
    ) {
        let idx = ((src_ip_be.wrapping_mul(2654435761)) >> 26) as usize;
        let slot = &mut self.slots[idx];

        if slot.src_ip_be != src_ip_be {
            // Anti-Eviction: не позволяем вытеснить активный бан в течение ~1 секунды (3 млрд тактов)
            if slot.banned != 0 && now_tsc.saturating_sub(slot.last_tsc) < 3_000_000_000 {
                self.poison_attempts_blocked += 1;
                return;
            }
            *slot = SentinelSlot {
                src_ip_be,
                trust_score: 0,
                banned: 0,
                promoted: 0,
                burst_strikes: 0,
                _pad: 0,
                last_tsc: now_tsc,
            };
        }

        let delta_tsc = now_tsc.saturating_sub(slot.last_tsc);
        slot.last_tsc = now_tsc;

        if is_clean {
            if slot.banned != 0 {
                return;
            }
            // Anti-Poisoning: пулемётный флуд (< 50 000 тактов ~ 15 мкс) не даёт очков доверия и копит страйки
            if delta_tsc < 50_000 {
                slot.burst_strikes = slot.burst_strikes.saturating_add(1);
                if slot.burst_strikes >= 32 {
                    slot.banned = 1;
                    slot.trust_score = 0;
                    self.learned_banned += 1;
                    self.poison_attempts_blocked += 1;
                    if slot.promoted != 0 {
                        slot.promoted = 0;
                        unsafe { crate::bpf_control::whitelist_del_ipv4(whitelist_map_fd, src_ip_be); }
                    }
                }
                return;
            }

            // Начисляем очко доверия только при естественном межпакетном интервале (>= 15 мс ~ 50 млн тактов)
            if delta_tsc >= 50_000_000 {
                slot.trust_score = slot.trust_score.saturating_add(1);
                slot.burst_strikes = slot.burst_strikes.saturating_sub(1);
                if slot.trust_score >= 16 && slot.promoted == 0 {
                    slot.promoted = 1;
                    self.learned_whitelisted += 1;
                    unsafe { crate::bpf_control::whitelist_add_ipv4(whitelist_map_fd, src_ip_be); }
                }
            }
        } else {
            if slot.banned == 0 {
                slot.banned = 1;
                self.learned_banned += 1;
                if slot.promoted != 0 {
                    slot.promoted = 0;
                    unsafe { crate::bpf_control::whitelist_del_ipv4(whitelist_map_fd, src_ip_be); }
                }
                if self.enforce_triggered == 0 {
                    self.enforce_triggered = 1;
                    let cfg = crate::bpf_control::ShieldConfig {
                        mode: crate::bpf_control::ShieldMode::Enforce as u32,
                        block_ttl_65: 1,
                        block_ttl_129: 1,
                    };
                    unsafe { crate::bpf_control::set_shield_mode(config_map_fd, &cfg); }
                }
            }
            slot.trust_score = 0;
        }
    }
}
