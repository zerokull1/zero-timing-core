// ZEROMANI (zerokull1) | 0x5A45524F4D414E49ULL
#![allow(dead_code)]

use core::sync::atomic::{AtomicU64, Ordering};

/// Изолированный в 64-байтной кэш-линии дек задач конкретного ядра (0 False Sharing)
#[repr(C, align(64))]
pub struct CoreWorkDeque {
    pub cursor: AtomicU64,      // Текущий прогресс (атомарно двигается хозяином и ворами)
    pub limit: u64,             // Верхняя граница пачки этого ядра
    pub stolen_by_me: u64,      // Сколько задач это ядро украло у отстающих соседей
    pub cpu_id: u32,
    pub numa_node: u32,
    pub _pad: [u64; 4],
}

impl CoreWorkDeque {
    pub fn init(&mut self, cpu_id: u32, numa_node: u32, start: u64, end: u64) {
        self.cursor = AtomicU64::new(start);
        self.limit = end;
        self.stolen_by_me = 0;
        self.cpu_id = cpu_id;
        self.numa_node = numa_node;
    }

    /// Быстрый локальный захват батча (например, 256 импульсов за 1 атомик вместо 256)
    #[inline(always)]
    pub fn pop_batch(&self, batch: u64) -> Option<(u64, u64)> {
        let mut cur = self.cursor.load(Ordering::Relaxed);
        loop {
            if cur >= self.limit { return None; }
            let next = (cur + batch).min(self.limit);
            match self.cursor.compare_exchange_weak(cur, next, Ordering::Acquire, Ordering::Relaxed) {
                Ok(_) => return Some((cur, next)),
                Err(actual) => cur = actual,
            }
        }
    }
}

/// Динамическое воровство задач у самого загруженного соседа:
/// Проход 0 — соседи внутри своего NUMA-сокета (общий L3 кэш),
/// Проход 1 — соседи на других сокетах (стойки 2+ CPU).
#[inline(always)]
pub unsafe fn pop_or_steal_batch(
    deques: *mut CoreWorkDeque,
    num_workers: usize,
    my_idx: usize,
    batch: u64,
) -> Option<(u64, u64)> {
    let me = unsafe { &mut *deques.add(my_idx) };
    if let Some(work) = me.pop_batch(batch) {
        return Some(work);
    }

    let my_numa = me.numa_node;
    for pass in 0..2 {
        let mut best_victim: Option<usize> = None;
        let mut max_rem: u64 = 0;

        for i in 0..num_workers {
            if i == my_idx { continue; }
            let cand = unsafe { &*deques.add(i) };
            if pass == 0 && cand.numa_node != my_numa { continue; }
            let cur = cand.cursor.load(Ordering::Relaxed);
            if cand.limit > cur {
                let rem = cand.limit - cur;
                if rem > max_rem {
                    max_rem = rem;
                    best_victim = Some(i);
                }
            }
        }

        if let Some(v_idx) = best_victim {
            let victim = unsafe { &*deques.add(v_idx) };
            let steal_sz = (max_rem / 2).max(1).min(batch * 2);
            if let Some((s, e)) = victim.pop_batch(steal_sz) {
                me.stolen_by_me += e - s;
                return Some((s, e));
            }
        }
    }
    None
}
