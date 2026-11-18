# 🛡️ Zero-Timing Security Advisories & Mitigation Log

Журнал архитектурного разбора критических уязвимостей (CVE) и современных техник обхода DPI/WAF с реализацией детерминированных безветвящихся фильтров в контуре `zero-timing-core`.

---

## Сводная таблица закрытых векторов

| Дата | Уязвимость / Вектор | Уровень риска | Слой защиты в `zero-timing-core` | Цена (CPU Cycles) |
| :--- | :--- | :---: | :--- | :---: |
| **18.11.2026** | **CVE-2026-98432** (Linux Kernel IPv4 IP Options UAF) | Critical | Отсечка `IHL != 5` на входе в `xdp_zero_shield.c`, ASM-проверка `verify_ipv4_no_options_asm` (`src/l7_shield.rs`) и `nftables` ingress (`ip hdrlength != 5 drop`) | **~2 такта** |
| **18.11.2026** | **AI Scraper & C2 Zero-Jitter Beacons** | High | Целочисленный детектор дисперсии интервалов `detect_ai_beacon_jitter_asm` (`src/adaptive_gateway.rs`) + перевод в `Semantic Context Tarpit` (1B/2s) и `RTO Jitter-Mirroring` | **~3 такта** |
| **18.11.2026** | **RMM Agents & Compromised SOHO Proxies** | High | Контроль несоответствия размера ядрового окна TCP и TLS ClientHello `inspect_rmm_soho_window_asm` (`src/l7_shield.rs`, `soho_proxy_asm.S`) | **~4 такта** |
| **15.11.2026** | **CVE-2023-44487** (HTTP/2 Rapid Reset Flood) | High | Безветвящийся трекер соотношения `HEADERS` / `RST_STREAM` (`h2_rapid_reset_guard.c`, Капсула `#15`) | **~8.4 такта** |
| **15.11.2026** | **CVE-2023-48795** (SSH-2 Terrapin & Pre-Auth Abuse) | Medium | Контроль последовательности пакетов и флагов до завершения handshake (`top5_critical_guard.c`, Капсула `#15`) | **~5 тактов** |
| **14.11.2026** | **TLS Record Splitting & QUIC Initial Evasion** | High | SWAR/AVX-512 проверка минимальной длины записи (`< 40B`) и порога RFC 9000 Section 14.1 (`< 1200B`) в `src/l7_shield.rs` и XDP | **~6 тактов** |
| **14.11.2026** | **HTTP Request Smuggling (TE.CL / CL.TE)** | High | Канонизация границ `\r\n\r\n` и блокировка конфликтующих заголовков в окне до `512B` без динамических аллокаций | **~12 тактов** |

---

## Принципы реагирования на новые угрозы

1. **Zero-Allocation & Branchless.** Любой новый фильтр обязан укладываться в бюджет кэша **L1i (32 КБ)** без использования кучи и условных переходов (`cmov` / SWAR / SIMD).
2. **Fail-Close на границе периметра.** Пакеты с аномалиями заголовков (`IHL != 5`, IPv4-фрагментация `IP_MF | IP_OFFSET`, перекрытие TCP SEQ) отбрасываются на уровне `XDP_DROP` до выделения `sk_buff` в ядре ОС.
3. **Защита от отравления обучения (Anti-Poisoning).** Адаптивный шлюз `OnlineSentinelBot` использует криптографическую индексацию `SipHash-1-3`, временную аренду записей (`TTL Lease Decay`) и изоляцию активных банов (`Anti-Eviction`).
