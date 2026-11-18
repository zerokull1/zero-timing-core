# Security Advisories & Mitigated Vectors

Журнал актуальных уязвимостей и техник обхода DPI/WAF, перекрытых архитектурой `zero-timing-core` и контуром периметровой защиты хоста.

| ID / Вектор | Суть угрозы | Уровень перекрытия | Статус |
| :--- | :--- | :--- | :--- |
| **CVE-2026-98432** (Nov 2026) | Гонка `TCP SYN` с IPv4 Options (`Record Route` / `Timestamp`) и вектором `MPTCP` (Use-After-Free) | Netfilter `raw prerouting` (`ip hdrlength != 5 drop`) + отключение `net.mptcp.enabled = 0` | **Mitigated** |
| **NoisyTCP** (Nov 2026) | Kernel Panic в TCP-стеке Linux при аномальных комбинациях флагов | Ядро `7.3.4-zen2-2` + ранняя отсечка Null/Xmas/`SYN+FIN`/`SYN+RST`/`FIN+RST` до `conntrack` | **Mitigated** |
| **CVE-2026-114938** (Java4Shell, CVSS 9.2) | Pre-Auth RCE в декодере Base64 OpenJDK на CPU с AVX-512 VBMI | Чистый `#![no_std]` Rust/ASM стек без JVM и сторонних зависимостей | **Not Affected** |
| **ScreenConnect / RMM & SOHO Proxies** | Туннелирование и запуск пейлоадов через взломанные SOHO-роутеры и RMM | Безветвящийся инспектор `inspect_rmm_soho_window_asm` (`src/l7_shield.rs`) + Капсула №18 | **Mitigated** |
| **AI Automated Scanners / Zero-Jitter Beacons** | Машинный ритм зондов и автоподбор порогов WAF | Целочисленный детектор джиттера по `RDTSC` (`src/adaptive_gateway.rs`) + Semantic/RTO Tarpit | **Mitigated** |
| **CVE-2023-44487** (HTTP/2 Rapid Reset) | Лавинный сброс потоков `RST_STREAM` | Потоковый инспектор `h2_rapid_reset_guard` + Капсула №15 | **Mitigated** |
| **CVE-2023-48795** (SSH Terrapin) | Обрезка порядковых номеров при рукопожатии SSH-2 | Проверка целостности pre-auth кадрования | **Mitigated** |
| **TLS Record Splitting & HTTP Smuggling** | Микро-фрагментация `ClientHello` (`< 40B`) и рассинхрон `CL.TE` / `TE.CL` | Безветвящийся x86_64 ASM парсер `src/l7_shield.rs` (`cmov`, `~13–20` тактов/кадр) | **Mitigated** |
| **Timing Side-Channel & Hash-Collision DoS** | Утечка по времени сравнения и коллизии в таблице потоков | `constant_time_gate` (`lfence+rdtsc`, разброс `0.002` такта) + `AES-NI`/`CRC32C`/`SipHash-1-3` | **Mitigated** |

## Воспроизводимый профиль периметра хоста
Эталонные правила `nftables` (`hook prerouting priority raw`) и параметры `sysctl` сохранены в каталоге `tools/host_hardening/`.
