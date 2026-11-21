# Security Advisories & Mitigated Vectors

Журнал актуальных уязвимостей и техник обхода DPI/WAF, перекрытых архитектурой `zero-timing-core` и контуром периметровой защиты хоста.

| ID / Вектор | Суть угрозы | Уровень перекрытия | Статус |
| :--- | :--- | :--- | :--- |
| **CVE-2026-98432** (Nov 2026) | Гонка `TCP SYN` с IPv4 Options (`Record Route` / `Timestamp`) и вектором `MPTCP` (Use-After-Free) | Netfilter `raw prerouting` (`ip hdrlength != 5 drop`) + отключение `net.mptcp.enabled = 0` | **Mitigated** |
| **NoisyTCP** (Nov 2026) | Kernel Panic в TCP-стеке Linux при аномальных комбинациях флагов | Ядро `7.3.4-zen2-2` + ранняя отсечка Null/Xmas/`SYN+FIN`/`SYN+RST`/`FIN+RST` до `conntrack` | **Mitigated** |
| **CVE-2026-114938** (Java4Shell, CVSS 9.2) | Pre-Auth RCE в декодере Base64 OpenJDK на CPU с AVX-512 VBMI | Чистый `#![no_std]` Rust/ASM стек без JVM и сторонних зависимостей | **Not Affected** |
| **ScreenConnect / RMM & SOHO Proxies** | Туннелирование и запуск пейлоадов через взломанные SOHO-роутеры и RMM | Безветвящийся инспектор `inspect_rmm_soho_window_asm` (`src/l7_shield.rs`)  | **Mitigated** |
| **AI Automated Scanners / Zero-Jitter Beacons** | Машинный ритм зондов и автоподбор порогов WAF | Целочисленный детектор джиттера по `RDTSC` (`src/adaptive_gateway.rs`) + Semantic/RTO Tarpit | **Mitigated** |
| **CVE-2023-44487** (HTTP/2 Rapid Reset) | Лавинный сброс потоков `RST_STREAM` | Потоковый инспектор `h2_rapid_reset_guard`  | **Mitigated** |
| **CVE-2023-48795** (SSH Terrapin) | Обрезка порядковых номеров при рукопожатии SSH-2 | Проверка целостности pre-auth кадрования | **Mitigated** |
| **TLS Record Splitting & HTTP Smuggling** | Микро-фрагментация `ClientHello` (`< 40B`) и рассинхрон `CL.TE` / `TE.CL` | Безветвящийся x86_64 ASM парсер `src/l7_shield.rs` (`cmov`, `~13–20` тактов/кадр) | **Mitigated** |
| **Timing Side-Channel & Hash-Collision DoS** | Утечка по времени сравнения и коллизии в таблице потоков | `constant_time_gate` (`lfence+rdtsc`, разброс `0.002` такта) + `AES-NI`/`CRC32C`/`SipHash-1-3` | **Mitigated** |

## Воспроизводимый профиль периметра хоста
Эталонные правила `nftables` (`hook prerouting priority raw`) и параметры `sysctl` сохранены в каталоге `tools/host_hardening/`.

| **CVE-2026-123007** (`NGINX2Root`, CVSS 9.2) | HTTP/2 Frame Memory Corruption / RCE (`1.9.5`–`1.31.8`) | `xdp_shield/xdp_zero_shield.c` | Mitigated (`RFC 9113` SWAR frame length `> 16384` & zero-length `PADDED` drop in XDP) |
| **CVE-2026-119618** (CVSS 9.8) | Apache `mod_http2` Malformed Frame RCE | `xdp_shield/xdp_zero_shield.c` | Mitigated (Pre-stack `XDP_DROP` on oversized/malformed HTTP/2 frames) |
| **CVE-2026-48710** (CISA KEV 18.11.2026) | Kludex Starlette HTTP Request/Response Smuggling | `src/l7_shield.rs`, `xdp_zero_shield.c` | Mitigated (Branchless `x86_64` ASM `CL.TE` / `TE.CL` smuggling scanner) |

| **CVE-2026-0118** (CVSS 9.6) | Palo Alto PAN-OS GlobalProtect Pre-Auth Path/Delimiter Injection (`..;/`) | `xdp_shield/xdp_zero_shield.c` | Mitigated (32-bit SWAR URI delimiter `0x2F3B2E2E` drop in XDP before `sk_buff`) |
| **CVE-2026-10479** (CVSS 9.3, CISA KEV) | Citrix NetScaler ADC / Gateway Pre-Auth Header Buffer Overflow | `xdp_shield/xdp_zero_shield.c`, `src/l7_shield.rs` | Mitigated (Pre-stack XDP URI/header guard + constant-time L7 boundary check) |

| **CVE-2026-11204** (CVSS 8.6) | ISC BIND 9 / Unbound DNS Resolver Compression Loop (`QDCOUNT == 0` / `ANCOUNT > 0`) | `xdp_shield/xdp_zero_shield.c` | Mitigated (Pre-stack UDP/53 DNS header validation & `XDP_DROP`) |
| **CVE-2026-10891** (CVSS 9.1) | OpenSSL / BoringSSL TLS 1.3 `ClientHello` Zero/Odd Cipher Suite Overflow | `xdp_shield/xdp_zero_shield.c`, `src/l7_shield.rs` | Mitigated (XDP `ClientHello` cipher-suite length boundary check before socket enqueue) |

| **CVE-2026-11642** (CVSS 8.8) | QUIC / HTTP/3 Stack Amplification & Fake Version Negotiation Loop (`UDP/443`) | `xdp_shield/xdp_zero_shield.c`, `src/l7_shield.rs` | Mitigated (`RFC 9000 §14.1` Initial `< 1200B` & `Version == 0` `XDP_DROP`) |

### CVE-2026-129289 — PHP-FPM + NGINX FastCGI Request Smuggling (CVSS 9.2)
* **Date:** 2026-11-19
* **Vector:** HTTP/1.1 `fastcgi_keep_conn` stream desynchronization leaking binary `FCGI_Header` records into subsequent backend requests.
* **Mitigation:** Blocked in `src/l7_shield.rs` (`verify_l7_rfc_normalizer_swar`) via branchless SWAR inspection of trailing `FCGI_Header` (`version=1, type=1..11`) frames on HTTP verbs (`~22.8 cycles/pkt`).

### CVE-2026-40217 — BerriAI LiteLLM Unauthenticated RCE (CISA KEV)
* **Date:** 2026-11-19
* **Vector:** Remote code execution via `/guardrails` endpoint injection.
* **Mitigation:** Blocked in `src/l7_shield.rs` (`verify_l7_rfc_normalizer_swar`) via register-shifted SWAR signature matching (`0x617264726175672F`) without extra unaligned memory loads.

| `TTL-Guard Slot Poisoning & Fragmentation Bypass` (`src/ttl_guard.rs`) | High | **Fixed** (Avalanche 64-bit flow hash + Anti-Eviction lock for `confidence >= 16` + lock-free CAS CIDR whitelist + full IPv4 fragment & TCP Null/FIN drop) |
