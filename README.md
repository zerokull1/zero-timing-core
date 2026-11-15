# Zero-Timing Core (`v1.0-core`)

**Deterministic `no_std` Rust & `x86_64` Assembly data-plane core, Ring -1 micro-hypervisor, and zero-disk DDR-sealed 11-module ecosystem (`474.78 Mpps`).**

## Visual Architecture Diagrams (`architecture_visuals/`)
* [**1. Core Pipeline (`01_core_pipeline.md`)**](architecture_visuals/01_core_pipeline.md) — Ephemeral UEFI Stage 0, Ring -1 EPT/NPT hypervisor, YMM15 vault, and `v1.0-core` capsule.
* [**2. Host & DDR Shield (`02_host_and_ddr_shield.md`)**](architecture_visuals/02_host_and_ddr_shield.md) — `zero-host-guard` (`inotify + SIGSTOP`), internal MTD -> `TC BPF` egress (`TTL=65`), and `memfd_create + mlock + W^X` arena.
* [**3. 11-Module Vertical Pipeline (`03_modules_vertical.md`)**](architecture_visuals/03_modules_vertical.md) — Full vertical flow across L2/L4/L7 self-learning & pure `.S` `x86_64` ASM guards.

## Build, Benchmarks & License
* **One-Command Build & Verify:** Run `make test && make clean` (all benchmark scripts live in [`benchmarks/README.md`](benchmarks/README.md)).
* **License & Support:** GPL-3.0 (`LICENSE`). TON / USDT: `UQBTjCDPiQIUl73F_1f-3ArppvjdfJ7mfONIyfDZl5d9z66Z`

---

### Latest Core Telemetry & L1/L3 Cache Footprint (v1.0-core Frozen)
- **Executable Footprint (`.text`):** `17.7 KB` (`11,234 B` core + `6,877 B` sealed DDR capsules) — fits entirely inside **32 KB L1 Instruction Cache** with `14.3 KB` (`44.7%`) free headroom.
- **Hardware PMU (`RDPMC` on 10,000,000 frames):** `484.35 Mpps` (`6.80 cycles/frame`), `109` cache misses (**99.999% cache hit rate**), `737` branch mispredictions.
- **Protocol & Evasion Coverage (`PROT_NONE` Guard-Page Verified):** HTTP/1.1, HTTP/2 Rapid Reset (`CVE-2023-44487`, `~8.4 cycles/frame`), TLS 1.3 Record Splitting, QUIC Initial (`RFC 9000`), DNS/NTP Amplification, Modbus TCP, and Contrastive SWAR/AVX2 Self-Learning (`0.00%` False Positives across 1,000,000 clean frames).
