# Zero-Timing Core (`v2.4` / `zero_hal v1.0.0`)

**Deterministic `#![no_std]` Rust & `x86_64` Assembly data-plane core, reusable hardware abstraction layer (`zero_hal`), Ring -1 micro-hypervisor, and MOK-signed Ring-0 Linux kernel DPI engine (`484.35 Mpps`).**

## Reusable Hardware Abstraction Layer (`zero_hal/`)
* **`zero_hal::tsc`** — Serializing `lfence+rdtsc` / `rdtscp+lfence` timers and constant-time execution gates (`constant_time_gate`, `constant_time_jittered_gate`).
* **`zero_hal::numa`** — Direct `sys_mmap` (`MAP_HUGETLB | MAP_HUGE_2MB`) + `sys_mbind` (`MPOL_BIND | MPOL_MF_MOVE`) and 64-byte cache-line prefaulting.
* **`zero_hal::ddr_arena`** — Diskless `memfd_create` + `F_ADD_SEALS` + `mlock` + strict `W^X` (`PROT_READ | PROT_EXEC`) arenas, non-temporal `vmovntdq` + `clflush` memory wiping, and `clflushopt` cache-evicting reads.
* **`zero_hal::ymm_vault`** — Register-pinned 256-bit epoch key storage in `YMM15` with zero DDR footprint.
* **`zero_hal::io_uring_ring`** — 256-byte zero-copy telemetry slots (`ZEROMANI` magic) and direct `sys_io_uring_enter`.

## Visual Architecture Diagrams (`architecture_visuals/`)
* [**1. Core Pipeline (`01_core_pipeline.md`)**](architecture_visuals/01_core_pipeline.md) — Ephemeral UEFI Stage 0, Ring -1 EPT/NPT hypervisor, `YMM15` vault, and sealed capsule.
* [**2. Host & DDR Shield (`02_host_and_ddr_shield.md`)**](architecture_visuals/02_host_and_ddr_shield.md) — `zero-host-guard` (`inotify + SIGSTOP`), internal MTD -> `TC BPF` egress (`TTL=65`), and `memfd_create + mlock + W^X` arena.
* [**3. 11-Module Vertical Pipeline (`03_modules_vertical.md`)**](architecture_visuals/03_modules_vertical.md) — Full vertical flow across L2/L4/L7 self-learning & pure `.S` `x86_64` ASM guards.

## Build, Benchmarks & License
* **One-Command Release Build (LTO):** `cargo build --release` (compiles `zero_hal v1.0.0` + `zero_project` in ~0.5s).
* **Full Test Suite:** `make test && make clean` (benchmark scripts in [`benchmarks/README.md`](benchmarks/README.md)).
* **License:** GPL-3.0 (`LICENSE`).

---

### Core Telemetry & L1/L3 Cache Footprint
- **Executable Footprint (`.text`):** `17.7 KB` (`11,234 B` core + `6,877 B` sealed DDR capsules) — fits entirely inside **32 KB L1 Instruction Cache** with `14.3 KB` (`44.7%`) free headroom.
- **Hardware PMU (`RDPMC` on 10,000,000 frames):** `484.35 Mpps` (`6.80 cycles/frame`), `109` cache misses (**99.999% cache hit rate**), `737` branch mispredictions.
- **Protocol & Evasion Coverage (`PROT_NONE` Guard-Page Verified):** HTTP/1.1, 128-byte HTTP `TE.CL`/`CL.TE` Smuggling with `CRLFCRLF` boundary stop, HTTP/2 Rapid Reset (`CVE-2023-44487`, `~8.4 cycles/frame`), TLS 1.3 Record Splitting, QUIC Initial (`RFC 9000`), DNS/NTP Amplification, Modbus TCP, and Contrastive SWAR/AVX2 Self-Learning (`0.00%` False Positives across 1,000,000 clean frames).

## Ring-0 Linux Kernel Module (`DKMS v2.4`) & Zero-Syscall Telemetry (`zero_top`)

The monolithic Ring-0 kernel engine (`kernel_ring0/zero_timing_ring0.c`) provides inline `NF_INET_PRE_ROUTING` packet inspection with branchless `x86_64` ASM L7 DPI, 128-byte sliding GPR HTTP smuggling detection, lock-free `SSE4.2 CRC32C` flow tracking, constant-time `RDTSC` + per-CPU `Xorshift64*` gating, and a `SipHash-1-3` anti-poisoning sentinel bot.

### 1. DKMS Kernel Module Installation (`v2.4`)
```bash
sudo mkdir -p /usr/src/zero-timing-ring0-2.4
sudo cp kernel_ring0/* /usr/src/zero-timing-ring0-2.4/
sudo dkms add -m zero-timing-ring0 -v 2.4
sudo dkms build -m zero-timing-ring0 -v 2.4
sudo dkms install -m zero-timing-ring0 -v 2.4
sudo modprobe zero_timing_ring0
```

### 2. Live Ring-0 Control (`/proc/zero_timing_ring0`) & `zero_top`
```bash
# Switch between Monitor (Fail-Safe) and Enforce (NF_DROP) modes:
echo enforce | sudo tee /proc/zero_timing_ring0
echo const256 | sudo tee /proc/zero_timing_ring0

# Build and run the no_std/no_main live telemetry reader:
cargo build --release --bin zero_top
./target/release/zero_top
```

---

## 🛡️ Security Advisories & Mitigation Log

Tracking of critical CVEs and branchless data-plane mitigations is maintained in [SECURITY_ADVISORIES.md](SECURITY_ADVISORIES.md).

---

## 🖥️ Rackmount R&D Stand Fundraiser (Dell PowerEdge R730 + 10GbE SFP+)

This project is an independent open-source deterministic data-plane R&D initiative. All contributions go directly toward acquiring a dedicated rackmount testbed (**Dell PowerEdge R730**, `2x Intel Xeon E5-2690 v4`, `Intel X520-DA2 10GbE SFP+`) to publish hardware wire-to-wire `XDP_DRV`, `Intel DDIO`, and `Intel CAT` L3 cache pinning benchmarks.

* **TON (The Open Network):** `UQBTjCDPiQIUl73F_1f-3ArppvjdfJ7mfONIyfDZl5d9z66Z`

> **SysAdmin Field Note (Local LLM / Ollama):** The autonomous watchdog (`zero-host-guard` & `OnlineSentinelBot`) treats background local inference daemons (such as **Ollama**) as unauthorized threats due to aggressive filesystem scanning and local port binding, automatically isolating/terminating them under strict zero-trust perimeter rules.
