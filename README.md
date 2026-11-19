# Zero-Timing Core (`v3.0` — Elastic Multi-Core Data-Plane / `zero_hal v1.0.0`)

[![CI](https://github.com)](https://github.com)
![Language](https://shields.io)
![ASM](https://shields.io)
![License](https://shields.io)

**Zero-Timing Core** is a deterministic, zero-allocation (`#![no_std]`, `#![no_main]`, zero `libc`) network data-plane and perimeter defense engine written in pure Rust and raw `x86_64` Assembly.

🇷🇺 **[Русская версия документации (README.ru.md)](README.ru.md)** | 🛡️ **[Security Advisories & Mitigations](SECURITY_ADVISORIES.md)**

> **Note for System Administrators:** The built-in watchdog (`zero-host-guard` & `OnlineSentinelBot`) automatically treats unauthorized background local LLM daemons (such as Ollama) scanning local ports/disks as rogue processes and isolates them (`SIGSTOP` / `DROP`).

---

## Architecture Pipeline (`v3.0`)

```mermaid
flowchart LR
    NIC["NIC / AF_XDP UMEM<br/>(2MB HugePages)"] --> TOPO["topology_placer<br/>(1..1M+ Cores / NUMA)"]
    TOPO --> WS["Lock-Free Work-Stealing<br/>(169 cycles/pulse)"]
    WS --> L7["Branchless L7 ASM<br/>(TLS 1.3 / HTTP / QUIC)"]
    L7 --> BOT["JA4-SentinelBot<br/>(SipHash-1-3 + TTL Decay)"]
    BOT --> TRAP["pulse_barrier<br/>(W^X + UD2 + PROT_NONE)"]
    TRAP --> YMM["Hot YMM15 Enclave<br/>(vmovntdq + CLFLUSH)"]
```

---

## Key Engineering Highlights

* **Elastic Self-Placing Multi-Core (`src/topology_placer.rs`, `src/bin/zero_elastic_core.rs`):** Unlimited CPU affinity topology scanner (`SYS_sched_getaffinity`), automatic detection of `L1d` / `128-bit LOCK` / `AVX2`, hot-core selection for `YMM15`, and lock-free `Work-Stealing` across NUMA nodes (**30,000,000 pulses @ 169 cycles/pulse**).
* **Last-Barrier Pulse Trap & `W^X` Arena (`src/pulse_barrier.rs`, `src/bin/zero_pure_asm_engine.rs`):** Memory-sealed execution (`memfd_create` + `mlock` + `PROT_NONE` guard pages + `0x0F0B` `UD2` minefields), hardware `SSE4.2` `CRC32C` fail-close verification, 3-phase `TTL-Mirage` (`65 -> 65..118 -> 0x00`), and register-pinned key storage in `YMM15` wiped via non-temporal `vmovntdq` + `CLFLUSH`.
* **Branchless `x86_64` ASM L7 Inspection (`src/l7_shield.rs`):** Constant-time `cmov` / SWAR / `AVX-512` (`vpcmpeqb` + `kmovq`) inspection for TLS 1.3 `ClientHello`, Record Splitting, Downgrade, HTTP Request Smuggling, QUIC Initial (`RFC 9000`), RMM/SOHO proxy window mismatches, and 9 industrial/enterprise protocols (`HTTP/2 Rapid Reset`, `Modbus TCP`, `DNS`, `NTP`, `SMBv3`, `SSH-2`, `BGP/VXLAN`, `LDAP/Kerberos`, `RoCEv2`).
* **Silicon-Backed Flow & Timing Gates (`src/flow_table.rs`, `src/tsc.rs`):** `Intel AES-NI` (`aesenc`) + `SSE4.2` (`crc32q`) 5-tuple hashing against collision DoS and serialized `lfence + rdtsc` constant-time execution windows (`0.002` cycles side-channel delta).
* **Cross-Architecture HAL (`zero_hal v1.0.0`):** Zero-dependency hardware abstraction layer compiled cleanly with 0 warnings across **`x86_64`**, **`s390x` (IBM LinuxONE / z15)**, **`aarch64` (ARM64 NEON)**, and **`riscv64gc`**.
* **Pre-OS Ring `-1` Micro-Hypervisor (`uefi_stage0/`, `src/thin_hypervisor.rs`):** Bare-metal `BOOTX64.EFI` activating `Intel VT-x` (`VMXON`) / `AMD-V` (`SVM`) with 4-level `EPT Execute-Only` (`R=0, W=0, X=1`) page protection prior to OS kernel boot.

---

## Verified Hardware Benchmarks (Baseline: Intel Core i5-4590 Haswell)

| Benchmark / Subsystem | Metric | Hardware Counter / Verification |
| :--- | :--- | :--- |
| **Elastic Work-Stealing (`30M` pulses)** | **169 cycles/pulse** | `9,849,984` stolen tasks, `NUMA=1`, `W^X+CRC32C=OK` |
| **Pure ASM Engine (`zero_pure_asm_engine`)** | **26 cycles/pkt** | `.text` size: **6,746 bytes** (`0.13s` LTO build) |
| **L7 128-bit ASM Inspector (`50M` frames)** | **12.95 cycles/pkt** | `IPC 2.82`, `0.095%` branch-misses (`perf stat`) |
| **Sealed DDR Arena (`10M` frames)** | **484.35 Mpps** (`6.80` cycles) | `99.999%` L1/L2 cache hit rate (`RDPMC`) |
| **2-Level Gate (`10M` frames)** | **2.71 cycles/pkt** | `0` DDR reads on Level-1 reject |
| **Constant-Time Comparator (`3M` runs)** | **0.002 cycles** delta | Serialized `RDTSCP`, zero timing leak |
| **Memory Boundary Fuzzing (`PROT_NONE`)** | **0 `SIGSEGV`** | `> 1.1 Billion` mutated frames across `mprotect(PROT_NONE)` |
| **Pre-OS Ring `-1` (`QEMU + OVMF KVM`)** | **2–3 cycles/frame** | `VMXON + EPT Execute-Only (R=0,W=0,X=1)` verified |

---

## Quick Build & Verification

```bash
cargo build --release
./target/release/core_self_test
./target/release/zero_pure_asm_engine
./target/release/zero_elastic_core
```

---

## Rackmount Hardware Fund (Spring 2027 Wire-Rate Lab)

Core desktop R&D is in **Feature Freeze** while preparing physical `10GbE SFP+` validation on dedicated rackmount hardware (**Dell PowerEdge R730**, `2x Intel Xeon E5-2690 v4`, `Intel X520-DA2`, `Intel CAT` L3 cache pinning & `DDIO`).

* **TON Wallet:** `UQBTjCDPiQIUl73F_1f-3ArppvjdfJ7mfONIyfDZl5d9z66Z`
* **Tonviewer:** [Open Wallet & QR](https://tonviewer.com)
