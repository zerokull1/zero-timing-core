# Zero-Timing Manifesto (`v1.0-core`)

**Deterministic `no_std` Rust & `x86_64` Assembly data-plane core, Ring -1 micro-hypervisor, and zero-disk DDR-sealed 11-module ecosystem (`474.78 Mpps`).**

## Visual Architecture Diagrams (`architecture_visuals/`)
* [**1. Core Pipeline (`01_core_pipeline.md`)**](architecture_visuals/01_core_pipeline.md) — Ephemeral UEFI Stage 0, Ring -1 EPT/NPT hypervisor, YMM15 vault, and `v1.0-core` capsule.
* [**2. Host & DDR Shield (`02_host_and_ddr_shield.md`)**](architecture_visuals/02_host_and_ddr_shield.md) — `zero-host-guard` (`inotify + SIGSTOP`), internal MTD -> `TC BPF` egress (`TTL=65`), and `memfd_create + mlock + W^X` arena.
* [**3. 11-Module Vertical Pipeline (`03_modules_vertical.md`)**](architecture_visuals/03_modules_vertical.md) — Full vertical flow across L2/L4/L7 self-learning & pure `.S` `x86_64` ASM guards.

## Build, Benchmarks & License
* **One-Command Build & Verify:** Run `make test && make clean` (all benchmark scripts live in [`benchmarks/README.md`](benchmarks/README.md)).
* **License & Support:** GPL-3.0 (`LICENSE`). TON / USDT: `UQBTjCDPiQIUl73F_1f-3ArppvjdfJ7mfONIyfDZl5d9z66Z`
