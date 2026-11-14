# Zero-Timing Manifesto (`v1.0-core`)

**Deterministic, ultra-low-latency `no_std` Rust & `x86_64` Assembly data-plane core, Ring -1 micro-hypervisor, and 11-module plug-in ecosystem.**

* **Frozen Core (`src/`, `uefi_stage0/`, `zero-vault/`):** Constant-time `x86_64` ASM L7 DPI, zero-copy `AF_XDP` in 2MB HugePages (`42.36 Mpps`), Ring -1 EPT/NPT micro-hypervisor, and YMM15 key vault.
* **Plug-In Modules (`modules/`):** Dynamic `ZEROMANI`-signed C & pure `x86_64` ASM (`.S`) extensions:
  * `deception_tarpit` (ID=1): TCP Zero-Window tarpit (`126.34 Mpps`).
  * `xdp_live_daemon` (ID=2) & `entropy_shaper` (ID=3): Live BPF sync & Shannon IAT shaper.
  * `http_table_guard` (ID=4) & `https_tls_guard` (ID=7): Self-learning HPACK/Smuggling & non-MITM ClientHello/SNI guard.
  * `anti_spoof_guard` (ID=5): Self-learning `MAC+IP+TTL` binding (`234.19 Mpps`).
  * `ai_agent_watchdog` (ID=6): Kernel `inotify` + `SIGSTOP` host file guard.
  * `ssl_vpn_session_guard` (ID=8): Pure `x86_64` ASM (`crc32q` + `cmov`, `3.53 cycles/pkt`) session-ticket anti-hijack.
  * `egress_wire_mutator` (ID=9): Internal host MTD with `TC BPF` egress de-mutation (`TTL=65`).
  * `rmm_control_guard` (ID=10) & `residential_proxy_guard` (ID=11): Pure `.S` `x86_64` ASM RMM RCE & SOHO-router proxy botnet detectors.
* **Benchmarks (`benchmarks/`):** All performance scripts and hardware logs live in [`benchmarks/README.md`](benchmarks/README.md) (`make test && make clean`).
* **License & Support:** GPL-3.0 (`LICENSE`). TON / USDT: `UQBTjCDPiQIUl73F_1f-3ArppvjdfJ7mfONIyfDZl5d9z66Z`
* **Visual Architecture (`docs/ARCHITECTURE_VISUAL.md`):** Vertical diagrams of the frozen core and 11-module pipeline.
