# Zero-Timing Manifesto (`v1.0-core`)

**Deterministic `no_std` Rust & `x86_64` Assembly data-plane core, Ring -1 micro-hypervisor, and 11-module plug-in ecosystem.**

## 1. Frozen Core Architecture (`v1.0-core`)

```mermaid
flowchart TD
    HW["Hardware CPU / RAM / NIC (Intel VT-x / AMD-V)"] --> S0["Stage 0: Ephemeral UEFI BIOS (uefi_stage0/)<br/>USB Quorum + Zero NVRAM Write"]
    S0 --> HV["Ring -1 Micro-Hypervisor (src/thin_hypervisor.rs)<br/>EPT Execute-Only / NPT Memory Isolation"]
    HV --> VAULT["Silicon Key Vault (zero-vault/)<br/>Keys Pinned in YMM15 CPU Registers"]
    VAULT --> CORE["Data-Plane Pipeline (2MB HugePages + PROT_NONE)<br/>Branchless x86_64 ASM / SWAR (42.36 Mpps)"]
    CORE --> CAPS["Frozen Core Capsule v1.0-core<br/>256-bit Mutagen + ZEROMANI Signature"]
```

## 2. Plug-In Module Pipeline (`modules/` — 11 Modules)

```mermaid
flowchart TD
    PKT["Incoming Frame (VLAN / IHL / TCP Dynamic Cursor)"] --> VERIFY{"ZEROMANI Signature Check (ABI v1)"}
    VERIFY --> L2["Module #5: Anti-Spoof MAC + IP + TTL (234.19 Mpps)"]
    L2 --> L4["Module #11: SOHO Router Proxy Botnet Detector (.S ASM)"]
    L4 --> L7A["Modules #4 & #7: Self-Learning HTTP/HPACK & HTTPS/TLS"]
    L7A --> L7B["Modules #8 & #10: x86_64 ASM SSL-VPN & RMM Guard (.S ASM)"]
    L7B -- "Attack Detected" --> TRAP["Module #1: Sticky TCP Window = 0 Tarpit (126.34 Mpps)"]
    L7B -- "Clean Traffic" --> SHAPE["Module #3: Shannon Entropy & IAT Jitter Shaper"]
    SHAPE --> EGRESS["Module #9: Host MTD -> TC BPF Egress Clean TTL=65"]
    VERIFY -. "Host Process Watch" .-> WD["Module #6: Kernel inotify + SIGSTOP Watchdog"]
```

* **Benchmarks & Build:** Run `make test && make clean` (see [`benchmarks/README.md`](benchmarks/README.md)).
* **License & Support:** GPL-3.0 (`LICENSE`). TON / USDT: `UQBTjCDPiQIUl73F_1f-3ArppvjdfJ7mfONIyfDZl5d9z66Z`
