# Zero-Timing Core (`v3.0` — Эластичный многоядерный Data-Plane / `zero_hal v1.0.0`)

[![CI](https://github.com)](https://github.com)
![Language](https://shields.io)
![ASM](https://shields.io)
![License](https://shields.io)

**Zero-Timing Core** — детерминированный движок обработки сетевого трафика и защиты периметра без динамических аллокаций (`#![no_std]`, `#![no_main]`, без `libc`), написанный на чистом Rust и `x86_64` Assembly.

🇬🇧 **[English Documentation (README.md)](README.md)** | 🛡️ **[Журнал закрытых уязвимостей (SECURITY_ADVISORIES.md)](SECURITY_ADVISORIES.md)**

> **Примечание для системных администраторов:** Внутренний сторожевой контур (`zero-host-guard` и `OnlineSentinelBot`) автоматически распознаёт неавторизованные фоновые LLM-демоны (например, Ollama), сканирующие порты и диск, как угрозу и изолирует их (`SIGSTOP` / `DROP`).

---

## Архитектурный конвейер (`v3.0`)

```mermaid
flowchart LR
    NIC["NIC / AF_XDP UMEM<br/>(2MB HugePages)"] --> TOPO["topology_placer<br/>(1..1M+ ядер / NUMA)"]
    TOPO --> WS["Lock-Free Work-Stealing<br/>(169 тактов/импульс)"]
    WS --> L7["Безветвящийся L7 ASM<br/>(TLS 1.3 / HTTP / QUIC)"]
    L7 --> BOT["JA4-SentinelBot<br/>(SipHash-1-3 + TTL Decay)"]
    BOT --> TRAP["pulse_barrier<br/>(W^X + UD2 + PROT_NONE)"]
    TRAP --> YMM["Горячий анклав YMM15<br/>(vmovntdq + CLFLUSH)"]
```

---

## Ключевые инженерные решения

* **Эластичное многоядерное ядро (`src/topology_placer.rs`, `src/bin/zero_elastic_core.rs`):** Безлимитный сканер топологии ядер (`SYS_sched_getaffinity`), автодетект `L1d` / `128-bit LOCK` / `AVX2`, автоматический выбор лучшего ядра под `YMM15` и безблокировочный `Work-Stealing` между NUMA-узлами (**30 000 000 импульсов @ 169 тактов/импульс**).
* **Последний барьер и арена `W^X` (`src/pulse_barrier.rs`, `src/bin/zero_pure_asm_engine.rs`):** Запечатывание исполняемого кода в памяти (`memfd_create` + `mlock` + охранные страницы `PROT_NONE` + минные поля `0x0F0B` `UD2`), аппаратная проверка `SSE4.2` `CRC32C` (Fail-Close), трёхфазный `TTL-Mirage` (`65 -> 65..118 -> 0x00`) и хранение ключей в регистре `YMM15` с выжиганием DDR через `vmovntdq` + `CLFLUSH`.
* **Безветвящийся L7-инспектор на `x86_64` ASM (`src/l7_shield.rs`):** Константный по времени анализ (`cmov` / SWAR / `AVX-512` `vpcmpeqb` + `kmovq`) для TLS 1.3 `ClientHello`, Record Splitting, Downgrade, HTTP Request Smuggling, QUIC Initial (`RFC 9000`), прокси на взломанных SOHO-роутерах / RMM-агентов и 9 критических протоколов (`HTTP/2 Rapid Reset`, `Modbus TCP`, `DNS`, `NTP`, `SMBv3`, `SSH-2`, `BGP/VXLAN`, `LDAP/Kerberos`, `RoCEv2`).
* **Кремниевая криптография и константные окна (`src/flow_table.rs`, `src/tsc.rs`):** Аппаратное хэширование 5-tuple на `Intel AES-NI` (`aesenc`) + `SSE4.2` (`crc32q`) против Hash-Collision DoS и сериализующие окна исполнения `lfence + rdtsc` (`0.002` такта разницы по времени).
* **Мультиархитектурный HAL (`zero_hal v1.0.0`):** Слой аппаратной абстракции без внешних зависимостей с чистой сборкой (0 предупреждений) под **`x86_64`**, **`s390x` (IBM LinuxONE / z15)**, **`aarch64` (ARM64 NEON)** и **`riscv64gc`**.
* **Pre-OS микро-гипервизор Ring `-1` (`uefi_stage0/`, `src/thin_hypervisor.rs`):** Автономный `BOOTX64.EFI`, активирующий `Intel VT-x` (`VMXON`) / `AMD-V` (`SVM`) с 4-уровневой защитой страниц `EPT Execute-Only` (`R=0, W=0, X=1`) до загрузки ядра ОС.

---

## Верифицированные замеры (Baseline: Intel Core i5-4590 Haswell)

| Тест / Подсистема | Показатель | Аппаратная телеметрия |
| :--- | :--- | :--- |
| **Elastic Work-Stealing (`30M` импульсов)** | **169 тактов/импульс** | `9 849 984` перехваченных задач, `NUMA=1`, `W^X+CRC32C=OK` |
| **Pure ASM Engine (`zero_pure_asm_engine`)** | **26 тактов/пакет** | Размер секции `.text`: **6 746 байт** (`0.13s` сборка LTO) |
| **L7 128-bit ASM инспектор (`50M` кадров)** | **12.95 такта/пакет** | `IPC 2.82`, `0.095%` branch-misses (`perf stat`) |
| **Запечатанная DDR-арена (`10M` кадров)** | **484.35 Mpps** (`6.80` такта) | `99.999%` попаданий в кэш L1/L2 (`RDPMC`) |
| **Двухуровневый вход (`10M` кадров)** | **2.71 такта/пакет** | `0` обращений к DDR при отсечении на Уровне 1 |
| **Constant-Time сравнение (`3M` замеров)** | **0.002 такта** разница | Сериализующий `RDTSCP`, нулевая утечка по времени |
| **Фаззинг границ памяти (`PROT_NONE`)** | **0 `SIGSEGV`** | `> 1.1 млрд` мутированных кадров впритык к `mprotect(PROT_NONE)` |
| **Pre-OS Ring `-1` (`QEMU + OVMF KVM`)** | **2–3 такта/кадр** | `VMXON + EPT Execute-Only (R=0,W=0,X=1)` подтверждено |

---

## Быстрая сборка и проверка

```bash
cargo build --release
./target/release/core_self_test
./target/release/zero_pure_asm_engine
./target/release/zero_elastic_core
```

---

## Целевой сбор на стоечный стенд (Весна 2027, 10GbE Wire-Rate Lab)

Разработка десктопного ядра переведена в режим **Feature Freeze** до развёртывания выделенного стоечного сервера (**Dell PowerEdge R730**, `2x Intel Xeon E5-2690 v4`, `Intel X520-DA2 10GbE SFP+`, аппаратная изоляция L3-кэша `Intel CAT` и `DDIO`).

* **Кошелёк TON:** `UQBTjCDPiQIUl73F_1f-3ArppvjdfJ7mfONIyfDZl5d9z66Z`
* **Tonviewer:** [Открыть кошелёк и QR-код](https://tonviewer.com)
