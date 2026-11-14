# Zero-Timing Manifesto (`v1.0-core`)

**Deterministic `no_std` Rust & `x86_64` Assembly data-plane core, Ring -1 micro-hypervisor, and zero-disk DDR-sealed 11-module ecosystem.**

## 1. Frozen Core Architecture (`v1.0-core`)
Архитектура включает аппаратную изоляцию, микрогипервизор Ring -1, хранилище ключей в регистрах YMM15 и криптографически защищенную капсулу ядра.

## 2. Zero-Disk DDR Arena & 11-Module Pipeline (`modules/`)
Ядро опирается на DDR-арену (`memfd_create + mlock + W^X` со скоростью до `474.78 Mpps` / `6.93 cycles/pkt`) и конвейер из 11 специализированных модулей (фильтрация MAC/IP/TTL, анти-ботнет, HTTP/TLS, трап TCP Window=0 и мониторинг `inotify`).

* **Benchmarks & Build:** Запуск `make test && make clean` (подробнее в [`benchmarks/README.md`](benchmarks/README.md)).
* **License & Support:** GPL-3.0 (`LICENSE`). TON / USDT: `UQBTjCDPiQIUl73F_1f-3ArppvjdfJ7mfONIyfDZl5d9z66Z`
