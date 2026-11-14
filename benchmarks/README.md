# Тесты производительности и стендовые замеры (`benchmarks/`)

Все скрипты воспроизведения замеров, прогона PCAP-дампов и комплексной верификации вынесены в этот каталог, чтобы не перегружать корневой `README.md`.

## Запуск замеров
* **Комплексная проверка модулей и `io_uring` дампа (22.68 ГБ/с):** `make test && make clean`
* **Офлайн-прогон синтетического или реального `.pcap` трафика:** `python3 benchmarks/pcap_bench.py --count 100000`
* **Полный стендовый прогон ядра:** `./benchmarks/demo_run.sh` и `./benchmarks/verify_all.sh`
* **Сырые аппаратные логи (`lscpu`, `/proc/meminfo`, `rdtscp`):** архивированы в [`docs/BENCHMARK_LOGS.md`](../docs/BENCHMARK_LOGS.md).
