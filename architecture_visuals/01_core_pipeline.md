# 1. Как устроено ядро (`v1.0-core`)

~~~mermaid
flowchart TD
    HW["Железо CPU / RAM / NIC (Intel VT-x / AMD-V)"] --> S0["Stage 0: Эфемерный UEFI BIOS (uefi_stage0/)<br/>USB-кворум + 0 байт записи в NVRAM"]
    S0 --> HV["Ring -1 Микрогипервизор (src/thin_hypervisor.rs)<br/>EPT Execute-Only / NPT изоляция памяти"]
    HV --> VAULT["Кремниевый сейф ключей (zero-vault/)<br/>Ключи закреплены в регистрах YMM15 CPU"]
    VAULT --> CORE["Конвейер ядра (2MB HugePages + PROT_NONE)<br/>Безветвящийся x86_64 ASM / SWAR (42.36 Mpps)"]
    CORE --> CAPS["Замороженная капсула v1.0-core<br/>256-битный мутаген + подпись ZEROMANI"]
~~~
