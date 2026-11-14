# 2. Как устроена защита хоста и DDR-арены

~~~mermaid
flowchart TD
    HOST["Операционная система хоста"] --> WD["Демон охраны ФС (zero-host-guard)<br/>Ядро inotify + SIGSTOP для самовольных ботов"]
    HOST --> MTD["Внутренняя мутация трафика в кольцах памяти"]
    MTD --> EGRESS["Шлюз сетевой карты (TC BPF egress)<br/>Снятие мутации + чистый TTL=65 под смартфон"]
    CORE_MEM["Код и базы 11 модулей"] --> MEMFD["Анонимный объект в RAM (memfd_create)"]
    MEMFD --> MLOCK["Блокировка от swap (mlock=1) + запрет записи W^X"]
    MLOCK --> WIPE["Мгновенное затирание при выходе (explicit_bzero)"]
~~~
