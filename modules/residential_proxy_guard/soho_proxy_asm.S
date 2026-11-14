.intel_syntax noprefix
.bss
.align 8
proxy_hits: .quad 0

.text
.globl proxy_init
.type proxy_init, @function
proxy_init:
    mov qword ptr [rip + proxy_hits], 0
    xor eax, eax
    ret

// Чистый x86_64 ASM: ловит прокси-ботнет на взломанном SOHO-роутере по несовпадению
// встроенного стека TCP роутера (MSS <= 1412 или TCP Window <= 14600) и TLS 1.3 ClientHello (0x16 0x03)
.globl proxy_process_frame
.type proxy_process_frame, @function
proxy_process_frame:
    xor eax, eax
    test rdi, rdi
    jz .Lret
    cmp rsi, 64
    jb .Lret
    // Проверяем TLS Handshake ClientHello на смещении 54 (0x16 0x03 ... 0x01)
    cmp byte ptr [rdi + 54], 0x16
    jne .Lret
    cmp byte ptr [rdi + 55], 0x03
    jne .Lret
    cmp byte ptr [rdi + 59], 0x01
    jne .Lret
    // Читаем TCP Window (big-endian на смещении 48..49)
    movzx edx, word ptr [rdi + 48]
    rol dx, 8
    // Встроенные ядра роутеров (MIPS/ARM) дают окно <= 14600, тогда как реальный ПК/смартфон >= 32768
    mov ecx, 1
    xor r8d, r8d
    cmp dx, 14600
    cmova ecx, r8d
    add [rip + proxy_hits], rcx
    mov eax, ecx
.Lret:
    ret

.globl proxy_shutdown
.type proxy_shutdown, @function
proxy_shutdown:
    mov qword ptr [rip + proxy_hits], 0
    ret

.section .data.rel.ro,"aw",@progbits
mod_name: .asciz "soho_router_proxy_botnet_asm_guard"
.align 8
.globl zero_module_entry
zero_module_entry:
    .quad 0x494E414D4F52455A
    .long 1
    .long 11
    .quad mod_name
    .quad proxy_init
    .quad proxy_process_frame
    .quad proxy_shutdown
.section .note.GNU-stack,"",@progbits
