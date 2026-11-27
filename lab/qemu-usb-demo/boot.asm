; Minimal x86 BIOS boot fixture; no third-party binary content.
bits 16
org 0x7c00
    cli
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, 0x7c00
    sti
    mov ax, 0x0003
    int 0x10
    mov si, title
.print:
    lodsb
    test al, al
    jz .ready
    mov ah, 0x0e
    mov bx, 0x0007
    int 0x10
    jmp .print
.ready:
    mov si, marker
.debug:
    lodsb
    test al, al
    jz .idle
    out 0xe9, al
    jmp .debug
.idle:
    hlt
    jmp .idle
title db 13,10
    db '  USB FABRIC / QEMU DEVICE DEMONSTRATOR',13,10
    db '  =====================================',13,10,13,10
    db '  Bootable x86 virtual machine fixture',13,10
    db '  BIOS guest running under QEMU',13,10,13,10
    db '  Host QMP test: virtual USB keyboard',13,10
    db '  Host QMP test: tablet add and remove',13,10,13,10
    db '  No guest USB stack or USB/IP claim.',13,10
    db '  See runtime receipt for observed results.',13,10,13,10
    db '  BOOT READY',13,10,0
marker db 'USB_DEMO_BOOT_READY',10,0
times 510-($-$$) db 0
dw 0xaa55
