; ================================================================
;  asm/xor_block.asm  —  XOR Block Accumulation  (NASM x86-64)
; ================================================================
;
;  void xor_block(uint8_t *dst, const uint8_t *src, size_t len);
;
;  Linux System V AMD64 ABI:
;    rdi = dst   (output buffer, modified in place: dst[i] ^= src[i])
;    rsi = src   (source buffer, read-only)
;    rdx = len   (number of bytes to XOR)
;
;  Used in PBKDF2:
;    For each HMAC iteration:  T[i] ^= U[i]   (32 bytes, len=32)
;    This loop runs  iterations × blocks  times — it IS the hot path.
;
;  Strategy:
;    Process 8 bytes at a time (QWORD) using XOR on 64-bit registers.
;    Handle remaining 0-7 bytes one byte at a time.
;
;  Performance vs C:
;    - C compiler may or may not vectorise xor_block
;    - This ASM guarantees QWORD unrolled XOR every time
;    - For 32-byte HMAC output: exactly 4 QWORD iterations → no tail
;
; ================================================================

section .text
global xor_block

xor_block:
    ; rdi = dst
    ; rsi = src
    ; rdx = len

    ; ── Fast path: 8 bytes at a time ──────────────────────────────
    ; rcx = number of full 8-byte chunks
    mov     rcx, rdx
    shr     rcx, 3              ; rcx = len / 8
    jz      .tail               ; skip if less than 8 bytes

.qword_loop:
    mov     rax, qword [rsi]    ; load 8 bytes from src
    xor     qword [rdi], rax    ; XOR into dst (memory destination)
    add     rdi, 8
    add     rsi, 8
    dec     rcx
    jnz     .qword_loop

    ; ── Tail: remaining 0-7 bytes one at a time ───────────────────
.tail:
    and     rdx, 7              ; rdx = len % 8
    jz      .done

.byte_loop:
    mov     al, byte [rsi]
    xor     byte [rdi], al
    inc     rdi
    inc     rsi
    dec     rdx
    jnz     .byte_loop

.done:
    ret