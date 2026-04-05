; ================================================================
;  asm/sha256_block.asm  —  SHA256 Block Compression  (NASM x86-64)
; ================================================================
;
;  void sha256_block_compress(uint32_t state[8], const uint8_t block[64]);
;
;  Linux System V AMD64 ABI:
;    rdi = state  (uint32_t[8]  — a,b,c,d,e,f,g,h)
;    rsi = block  (const uint8_t[64] — one 512-bit message block)
;
;  This function performs the SHA-256 compression function:
;    1. Load 16 big-endian words from block into W[0..15]
;    2. Expand message schedule to W[16..63]
;    3. Run 64 compression rounds
;    4. Add compressed values back into state[]
;
;  Register allocation (compression rounds):
;    a = r8d    b = r9d    c = r10d   d = r11d
;    e = r12d   f = r13d   g = r14d   h = r15d
;    K ptr = rdi    round counter = rbx    state ptr = rbp
;    temporaries: eax, ecx, edx, esi
;
;  Stack layout (after 6 pushes + sub rsp,264):
;    [rsp +   0 .. 255]  W[0..63]  message schedule (256 bytes)
;    [rsp + 256 .. 263]  alignment padding (8 bytes)
;    --- saved registers: r15 r14 r13 r12 rbx rbp ---
;    --- return address ---
;
;  Total stack delta: 6*8 + 264 = 312 bytes → rsp aligned to 16
; ================================================================

section .rodata
align 64
sha256_K:
    dd 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5
    dd 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5
    dd 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3
    dd 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174
    dd 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc
    dd 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da
    dd 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7
    dd 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967
    dd 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13
    dd 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85
    dd 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3
    dd 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070
    dd 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5
    dd 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3
    dd 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208
    dd 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2

section .text
global sha256_block_compress

sha256_block_compress:
    ; ── Prologue: save callee-saved registers ──────────────────────────
    push    rbp
    push    rbx
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, 264            ; W[64] = 256B + 8B alignment pad
                                ; total frame: 6*8+264 = 312 (16-aligned ✓)

    ; Save state pointer into rbp (we need rdi later for K)
    mov     rbp, rdi            ; rbp = state[]
                                ; rsi = block[]  (used in load phase)

    ; ── Phase 1: Load W[0..15] from block (big-endian → little-endian) ─
    xor     rbx, rbx            ; rbx = word index 0..15
.load_w:
    mov     eax, dword [rsi + rbx*4]
    bswap   eax                 ; convert big-endian network → host
    mov     dword [rsp + rbx*4], eax
    inc     rbx
    cmp     rbx, 16
    jl      .load_w

    ; ── Phase 2: Expand W[16..63] ──────────────────────────────────────
    ; σ0(x) = ROTR(x,7)  ^ ROTR(x,18) ^ SHR(x,3)
    ; σ1(x) = ROTR(x,17) ^ ROTR(x,19) ^ SHR(x,10)
    ; W[i]  = W[i-16] + σ0(W[i-15]) + W[i-7] + σ1(W[i-2])
    ;
    ; Addressing (rbx = i, rsp = W base):
    ;   W[i-15] → [rsp + rbx*4 - 60]
    ;   W[i-16] → [rsp + rbx*4 - 64]
    ;   W[i-7]  → [rsp + rbx*4 - 28]
    ;   W[i-2]  → [rsp + rbx*4 -  8]
    ; rbx still = 16 after load loop

.expand_w:
    ; --- σ0(W[i-15]) ---
    mov     eax, dword [rsp + rbx*4 - 60]   ; W[i-15]
    mov     ecx, eax
    mov     edx, eax
    ror     eax, 7
    ror     ecx, 18
    shr     edx, 3
    xor     eax, ecx
    xor     eax, edx                          ; eax = σ0

    ; --- σ1(W[i-2]) ---
    mov     r8d, dword [rsp + rbx*4 - 8]    ; W[i-2]
    mov     r9d, r8d
    mov     r10d, r8d
    ror     r8d, 17
    ror     r9d, 19
    shr     r10d, 10
    xor     r8d, r9d
    xor     r8d, r10d                         ; r8d = σ1

    ; --- W[i] = W[i-16] + σ0 + W[i-7] + σ1 ---
    mov     r9d, dword [rsp + rbx*4 - 64]   ; W[i-16]
    add     r9d, eax                          ; + σ0
    add     r9d, dword [rsp + rbx*4 - 28]   ; + W[i-7]
    add     r9d, r8d                          ; + σ1
    mov     dword [rsp + rbx*4], r9d

    inc     rbx
    cmp     rbx, 64
    jl      .expand_w

    ; ── Phase 3: Load working variables a..h from state ────────────────
    mov     r8d,  dword [rbp +  0]  ; a
    mov     r9d,  dword [rbp +  4]  ; b
    mov     r10d, dword [rbp +  8]  ; c
    mov     r11d, dword [rbp + 12]  ; d
    mov     r12d, dword [rbp + 16]  ; e
    mov     r13d, dword [rbp + 20]  ; f
    mov     r14d, dword [rbp + 24]  ; g
    mov     r15d, dword [rbp + 28]  ; h

    ; Set up K pointer and round counter
    lea     rdi, [rel sha256_K]     ; rdi = &K[0]
    xor     rbx, rbx                ; rbx = round index 0..63

    ; ── Phase 4: 64 Compression Rounds ─────────────────────────────────
    ; Each round:
    ;   Σ1(e) = ROTR(e,6)  ^ ROTR(e,11) ^ ROTR(e,25)
    ;   Ch(e,f,g)  = (e & f) ^ (~e & g)
    ;   T1 = h + Σ1(e) + Ch(e,f,g) + K[i] + W[i]
    ;   Σ0(a) = ROTR(a,2)  ^ ROTR(a,13) ^ ROTR(a,22)
    ;   Maj(a,b,c) = (a & b) ^ (a & c) ^ (b & c)
    ;   T2 = Σ0(a) + Maj(a,b,c)
    ;   h=g, g=f, f=e, e=d+T1, d=c, c=b, b=a, a=T1+T2

.rounds:
    ; ---- T1 ----

    ; Σ1(e): ROTR(e,6) ^ ROTR(e,11) ^ ROTR(e,25)
    mov     eax, r12d
    mov     ecx, r12d
    ror     eax, 6
    ror     ecx, 11
    xor     eax, ecx
    mov     ecx, r12d
    ror     ecx, 25
    xor     eax, ecx                ; eax = Σ1(e)

    ; Ch(e,f,g) = (e & f) ^ (~e & g)
    mov     ecx, r12d
    and     ecx, r13d               ; e & f
    mov     edx, r12d
    not     edx
    and     edx, r14d               ; ~e & g
    xor     ecx, edx                ; ecx = Ch(e,f,g)

    ; T1 = Σ1 + h + Ch + K[i] + W[i]
    add     eax, r15d               ; + h
    add     eax, ecx                ; + Ch
    add     eax, dword [rdi + rbx*4]  ; + K[i]
    add     eax, dword [rsp + rbx*4]  ; + W[i]
    ; eax = T1

    ; ---- T2 ----

    ; Σ0(a): ROTR(a,2) ^ ROTR(a,13) ^ ROTR(a,22)
    mov     esi, r8d
    mov     ecx, r8d
    ror     esi, 2
    ror     ecx, 13
    xor     esi, ecx
    mov     ecx, r8d
    ror     ecx, 22
    xor     esi, ecx                ; esi = Σ0(a)

    ; Maj(a,b,c) = (a&b) ^ (a&c) ^ (b&c)
    mov     ecx, r8d
    and     ecx, r9d                ; a & b
    mov     edx, r8d
    and     edx, r10d               ; a & c
    xor     ecx, edx
    mov     edx, r9d
    and     edx, r10d               ; b & c
    xor     ecx, edx                ; ecx = Maj(a,b,c)

    add     esi, ecx                ; esi = T2 = Σ0 + Maj

    ; ---- Rotate working variables ----
    ; h=g, g=f, f=e, e=d+T1, d=c, c=b, b=a, a=T1+T2
    mov     r15d, r14d              ; h = g
    mov     r14d, r13d              ; g = f
    mov     r13d, r12d              ; f = e
    mov     ecx, r11d               ; save d
    add     ecx, eax                ; d + T1
    mov     r12d, ecx               ; e = d + T1
    mov     r11d, r10d              ; d = c
    mov     r10d, r9d               ; c = b
    mov     r9d,  r8d               ; b = a
    add     eax, esi                ; T1 + T2
    mov     r8d,  eax               ; a = T1 + T2

    inc     rbx
    cmp     rbx, 64
    jl      .rounds

    ; ── Phase 5: Add compressed chunk to state ──────────────────────────
    add     dword [rbp +  0], r8d
    add     dword [rbp +  4], r9d
    add     dword [rbp +  8], r10d
    add     dword [rbp + 12], r11d
    add     dword [rbp + 16], r12d
    add     dword [rbp + 20], r13d
    add     dword [rbp + 24], r14d
    add     dword [rbp + 28], r15d

    ; ── Epilogue ────────────────────────────────────────────────────────
    add     rsp, 264
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    pop     rbp
    ret