/* ================================================================
   pbkdf2.c  —  PBKDF2-HMAC-SHA256
   ================================================================
   RFC 2898 PBKDF2 using HMAC-SHA256 as the PRF:

     T[i] = U1 ^ U2 ^ ... ^ Uc

     U1 = HMAC(password, salt ∥ INT(i))
     Uj = HMAC(password, U(j-1))    for j = 2..c

   DK = T[1] ∥ T[2] ∥ ... ∥ T[⌈dkLen/hLen⌉]

   Hot loop:
     xor_block() is called (iterations-1) × blocks times.
     It is implemented in ASM: asm/xor_block.asm
   ================================================================ */

#include <stdlib.h>
#include <string.h>
#include "hmac-sha256.h"
#include "pbkdf2.h"

#define PRF_LEN 32   /* HMAC-SHA256 output length */

/* ── ASM hot loop (asm/xor_block.asm) ───────────────────────────
   void xor_block(uint8_t *dst, const uint8_t *src, size_t len);
   Performs: dst[i] ^= src[i]  for i in 0..len-1
   Processes 8 bytes per iteration (QWORD XOR) for speed.        */
extern void xor_block(uint8_t *dst, const uint8_t *src, size_t len);

/* Write 32-bit unsigned int as big-endian 4 bytes */
static void write_be32(uint8_t *out, uint32_t v)
{
    out[0] = (uint8_t)((v >> 24) & 0xff);
    out[1] = (uint8_t)((v >> 16) & 0xff);
    out[2] = (uint8_t)((v >>  8) & 0xff);
    out[3] = (uint8_t)((v >>  0) & 0xff);
}

void pbkdf2_hmac_sha256_compute(
    const uint8_t *password, size_t   pass_len,
    const uint8_t *salt,     size_t   salt_len,
    uint32_t       iterations,
    uint32_t       key_len,
    uint8_t       *out)
{
    /* Build salt ∥ INT(block_num) buffer once — reuse for each block */
    size_t   s1_len   = salt_len + 4;
    uint8_t *s1       = (uint8_t *)malloc(s1_len);
    if (!s1) return;
    memcpy(s1, salt, salt_len);

    uint32_t block_num = 1;
    size_t   remaining = key_len;
    uint8_t *ptr       = out;

    while (remaining > 0) {
        /* ── U1 = HMAC(password, salt ∥ INT(block_num)) ─────────── */
        write_be32(s1 + salt_len, block_num);

        uint8_t U[PRF_LEN];
        uint8_t T[PRF_LEN];

        hmac_sha256_compute(password, pass_len, s1, s1_len, U);
        memcpy(T, U, PRF_LEN);

        /* ── U2..Uc = HMAC(password, U(j-1)) ────────────────────── */
        for (uint32_t i = 1; i < iterations; i++) {
            uint8_t U_next[PRF_LEN];
            hmac_sha256_compute(password, pass_len, U, PRF_LEN, U_next);
            memcpy(U, U_next, PRF_LEN);
            xor_block(T, U, PRF_LEN);  /* T ^= Uj */
        }

        /* ── Copy T[block_num] to output ─────────────────────────── */
        size_t copy = (remaining < PRF_LEN) ? remaining : PRF_LEN;
        memcpy(ptr, T, copy);
        ptr       += copy;
        remaining -= copy;
        block_num++;
    }

    free(s1);
}