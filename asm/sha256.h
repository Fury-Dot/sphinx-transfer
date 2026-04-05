/* ================================================================
   sha256.h  —  SHA-256 Hash Function
   ================================================================
   Uses sha256_block_compress() from asm/sha256_block.asm as the
   inner compression function. Everything else (padding, streaming)
   is handled here in C.
   ================================================================ */

#ifndef SHA256_H
#define SHA256_H

#include <stdint.h>
#include <stddef.h>

/* SHA-256 context */
typedef struct {
    uint32_t state[8];   /* current hash state (a..h)        */
    uint64_t bitcount;   /* total bits processed              */
    uint8_t  buf[64];    /* partial block buffer              */
    uint32_t buflen;     /* bytes currently in buf            */
} sha256_ctx_t;

/* ── Streaming API ──────────────────────────────────────────── */
void sha256_init   (sha256_ctx_t *ctx);
void sha256_update (sha256_ctx_t *ctx, const uint8_t *data, size_t len);
void sha256_final  (sha256_ctx_t *ctx, uint8_t digest[32]);

/* ── One-shot API ───────────────────────────────────────────── */
void sha256_hash(const uint8_t *data, size_t len, uint8_t digest[32]);

/* ── ASM compression block (defined in asm/sha256_block.asm) ── */
extern void sha256_block_compress(uint32_t state[8], const uint8_t block[64]);

#endif /* SHA256_H */