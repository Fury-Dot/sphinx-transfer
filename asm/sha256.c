/* ================================================================
   sha256.c  —  SHA-256 (streaming + padding in C, block in ASM)
   ================================================================ */

#include <string.h>
#include "sha256.h"

/* SHA-256 initial hash values (first 32 bits of fractional parts
   of the square roots of the first 8 primes)                      */
static const uint32_t SHA256_H0[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

/* ── Streaming API ───────────────────────────────────────────── */

void sha256_init(sha256_ctx_t *ctx)
{
    memcpy(ctx->state, SHA256_H0, sizeof(SHA256_H0));
    ctx->bitcount = 0;
    ctx->buflen   = 0;
}

void sha256_update(sha256_ctx_t *ctx, const uint8_t *data, size_t len)
{
    while (len > 0) {
        size_t space = 64 - ctx->buflen;
        size_t copy  = (len < space) ? len : space;

        memcpy(ctx->buf + ctx->buflen, data, copy);
        ctx->buflen   += (uint32_t)copy;
        ctx->bitcount += copy * 8ULL;
        data          += copy;
        len           -= copy;

        /* When buffer is full, compress it via ASM */
        if (ctx->buflen == 64) {
            sha256_block_compress(ctx->state, ctx->buf);
            ctx->buflen = 0;
        }
    }
}

void sha256_final(sha256_ctx_t *ctx, uint8_t digest[32])
{
    /* SHA-256 padding:
         append 0x80, then zeros, then 64-bit big-endian bit count
         pad so that total length ≡ 56 (mod 64)                    */

    uint8_t pad[64];
    memset(pad, 0, sizeof(pad));
    pad[0] = 0x80;

    /* Bytes needed to reach next 56-mod-64 boundary */
    size_t padlen = (ctx->buflen < 56)
                    ? (56 - ctx->buflen)
                    : (120 - ctx->buflen);

    /* Append bit count as 64-bit big-endian */
    uint8_t  count[8];
    uint64_t bc = ctx->bitcount;
    for (int i = 7; i >= 0; i--) {
        count[i] = (uint8_t)(bc & 0xff);
        bc >>= 8;
    }

    sha256_update(ctx, pad,   padlen);
    sha256_update(ctx, count, 8);

    /* Convert 32-bit state words to big-endian bytes */
    for (int i = 0; i < 8; i++) {
        digest[i*4 + 0] = (uint8_t)((ctx->state[i] >> 24) & 0xff);
        digest[i*4 + 1] = (uint8_t)((ctx->state[i] >> 16) & 0xff);
        digest[i*4 + 2] = (uint8_t)((ctx->state[i] >>  8) & 0xff);
        digest[i*4 + 3] = (uint8_t)((ctx->state[i] >>  0) & 0xff);
    }
}

/* ── One-shot API ────────────────────────────────────────────── */

void sha256_hash(const uint8_t *data, size_t len, uint8_t digest[32])
{
    sha256_ctx_t ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, digest);
}