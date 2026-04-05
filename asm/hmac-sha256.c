/* ================================================================
   hmac_sha256.c  —  HMAC-SHA256
   ================================================================
   RFC 2104 HMAC using SHA-256:

     HMAC(K, m) = SHA256((K' ⊕ opad) ∥ SHA256((K' ⊕ ipad) ∥ m))

   where:
     K'   = K padded / hashed to block size (64 bytes)
     ipad = 0x36 repeated 64 times
     opad = 0x5c repeated 64 times
   ================================================================ */

#include <string.h>
#include "sha256.h"
#include "hmac-sha256.h"

#define BLOCK_SIZE  64   /* SHA-256 block size in bytes */
#define DIGEST_SIZE 32   /* SHA-256 output size in bytes */

void hmac_sha256_compute(const uint8_t *key,  size_t key_len,
                          const uint8_t *data, size_t data_len,
                          uint8_t        mac[32])
{
    uint8_t  k_norm[BLOCK_SIZE];   /* normalized key               */
    uint8_t  ipad[BLOCK_SIZE];     /* inner padding key            */
    uint8_t  opad[BLOCK_SIZE];     /* outer padding key            */
    uint8_t  inner[DIGEST_SIZE];   /* inner hash result            */
    sha256_ctx_t ctx;

    /* Step 1: Normalize key to block size
       - If key > 64 bytes: hash it first
       - If key < 64 bytes: zero-pad on the right               */
    memset(k_norm, 0, BLOCK_SIZE);
    if (key_len > BLOCK_SIZE) {
        sha256_hash(key, key_len, k_norm);  /* hash long key    */
    } else {
        memcpy(k_norm, key, key_len);       /* copy short key   */
    }

    /* Step 2: Build ipad and opad keys */
    for (int i = 0; i < BLOCK_SIZE; i++) {
        ipad[i] = k_norm[i] ^ 0x36;
        opad[i] = k_norm[i] ^ 0x5c;
    }

    /* Step 3: Inner hash = SHA256(ipad_key ∥ message) */
    sha256_init  (&ctx);
    sha256_update(&ctx, ipad, BLOCK_SIZE);
    sha256_update(&ctx, data, data_len);
    sha256_final (&ctx, inner);

    /* Step 4: Outer hash = SHA256(opad_key ∥ inner) */
    sha256_init  (&ctx);
    sha256_update(&ctx, opad,  BLOCK_SIZE);
    sha256_update(&ctx, inner, DIGEST_SIZE);
    sha256_final (&ctx, mac);
}