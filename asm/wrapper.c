/* ================================================================
   crypto_wrapper.c  —  ctypes-compatible Public API
   ================================================================
   Exposes exactly the function signatures that crypto_engine.py
   expects via ctypes:

     int pbkdf2_hmac_sha256(pass, pass_len, salt, salt_len,
                             iterations, key_len, out)

     int hmac_sha256(key, key_len, data, data_len, out)

   Both return 0 on success.

   Python usage (crypto_engine.py ASMBridge):
     lib = ctypes.CDLL("./crypto_asm.so")
     lib.pbkdf2_hmac_sha256(password, len, salt, len, iters, klen, out)
     lib.hmac_sha256(key, key_len, data, data_len, out)
   ================================================================ */

#include <stdint.h>
#include <stddef.h>
#include "hmac-sha256.h"
#include "pbkdf2.h"

extern void xor_block(uint8_t *dst, const uint8_t *src, size_t len);

/*
 * PBKDF2-HMAC-SHA256 key derivation.
 */
int pbkdf2_hmac_sha256(const uint8_t *pass,    size_t   pass_len,
                        const uint8_t *salt,    size_t   salt_len,
                        uint32_t       iterations,
                        uint32_t       key_len,
                        uint8_t       *out)
{
    pbkdf2_hmac_sha256_compute(pass, pass_len,
                                salt, salt_len,
                                iterations, key_len,
                                out);
    return 0;
}

/*
 * HMAC-SHA256 message authentication code.
 */
int hmac_sha256(const uint8_t *key,  size_t   key_len,
                const uint8_t *data, size_t   data_len,
                uint8_t       *out)
{
    hmac_sha256_compute(key, key_len, data, data_len, out);
    return 0;
}

/*
 * xor_block wrapper for CTR mode acceleration.
 * Performs: dst[i] ^= src[i] for i in 0..len-1
 */
void xor_block_wrapper(uint8_t *dst, const uint8_t *src, size_t len)
{
    xor_block(dst, src, len);
}