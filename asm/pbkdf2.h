/* ================================================================
   pbkdf2.h  —  PBKDF2-HMAC-SHA256
   ================================================================ */

#ifndef PBKDF2_H
#define PBKDF2_H

#include <stdint.h>
#include <stddef.h>

/*
 * Derive a key using PBKDF2-HMAC-SHA256.
 *
 * password   : user password bytes
 * pass_len   : password length
 * salt       : random salt (should be 16+ bytes)
 * salt_len   : salt length
 * iterations : iteration count (e.g. 100000)
 * key_len    : desired output key length in bytes
 * out        : output buffer (must be at least key_len bytes)
 */
void pbkdf2_hmac_sha256_compute(
    const uint8_t *password, size_t   pass_len,
    const uint8_t *salt,     size_t   salt_len,
    uint32_t       iterations,
    uint32_t       key_len,
    uint8_t       *out);

#endif /* PBKDF2_H */