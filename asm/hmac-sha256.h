/* ================================================================
   hmac_sha256.h  —  HMAC-SHA256
   ================================================================ */

#ifndef HMAC_SHA256_H
#define HMAC_SHA256_H

#include <stdint.h>
#include <stddef.h>

/*
 * Compute HMAC-SHA256.
 *
 * key      : secret key bytes
 * key_len  : length of key
 * data     : message bytes
 * data_len : length of message
 * mac      : output buffer (32 bytes)
 */
void hmac_sha256_compute(const uint8_t *key,  size_t key_len,
                          const uint8_t *data, size_t data_len,
                          uint8_t        mac[32]);

#endif /* HMAC_SHA256_H */