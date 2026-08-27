// Minimal crypto_api.h for standalone Ed25519 harness
// Provides crypto_hash_sha512 via OpenBSD sha2.c (same as OpenSSH's non-OpenSSL path)
#ifndef CRYPTO_API_STUB_H
#define CRYPTO_API_STUB_H

#include <stdint.h>
#include <stdlib.h>

typedef int8_t crypto_int8;
typedef uint8_t crypto_uint8;
typedef int16_t crypto_int16;
typedef uint16_t crypto_uint16;
typedef int32_t crypto_int32;
typedef uint32_t crypto_uint32;
typedef int64_t crypto_int64;
typedef uint64_t crypto_uint64;

#define crypto_hash_sha512_BYTES 64U

// randombytes: only used by crypto_sign_ed25519_keypair (random sk), which the
// harness never calls (we use keypair_from_seed). Provide a failing stub.
#define randombytes(buf, buf_len) abort()

// sha2.c types/protos come through ed25519_sha2_compat.h included before this.
int crypto_hash_sha512(unsigned char *out, const unsigned char *in,
    unsigned long long inlen);

#endif
