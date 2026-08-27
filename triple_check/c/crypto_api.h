/* Triple-check shim: minimal crypto_api.h (no OpenSSL path) */
#ifndef crypto_api_shim_h
#define crypto_api_shim_h

#include "includes.h"

typedef int8_t crypto_int8;
typedef uint8_t crypto_uint8;
typedef int16_t crypto_int16;
typedef uint16_t crypto_uint16;
typedef int32_t crypto_int32;
typedef uint32_t crypto_uint32;
typedef int64_t crypto_int64;
typedef uint64_t crypto_uint64;

#define crypto_hash_sha512_BYTES 64U

/* Provided by main.c driver */
int crypto_hash_sha512(unsigned char *out, const unsigned char *in,
    unsigned long long inlen);

#endif /* crypto_api_shim_h */
