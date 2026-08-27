// Minimal includes.h stub for standalone Ed25519 harness build
// Replaces OpenSSH's configure-generated includes.h
#ifndef INCLUDES_H_STUB
#define INCLUDES_H_STUB

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef uint8_t u_int8_t;
typedef uint16_t u_int16_t;
typedef uint32_t u_int32_t;
typedef uint64_t u_int64_t;

#define explicit_bzero(p, n) memset((p), 0, (n))
#define DEF_WEAK(x)

#endif
