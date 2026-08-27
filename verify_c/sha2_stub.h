// Stub for sha2.c compilation (avoid OpenSSH's configure)
#ifndef SHA2_STUB_H
#define SHA2_STUB_H

// BYTE_ORDER macros (assume little-endian on x86_64 Windows)
#define LITTLE_ENDIAN 1234
#define BIG_ENDIAN 4321
#define BYTE_ORDER LITTLE_ENDIAN

// Types sha2.c needs
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t u_int8_t;
typedef uint32_t u_int32_t;
typedef uint64_t u_int64_t;

// Compatibility macros
#define explicit_bzero(p, n) memset((p), 0, (n))
#define DEF_WEAK(x)  // no-op for stand-alone build

#endif