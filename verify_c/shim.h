// Force-included shim for chacha.c compilation
// Provides types chacha.h needs (u_char, u_int) without pulling in OpenSSH's
// full headers.

#include <stdint.h>
typedef uint8_t u_char;
typedef unsigned int u_int;
