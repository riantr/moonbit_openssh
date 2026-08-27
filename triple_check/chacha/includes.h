/* Triple-check shim: minimal includes.h for chacha (no OpenSSH system headers) */
#ifndef INCLUDES_SHIM_H
#define INCLUDES_SHIM_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>

typedef uint8_t u_char;
typedef unsigned int u_int;

#endif /* INCLUDES_SHIM_H */
