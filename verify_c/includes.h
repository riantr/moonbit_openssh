// Stub includes.h to bypass OpenSSH's full include chain
// when compiling chacha.c standalone
#ifndef INCLUDES_H_STUB
#define INCLUDES_H_STUB

#include <sys/types.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// BSD types that chacha.c uses
typedef uint8_t u_char;
typedef unsigned int u_int;

#endif
