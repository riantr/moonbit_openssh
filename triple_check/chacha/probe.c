/* probe.c - try various state[12..15] configurations to find which one
 * produces the keystream b976ccbbc23b32250fb018df323a68aa (claimed by
 * MoonBit wbtest for KAT2). */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#include "chacha.h"

int main(void) {
    u_char key[32];
    for (int i = 0; i < 32; i++) key[i] = (u_char)i;
    u_char zero[16] = {0};
    u_char out[16];
    const u_char target[16] = {
        0xb9,0x76,0xcc,0xbb,0xc2,0x3b,0x32,0x25,0x0f,0xb0,0x18,0xdf,0x32,0x3a,0x68,0xaa,
    };

    /* 1. state[12,13]=ctr=[0,0,0,0,1,0,0,0], state[14,15]=iv=[0,0,0,0,0,0,0,1] */
    {
        struct chacha_ctx ctx;
        chacha_keysetup(&ctx, key, 256);
        u_char iv[8]  = {0,0,0,0,0,0,0,1};
        u_char ctr[8] = {0,0,0,0,1,0,0,0};
        chacha_ivsetup(&ctx, iv, ctr);
        chacha_encrypt_bytes(&ctx, zero, out, 16);
        printf("Config1 (state[12,13]=ctr, [14,15]=iv): ");
        for (int i = 0; i < 16; i++) printf("%02x", out[i]);
        printf("%s\n", memcmp(out, target, 16) == 0 ? "  MATCH" : "");
    }

    /* 2. state[12,13]=iv=[0,0,0,0,0,0,0,1], state[14,15]=ctr=[0,0,0,0,1,0,0,0] */
    {
        struct chacha_ctx ctx;
        chacha_keysetup(&ctx, key, 256);
        u_char iv[8]  = {0,0,0,0,0,0,0,1};
        u_char ctr[8] = {0,0,0,0,1,0,0,0};
        chacha_ivsetup(&ctx, ctr, iv);  /* swap args! */
        chacha_encrypt_bytes(&ctx, zero, out, 16);
        printf("Config2 (state[12,13]=iv, [14,15]=ctr): ");
        for (int i = 0; i < 16; i++) printf("%02x", out[i]);
        printf("%s\n", memcmp(out, target, 16) == 0 ? "  MATCH" : "");
    }

    /* 3. state[12,13,14,15] = iv[0..3] || ctr[0..3] (RFC 7539 IETF, 12-byte nonce) */
    {
        struct chacha_ctx ctx;
        chacha_keysetup(&ctx, key, 256);
        u_char iv[8]  = {0,0,0,0,0,0,0,1};
        u_char ctr[8] = {0,0,0,0,1,0,0,0};
        /* RFC 7539 form: state[12]=ctr_lo, state[13..15]=iv (12-byte nonce) */
        ctx.input[12] = (ctr[0]) | (ctr[1]<<8) | (ctr[2]<<16) | (ctr[3]<<24);
        ctx.input[13] = (iv[0]) | (iv[1]<<8) | (iv[2]<<16) | (iv[3]<<24);
        ctx.input[14] = (iv[4]) | (iv[5]<<8) | (iv[6]<<16) | (iv[7]<<24);
        ctx.input[15] = 0;
        chacha_encrypt_bytes(&ctx, zero, out, 16);
        printf("Config3 (RFC 7539, ctr||iv):  ");
        for (int i = 0; i < 16; i++) printf("%02x", out[i]);
        printf("%s\n", memcmp(out, target, 16) == 0 ? "  MATCH" : "");
    }

    return 0;
}
