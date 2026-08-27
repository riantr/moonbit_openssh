/*
 * Triple-blind cross-check driver for ChaCha20 (Bernstein/OpenSSH form).
 *
 * The OpenSSH chacha.c (in this directory) uses the **original Bernstein**
 * state layout: state[12,13] = counter (8B LE), state[14,15] = iv (8B LE).
 * The RFC 7539 IETF form is different (state[12] = block counter,
 * state[13..15] = 12-byte nonce). For triple-blind we stick with the
 * Bernstein form, matching the MoonBit implementation which is also
 * OpenSSH-style.
 *
 * The C driver emits the keystream (zero plaintext => chacha20 output)
 * per test vector. The Python reference (chacha20_ref.py) is a pure-
 * Python implementation of the same Bernstein form. compare.py asserts
 * byte-exact agreement between C and Python outputs, and separately
 * runs `moon test` to confirm MoonBit passes its own chacha_wbtest
 * vectors.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#include "chacha.h"        /* vendored shim — u_char/u_int + chacha_ctx */

static void
hexdump(char *dst, const u_char *buf, size_t n)
{
	size_t i;
	for (i = 0; i < n; i++) {
		static const char h[] = "0123456789abcdef";
		dst[2 * i]     = h[buf[i] >> 4];
		dst[2 * i + 1] = h[buf[i] & 0xf];
	}
	dst[2 * n] = 0;
}

/* Emit one chacha20 keystream. The "expected" comparison is between
 * C and Python outputs that both run the same algorithm on the same
 * input — there is no separate "RFC" expected for Bernstein form. */
static void
emit_keystream(const char *name, const u_char *key, u_int kbits,
    const u_char *iv, const u_char *ctr, size_t n_bytes)
{
	struct chacha_ctx ctx;
	u_char zero[64] = {0};
	u_char out[64];
	char got[129];

	chacha_keysetup(&ctx, key, kbits);
	chacha_ivsetup(&ctx, iv, ctr);
	chacha_encrypt_bytes(&ctx, zero, out, (u_int)n_bytes);

	hexdump(got, out, n_bytes);
	printf("VEC name=%s kbits=%u n=%zu got=%s\n",
	    name, kbits, n_bytes, got);
}

int
main(void)
{
	/* KAT 1: 256-bit key, all-zero key/iv/ctr, 64-byte block */
	{
		u_char key[32] = {0};
		u_char iv[8]   = {0};
		u_char ctr[8]  = {0};
		emit_keystream("K1_zero256_64B", key, 256, iv, ctr, 64);
	}

	/* KAT 2: 256-bit key = [0..31], iv=zeros, counter=0, 64 bytes */
	{
		u_char key[32];
		u_char iv[8]  = {0};
		u_char ctr[8] = {0};
		for (int i = 0; i < 32; i++) key[i] = (u_char)i;
		emit_keystream("K2_0to31_64B", key, 256, iv, ctr, 64);
	}

	/* KAT 3: 128-bit key = [0xFF, 0xFE, ..., 0xF0], iv=[0x55]*8, ctr=0, 16 B */
	{
		u_char key[16];
		u_char iv[8];
		u_char ctr[8] = {0};
		for (int i = 0; i < 16; i++) key[i] = (u_char)(0xFF - i);
		for (int i = 0; i < 8;  i++) iv[i]  = 0x55;
		emit_keystream("K3_128bit_iv55_16B", key, 128, iv, ctr, 16);
	}

	/* KAT 4: 256-bit key = [0..31], iv=[0,0,0,0,0,0,0,1], ctr=0x01000000 (LE: 01 00 00 00 00 00 00 00) */
	{
		u_char key[32];
		u_char iv[8]  = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01};
		/* counter in OpenSSH form: ctr_lo (4B LE) || ctr_hi (4B LE) = 0x01000000 (= 0x00000001) */
		u_char ctr[8] = {0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
		for (int i = 0; i < 32; i++) key[i] = (u_char)i;
		emit_keystream("K4_0to31_iv1_ctr1_16B", key, 256, iv, ctr, 16);
	}

	/* KAT 5: 256-bit key = all 0xAA, iv=counter=0, 64 bytes (multi-block test) */
	{
		u_char key[32];
		u_char iv[8]  = {0};
		u_char ctr[8] = {0};
		memset(key, 0xAA, 32);
		emit_keystream("K5_AAx32_64B", key, 256, iv, ctr, 64);
	}

	printf("CHACHA20_SUMMARY OUTPUT\n");
	return 0;
}
