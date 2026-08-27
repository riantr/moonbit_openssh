/*
 * Triple-blind cross-check driver for SHA-256 (FIPS 180-4 § B.1).
 *
 * Same pattern as triple_check/sha512/ but using SHA256_* routines from
 * OpenBSD's sha2.c. Expected digests are derived from Python's
 * hashlib.sha256 (regenerate via gen_expected.py).
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#include "../../verify_c/sha2_stub.h"
#include "../../verify_c/bsd-sha2.h"
#include "../../verify_c/sha2.c"

static void
hexdump(char *dst, const uint8_t *buf, size_t n)
{
	size_t i;
	for (i = 0; i < n; i++) {
		static const char h[] = "0123456789abcdef";
		dst[2 * i]     = h[buf[i] >> 4];
		dst[2 * i + 1] = h[buf[i] & 0xf];
	}
	dst[2 * n] = 0;
}

static int
run_vector(const char *name, const uint8_t *msg, size_t mlen,
    const uint8_t *expected)
{
	SHA2_CTX ctx;
	uint8_t digest[SHA256_DIGEST_LENGTH];
	char got[65], exp[65];
	int ok;

	SHA256Init(&ctx);
	SHA256Update(&ctx, msg, mlen);
	SHA256Final(digest, &ctx);

	hexdump(got, digest, SHA256_DIGEST_LENGTH);
	hexdump(exp, expected, SHA256_DIGEST_LENGTH);
	ok = (memcmp(digest, expected, SHA256_DIGEST_LENGTH) == 0);

	printf("VEC name=%s len=%zu got=%s exp=%s pass=%d\n",
	    name, mlen, got, exp, ok);
	return ok;
}

int
main(void)
{
	int all_ok = 1;

	/* FIPS 180-4 § B.1 Test 1: "abc" (3 bytes) */
	{
		uint8_t msg[] = "abc";
		uint8_t expected[32] = {
			0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad,
		};
		all_ok &= run_vector("FIPS_B1_T1_abc", msg, 3, expected);
	}

	/* FIPS 180-4 § B.1 Test 2: 56 bytes */
	{
		uint8_t msg[] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
		uint8_t expected[32] = {
			0x24,0x8d,0x6a,0x61,0xd2,0x06,0x38,0xb8,0xe5,0xc0,0x26,0x93,0x0c,0x3e,0x60,0x39,0xa3,0x3c,0xe4,0x59,0x64,0xff,0x21,0x67,0xf6,0xec,0xed,0xd4,0x19,0xdb,0x06,0xc1,
		};
		all_ok &= run_vector("FIPS_B1_T2_56B", msg, 56, expected);
	}

	/* FIPS 180-4 § B.1 Test 3: "a" repeated 1,000,000 times */
	{
		uint8_t *msg = (uint8_t *)malloc(1000000);
		uint8_t expected[32] = {
			0xcd,0xc7,0x6e,0x5c,0x99,0x14,0xfb,0x92,0x81,0xa1,0xc7,0xe2,0x84,0xd7,0x3e,0x67,0xf1,0x80,0x9a,0x48,0xa4,0x97,0x20,0x0e,0x04,0x6d,0x39,0xcc,0xc7,0x11,0x2c,0xd0,
		};
		memset(msg, 'a', 1000000);
		all_ok &= run_vector("FIPS_B1_T3_1Mx_a", msg, 1000000, expected);
		free(msg);
	}

	/* FIPS 180-4 § B.2 boundary: 64 bytes of 'a' (single 512-bit block) */
	{
		uint8_t msg[64];
		uint8_t expected[32] = {
			0xff,0xe0,0x54,0xfe,0x7a,0xe0,0xcb,0x6d,0xc6,0x5c,0x3a,0xf9,0xb6,0x1d,0x52,0x09,0xf4,0x39,0x85,0x1d,0xb4,0x3d,0x0b,0xa5,0x99,0x73,0x37,0xdf,0x15,0x46,0x68,0xeb,
		};
		memset(msg, 'a', 64);
		all_ok &= run_vector("B2_T1_64a", msg, 64, expected);
	}

	/* FIPS 180-4 § B.2 multi-block: 56-byte pattern × 64 (3584 bytes) */
	{
		uint8_t *msg = (uint8_t *)malloc(3584);
		uint8_t expected[32] = {
			0xa6,0x5c,0x13,0xcc,0x66,0xe4,0x3a,0x90,0xc9,0x89,0x00,0x95,0x52,0x8d,0xe8,0x36,0x50,0x35,0x7e,0x33,0x35,0xf2,0xde,0xd1,0xd1,0x66,0x6d,0x0c,0xad,0xbf,0x71,0x2d,
		};
		for (int i = 0; i < 64; i++) {
			memcpy(msg + i * 56,
			    "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56);
		}
		all_ok &= run_vector("B2_T2_8960B", msg, 3584, expected);
		free(msg);
	}

	printf("SHA256_SUMMARY %s\n", all_ok ? "PASS" : "FAIL");
	return all_ok ? 0 : 1;
}
