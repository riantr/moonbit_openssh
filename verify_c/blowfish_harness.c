/*
 * blowfish_harness.c -- the reference side of Loop #86.
 *
 * Everything below the includes is OpenSSH's own code:
 *
 *   sha2.c               OpenBSD's SHA-2 (already in this repository)
 *   blowfish_ref.c       OpenSSH's openbsd-compat/blowfish.c
 *   bcrypt_pbkdf_ref.c   OpenSSH's openbsd-compat/bcrypt_pbkdf.c
 *
 * This file only picks the inputs and prints the answers.  The answers
 * are what `src/blowfish` and `src/bcrypt_pbkdf` are checked against, so
 * they have to come from OpenSSH and not from us.
 *
 * Output is one record per line: a name, a space, and a hex string.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "sha2.c"
#include "blowfish_ref.c"
#include "bcrypt_pbkdf_ref.c"

/* ------------------------------------------------------------------ */
/* FNV-1a, 64 bit, over the byte image of a word array.                */
/*                                                                     */
/* The bytes are taken little-endian, explicitly, so the answer does    */
/* not depend on the host's byte order.                                */
/* ------------------------------------------------------------------ */

static void
fnv_bytes(uint64_t *h, const uint8_t *p, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++) {
		*h ^= (uint64_t)p[i];
		*h *= 0x100000001b3ULL;
	}
}

static uint64_t
fnv_words(const uint32_t *w, size_t n)
{
	uint64_t h = 0xcbf29ce484222325ULL;
	uint8_t b[4];
	size_t i;
	int k;

	for (i = 0; i < n; i++) {
		for (k = 0; k < 4; k++)
			b[k] = (uint8_t)((w[i] >> (8 * k)) & 0xFF);
		fnv_bytes(&h, b, 4);
	}
	return h;
}

static void
print_hex(const char *name, const uint8_t *p, size_t n)
{
	size_t i;

	printf("%s ", name);
	for (i = 0; i < n; i++)
		printf("%02x", p[i]);
	printf("\n");
}

/* A word array as hex, big-endian per word, so the answer does not depend
 * on the host's byte order. */
static void
print_words(const char *name, const uint32_t *w, size_t n)
{
	size_t i;

	printf("%s ", name);
	for (i = 0; i < n; i++)
		printf("%08x", w[i]);
	printf("\n");
}

/* The 64-bit checksum, split into two 32-bit halves so that a MoonBit
 * test can compare it without needing to print hex. */
static void
print_fnv(const char *name, uint64_t v)
{
	printf("%s %08x %08x\n", name,
	    (unsigned)((v >> 32) & 0xFFFFFFFFULL),
	    (unsigned)(v & 0xFFFFFFFFULL));
}

/* The four S-boxes as one flat array, so it can be hashed. */
static void
flatten_s(const blf_ctx *c, uint32_t *out)
{
	int i, k;

	for (i = 0; i < 4; i++)
		for (k = 0; k < 256; k++)
			out[i * 256 + k] = c->S[i][k];
}

/* ------------------------------------------------------------------ */

int
main(void)
{
	blf_ctx c;
	uint32_t flat[1024];
	uint8_t salt[64], key[64];
	uint8_t out[1024];
	int i;

	/* ---- the initial state: pi ---- */
	Blowfish_initstate(&c);
	print_words("PI_P", c.P, 18);
	flatten_s(&c, flat);
	print_fnv("PI_S_FNV", fnv_words(flat, 1024));

	/* ---- the salted schedule ---- */
	for (i = 0; i < 64; i++) {
		salt[i] = (uint8_t)i;
		key[i] = (uint8_t)(255 - i);
	}
	Blowfish_initstate(&c);
	Blowfish_expandstate(&c, salt, 64, key, 64);
	print_words("EXPANDSTATE_P", c.P, 18);
	flatten_s(&c, flat);
	print_fnv("EXPANDSTATE_S_FNV", fnv_words(flat, 1024));

	/* ---- the unsalted schedule ---- */
	for (i = 0; i < 64; i++)
		key[i] = (uint8_t)i;
	Blowfish_initstate(&c);
	Blowfish_expand0state(&c, key, 64);
	print_words("EXPAND0_P", c.P, 18);
	flatten_s(&c, flat);
	print_fnv("EXPAND0_S_FNV", fnv_words(flat, 1024));

	/* ---- the published ECB vector ----
	 *
	 * The key is the alphabet and the plaintext is the word BLOWFISH;
	 * the answer is the one Eric Young's original test program prints.
	 * It is in OpenSSH's own blowfish.c too, in the `main()` that the
	 * file carries but does not compile.
	 */
	{
		const char *k = "abcdefghijklmnopqrstuvwxyz";
		uint32_t data[2] = { 0x424c4f57L, 0x46495348L };

		blf_key(&c, (const u_int8_t *)k, 26);
		blf_enc(&c, data, 1);
		print_words("ECB_BLOWFISH", data, 2);
		blf_dec(&c, data, 1);
		print_words("ECB_BLOWFISH_DEC", data, 2);
	}

	/* ---- the keystream reader ----
	 *
	 * The cursor is shared between the key and the salt streams, and
	 * that is the part of the schedule that is easy to get wrong, so
	 * the reader is pinned down on its own here.
	 */
	{
		const uint8_t data[8] = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h' };
		u_int16_t cur = 0;
		uint32_t w;

		for (i = 0; i < 3; i++) {
			w = Blowfish_stream2word(data, 8, &cur);
			printf("STREAM2WORD_%d %08x %u\n", i, w, (unsigned)cur);
		}
		/* starting past the end wraps to the beginning */
		cur = 7;
		w = Blowfish_stream2word(data, 8, &cur);
		printf("STREAM2WORD_WRAP %08x %u\n", w, (unsigned)cur);
	}

	/* ---- bcrypt_pbkdf ---- */
	{
		uint8_t s16[16];
		const char *p1 = "password";
		const char *p2 = "correct horse battery staple";
		const char *p3 = "x";

		for (i = 0; i < 16; i++)
			s16[i] = (uint8_t)i;
		memset(out, 0, sizeof(out));
		bcrypt_pbkdf(p1, strlen(p1), s16, 16, out, 48, 16);
		print_hex("BCRYPT_1", out, 48);

		for (i = 0; i < 16; i++)
			s16[i] = (uint8_t)(0xf0 + i);
		memset(out, 0, sizeof(out));
		bcrypt_pbkdf(p2, strlen(p2), s16, 16, out, 48, 4);
		print_hex("BCRYPT_2", out, 48);

		for (i = 0; i < 16; i++)
			s16[i] = 0x5a;
		memset(out, 0, sizeof(out));
		bcrypt_pbkdf(p3, strlen(p3), s16, 16, out, 32, 1);
		print_hex("BCRYPT_3", out, 32);

		/* a longer key, to exercise the non-linear scatter */
		memset(out, 0, sizeof(out));
		bcrypt_pbkdf(p1, strlen(p1), s16, 16, out, 100, 2);
		print_hex("BCRYPT_4", out, 100);
	}

	return 0;
}
