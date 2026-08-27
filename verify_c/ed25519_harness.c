// Ed25519 KAT harness 锟?uses OpenSSH's original ed25519.c (TweetNaCl ref10)
// verbatim, with sha2.c providing SHA-512. Verifies the MoonBit Ed25519
// implementation against the same C reference on RFC 8032 vectors.
//
// Build: gcc -o ed25519_kat.exe ed25519_harness.c
// (ed25519.c is #included at the bottom; it pulls in ed25519_includes_stub.h /
//  ed25519_crypto_api_stub.h via -D include remapping)

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

// --- SHA-512 via OpenBSD sha2.c ---
#include "sha2_stub.h"          // BYTE_ORDER + u_int types + explicit_bzero
#include "bsd-sha2.h"           // SHA2_CTX / SHA512Init/Update/Final
#include "sha2.c"               // OpenBSD original implementation (BSD-licensed)

static int crypto_hash_sha512(unsigned char *out, const unsigned char *in,
    unsigned long long inlen)
{
	SHA2_CTX ctx;
	SHA512Init(&ctx);
	SHA512Update(&ctx, in, inlen);
	SHA512Final(out, &ctx);
	return 0;
}

// --- Pull in OpenSSH's Ed25519 verbatim ---
// ed25519_ref.c is a copy of OpenSSH ed25519.c with its two includes
// remapped to our stub headers (done at copy time, not via #define tricks).
#include "ed25519_ref.c"        // copy of OpenSSH ed25519.c (public domain)

// --- Test driver ---

static void hexdump(const char *label, const unsigned char *buf, size_t n)
{
	printf( "%s", label);
	for (size_t i = 0; i < n; i++)
		printf( "%02x", buf[i]);
	printf( "\n");
}

static int unhex(const char *hex, unsigned char *out, size_t nout)
{
	size_t n = strlen(hex);
	if (n != nout * 2)
		return -1;
	for (size_t i = 0; i < nout; i++) {
		unsigned int b;
		if (sscanf(hex + 2 * i, "%2x", &b) != 1)
			return -1;
		out[i] = (unsigned char)b;
	}
	return 0;
}

struct kat {
	const char *name;
	const char *seed;   /* 64 hex chars */
	const char *msg;    /* even number of hex chars, may be "" */
	const char *pk;     /* 64 hex chars */
	const char *sig;    /* 128 hex chars */
};


int main(void)
{
	int all_ok = 1;

	/* RFC 8032 SS 7.1 Test 1: empty message */
	{
		unsigned char seed[32], pk[32], sk[64], sig[64];
		const unsigned char *m = (const unsigned char *)"";
		unsigned long long mlen = 0;
		unhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", seed, 32);

		crypto_sign_ed25519_keypair_from_seed(pk, sk, seed);

		unsigned char expect_pk[32], expect_sig[64];
		unhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", expect_pk, 32);
		unhex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b", expect_sig, 64);

		unsigned long long smlen = 0;
		unsigned char sm[64 + 16]; /* empty msg -> only 64 bytes needed */
		crypto_sign_ed25519(sm, &smlen, m, mlen, sk);
		memcpy(sig, sm, 64);

		int ok_pk = memcmp(pk, expect_pk, 32) == 0;
		int ok_sig = memcmp(sig, expect_sig, 64) == 0;

		/* verify path */
		unsigned char mout[64 + 16]; /* must hold smlen = mlen + 64 bytes */
		unsigned long long mlen_out = 0;
		int vok = crypto_sign_ed25519_open(mout, &mlen_out, sm, smlen, pk) == 0;

		printf( "===== %s =====\n", "RFC 8032 Test 1 (empty msg)");
		hexdump("got pk       ", pk, 32);
		hexdump("expected pk  ", expect_pk, 32);
		hexdump("got sig      ", sig, 64);
		hexdump("expected sig ", expect_sig, 64);
		printf( "pk: %s  sig: %s  verify: %s\n\n",
		    ok_pk ? "PASS" : "FAIL",
		    ok_sig ? "PASS" : "FAIL",
		    vok ? "PASS" : "FAIL");
		all_ok &= ok_pk && ok_sig && vok;
	}

	/* RFC 8032 SS 7.1 Test 2: 1-byte msg 0x72 */
	{
		unsigned char seed[32], pk[32], sk[64], sig[64];
		unsigned char m[1];
		unhex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb", seed, 32);
		m[0] = 0x72;

		crypto_sign_ed25519_keypair_from_seed(pk, sk, seed);

		unsigned char expect_pk[32], expect_sig[64];
		unhex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", expect_pk, 32);
		unhex("92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00", expect_sig, 64);

		unsigned long long smlen = 0;
		unsigned char sm[65 + 16];
		crypto_sign_ed25519(sm, &smlen, m, 1, sk);
		memcpy(sig, sm, 64);

		int ok_pk = memcmp(pk, expect_pk, 32) == 0;
		int ok_sig = memcmp(sig, expect_sig, 64) == 0;

		unsigned char mout[65 + 16]; /* must hold smlen = mlen + 64 */
		unsigned long long mlen_out = 0;
		int vok = crypto_sign_ed25519_open(mout, &mlen_out, sm, smlen, pk) == 0;

		printf( "===== %s =====\n", "RFC 8032 Test 2 (msg=0x72)");
		hexdump("got pk       ", pk, 32);
		hexdump("expected pk  ", expect_pk, 32);
		hexdump("got sig      ", sig, 64);
		hexdump("expected sig ", expect_sig, 64);
		printf( "pk: %s  sig: %s  verify: %s\n\n",
		    ok_pk ? "PASS" : "FAIL",
		    ok_sig ? "PASS" : "FAIL",
		    vok ? "PASS" : "FAIL");
		all_ok &= ok_pk && ok_sig && vok;
	}

	/* RFC 8032 SS 7.1 Test 3: 2-byte msg 0xaf82 */
	{
		unsigned char seed[32], pk[32], sk[64], sig[64], m[2];
		unhex("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7", seed, 32);
		m[0] = 0xaf; m[1] = 0x82;

		crypto_sign_ed25519_keypair_from_seed(pk, sk, seed);

		unsigned char expect_pk[32], expect_sig[64];
		unhex("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", expect_pk, 32);
		unhex("6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a", expect_sig, 64);

		unsigned long long smlen = 0;
		unsigned char sm[66 + 16];
		crypto_sign_ed25519(sm, &smlen, m, 2, sk);
		memcpy(sig, sm, 64);

		int ok_pk = memcmp(pk, expect_pk, 32) == 0;
		int ok_sig = memcmp(sig, expect_sig, 64) == 0;

		unsigned char mout[66 + 16]; /* must hold smlen = mlen + 64 */
		unsigned long long mlen_out = 0;
		int vok = crypto_sign_ed25519_open(mout, &mlen_out, sm, smlen, pk) == 0;

		/* tampered-message rejection: flip one bit of m */
		sm[64 + 0] ^= 0x20; /* af -> 8f in signed-message copy */
		int trej = crypto_sign_ed25519_open(mout, &mlen_out, sm, smlen, pk) != 0;
		sm[64 + 0] ^= 0x20; /* restore */

		printf( "===== %s =====\n", "RFC 8032 Test 3 (msg=0xaf82)");
		hexdump("got pk       ", pk, 32);
		hexdump("expected pk  ", expect_pk, 32);
		hexdump("got sig      ", sig, 64);
		hexdump("expected sig ", expect_sig, 64);
		printf( "pk: %s  sig: %s  verify: %s  tampered-reject: %s\n\n",
		    ok_pk ? "PASS" : "FAIL",
		    ok_sig ? "PASS" : "FAIL",
		    vok ? "PASS" : "FAIL",
		    trej ? "PASS" : "FAIL");
		all_ok &= ok_pk && ok_sig && vok && trej;
	}

	/* Malleability check: s = L must be rejected by OpenSSH's sc25519_inrange */
	{
		unsigned char seed[32], pk[32], sk[64];
		unhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", seed, 32);
		crypto_sign_ed25519_keypair_from_seed(pk, sk, seed);

		unsigned char m[4] = { 't', 'e', 's', 't' };
		unsigned long long smlen = 0;
		unsigned char sm[68 + 16];
		crypto_sign_ed25519(sm, &smlen, m, 4, sk);

		/* overwrite s with L (LE): ED D3 F5 5C ... 00 10 */
		unhex("edd3f55c1a631258d69cf7a2de9f130d14000000000000000000000000000010",
		    sm + 32, 32);

		unsigned char mout[68];
		unsigned long long mlen_out = 0;
		int lrej = crypto_sign_ed25519_open(mout, &mlen_out, sm, smlen, pk) != 0;

		printf( "===== %s =====\n", "Malleability (s == L rejected)");
		printf( "s==L reject: %s\n\n", lrej ? "PASS" : "FAIL");
		all_ok &= lrej;
	}

	printf( "\n===== Ed25519 SUMMARY: %s =====\n",
	    all_ok ? "ALL PASS" : "SOME FAILED");
	return all_ok ? 0 : 1;
}


