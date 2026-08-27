// SHA-256 KAT 验证 - 用 OpenBSD 原版 sha2.c 跑 FIPS 180-4 测试向量
// 与 MoonBit 实现对比,确认算法正确
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "sha2.c"  // OpenBSD original

static void hexdump(const char *label, const uint8_t *buf, size_t n) {
  fprintf(stderr, "%s: ", label);
  for (size_t i = 0; i < n; i++) fprintf(stderr, "%02x", buf[i]);
  fprintf(stderr, "\n");
}

static int run_vector(const char *name, const uint8_t *msg, size_t mlen, const uint8_t *expected) {
  SHA2_CTX ctx;
  uint8_t digest[SHA256_DIGEST_LENGTH];
  SHA256Init(&ctx);
  SHA256Update(&ctx, msg, mlen);
  SHA256Final(digest, &ctx);
  fprintf(stderr, "===== %s (msg=%zu bytes) =====\n", name, mlen);
  hexdump("got     ", digest, SHA256_DIGEST_LENGTH);
  hexdump("expected", expected, SHA256_DIGEST_LENGTH);
  int ok = (memcmp(digest, expected, SHA256_DIGEST_LENGTH) == 0);
  fprintf(stderr, "result: %s\n\n", ok ? "PASS" : "FAIL");
  return ok;
}

int main(void) {
  int all_ok = 1;

  // FIPS 180-4 Appendix B.1 Test 1: "abc"
  {
    uint8_t msg[] = "abc";
    uint8_t expected[] = {
      0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
      0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
      0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
      0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
    };
    all_ok &= run_vector("FIPS Test 1 abc", msg, 3, expected);
  }

  // FIPS 180-4 Appendix B.1 Test 3: 56 bytes
  {
    uint8_t msg[] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    uint8_t expected[] = {
      0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8,
      0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39,
      0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67,
      0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1,
    };
    all_ok &= run_vector("FIPS Test 3 56-byte", msg, 56, expected);
  }

  // RFC 4231 Test 1: HMAC-SHA256("Hi There", 0x0b*20)
  // 用 sha256 验证: SHA256((0x0b*20 XOR 0x36*20 || 0x0b*20 XOR 0x5c*20 || ...))
  // 这里只跑 SHA256 部分(直接 SHA256("abc") 验证)
  // HMAC 验证在 hmac_harness.c

  fprintf(stderr, "\n===== SHA256 SUMMARY: %s =====\n", all_ok ? "ALL PASS" : "SOME FAILED");
  return all_ok ? 0 : 1;
}