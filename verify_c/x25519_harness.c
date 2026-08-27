// X25519 KAT 验证 - 用 OpenBSD 原版 smult_curve25519_ref.c 跑 RFC 7748 § 5.2
// 与 MoonBit 实现对比,确认算法正确
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "smult_curve25519_ref.c"

static void hexdump(const char *label, const uint8_t *buf, size_t n) {
  fprintf(stderr, "%s: ", label);
  for (size_t i = 0; i < n; i++) fprintf(stderr, "%02x", buf[i]);
  fprintf(stderr, "\n");
}

static void parse(const char *hex, uint8_t *out, size_t n) {
  for (size_t i = 0; i < n; i++) {
    unsigned int v;
    sscanf(hex + 2 * i, "%02x", &v);
    out[i] = (uint8_t)v;
  }
}

int main(void) {
  int all_ok = 1;

  // RFC 7748 § 5.2 Vector 1 (Alice)
  {
    uint8_t scalar[32];
    uint8_t point[32];
    uint8_t expected[32];
    uint8_t got[32];
    parse("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4", scalar, 32);
    parse("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c", point, 32);
    parse("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552", expected, 32);
    crypto_scalarmult_curve25519(got, scalar, point);
    fprintf(stderr, "===== RFC 7748 Alice =====\n");
    hexdump("got     ", got, 32);
    hexdump("expected", expected, 32);
    int ok = (memcmp(got, expected, 32) == 0);
    fprintf(stderr, "result: %s\n\n", ok ? "PASS" : "FAIL");
    all_ok &= ok;
  }

  // RFC 7748 § 5.2 Vector 2 (Bob)
  {
    uint8_t scalar[32];
    uint8_t point[32];
    uint8_t expected[32];
    uint8_t got[32];
    parse("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d", scalar, 32);
    parse("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493", point, 32);
    parse("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957", expected, 32);
    crypto_scalarmult_curve25519(got, scalar, point);
    fprintf(stderr, "===== RFC 7748 Bob =====\n");
    hexdump("got     ", got, 32);
    hexdump("expected", expected, 32);
    int ok = (memcmp(got, expected, 32) == 0);
    fprintf(stderr, "result: %s\n\n", ok ? "PASS" : "FAIL");
    all_ok &= ok;
  }

  fprintf(stderr, "\n===== X25519 SUMMARY: %s =====\n", all_ok ? "ALL PASS" : "SOME FAILED");
  return all_ok ? 0 : 1;
}