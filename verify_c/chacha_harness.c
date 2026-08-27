// 用 OpenSSH 原版 chacha.c,加每轮后日志
#include <stdio.h>
#include <string.h>
#include <stdint.h>

typedef uint8_t u_char;
typedef unsigned int u_int;

struct chacha_ctx { u_int input[16]; };
void chacha_keysetup(struct chacha_ctx *x, const u_char *k, u_int kbits);
void chacha_ivsetup(struct chacha_ctx *x, const u_char *iv, const u_char *ctr);
void chacha_encrypt_bytes(struct chacha_ctx *x, const u_char *m, u_char *c, u_int bytes);

int main(void) {
  // Test 3: 128-bit key=[0xFF, 0xFE, ..., 0xF0], iv=[0x55]*8, counter=[0]*8
  fprintf(stderr, "===== TEST 3: 128-bit key, iv=0x55*8, counter=0 =====\n");
  {
    u_char key[16];
    for (int i = 0; i < 16; i++) key[i] = 0xFF - i;
    u_char iv[8];
    for (int i = 0; i < 8; i++) iv[i] = 0x55;
    u_char counter[8] = {0};
    struct chacha_ctx ctx;
    chacha_keysetup(&ctx, key, 128);
    chacha_ivsetup(&ctx, iv, counter);
    fprintf(stderr, "INPUT state: x0=0x%08x x1=0x%08x x2=0x%08x x3=0x%08x\n",
            ctx.input[0], ctx.input[1], ctx.input[2], ctx.input[3]);
    fprintf(stderr, "              x4=0x%08x x5=0x%08x x6=0x%08x x7=0x%08x\n",
            ctx.input[4], ctx.input[5], ctx.input[6], ctx.input[7]);
    fprintf(stderr, "              x8=0x%08x x9=0x%08x x10=0x%08x x11=0x%08x\n",
            ctx.input[8], ctx.input[9], ctx.input[10], ctx.input[11]);
    fprintf(stderr, "              x12=0x%08x x13=0x%08x x14=0x%08x x15=0x%08x\n",
            ctx.input[12], ctx.input[13], ctx.input[14], ctx.input[15]);
    u_char in[64] = {0};
    u_char out[64];
    chacha_encrypt_bytes(&ctx, in, out, 64);
    fprintf(stderr, "KEYSTREAM:\n");
    for (int i = 0; i < 16; i++) fprintf(stderr, "%02x ", out[i]);
    fprintf(stderr, "\n");
  }
  return 0;
}
