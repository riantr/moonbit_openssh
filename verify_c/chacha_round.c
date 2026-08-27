// 简化版 chacha20 单轮 debug,与 OpenSSH 原版 chacha.c 对比
// 必须和 chacha.c 的 QR 完全等价
#include <stdio.h>
#include <string.h>
#include <stdint.h>

typedef uint8_t u8;
typedef uint32_t u32;

#define ROTL32(v, n) (((v) << (n)) | ((v) >> (32 - (n))))

// 单条 QR(完全镜像 OpenSSH chacha.c 的 QR 宏)
#define QUARTERROUND(a,b,c,d) \
  a += b; d ^= a; d = ROTL32(d,16); \
  c += d; b ^= c; b = ROTL32(b,12); \
  a += b; d ^= a; d = ROTL32(d, 8); \
  c += d; b ^= c; b = ROTL32(b, 7);

int main(void) {
  // Test 1 state: sigma + 12 zeros
  u32 state[16] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
                   0,0,0,0,0,0,0,0,0,0,0,0};

  for (int round = 0; round < 10; round++) {
    u32 x0=state[0], x1=state[1], x2=state[2], x3=state[3];
    u32 x4=state[4], x5=state[5], x6=state[6], x7=state[7];
    u32 x8=state[8], x9=state[9], x10=state[10], x11=state[11];
    u32 x12=state[12], x13=state[13], x14=state[14], x15=state[15];

    QUARTERROUND(x0, x4, x8, x12);
    QUARTERROUND(x1, x5, x9, x13);
    QUARTERROUND(x2, x6, x10, x14);
    QUARTERROUND(x3, x7, x11, x15);
    QUARTERROUND(x0, x5, x10, x15);
    QUARTERROUND(x1, x6, x11, x12);
    QUARTERROUND(x2, x7, x8, x13);
    QUARTERROUND(x3, x4, x9, x14);

    state[0]=x0; state[1]=x1; state[2]=x2; state[3]=x3;
    state[4]=x4; state[5]=x5; state[6]=x6; state[7]=x7;
    state[8]=x8; state[9]=x9; state[10]=x10; state[11]=x11;
    state[12]=x12; state[13]=x13; state[14]=x14; state[15]=x15;

    if (round < 3 || round == 9) {
      printf("after %d round(s):\n", round+1);
      for (int i = 0; i < 4; i++) {
        printf("  state[%d] = 0x%08x = %u\n", i, state[i], state[i]);
      }
    }
  }
  // Add original state
  u32 orig[16] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
                  0,0,0,0,0,0,0,0,0,0,0,0};
  for (int i = 0; i < 16; i++) state[i] += orig[i];
  printf("after add:\n");
  for (int i = 0; i < 4; i++) {
    printf("  state[%d] = 0x%08x = %u\n", i, state[i], state[i]);
  }
  return 0;
}
