// 用 OpenSSH 原版完整宏定义,只改 state 初始化和加日志
#include <stdio.h>
#include <string.h>
#include <stdint.h>

typedef uint8_t u8;
typedef uint32_t u32;

// 直接从 OpenSSH chacha.c 复制宏定义
#define U8C(v) (v##U)
#define U32C(v) (v##U)

#define U8V(v) ((u8)(v) & U8C(0xFF))
#define U32V(v) ((u32)(v) & U32C(0xFFFFFFFF))

#define ROTL32(v, n) \
  (U32V((v) << (n)) | ((v) >> (32 - (n))))

#define U8TO32_LITTLE(p) \
  (((u32)((p)[0])      ) | \
   ((u32)((p)[1]) <<  8) | \
   ((u32)((p)[2]) << 16) | \
   ((u32)((p)[3]) << 24))

#define ROTATE(v,c) (ROTL32(v,c))
#define XOR(v,w) ((v) ^ (w))
#define PLUS(v,w) (U32V((v) + (w)))
#define PLUSONE(v) (PLUS((v),1))

#define QUARTERROUND(a,b,c,d) \
  a = PLUS(a,b); d = ROTATE(XOR(d,a),16); \
  c = PLUS(c,d); b = ROTATE(XOR(b,c),12); \
  a = PLUS(a,b); d = ROTATE(XOR(d,a), 8); \
  c = PLUS(c,d); b = ROTATE(XOR(b,c), 7);

int main(void) {
  // Test 2 state
  u32 state[16] = {
    0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
    0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
    0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
    0x00000000, 0x01000000, 0x00000000, 0x01000000
  };

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
  u32 orig[16] = {
    0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
    0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
    0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
    0x00000000, 0x01000000, 0x00000000, 0x01000000
  };
  for (int i = 0; i < 16; i++) state[i] += orig[i];
  printf("after add:\n");
  for (int i = 0; i < 4; i++) {
    printf("  state[%d] = 0x%08x = %u\n", i, state[i], state[i]);
  }
  return 0;
}
