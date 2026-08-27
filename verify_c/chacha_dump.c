// 打印 sigma 和 tau 字符串的字节级内容
#include <stdio.h>
#include "includes.h"
#include "chacha.h"

int main(void) {
  // sigma 和 tau 是 static 内部变量,需要重新声明
  const char sigma[] = "expand 32-byte k";
  const char tau[] = "expand 16-byte k";
  printf("sigma bytes: ");
  for (int i = 0; i < 16; i++) printf("%02x ", (unsigned char)sigma[i]);
  printf("\n");
  printf("tau bytes:   ");
  for (int i = 0; i < 16; i++) printf("%02x ", (unsigned char)tau[i]);
  printf("\n");
  // 期望 input[3] = U8TO32_LITTLE(sigma+12)
  printf("sigma3 (LE u32 of bytes 12-15): 0x%08x\n",
         ((unsigned int)(unsigned char)sigma[12]) |
         ((unsigned int)(unsigned char)sigma[13] << 8) |
         ((unsigned int)(unsigned char)sigma[14] << 16) |
         ((unsigned int)(unsigned char)sigma[15] << 24));
  printf("sigma2 (LE u32 of bytes 8-11):  0x%08x\n",
         ((unsigned int)(unsigned char)sigma[8]) |
         ((unsigned int)(unsigned char)sigma[9] << 8) |
         ((unsigned int)(unsigned char)sigma[10] << 16) |
         ((unsigned int)(unsigned char)sigma[11] << 24));
  return 0;
}
