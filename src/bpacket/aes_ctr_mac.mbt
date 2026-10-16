///| aes128-ctr + hmac-sha2-256 会话上下文(加密并认证 / encrypt-and-MAC)
///
/// 对应 OpenSSH cipher.c:93 的 `aes128-ctr` 配 mac.c:62 的 `hmac-sha2-256`,
/// 也就是 Loop #31/#32 与真实 sshd 协商出来的这一对。
///
/// 下面四条语义全部照抄 C 源码,而不是按 RFC 直觉填的。写错了其中任何一条,
/// 症状都是「包能发出去、服务器不回话」,排查起来极其昂贵:
///
///   * block size 是 **16**,不是 8。cipher.c:93 的表项第 2 列是 16:
///     `{ "aes128-ctr", 16, 16, 0, 0, 0, EVP_aes_128_ctr }`
///     (name, block_size, key_len, iv_len, auth_len, flags, evp)。
///     所以 padding 必须把「4 + packet_length」凑成 16 的倍数,即
///     `packet_length ≡ 12 (mod 16)`。Loop #31/#32 明文阶段用的
///     `≡ 4 (mod 8)`(block=8)与它不兼容,切换时必须由 mode 自己决定块长。
///
///   * 表里 `iv_len` 写的是 0,但 `cipher_ivlen()`(cipher.c:170-176)对 0 回落到
///     block_size。所以派生出的 'A'/'B' 是 16 字节计数器,而且它在整条连接上
///     **持续递增**——不是每个包从 IV 重来。这是 CTR 流密码的常态,漏掉递增
///     会让两个明文不同的包产生完全相同的密钥流,等于把明文xor关系送人。
///
///   * `hmac-sha2-256` 的 truncatebits 是 0(mac.c:62),即**完整 32 字节 MAC**。
///     很多第三方实现默认截断到 16 字节(把 hmac-sha2-256 和 hmac-sha1-96 搞混),
///     那样与 OpenSSH 互不通,而对端只会报一个笼统的 MAC 错误。
///
///   * 非 EtM 的 MAC 覆盖的是**解密后**的整包 `4 + packet_length` 字节。
///     packet.c:1749-1754 传给 `mac_check` 的是 `sshbuf_ptr(state->incoming_packet)`
///     与它的长度,而 `incoming_packet` 在 packet.c:1687 已被塞进首块、
///     在 packet.c:1738 又追加了剩余部分,合起来正好是完整明文包。
///     MAC 本身追加在**密文之后**,不在之前。

///|
/// hmac-sha2-256 的 MAC 长度。
///
/// mac.c:62 的 truncatebits = 0,所以是全长而非 16 字节截断。
pub const HMAC_SHA256_LEN : Int32 = 32

///|
/// aes128-ctr 的 block size,同时也是 IV / 计数器长度。
///
/// cipher.c:93 第 2 列 block_size = 16;cipher_ivlen() 对 iv_len=0 回落到它。
pub const AESCTR_BLOCK : Int32 = 16

///|
/// 一个方向上的 aes128-ctr + hmac-sha2-256 状态。
///
/// ctos 与 stoc 各持一份:CTR 计数器按方向独立递增(对应 packet.c:1218 分离的
/// `state->p_send.seqnr` 与 `state->p_read.seqnr`)。共用一个计数器会让第二个
/// 方向从错误的密钥流偏移开始解密——这属于「能连上但数据全错」的静默失败,
/// 比显式报错更难查,所以这里由类型系统之外的注释钉死。
pub struct AesCtrMacCtx {
  priv key : FixedArray[Byte] // 16 字节 AES-128 密钥('C' 或 'D')
  priv mac_key : FixedArray[Byte] // 32 字节 HMAC 密钥('E' 或 'F')
  priv ctr : FixedArray[Byte] // 16 字节计数器,整条连接持续递增
}

///|
/// 构造一个方向上下文。
///
/// `key` 是 'C'/'D' 加密密钥,`iv` 是同方向的 'A'/'B' 计数器初值,
/// `mac_key` 是 'E'/'F' MAC 密钥。
///
/// 长度不符是程序员错误(密钥派生算错了),用 abort 而不是返回 Option——
/// 它发生在 NEWKEYS 那一刻,不是可以从网络上恢复的协议错误。
pub fn AesCtrMacCtx::new(
  key : FixedArray[Byte],
  iv : FixedArray[Byte],
  mac_key : FixedArray[Byte],
) -> AesCtrMacCtx {
  if key.length() != AESCTR_BLOCK || iv.length() != AESCTR_BLOCK {
    abort("AesCtrMacCtx::new: aes128-ctr needs a 16-byte key and 16-byte IV")
  }
  if mac_key.length() != HMAC_SHA256_LEN {
    abort("AesCtrMacCtx::new: hmac-sha2-256 needs a 32-byte MAC key")
  }
  let ctr : FixedArray[Byte] = FixedArray::make(AESCTR_BLOCK, b'\x00')
  for i = 0; i < AESCTR_BLOCK; i = i + 1 {
    ctr[i] = iv[i]
  }
  { key, mac_key, ctr, }
}

///|
/// 当前计数器快照,供报告与 KAT 断言。
pub fn AesCtrMacCtx::counter(self : AesCtrMacCtx) -> FixedArray[Byte] {
  let out : FixedArray[Byte] = FixedArray::make(AESCTR_BLOCK, b'\x00')
  for i = 0; i < AESCTR_BLOCK; i = i + 1 {
    out[i] = self.ctr[i]
  }
  out
}

///|
/// 计数器按大端 +1(整 16 字节,末位进位)。
///
/// 写成带 carry 的循环而不是「找到第一个非 0xFF 就停」:后者在计数器
/// 低位全满时会走完 16 次或者漏掉高位的进位,而那正是长时间连接迟早会碰到的状态。
fn ctr_increment(ctr : FixedArray[Byte]) -> Unit {
  let mut carry = 1
  let mut i = AESCTR_BLOCK - 1
  while i >= 0 && carry > 0 {
    let v = ctr[i].to_int() + carry
    ctr[i] = (v & 0xFF).to_byte()
    carry = v >> 8
    i = i - 1
  }
}

///|
/// 把计数器向前推进 `nbytes` 个密文字节所对应的块数。
fn AesCtrMacCtx::advance(self : AesCtrMacCtx, nbytes : Int32) -> Unit {
  let blocks = (nbytes + AESCTR_BLOCK - 1) / AESCTR_BLOCK
  let mut i = 0
  while i < blocks {
    ctr_increment(self.ctr)
    i = i + 1
  }
}

///|
/// 加密/解密一段数据,并把计数器推进到下一段的位置。
///
/// CTR 是对称的,加密与解密走同一条密钥流,所以这一个函数两边都用。
/// 复用 `src/aes` 里已过 NIST SP 800-38A KAT 的 `aes_ctr`,而不是在这里
/// 再抄一份密钥流循环——两份实现只要有一份漂移,故障就会表现为偶发的单字节错误。
pub fn AesCtrMacCtx::crypt(
  self : AesCtrMacCtx,
  input : FixedArray[Byte],
) -> FixedArray[Byte] {
  let out = @aes.aes_ctr(self.key, self.ctr, input)
  self.advance(input.length())
  out
}

///|
/// 只解密开头 4 字节以取出 `packet_length`,**不**推进计数器。
///
/// 对应 packet.c:1687-1690 的首块解密。之所以不把解密结果留下复用,
/// 是因为留首块要在 RecvCtx 上多挂一个跨调用字段;而在 CTR 下重新解一次
/// 整包只是多算一个块(16 字节密钥流),换来的是状态机少一条分支。
/// 头部同样按块长攒够才解,避免半块输入算出一个假的包长。
pub fn AesCtrMacCtx::peek_len(
  self : AesCtrMacCtx,
  ct_head : FixedArray[Byte],
) -> UInt32? {
  if ct_head.length() < 4 {
    return None
  }
  let four : FixedArray[Byte] = FixedArray::make(4, b'\x00')
  for i = 0; i < 4; i = i + 1 {
    four[i] = ct_head[i]
  }
  let pt4 = @aes.aes_ctr(self.key, self.ctr, four)
  Some(
    (pt4[0].to_uint() << 24) |
    (pt4[1].to_uint() << 16) |
    (pt4[2].to_uint() << 8) |
    pt4[3].to_uint(),
  )
}

///|
/// 对**明文**整包计算 MAC:`HMAC-SHA256(K_mac, seqnr_be32 ‖ plaintext)`。
///
/// packet.c:165-170 与 mac.c:155-175:先把 4 字节大端 seqno 喂进去,
/// 再喂整段数据。非 EtM 下这段数据是解密后的内容,所以顺序是「先算 MAC 再解密」
/// 与「先解密再算 MAC」都成立——只要喂进去的是同一串字节。
///
/// hmac-sha2-256 无 truncatebits,返回完整 32 字节。
pub fn AesCtrMacCtx::mac(
  self : AesCtrMacCtx,
  seqnr : UInt32,
  plaintext : FixedArray[Byte],
) -> FixedArray[Byte] {
  let n = plaintext.length()
  let buf : FixedArray[Byte] = FixedArray::make(4 + n, b'\x00')
  write_u32be(buf, 0, seqnr)
  for i = 0; i < n; i = i + 1 {
    buf[4 + i] = plaintext[i]
  }
  @hmac.hmac_sha256(self.mac_key, buf)
}

///|
/// 校验收到的 MAC。
///
/// 逐字节累积差异再判零,而不是遇到不等就返回 false:MAC 校验是唯一一处
/// 时序差异可被用来逐字节爆破原像的地方,这里没有性能压力,不需要提前退出。
pub fn AesCtrMacCtx::mac_ok(
  self : AesCtrMacCtx,
  seqnr : UInt32,
  plaintext : FixedArray[Byte],
  received : FixedArray[Byte],
) -> Bool {
  if received.length() != HMAC_SHA256_LEN {
    return false
  }
  let want = self.mac(seqnr, plaintext)
  let mut diff = 0
  for i = 0; i < HMAC_SHA256_LEN; i = i + 1 {
    diff = diff | (want[i].to_int() ^ received[i].to_int())
  }
  diff == 0
}
