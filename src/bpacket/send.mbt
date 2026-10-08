///| 发送方向:组帧 + 加密 + 序号推进
///
/// 对应 OpenSSH ssh_packet_send2_wrapped(packet.c:1225-1389)
/// 去除压缩/mux/extra_pad/非 EtM HMAC 后的协议核心。

///|
/// 一次 emit 的产物
pub struct SentPacket {
  /// 明文帧 [packlen u32][padlen u8][type][payload][padding],长 4+packlen
  frame : FixedArray[Byte]
  /// 真正上线的字节,按模式分三种形状:
  ///
  /// ```
  /// Unencrypted   frame                                  (4+packlen)
  /// Aead          ct_body ‖ tag(16)                     (长度字段不加密,aadlen=4)
  /// MacEncrypt    ct(frame) ‖ mac(32)                   (整帧加密 + 32 字节 HMAC)
  /// ```
  ///
  /// MacEncrypt 这一行是 Loop #33 补的,和 AEAD 有两处不一样,写在一起
  /// 容易被读成 AEAD 的翻版:
  ///
  ///   * **tag 是 32 字节不是 16。** `mac.c:62` 给 hmac-sha2-256 的
  ///     `truncatebits = 0`。AEAD 的 chacha20-poly1305 tag 恰好也是 16,
  ///     于是「16」这个数字在这里看起来仍然像是对的——但它错得毫无提示。
  ///   * **MAC 在密文之后、覆盖的是明文。** 非 EtM 路径
  ///     (`packet.c:1352-1358`)把未加密的 send_packet 喂给 mac_compute。
  ///     顺序反过来就是「先 MAC 后加密」,对面会拿 MAC 去比密文,于是每一
  ///     个包都验不过。
  wire : FixedArray[Byte]
}

///|
/// emit 结果
pub enum EmitResult {
  /// 成功发出;seqnr 已推进
  Ok(SentPacket)
  /// 包已构造,但 ++seqnr 回绕且处于初始 KEX——连接必须终止。
  ///
  /// 与 C 的差异(navigator §3):C 先入队再断连;此处不出 wire 字节,
  /// 两端都立即终止,无可观测差别。
  SeqnrWrapFatal
}

///|
/// 构造并发送一个 SSH2 二进制包
///
/// - msg_type: 消息号(1..=255;0 是程序员错误 → abort,对齐 C 中
///   sshpkt_start 的调用方契约——消息号恒 >= SSH2_MSG_MIN)
/// - payload: 不含消息号本身的消息体
/// - pad_src: 随机 padding 源。**Aead 与 MacEncrypt 都取前 padlen 字节**
///   (加密态下 padding 必须随机,否则同一条明文会产出同一条密文);生产环境
///   接 CSPRNG,测试注入确定性字节。Unencrypted 模式强制全零
///   (packet.c:1307-1315 explicit_bzero 分支),pad_src 被忽略。
///
///   注意 MacEncrypt 也用 pad_src:它是 Loop #33 加进来的加密模式,如果按
///   「非 AEAD 就算明文」的直觉去读旧文档,会以为这里传全零没问题——
///   实际上那样做不会报错,只会让 padding 失去随机性。
///
/// 程序员错误(msg_type==0 / pad_src 不足 / 总长越界)用 abort,
/// 协议级错误只在接收方向产生。
pub fn SendCtx::emit(
  self : SendCtx,
  msg_type : Byte,
  payload : FixedArray[Byte],
  pad_src : FixedArray[Byte],
) -> EmitResult {
  if msg_type == b'\x00' {
    abort("SendCtx::emit: msg_type must be >= 1")
  }
  let bs = block_size_of(self.mode)
  let aadlen = aadlen_of(self.mode)
  let n = payload.length()
  // packet.c:1276-1285:len 为缓冲区长度,EtM/AEAD 下扣除不加密的 length 字段
  let len_for_pad = 6 + n - aadlen
  let mut padlen = bs - len_for_pad % bs
  if padlen < 4 {
    // RFC 4253 §6:padding 至少 4 字节
    padlen = padlen + bs
  }
  let total = 6 + n + padlen // 明文帧总长 = 4(len) + 1(padlen) + (1+n) + padlen
  let packlen = total - 4 // packet_length 值 = 1 + n_total + padlen
  if packlen > MAX_PACKET_SIZE {
    abort("SendCtx::emit: packet exceeds PACKET_MAX_SIZE")
  }
  match self.mode {
    Aead(_) | MacEncrypt(_) =>
      if pad_src.length() < padlen {
        abort("SendCtx::emit: pad_src smaller than padlen")
      }
    Unencrypted => ()
  }
  // 组帧(packet.c:1316-1325)
  let frame : FixedArray[Byte] = FixedArray::make(total, b'\x00')
  write_u32be(frame, 0, packlen.reinterpret_as_uint())
  frame[4] = padlen.to_byte()
  frame[5] = msg_type
  for i = 0; i < n; i = i + 1 {
    frame[6 + i] = payload[i]
  }
  // padding 内容(packet.c:1307-1315):加密→随机(pad_src 注入),未加密→全零
  match self.mode {
    Aead(_) | MacEncrypt(_) =>
      for i = 0; i < padlen; i = i + 1 {
        frame[6 + n + i] = pad_src[i]
      }
    Unencrypted => () // make 时已清零
  }
  // 密封装包(packet.c:1337-1357):
  //   none=透传,chachapoly=crypt(encrypt),
  //   aes128-ctr=加密整帧 ‖ 32 字节 MAC,且 MAC 覆盖的是**明文**整帧
  //   (非 EtM;packet.c:1352-1358 喂给 mac_compute 的是未加密的 send_packet)
  let wire : FixedArray[Byte] = match self.mode {
    Unencrypted => copy_bytes(frame, 0, total)
    Aead(ctx) =>
      match ctx.crypt(self.seqnr, frame, aadlen, total - aadlen, true) {
        Some(w) => w
        None => abort("SendCtx::emit: crypt failed on encrypt path")
      }
    MacEncrypt(ctx) => {
      // 先算 MAC 再加密:两者读的都是同一份明文 frame,顺序只影响
      // 计数器何时推进,不影响任何线上字节。
      let mac = ctx.mac(self.seqnr, frame)
      let ct = ctx.crypt(frame)
      let out : FixedArray[Byte] = FixedArray::make(
        total + HMAC_SHA256_LEN,
        b'\x00',
      )
      for i = 0; i < total; i = i + 1 {
        out[i] = ct[i]
      }
      for i = 0; i < HMAC_SHA256_LEN; i = i + 1 {
        out[total + i] = mac[i]
      }
      out
    }
  }
  // 序号推进(packet.c:1363-1379):先 ++ 与回绕检查,再 strict-kex NEWKEYS 归零
  match bump_seqnr(self.seqnr, self.initial_kex) {
    None => return SeqnrWrapFatal
    Some(next) => self.seqnr = next
  }
  if self.strict_kex && msg_type == MSG_NEWKEYS {
    self.seqnr = 0U
  }
  Ok({ frame, wire, })
}
