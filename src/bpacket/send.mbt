///| 发送方向:组帧 + 加密 + 序号推进
///
/// 对应 OpenSSH ssh_packet_send2_wrapped(packet.c:1225-1389)
/// 去除压缩/mux/extra_pad/非 EtM HMAC 后的协议核心。

///|
/// 一次 emit 的产物
pub struct SentPacket {
  /// 明文帧 [packlen u32][padlen u8][type][payload][padding],长 4+packlen
  frame : FixedArray[Byte]
  /// 线上字节 = Unencrypted ? frame : ct头(4) ‖ ct体(packlen) ‖ tag(16)
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
/// - pad_src: 随机 padding 源(Aead 模式取前 padlen 字节);生产环境接
///   CSPRNG,测试注入确定性字节。Unencrypted 模式强制全零
///   (packet.c:1307-1315 explicit_bzero 分支),pad_src 被忽略。
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
    Aead(_) =>
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
    Aead(_) =>
      for i = 0; i < padlen; i = i + 1 {
        frame[6 + n + i] = pad_src[i]
      }
    Unencrypted => () // make 时已清零
  }
  // 密封装包(packet.c:1337-1357):none=透传,chachapoly=crypt(encrypt)
  let wire : FixedArray[Byte] = match self.mode {
    Unencrypted => copy_bytes(frame, 0, total)
    Aead(ctx) =>
      match ctx.crypt(self.seqnr, frame, aadlen, total - aadlen, true) {
        Some(w) => w
        None => abort("SendCtx::emit: crypt failed on encrypt path")
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
