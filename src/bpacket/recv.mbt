///| 接收方向:流式状态机解析
///
/// 对应 OpenSSH ssh_packet_read_poll2(packet.c:1624-1858)
/// 去除压缩/mux/discard-after-MAC-error/非 EtM HMAC 后的协议核心。
///
/// 契约:input 必须从当前包起点开始的连续字节;返回的 consumed 告诉
/// 调用方本次消费多少字节,剩余部分切片后继续喂。

///|
/// 消费一次输入
pub fn RecvCtx::recv(self : RecvCtx, input : FixedArray[Byte]) -> RecvResult {
  let bs = block_size_of(self.mode)
  let aadlen = aadlen_of(self.mode)
  let authlen = authlen_of(self.mode)
  // ---- 阶段 1:提取包长(self.packlen == 0 表示等包头)----
  if self.packlen == 0U {
    // AEAD 只需 4 字节(cipher_get_length → chachapoly_get_length);
    // plain 需要 block_size 字节——对齐 packet.c:1676 的首块解密门槛
    // (明文其实 4 字节即可判长,这里选择行为等价)。
    let min_hdr = if aadlen > 0 { 4 } else { bs }
    if input.length() < min_hdr {
      return { consumed: 0, event: NeedMore, }
    }
    let plen : UInt = match self.mode {
      Aead(ctx) => ctx.get_length(self.seqnr, input)
      Unencrypted => read_u32be(input, 0)
    }
    // packet.c:1660-1669 / 1687-1698:packlen < 1+4 或 > PACKET_MAX_SIZE
    if plen < MIN_PACKET_LENGTH.reinterpret_as_uint() ||
      plen > MAX_PACKET_SIZE.reinterpret_as_uint() {
      return { consumed: 0, event: Failed(BadLength(plen)), }
    }
    self.packlen = plen
  }
  let packlen_int = self.packlen.reinterpret_as_int()
  // ---- 阶段 2:长度校验与等待(packet.c:1704-1731)----
  // need = 需要解密的体长;AEAD 时 length 字段不加密(need=packlen),
  // plain 时整帧都过密码学(need=4+packlen-bs,C 的首块已扣)。
  // 统一形式:need = 4 + packlen - aadlen。
  let need = 4 + packlen_int - aadlen
  if need % bs != 0 {
    return {
      consumed: 0,
      event: Failed(AlignError(need.reinterpret_as_uint())),
    }
  }
  let total = aadlen + need + authlen // = 4 + packlen + authlen(两模式通用)
  if input.length() < total {
    return { consumed: 0, event: NeedMore, }
  }
  // ---- 阶段 3:解密(packet.c:1736-1754)----
  // EtM 先验 MAC 属范围外;AEAD 的 tag 校验在 crypt 内部先行(先验后解)。
  let pt : FixedArray[Byte] = match self.mode {
    Unencrypted => copy_bytes(input, 0, total)
    Aead(ctx) =>
      match ctx.crypt(self.seqnr, input, aadlen, need, false) {
        Some(p) => p
        None => return { consumed: 0, event: Failed(AuthFailed), }
      }
  }
  // ---- 序号推进(C 行序:1778-1788 在 padlen/type 解析之前)----
  let seqnr_used = self.seqnr
  match bump_seqnr(self.seqnr, self.initial_kex) {
    None => return { consumed: 0, event: Failed(SeqnrWrapInitial), }
    Some(next) => self.seqnr = next
  }
  // ---- 解析(统一布局 [len u32][padlen][payload][padding],padlen 恒在 @[4])----
  let padlen = pt[4].to_uint()
  // packet.c:1793-1799
  if padlen < 4U {
    return { consumed: 0, event: Failed(BadPadlen(padlen)), }
  }
  // sshbuf_consume_end 失败路径的显式化:padlen 不能吃掉 type 字节
  if padlen > self.packlen - 1U {
    return { consumed: 0, event: Failed(PadOverflow(padlen)), }
  }
  let payload_len = packlen_int - 1 - padlen.reinterpret_as_int() // 含 type 字节
  if payload_len < 1 {
    // C 中 sshbuf_get_u8 对空缓冲失败(SSH_ERR 内部错误路径)
    return { consumed: 0, event: Failed(EmptyPayload), }
  }
  let msg_type = pt[5]
  // packet.c:1828-1834:type < SSH2_MSG_MIN(=1)
  if msg_type == b'\x00' {
    return { consumed: 0, event: Failed(BadType(msg_type.to_uint())), }
  }
  let out : FixedArray[Byte] = FixedArray::make(payload_len - 1, b'\x00')
  for i = 0; i < payload_len - 1; i = i + 1 {
    out[i] = pt[6 + i]
  }
  self.packlen = 0U
  // strict-kex:NEWKEYS 处理完后读序号归零(packet.c:1849-1852)
  if self.strict_kex && msg_type == MSG_NEWKEYS {
    self.seqnr = 0U
  }
  { consumed: total, event: Packet(seqnr_used, msg_type, out), }
}
