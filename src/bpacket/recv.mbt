///| 接收方向:流式状态机解析
///
/// 对应 OpenSSH ssh_packet_read_poll2(packet.c:1624-1858)
/// 去除压缩/mux/discard-after-MAC-error/非 EtM HMAC 后的协议核心。
///
/// 契约:input 必须从当前包起点开始的连续字节;返回的 consumed 告诉
/// 调用方本次消费多少字节,剩余部分切片后继续喂。

///|
/// 消费一次输入

///|
/// 不改变任何状态地问一句:看完这 4 个包头字节,这个包在**线上**还剩多少字节。
///
/// 连接层需要它来做精确读。流式接口 `recv` 只能回答「不够」,可等待期间它
/// 没法告诉 socket 该再去拿几个;而按固定块长攒会读过头——下一个包的前几个
/// 字节被一并取走,就得一直阻塞到对方发下一个消息为止。问一次长度再精确读,
/// 是唯一能同时服务「未加密按长度读」和「加密先解密长度再读」的做法。
///
/// 三个模式都只用 4 个密文字节就能判长:
///   * Unencrypted:长度字段本来就在明文里;
///   * Aead:长度字段不加密(chacha20-poly1305 同样如此);
///   * MacEncrypt:CTR 是流密码,用计数器快照解 4 个字节就够,
///     `peek_len` 不推进计数器,随后 `recv` 从头再解一遍结果一致。
///
/// 返回的是**已读走的 4 字节之外**还要再拿的字节数,即
/// `packlen + authlen + maclen`(整体线上长度是 4 加上它)。
///
/// 只能在包首调用;`packlen != 0` 的半包状态下返回 None,因为那时头已经
/// 被消费掉了,再问一次会拿错长度。
pub fn RecvCtx::wire_len_from_header(
  self : RecvCtx,
  hdr : FixedArray[Byte],
) -> Int32? {
  if self.packlen != 0U {
    return None
  }
  if hdr.length() < 4 {
    return None
  }
  let plen : UInt32 = match self.mode {
    Unencrypted => read_u32be(hdr, 0)
    Aead(ctx) => ctx.get_length(self.seqnr, hdr)
    MacEncrypt(ctx) =>
      match ctx.peek_len(hdr) {
        None => return None
        Some(v) => v
      }
  }
  // 与 recv 的长度校验保持一致:越界的长度在这里就被挡住,不要读到一半
  // 才发现对端发了一个荒谬的 packlen。
  if plen < MIN_PACKET_LENGTH.reinterpret_as_uint() ||
    plen > MAX_PACKET_SIZE.reinterpret_as_uint() {
    return None
  }
  Some(plen.reinterpret_as_int() + authlen_of(self.mode) + maclen_of(self.mode))
}

///|
pub fn RecvCtx::recv(self : RecvCtx, input : FixedArray[Byte]) -> RecvResult {
  let bs = block_size_of(self.mode)
  let aadlen = aadlen_of(self.mode)
  let authlen = authlen_of(self.mode)
  let maclen = maclen_of(self.mode)
  // ---- 阶段 1:提取包长(self.packlen == 0 表示等包头)----
  if self.packlen == 0U {
    // AEAD 只需 4 字节(cipher_get_length → chachapoly_get_length);
    // plain 需要 block_size 字节——对齐 packet.c:1676 的首块解密门槛
    // (明文其实 4 字节即可判长,这里选择行为等价)。
    let min_hdr = if aadlen > 0 { 4 } else { bs }
    if input.length() < min_hdr {
      return { consumed: 0, event: NeedMore, }
    }
    let plen : UInt32 = match self.mode {
      Aead(ctx) => ctx.get_length(self.seqnr, input)
      Unencrypted => read_u32be(input, 0)
      MacEncrypt(ctx) =>
        match ctx.peek_len(input) {
          None => return { consumed: 0, event: NeedMore, }
          Some(v) => v
        }
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
  let total = aadlen + need + authlen + maclen // = 4 + packlen + authlen + maclen(两模式通用)
  if input.length() < total {
    return { consumed: 0, event: NeedMore, }
  }
  // ---- 阶段 3:解密(packet.c:1736-1754)----
  // EtM 先验 MAC 属范围外;AEAD 的 tag 校验在 crypt 内部先行(先验后解)。
  //
  // MacEncrypt 下 need = 4 + packlen(aadlen=0),也就是**整帧**都要过密钥流:
  // CTR 是流密码,长度字段同样被加密,所以不需要像 C 那样先啃掉一个块——
  // peek_len 只是拿计数器快照解开头 4 字节取长度,真正的解密仍在这里一次做完。
  let pt : FixedArray[Byte] = match self.mode {
    Unencrypted => copy_bytes(input, 0, total)
    Aead(ctx) =>
      match ctx.crypt(self.seqnr, input, aadlen, need, false) {
        Some(p) => p
        None => return { consumed: 0, event: Failed(AuthFailed), }
      }
    MacEncrypt(ctx) => ctx.crypt(copy_bytes(input, 0, need))
  }
  // ---- 非 EtM:MAC 覆盖**解密后**的整包(packet.c:1749-1754)----
  // 必须在序号推进与 padlen/type 解析之前:校验没过就说明这串字节的来源不可信,
  // 拿它去算 packlen 或推进 seqnr 都会把连接带进一个更糟的状态。
  match self.mode {
    MacEncrypt(ctx) =>
      if !ctx.mac_ok(self.seqnr, pt, copy_bytes(input, need, need + maclen)) {
        return { consumed: 0, event: Failed(MacInvalid), }
      }
    _ => ()
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
