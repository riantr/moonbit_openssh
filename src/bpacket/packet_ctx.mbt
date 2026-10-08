///| SSH binary packet protocol — 上下文与错误类型
///
/// 对应 OpenSSH packet.c 的会话状态(packet_state/session_state)中
/// 与包格式直接相关的部分。范围裁定见 docs/bpacket/navigator.md §8。

///|
/// 包长上限(packet.c:99 PACKET_MAX_SIZE = 256*1024)
pub const MAX_PACKET_SIZE : Int = 262144

///|
/// 包长下限(packet.c:1660/1687 要求 packlen >= 1+4)
pub const MIN_PACKET_LENGTH : Int = 5

///|
/// SSH2_MSG_NEWKEYS(ssh2.h:94)
pub const MSG_NEWKEYS : Byte = b'\x15'

///|
/// 加密模式
///
/// - Unencrypted: none cipher 等价物(bs=8, aadlen=0, 无 tag);
///   KEX 完成前的初始包走此模式(cipher.c:350 CFLAG_NONE memcpy 透传)
/// - Aead: chacha20-poly1305@openssh.com(bs=8, aadlen=4, tag=16)
/// - MacEncrypt: aes128-ctr + hmac-sha2-256(bs=**16**, aadlen=0, maclen=32),
///   加密并认证(encrypt-and-MAC)。这就是 Loop #31/#32 与真实 sshd 协商出来的
///   那一对,也是 Loop #33 让会话真正跑起来要用的一对。
///
/// 块长由模式自己决定,不能写死:none 与 chachapoly 是 8,aes128-ctr 是 16
/// (cipher.c:93 第 2 列)。块长决定 padding 凑几,写死成 8 会让 NEWKEYS 之后
/// 的每一个包长度都对不上 block,服务器直接按 padding error 断链。
///
/// EtM(hmac-*-etm@openssh.com)路径尚未实现:它把 aadlen 变成 4(长度字段参与认证
/// 但不加密),需要在 Mode 上另加分支,不能靠给 MacEncrypt 加一个 Bool 糊过去。
pub(all) enum Mode {
  Unencrypted
  Aead(ChachaPolyCtx)
  MacEncrypt(AesCtrMacCtx)
}

///| 各模式参数(navigator §2)

///|
/// block size:none 与 chachapoly 在 OpenSSH cipher 表中都是 8
fn block_size_of(mode : Mode) -> Int {
  match mode {
    Unencrypted => 8
    Aead(_) => 8
    MacEncrypt(_) => AESCTR_BLOCK
  }
}

///|
/// 不加密参与密码学的明文前缀长度(length 字段)
fn aadlen_of(mode : Mode) -> Int {
  match mode {
    Unencrypted => 0
    Aead(_) => 4
    MacEncrypt(_) => 0
  }
}

///|
/// 认证标签长度
fn authlen_of(mode : Mode) -> Int {
  match mode {
    Unencrypted => 0
    Aead(_) => 16
    MacEncrypt(_) => 0
  }
}

///|
/// 独立 MAC 长度(encrypt-and-MAC 模式下追加在密文之后的校验码)
///
/// packet.c:1647 `maclen = mac && mac->enabled ? mac->mac_len : 0`;
/// AEAD 不另带 MAC(authlen 已经是它的认证标签),所以那里是 0。
fn maclen_of(mode : Mode) -> Int {
  match mode {
    Unencrypted => 0
    Aead(_) => 0
    MacEncrypt(_) => HMAC_SHA256_LEN
  }
}

///|
/// 发送方向上下文
///
/// 对应 state->p_send(seqnr/packets/blocks/bytes 中只保留协议相关的 seqnr)。
/// strict_kex: strict-kex 扩展下 NEWKEYS 后 seqnr 归零(packet.c:1376-1379)。
/// initial_kex: 初始密钥交换期间 seqnr 回绕是致命错误(packet.c:1363-1367);
/// rekey 场景由调用方置 false。它是**有生命周期**的:过 NEWKEYS 时必须由
/// 调用方调 `end_initial_kex` 清掉(kex.c:567 `kex->flags &= ~KEX_INITIAL`),
/// 否则之后每一个正常的包都要多走一次"回绕检查"——目前不致命,只是没人
/// 调过 setter,所以这个标志从建立起就一直是 true。
pub struct SendCtx {
  priv mut mode : Mode
  priv mut seqnr : UInt
  priv strict_kex : Bool
  priv mut initial_kex : Bool
}

///|
/// 接收方向上下文
///
/// packlen 是跨多次 recv 调用的部分包状态(packet.c:202 state->packlen;
/// 0 表示正在等包头)。对应 state->p_read。
pub struct RecvCtx {
  priv mut mode : Mode
  priv mut seqnr : UInt
  priv mut packlen : UInt
  priv strict_kex : Bool
  priv mut initial_kex : Bool
}

///|
/// 构造发送上下文
pub fn SendCtx::make(
  mode : Mode,
  seqnr : UInt,
  strict_kex : Bool,
  initial_kex : Bool,
) -> SendCtx {
  { mode, seqnr, strict_kex, initial_kex, }
}

///|
/// 默认构造:未加密、seqnr=0、非 strict、初始 KEX 中
pub fn SendCtx::new() -> SendCtx {
  SendCtx::make(Unencrypted, 0U, false, true)
}

///|
/// 当前序号(测试与集成层观测用)
pub fn SendCtx::seqnr(self : SendCtx) -> UInt {
  self.seqnr
}

///|
/// 切换加密模式(NEWKEYS 之后调用,语义对应 ssh_set_newkeys(MODE_OUT))
///
/// 注意:seqnr 不重置(packet.c:1014 注释明示);strict-kex 下由
/// NEWKEYS 包本身的 emit 归零。
pub fn SendCtx::set_mode(self : SendCtx, mode : Mode) -> Unit {
  self.mode = mode
}

///|
/// 初始密钥交换结束。
///
/// 对应 `kex.c:567` 的 `kex->flags &= ~KEX_INITIAL`:
///
/// ```
/// 	if ((kex->flags & KEX_INITIAL) != 0) {
/// 		/*
/// 		 * ... 初始 KEX 已经完成 ...
/// 		 */
/// 		kex->flags &= ~KEX_INITIAL;
/// 	}
/// ```
///
/// 在 NEWKEYS 之后调用。过了这个点之后 seqnr 回绕就不再是协议错误
/// (packet.c:1363-1367 只在 `KEX_INITIAL` 期间致命),而继续带着这个标志
/// 会让「回绕」在正常流量上一直是一个待触发的错误分支——所以它必须由
/// 调用方在正确的时间点清掉,而不是构造时就决定不管了。
pub fn SendCtx::end_initial_kex(self : SendCtx) -> Unit {
  self.initial_kex = false
}

///|
/// 是否仍处于初始密钥交换中(观测用)
pub fn SendCtx::in_initial_kex(self : SendCtx) -> Bool {
  self.initial_kex
}

///|
/// 构造接收上下文(参数含义同 SendCtx::make)
pub fn RecvCtx::make(
  mode : Mode,
  seqnr : UInt,
  strict_kex : Bool,
  initial_kex : Bool,
) -> RecvCtx {
  { mode, seqnr, packlen: 0U, strict_kex, initial_kex, }
}

///|
/// 默认构造:未加密、seqnr=0、非 strict、初始 KEX 中
pub fn RecvCtx::new() -> RecvCtx {
  RecvCtx::make(Unencrypted, 0U, false, true)
}

///|
/// 当前序号(测试与集成层观测用)
pub fn RecvCtx::seqnr(self : RecvCtx) -> UInt {
  self.seqnr
}

///|
/// 切换加密模式(NEWKEYS 之后调用,语义对应 ssh_set_newkeys(MODE_IN))
pub fn RecvCtx::set_mode(self : RecvCtx, mode : Mode) -> Unit {
  self.mode = mode
}

///|
/// 初始密钥交换结束,语义同 `SendCtx::end_initial_kex`(kex.c:567)
pub fn RecvCtx::end_initial_kex(self : RecvCtx) -> Unit {
  self.initial_kex = false
}

///|
/// 是否仍处于初始密钥交换中(观测用)
pub fn RecvCtx::in_initial_kex(self : RecvCtx) -> Bool {
  self.initial_kex
}

///|
/// 序号推进
///
/// 返回 None 表示回绕到 0 且处于初始 KEX——两端都必须断连
/// (packet.c:1363-1367 / 1778-1783)。非初始 KEX 的回绕正常允许。
fn bump_seqnr(seqnr : UInt, initial_kex : Bool) -> UInt? {
  let next = seqnr + 1U
  if next == 0U && initial_kex {
    None
  } else {
    Some(next)
  }
}

///|
/// 大端写 u32(POKE_U32)
fn write_u32be(buf : FixedArray[Byte], offset : Int, v : UInt) -> Unit {
  buf[offset] = ((v >> 24) & 0xFFU).to_byte()
  buf[offset + 1] = ((v >> 16) & 0xFFU).to_byte()
  buf[offset + 2] = ((v >> 8) & 0xFFU).to_byte()
  buf[offset + 3] = (v & 0xFFU).to_byte()
}

///|
/// 大端读 u32(PEEK_U32)
fn read_u32be(buf : FixedArray[Byte], offset : Int) -> UInt {
  (buf[offset].to_uint() << 24) |
  (buf[offset + 1].to_uint() << 16) |
  (buf[offset + 2].to_uint() << 8) |
  buf[offset + 3].to_uint()
}

///|
/// 取 bytes[from..until) 的拷贝
fn copy_bytes(
  bytes : FixedArray[Byte],
  from : Int,
  until : Int,
) -> FixedArray[Byte] {
  let n = until - from
  let arr : FixedArray[Byte] = FixedArray::make(n, b'\x00')
  for i = 0; i < n; i = i + 1 {
    arr[i] = bytes[from + i]
  }
  arr
}

///|
/// 接收端错误分类(navigator §7,全部为连接终止级)
pub enum PacketError {
  /// 包长越界(packlen ∉ [5, 262144])
  BadLength(UInt)
  /// 加密体不对齐(need % block_size != 0)
  AlignError(UInt)
  /// Poly1305 tag 校验失败
  AuthFailed
  /// hmac-sha2-256 MAC 校验失败(encrypt-and-MAC 路径)
  ///
  /// 连接必须终止:packet.c:1758-1769 在非 EtM 下丢弃本包并进入 discard 状态,
  /// 而 MAC 失败意味着我们和对端对同一段明文的看法不一致,继续读只会解出乱码。
  MacInvalid
  /// padding 长度小于 4
  BadPadlen(UInt)
  /// padding 超过剩余数据(consume_end 失败的显式化)
  PadOverflow(UInt)
  /// 去掉 header/padding 后无 payload(get_u8 失败的显式化)
  EmptyPayload
  /// 消息号为 0(< SSH2_MSG_MIN)
  BadType(UInt)
  /// 初始 KEX 期间序号回绕
  SeqnrWrapInitial
}

///|
/// 接收事件
pub enum RecvEvent {
  /// 数据不足一整包;保留内部状态,调用方继续攒字节后再喂
  NeedMore
  /// 完整解析出一个包:(使用的 seqnr, 消息号, payload 不含消息号本身)
  Packet(UInt, Byte, FixedArray[Byte])
  /// 协议级错误,连接必须终止
  Failed(PacketError)
}

///|
/// recv 结果:consumed 是本次应从输入流头部消费的字节数
///
/// 错误/未完成时 consumed 为 0(错误即断连,消费量失去意义)。
pub struct RecvResult {
  consumed : Int
  event : RecvEvent
}
