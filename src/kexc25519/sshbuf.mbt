///| SSH wire 格式写侧缓冲(对应 OpenSSH sshbuf 的本卷所需子集)

///|

///| 所有新代码用 kx_ 前缀避免与 inline 进来的 x25519/sha256 撞名。

///|
/// 增长式字节缓冲。内部用 Array[Byte] 追加,to_bytes 固化。
pub struct KxBuf {
  priv data : Array[Byte]
}

///|
pub fn KxBuf::new() -> KxBuf {
  let arr : Array[Byte] = []
  { data: arr }
}

///|
/// 单字节
pub fn KxBuf::put_u8(self : KxBuf, v : UInt) -> Unit {
  self.data.push((v & 0xFFU).to_byte())
}

///|
/// u32 大端(SSH2 网络序)
pub fn KxBuf::put_u32(self : KxBuf, v : UInt) -> Unit {
  for i = 0; i < 4; i = i + 1 {
    self.data.push(((v >> ((3 - i) * 8)) & 0xFFU).to_byte())
  }
}

///|
/// raw 字节追加
pub fn KxBuf::put_bytes(self : KxBuf, bytes : FixedArray[Byte]) -> Unit {
  for i = 0; i < bytes.length(); i = i + 1 {
    self.data.push(bytes[i])
  }
}

///|
/// SSH2 string:u32(len) ‖ raw
pub fn KxBuf::put_string(self : KxBuf, bytes : FixedArray[Byte]) -> Unit {
  self.put_u32(bytes.length().reinterpret_as_uint())
  self.put_bytes(bytes)
}

///| mpint 编码(对应 sshbuf_put_bignum2_bytes,sshbuf-getput-basic.c:569):

///|   1. 跳过前导零字节

///|   2. 若剩余首字节最高位为 1,前置 0x00(防负数解释)

///|   3. 输出 u32(len+prepend) ‖ [0x00] ‖ 有效字节

///|
///   全零输入 → 仅 u32(0)
pub fn KxBuf::put_mpint(self : KxBuf, v : FixedArray[Byte]) -> Unit {
  let mut start = 0
  let mut len = v.length()
  while start < v.length() && v[start] == b'\x00' {
    start = start + 1
    len = len - 1
  }
  let prepend : Bool = len > 0 && ((v[start].to_uint() >> 7) & 1U) == 1U
  self.put_u32((len + (if prepend { 1 } else { 0 })).reinterpret_as_uint())
  if prepend {
    self.data.push(b'\x00')
  }
  for i = 0; i < len; i = i + 1 {
    self.data.push(v[start + i])
  }
}

///|
/// 固化为不可变字节数组
pub fn KxBuf::to_bytes(self : KxBuf) -> FixedArray[Byte] {
  let n = self.data.length()
  let out : FixedArray[Byte] = FixedArray::make(n, b'\x00')
  for i = 0; i < n; i = i + 1 {
    out[i] = self.data[i]
  }
  out
}

///|
/// 便捷封装:直接得到 mpint 编码字节
pub fn kx_mpint(v : FixedArray[Byte]) -> FixedArray[Byte] {
  let buf = KxBuf::new()
  buf.put_mpint(v)
  buf.to_bytes()
}
