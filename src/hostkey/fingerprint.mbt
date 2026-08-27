///| SHA256 指纹(OpenSSH ssh-keygen -lf 的 "SHA256:<b64nopad>" 形态)
///
/// 对应 sshkey.c sshkey_fingerprint_raw(对 plain blob 求 digest)+
/// fingerprint_b64(标准 base64 后 strcspn(ret,"=") 截断 padding)。
/// 注:C 侧是对重序列化的 canonical blob 求 hash;对良构 plain blob
/// 输入与重序列化输出逐字节一致。

///|
/// 原始 32 字节摘要
pub fn fingerprint_sha256(blob : FixedArray[Byte]) -> FixedArray[Byte] {
  sha256(blob)
}

///|
/// "SHA256:xxxx" 文本形态(padding 去除)
pub fn fingerprint_text(blob : FixedArray[Byte]) -> String {
  let dg = sha256(blob)
  let b64 = hk_b64_nopad(dg)
  let out = "SHA256:"
  out + b64
}

///|
/// 标准 base64(去 '=' padding)
fn hk_b64_nopad(data : FixedArray[Byte]) -> String {
  let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
  let n = data.length()
  let sb = StringBuilder()
  // 6 位索引查字母表(String 索引返回 UInt16 码元)
  fn put(idx : Int) -> Unit {
    sb.write_char(Int::unsafe_to_char(alphabet[idx].to_int()))
  }

  let mut i = 0
  while i + 3 <= n {
    let v = (data[i].to_int() << 16) |
      (data[i + 1].to_int() << 8) |
      data[i + 2].to_int()
    put((v >> 18) & 63)
    put((v >> 12) & 63)
    put((v >> 6) & 63)
    put(v & 63)
    i = i + 3
  }
  let rem = n - i
  if rem == 1 {
    let v = data[i].to_int() << 16
    put((v >> 18) & 63)
    put((v >> 12) & 63)
  } else if rem == 2 {
    let v = (data[i].to_int() << 16) | (data[i + 1].to_int() << 8)
    put((v >> 18) & 63)
    put((v >> 12) & 63)
    put((v >> 6) & 63)
  }
  // padding 已省略(fingerprint_b64 的截断语义)
  sb.to_string()
}
