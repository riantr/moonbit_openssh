///| known_hosts 模式匹配（OpenSSH match.c:82-152 转写 + HMAC-SHA1 验证）
///
/// NFA 通配符匹配：`*` 匹配零或多字符，`?` 匹配单字符。
/// 哈希条目 `|1|<b64-salt>|<b64-hash>`：HMAC-SHA1(salt, host) 验证。

// ============================================================ SHA-1（内联）
//
// 参考 RFC 3174。SHA-1 输入按 512-bit 块处理，输出 160-bit。
// 用于 HMAC-SHA1(salt, host) 验证 |1| 条目。
// 已知 moonshadow / moonbitlang/core@0.10.3 默认可能不启用 SHA-1。

///| 32-bit 左循环
fn rotl32(x : UInt, n : Int) -> UInt {
  (x << n) | (x >> (32 - n))
}

///|
priv struct Sha1State {
  mut h0 : UInt
  mut h1 : UInt
  mut h2 : UInt
  mut h3 : UInt
  mut h4 : UInt
  // 消息缓冲（≤ 64 字节）
  buf : FixedArray[Byte]
  mut buf_len : Int
  mut total : UInt64
}

///| SHA-1 初始向量
fn sha1_state_new() -> Sha1State {
  {
    h0: 0x67452301U,
    h1: 0xEFCDAB89U,
    h2: 0x98BADCFEU,
    h3: 0x10325476U,
    h4: 0xC3D2E1F0U,
    buf: FixedArray::make(64, b'\x00'),
    buf_len: 0,
    total: 0UL,
  }
}

///| SHA-1 块处理（512-bit = 64 字节）
fn sha1_process_block(state : Sha1State) -> Unit {
  let w : FixedArray[UInt] = FixedArray::make(80, 0U)
  // 前 16 字：big-endian 读入
  for i = 0; i < 16; i = i + 1 {
    let off = i * 4
    w[i] = ((state.buf[off].to_uint() << 24) |
      ((state.buf[off + 1].to_uint() << 16)) |
      ((state.buf[off + 2].to_uint() << 8)) |
      state.buf[off + 3].to_uint())
  }
  // 扩展 16..80
  for i = 16; i < 80; i = i + 1 {
    w[i] = rotl32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1)
  }
  let mut a = state.h0
  let mut b = state.h1
  let mut c = state.h2
  let mut d = state.h3
  let mut e = state.h4
  for i = 0; i < 80; i = i + 1 {
    // RFC 3174 SHA-1 round functions:
    //   0-19 : f = (b & c) | ((~b) & d)           ; k = 0x5A827999  (ch)
    //   20-39: f = b ^ c ^ d                      ; k = 0x6ED9EBA1  (parity)
    //   40-59: f = (b & c) | (b & d) | (c & d)    ; k = 0x8F1BBCDC  (maj)
    //   60-79: f = b ^ c ^ d                      ; k = 0xCA62C1D6  (parity)
    let f = if i < 20 {
      (b & c) | ((b ^ 0xFFFFFFFFU) & d)
    } else if i < 40 {
      b ^ c ^ d
    } else if i < 60 {
      (b & c) | (b & d) | (c & d)
    } else {
      b ^ c ^ d
    }
    let k = if i < 20 {
      0x5A827999U
    } else if i < 40 {
      0x6ED9EBA1U
    } else if i < 60 {
      0x8F1BBCDCU
    } else {
      0xCA62C1D6U
    }
    let temp = rotl32(a, 5) + k + f + e + w[i]
    e = d
    d = c
    c = rotl32(b, 30)
    b = a
    a = temp
  }
  state.h0 = state.h0 + a
  state.h1 = state.h1 + b
  state.h2 = state.h2 + c
  state.h3 = state.h3 + d
  state.h4 = state.h4 + e
}

///| SHA-1 update（任意长度）
fn sha1_update(state : Sha1State, data : FixedArray[Byte], len : Int) -> Unit {
  state.total = state.total + len.to_uint64()
  let mut i = 0
  while i < len {
    let avail = 64 - state.buf_len
    let copy = if len - i < avail { len - i } else { avail }
    for j = 0; j < copy; j = j + 1 {
      state.buf[state.buf_len + j] = data[i + j]
    }
    state.buf_len = state.buf_len + copy
    i = i + copy
    if state.buf_len == 64 {
      sha1_process_block(state)
      state.buf_len = 0
    }
  }
}

///| SHA-1 finalize → 20 字节
fn sha1_final(state : Sha1State) -> FixedArray[Byte] {
  let bit_len = state.total * 8UL
  // padding: 0x80 then zeros, then 64-bit big-endian length
  let pad : FixedArray[Byte] = FixedArray::make(1, 0x80)
  sha1_update(state, pad, 1)
  // 填充 0 直到 buf_len = 56
  while state.buf_len != 56 {
    let zero : FixedArray[Byte] = FixedArray::make(1, b'\x00')
    sha1_update(state, zero, 1)
  }
  // 8-byte big-endian length
  let len_bytes : FixedArray[Byte] = FixedArray::make(8, b'\x00')
  len_bytes[0] = ((bit_len >> 56) & 0xFFUL).to_byte()
  len_bytes[1] = ((bit_len >> 48) & 0xFFUL).to_byte()
  len_bytes[2] = ((bit_len >> 40) & 0xFFUL).to_byte()
  len_bytes[3] = ((bit_len >> 32) & 0xFFUL).to_byte()
  len_bytes[4] = ((bit_len >> 24) & 0xFFUL).to_byte()
  len_bytes[5] = ((bit_len >> 16) & 0xFFUL).to_byte()
  len_bytes[6] = ((bit_len >> 8) & 0xFFUL).to_byte()
  len_bytes[7] = (bit_len & 0xFFUL).to_byte()
  sha1_update(state, len_bytes, 8)
  // 输出
  let out : FixedArray[Byte] = FixedArray::make(20, b'\x00')
  out[0] = ((state.h0 >> 24) & 0xFFU).to_byte()
  out[1] = ((state.h0 >> 16) & 0xFFU).to_byte()
  out[2] = ((state.h0 >> 8) & 0xFFU).to_byte()
  out[3] = (state.h0 & 0xFFU).to_byte()
  out[4] = ((state.h1 >> 24) & 0xFFU).to_byte()
  out[5] = ((state.h1 >> 16) & 0xFFU).to_byte()
  out[6] = ((state.h1 >> 8) & 0xFFU).to_byte()
  out[7] = (state.h1 & 0xFFU).to_byte()
  out[8] = ((state.h2 >> 24) & 0xFFU).to_byte()
  out[9] = ((state.h2 >> 16) & 0xFFU).to_byte()
  out[10] = ((state.h2 >> 8) & 0xFFU).to_byte()
  out[11] = (state.h2 & 0xFFU).to_byte()
  out[12] = ((state.h3 >> 24) & 0xFFU).to_byte()
  out[13] = ((state.h3 >> 16) & 0xFFU).to_byte()
  out[14] = ((state.h3 >> 8) & 0xFFU).to_byte()
  out[15] = (state.h3 & 0xFFU).to_byte()
  out[16] = ((state.h4 >> 24) & 0xFFU).to_byte()
  out[17] = ((state.h4 >> 16) & 0xFFU).to_byte()
  out[18] = ((state.h4 >> 8) & 0xFFU).to_byte()
  out[19] = (state.h4 & 0xFFU).to_byte()
  out
}

///| SHA-1 一次性（RFC 3174 test vector："abc" → a9993e364706816aba3e25717850c26c9cd0d89d）
pub fn sha1(data : FixedArray[Byte], len : Int) -> FixedArray[Byte] {
  let state = sha1_state_new()
  sha1_update(state, data, len)
  sha1_final(state)
}

// ============================================================ HMAC-SHA1（RFC 2104）

///| HMAC-SHA1(key, msg) → 20 字节
pub fn hmac_sha1(key : FixedArray[Byte], msg : FixedArray[Byte], msg_len : Int) -> FixedArray[Byte] {
  let block_key : FixedArray[Byte] = FixedArray::make(64, b'\x00')
  if key.length() > 64 {
    // 长 key：先 SHA1
    let h = sha1(key, key.length())
    for i = 0; i < 20; i = i + 1 {
      block_key[i] = h[i]
    }
  } else {
    for i = 0; i < key.length(); i = i + 1 {
      block_key[i] = key[i]
    }
  }
  // ipad = block_key XOR 0x36
  let ipad : FixedArray[Byte] = FixedArray::make(64, b'\x00')
  for i = 0; i < 64; i = i + 1 {
    ipad[i] = (block_key[i].to_int() ^ 0x36).to_byte()
  }
  // opad = block_key XOR 0x5C
  let opad : FixedArray[Byte] = FixedArray::make(64, b'\x00')
  for i = 0; i < 64; i = i + 1 {
    opad[i] = (block_key[i].to_int() ^ 0x5C).to_byte()
  }
  // inner = SHA1(ipad || msg)
  let inner_state = sha1_state_new()
  sha1_update(inner_state, ipad, 64)
  sha1_update(inner_state, msg, msg_len)
  let inner_hash = sha1_final(inner_state)
  // outer = SHA1(opad || inner_hash)
  let outer_state = sha1_state_new()
  sha1_update(outer_state, opad, 64)
  sha1_update(outer_state, inner_hash, 20)
  sha1_final(outer_state)
}

// ============================================================ base64 解码（用于 |1| 哈希条目的 salt/hash）

///| 标准 base64 解码（与 OpenSSH b64_pton 兼容；不含 padding 时也接受）
pub fn b64_decode(s : String) -> FixedArray[Byte]? {
  let bytes : StringView = s
  try {
    let result = @base64.decode(bytes, ignore_whitespace=false) catch {
      _ => return None
    }
    let arr : FixedArray[Byte] = FixedArray::make(result.length(), b'\x00')
    for i = 0; i < result.length(); i = i + 1 {
      arr[i] = result[i]
    }
    Some(arr)
  } catch {
    _ => None
  }
}

///| 长度常量：|1| 条目的 salt 与 hash 都是 SHA-1 输出长度
const HASH_LEN : Int = 20
const HASH_MAGIC : String = "|1|"
///| 分隔符 `|` 的 ASCII 码（UInt16 形式的 char code）
const HASH_DELIM_CODE : Int = 0x7C  // '|'

///| 检测字符串是否以 `|1|` 开头（哈希条目）
pub fn is_hashed_host(s : String) -> Bool {
  if s.length() < 3 { return false }
  s[0].to_int() == HASH_DELIM_CODE && s[1].to_int() == '1'.to_int() && s[2].to_int() == HASH_DELIM_CODE
}

///| 验证 `|1|<b64-salt>|<b64-hash>` 条目是否匹配 expected_host
/// 返回 true iff HMAC-SHA1(salt, expected_host) 与 hash 字节相等
pub fn match_hashed_host(expected_host : String, hashed_pattern : String) -> Bool {
  // 格式：|1|<b64-salt>|<b64-hash>
  // 跳过 "|1|" 前缀
  let mut i = 3
  // 找第一个 '|'（分隔 salt 和 hash）
  let mut sep_pos = -1
  while i < hashed_pattern.length() {
    if hashed_pattern[i].to_int() == HASH_DELIM_CODE { sep_pos = i; break }
    i = i + 1
  }
  if sep_pos < 0 { return false }
  let salt_b64 = hashed_pattern.substring(start=3, end=sep_pos)
  let hash_b64 = hashed_pattern.substring(start=sep_pos + 1, end=hashed_pattern.length())
  let salt = match b64_decode(salt_b64) {
    Some(b) => b
    None => return false
  }
  let expected_hash = match b64_decode(hash_b64) {
    Some(b) => b
    None => return false
  }
  // expected_host 转 FixedArray[Byte]
  let msg : FixedArray[Byte] = FixedArray::make(expected_host.length(), b'\x00')
  for i = 0; i < expected_host.length(); i = i + 1 {
    msg[i] = (expected_host[i].to_int() & 0xFF).to_byte()
  }
  // 计算 HMAC-SHA1(salt, msg)
  let actual = hmac_sha1(salt, msg, msg.length())
  // 字节比较
  if actual.length() != expected_hash.length() { return false }
  for i = 0; i < actual.length(); i = i + 1 {
    if actual[i] != expected_hash[i] { return false }
  }
  true
}

// ============================================================ 通配符匹配（OpenSSH match.c:82-152 转写）

///| NFA 通配符：`*` 零或多字符，`?` 单字符
/// MoonBit String indexing 返回 UInt16 码元，对 ASCII 输入安全。
const STAR_CODE : Int = 42   // '*'
const QMARK_CODE : Int = 63  // '?'

fn match_pattern_nfa(s : String, pattern : String) -> Bool {
  let m = pattern.length()
  if m == 0 { return s.length() == 0 }
  // states[i] = 1 表示在第 i 个 pattern 字符"状态"上活跃
  // states[m] 是接受状态（已匹配完整 pattern）
  let states : FixedArray[Int] = FixedArray::make(m + 1, 0)
  let next_states : FixedArray[Int] = FixedArray::make(m + 1, 0)
  states[0] = 1
  // epsilon 闭包：处理开头的 '*'
  epsilon_closure(states, pattern, m)
  let mut si = 0
  while si < s.length() {
    let sc = s[si].to_int()
    // 初始化 next_states
    for k = 0; k <= m; k = k + 1 { next_states[k] = 0 }
    for i = 0; i < m; i = i + 1 {
      if states[i] == 0 { continue }
      let pc = pattern[i].to_int()
      if pc == STAR_CODE {
        // '*' 匹配任意字符：保持在 i
        next_states[i] = 1
      } else if pc == QMARK_CODE || pc == sc {
        // '?' 或字面匹配：进入 i+1
        next_states[i + 1] = 1
      }
    }
    epsilon_closure(next_states, pattern, m)
    // swap
    for k = 0; k <= m; k = k + 1 { states[k] = next_states[k] }
    // 检查是否有活跃状态
    let mut active = 0
    for i = 0; i <= m; i = i + 1 {
      if states[i] == 1 { active = 1; break }
    }
    if active == 0 { return false }
    si = si + 1
  }
  states[m] == 1
}

///| 处理 '*' 的 epsilon 转移（"*" 可以零或多字符，所以可以跳到自己或后继）
fn epsilon_closure(states : FixedArray[Int], pattern : String, m : Int) -> Unit {
  // 反复处理直到不再有新状态
  let mut changed = true
  while changed {
    changed = false
    for i = 0; i < m; i = i + 1 {
      if states[i] == 1 && pattern[i].to_int() == STAR_CODE {
        // '*' 可以匹配空：进入 i+1
        if states[i + 1] == 0 {
          states[i + 1] = 1
          changed = true
        }
      }
    }
    // i+1 可能是 '*'，会引发链式传播；通过 changed 循环重新扫描
  }
}

///| 逗号分隔模式列表匹配（任一命中即返回 true）
pub fn match_host_pattern(host : String, pattern_list : String) -> Bool {
  let mut start = 0
  let mut i = 0
  while i <= pattern_list.length() {
    if i == pattern_list.length() || pattern_list[i] == ',' {
      if i > start {
        let pat = pattern_list.substring(start=start, end=i)
        let trimmed = trim_ws(pat)
        if trimmed.length() > 0 {
          // 跳过 `!` 否定前缀（语义跳过，不强制）
          let real = if trimmed.length() > 0 && trimmed[0].to_int() == '!'.to_int() {
            trimmed.substring(start=1, end=trimmed.length())
          } else {
            trimmed
          }
          // 哈希条目检测
          if is_hashed_host(real) {
            if match_hashed_host(host, real) { return true }
          } else {
            // 普通通配符
            if match_pattern_nfa(host, real) { return true }
          }
        }
      }
      start = i + 1
    }
    i = i + 1
  }
  false
}

///| trim ASCII 空白（match.mbt 私有副本）
fn trim_ws(s : String) -> String {
  let mut start = 0
  let mut end = s.length()
  while start < end {
    let c = s[start].to_int()
    if c != 0x20 && c != 0x09 { break }
    start = start + 1
  }
  while end > start {
    let c = s[end - 1].to_int()
    if c != 0x20 && c != 0x09 { break }
    end = end - 1
  }
  if start >= end { return "" }
  s.substring(start=start, end=end)
}

///|
/// Loop #14: split_host_str —— 解包 caller 传入的 `[host]:port` 形式。
/// 返回 (host_only, port_caller?)。
///   split_host_str("foo.example.com")        -> ("foo.example.com", None)
///   split_host_str("[foo.example.com]:2200") -> ("foo.example.com", Some(2200))
///   split_host_str("[foo.example.com]")      -> ("foo.example.com", None)
fn split_host_str(s : String) -> (String, Int?) {
  if s.length() >= 2 && s[0].to_int() == '['.to_int() {
    let mut close = -1
    let mut j = 1
    while j < s.length() {
      if s[j].to_int() == ']'.to_int() { close = j; break }
      j = j + 1
    }
    if close > 0 {
      let host_inner = s.substring(start=1, end=close)
      if close + 1 < s.length() && s[close + 1].to_int() == ':'.to_int() {
        let port_str = s.substring(start=close + 2, end=s.length())
        // 复用 parse_int_str 解析端口数字
        match parse_int_str(port_str) {
          Some(n) => (host_inner, Some(n))
          None => (host_inner, None)
        }
      } else {
        (host_inner, None)
      }
    } else {
      (s, None)
    }
  } else {
    (s, None)
  }
}

///|
/// Loop #14: parse_int_str — 复用 parse.mbt 同名 helper (跨文件共享)
/// 此处仅保留 fn 声明,实际定义在 parse.mbt:221