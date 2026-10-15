///| OpenSSH fnmatch 简化版 (Loop #24 G1)
///
/// 实现 OpenSSH match.c match_pattern (openbsd-style fnmatch)
///   - `?` 匹配任意单字符
///   - `*` 匹配任意长度 (含 0)
///   - 其他字符字面匹配
///   - 不支持 POSIX [] charclass (Loop #24 简化)
///   - case-sensitive (OpenSSH 默认)
///
/// 算法: 双指针回溯 (与 OpenSSH NFA 等价的简化实现)
///
/// 返回: true = match, false = not match

///|
/// fnmatch 主函数: str 是否匹配 pattern
pub fn fnmatch(pattern : String, str : String) -> Bool {
  fnmatch_bytes(pattern, str, 0, 0)
}

///|
/// 递归双指针匹配: p[pi..] vs s[si..]
fn fnmatch_bytes(p : String, s : String, pi : Int, si : Int) -> Bool {
  let mut pi2 = pi
  let mut si2 = si

  // 主循环: 同时前进两个指针
  while pi2 < p.length() {
    let p_char = p[pi2].to_int()
    if p_char == '*'.to_int() {
      // 跳过连续的 '*' (greedy compression)
      while pi2 < p.length() && p[pi2].to_int() == '*'.to_int() {
        pi2 = pi2 + 1
      }
      // 如果 pattern 结束,match
      if pi2 == p.length() {
        return true
      }
      // 否则尝试匹配剩余 pattern:递归尝试 s 的每个位置
      while si2 <= s.length() {
        if fnmatch_bytes(p, s, pi2, si2) {
          return true
        }
        si2 = si2 + 1
      }
      return false
    } else if si2 >= s.length() {
      // str 用完但 pattern 还有非 '*' 字符 → 不 match
      return false
    } else if p_char == '?'.to_int() || p_char == s[si2].to_int() {
      // '?' 匹配任意字符,或字面匹配
      pi2 = pi2 + 1
      si2 = si2 + 1
    } else {
      return false
    }
  }

  // pattern 全部匹配,str 也应该用完
  si2 == s.length()
}