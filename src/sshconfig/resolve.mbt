///| Loop #57: ssh_config **resolution** (readconf.c 的取值规则)
///
///| 旧实现只有解析，没有解析**优先级**。`match_host_option()` 在首个匹配的
///| `Host` 块里找一个 keyword，找不到就报「没这个选项」——于是文件末尾最常见的
///| `Host *` 默认块对已经命中前面某个块的 host 完全不可见。实测（对拍
///| `ssh -G`，OpenSSH_for_Windows_9.5p2）：
///|
///| ```
///| Host web1
///|   User deploy
///| Host *
///|   Port 2222
///| ```
///|
///| `ssh -G web1` → `user deploy` + `port 2222`。旧实现在 Port 上返回 None。
///|
///| 它是死代码（只有 `cmd/sshconfig_test` 引用），所以从 Loop #24 至今没人撞上。
///|
///|
///| ## 取值规则（全部对拍 `ssh -G` 确认，不是凭记忆）
///|
///| 1. **所有**匹配的 `Host` 块按文件顺序依次参与，不是只取第一个匹配的块。
///| 2. 单值关键字取**最先出现**的值（ssh_config(5)："Since the first obtained
///|    value for each parameter is used"）。
///| 3. 多值关键字**累积**。`IdentityFile` 是其中之一——实测两个 `Host x` 块各写
///|    一个，`ssh -G x` 两个都保留。**这一点不做区分就会静默说谎**：按单值处理
///|    会丢掉第二个 IdentityFile，按多值处理会让 User 变成一串。
///| 4. `Host` 块**之前**的选项是无条件生效的全局默认，且排在文件最前，优先级最高。
///| 5. 否定模式：某块只要有一个 `!` 模式命中，**整块跳过**（不是只否决那一个模式）。
///| 6. keyword 大小写不敏感（readconf.c 用 `strcasecmp`）；`Keyword=Value` 与
///|    `Keyword Value` 等价；`#` 起头到行尾都是注释。
///| 7. `Host` 模式本身**大小写敏感**——`Host Web1` 不匹配 host `web1`。实测确认，
///|    因为 ssh_config(5) 在这点上措辞含糊，照文档写比照实测写更容易错。
///|
///|
///| ## 没做的
///|
///| `Match`、`Include`、引号与转义、`ProxyJump` 的展开都没实现。`#` 一律当注释
///| 起点，所以路径里带 `#` 的 IdentityFile 会被截断——这是已知限制，写在这里而不是
///| 假装支持。

///| `lower`, `lower_char`, `starts_with_ci` and `lower_eq` live in match.mbt and
///| parser.mbt -- one definition per package, not one per file.

///| Is this keyword accumulated rather than first-wins?
pub fn is_multivalued(keyword : String) -> Bool {
  let k = lower(keyword)
  let multivalued = [
    "identityfile", "localforward", "remoteforward", "dynamicforward",
    "permitremoteopen", "sendenv", "setenv",
  ]
  let mut i = 0
  while i < multivalued.length() {
    if multivalued[i] == k {
      return true
    }
    i = i + 1
  }
  false
}

///| 一个 `Host` 块是否适用于某个 host。
///|
///| 三种情况：
///|   - `patterns` 为空 → 这是 `Host` 块之前的全局选项，无条件适用。
///|   - 某个 `!` 模式命中 → **整块跳过**，哪怕同时有正模式命中。
///|   - 否则至少一个正模式命中才适用。
fn section_applies(section : SshConfigSection, host : String) -> Bool {
  if section.patterns.length() == 0 {
    return true
  }
  let mut any_positive = false
  let mut i = 0
  while i < section.patterns.length() {
    let p = section.patterns[i]
    if starts_with_ci(p, "!") {
      // 否定模式命中即否决整块。实测：`Host !secret *` 对 host `secret`
      // 整块不生效，`compression` 落到后面 `Host *` 的 `no`。
      if fnmatch(sub(p, 1), host) {
        return false
      }
    } else {
      if fnmatch(p, host) {
        any_positive = true
      }
    }
    i = i + 1
  }
  any_positive
}

///|
fn sub(s : String, from : Int) -> String {
  let b = StringBuilder()
  let mut i = from
  while i < s.length() {
    b.write_char(s[i].unsafe_to_char())
    i = i + 1
  }
  b.to_string()
}

///| 按 `SshConfigSection[]` + host 解析出最终生效的选项，按文件顺序。
pub fn resolve_host(
  host : String,
  sections : Array[SshConfigSection],
) -> Array[SshConfigOption] {
  let out : Array[SshConfigOption] = []
  // 单值关键字：记下第一次出现的位置，之后的同名项直接丢。
  let decided : Array[String] = []
  let mut s = 0
  while s < sections.length() {
    let section = sections[s]
    if section_applies(section, host) {
      let mut o = 0
      while o < section.options.length() {
        let opt = section.options[o]
        let k = lower(opt.keyword)
        if is_multivalued(opt.keyword) {
          out.push(opt)
        } else {
          // 单值：只在还没定下来时记。`Host` 块之间的顺序就是优先级，
          // 所以这里不排序——第一个赢就是文件里靠前的那个赢。
          if !contains(decided, k) {
            decided.push(k)
            out.push(opt)
          }
        }
        o = o + 1
      }
    }
    s = s + 1
  }
  out
}

///|
fn contains(arr : Array[String], v : String) -> Bool {
  let mut i = 0
  while i < arr.length() {
    if arr[i] == v {
      return true
    }
    i = i + 1
  }
  false
}

///| 从解析结果里取一个单值 keyword（大小写不敏感）
pub fn resolved_value(
  host : String,
  sections : Array[SshConfigSection],
  keyword : String,
) -> String {
  let opts = resolve_host(host, sections)
  let k = lower(keyword)
  let mut i = 0
  while i < opts.length() {
    if lower(opts[i].keyword) == k {
      return opts[i].value
    }
    i = i + 1
  }
  ""
}

///| 从解析结果里取一个多值 keyword，返回全部值
pub fn resolved_values(
  host : String,
  sections : Array[SshConfigSection],
  keyword : String,
) -> Array[String] {
  let out : Array[String] = []
  let opts = resolve_host(host, sections)
  let k = lower(keyword)
  let mut i = 0
  while i < opts.length() {
    if lower(opts[i].keyword) == k {
      out.push(opts[i].value)
    }
    i = i + 1
  }
  out
}