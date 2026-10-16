///| Loop #54: the native half of the write-back -- a real file.
///

///|
///
/// Three outcomes, not two, and the third is the point.
///

///|
///
/// `Missing` is separated from `Unreadable` because they are different
/// situations that must not read alike. "There is no pin here" and "I could
/// not find out whether there is a pin here" collapse into the same downstream
/// answer -- refuse, which is the right answer for both -- but a user who
/// silently loses the ability to read their own known_hosts will not know why.
/// A read failure is printed, not swallowed.
///

///|
///
/// **Storage being broken is not a man in the middle.** Loop #52 reached the
/// same conclusion for IndexedDB in a private-mode browser, and it holds here:
/// turning an unreadable file into a failed connection would be the wrong
/// failure for the wrong reason. The connection is fine, the user just loses
/// the ability to pin. So `load` reports and the caller decides.
///

///|
///
/// **`exists` first, so a missing file is not reported as a read failure.**
/// Not an optimisation: `read_file` on a missing file raises `ENOENT`, and
/// without the check every first-ever TOFU run would print "unreadable" for a
/// file that does not exist yet -- which is the normal case, not a fault.

///|
/// 读一个 known_hosts 文件的结果
pub(all) enum LoadResult {
  /// 文件存在，内容（可能为空字符串）
  Read(String)
  /// 文件不存在——这是第一次 TOFU 的正常状态，不是错误
  Missing
  /// 文件在，但读不出来（权限、是个目录、不是合法 UTF-8……）
  Unreadable(String)
}

///|
/// 追加的结果
pub(all) enum AppendResult {
  /// 字节落盘了
  Appended
  /// 写不进去（只读、目录满、Windows 上被占用……）
  Failed(String)
}

///|
/// 把一个错误渲染成能给人看的一行
///
/// `OSError` 自带 `Show`，`to_string` 出来是 `context: strerror(errno)`，正好
/// 是要的那句。渲染不出来时退回类型名而不是抛异常——**报告失败的地方绝不能
/// 自己再失败**，否则用户看到的是一个崩溃而不是权限不足。
fn describe(e : Error) -> String {
  e.to_string()
}

///|
/// 读一个 known_hosts 文件
///

///|
/// 返回空文本的只有 `Missing`。`Unreadable` 必须原样上报：把它当成「没有
/// pin」在 strict 下会拒绝（方向对），但在非 strict 下会**放行**，而一个读不到
/// 自己的信任锚的人绝不该因为读不到而被放行。
pub async fn load(path : String) -> LoadResult {
  if !@fs.exists(path) {
    return LoadResult::Missing
  }
  try {
    let data = @fs.read_file(path)
    LoadResult::Read(data.text())
  } catch {
    e => LoadResult::Unreadable(describe(e))
  }
}

///|
/// 在文件末尾追加一段字节（追加，不是覆盖）
///

///| `chunk` 自带结尾换行由调用方负责——这个包不知道一行 known_hosts 长什么样，
/// 那是 `src/knownhosts` 的事。
///

///|
///
/// **A torn append costs you the line you were adding and nothing else.**
/// There is no lock here (see the module notes), and the write is a single
/// `write_file`, so a crash mid-write can leave a fragment. That is benign in
/// a specific, checked way: `parse_file` skips a line it cannot parse, so a
/// fragment is ignored rather than read as a wrong key -- which is the failure
/// that would matter, because a half-written entry that *did* parse would
/// report a mismatch against a host nobody changed.
///

///|
///
/// Read-modify-write (read the file, concatenate, write it all back) was the
/// other option and is worse: it can lose a concurrent writer's entry outright,
/// while an append can only ever fail to add its own.
pub async fn append(path : String, chunk : String) -> AppendResult {
  try {
    @fs.write_file(
      path,
      chunk,
      append=true,
      // The argument `moon.pkg` explains at length. Omitting it truncates the
      // file and then appends to the truncation.
      create_mode=@fs.CreateMode::OpenOrCreate,
    )
    AppendResult::Appended
  } catch {
    e => AppendResult::Failed(describe(e))
  }
}

///|
/// 文件末尾是否已经有 `\n`
///

///|
/// 文件不存在时按「需要补换行」处理——空文件不需要，但补一个也不会错，
/// 而判断「文件在不在」在这里没有价值。
fn ends_with_newline(text : String) -> Bool {
  text.length() > 0 && text[text.length() - 1] == '\n'
}

///|
/// 往文件里追加**一行**（`line` 不带结尾换行），自动补齐分隔换行
///

///| 这是驱动真正会调用的那个。行格式由 `src/knownhosts` 决定、重复判定也由
/// 那个包决定（`has_line`）——所以**这个包不依赖 `knownhosts`**，依赖是反的：
/// 格式层调平台层，不是反过来。少一条依赖边，少一处能漂移的地方。
///

///|
/// 补分隔换行属于文件卫生而不是格式知识，所以留在这里：一份最后一行没有换行的
/// known_hosts 直接追加会与新行**粘成一条**，而粘连出来的行解析不出来，等于把
/// 这次写回悄悄丢掉。
pub async fn append_terminated(path : String, line : String) -> AppendResult {
  match load(path) {
    Unreadable(why) => return AppendResult::Failed(why)
    Missing => append(path, line + "\n")
    Read(text) =>
      if ends_with_newline(text) {
        append(path, line + "\n")
      } else {
        append(path, "\n" + line + "\n")
      }
  }
}
