///| Loop #54: 落盘这一层的测试
///
///|
///
/// 这些测试只测**文件**，不测 known_hosts 的格式——行格式归 `src/knownhosts`，
/// 那边的往返测试已经覆盖。这里测的是「把一行安全地放到文件末尾」这件事本身，
/// 以及三种失败形态（没有 / 读不了 / 写不进）能不能被区分出来。

///|
/// 起一个本测试专用的路径
///
/// `moon test` 会清 `_build`，所以这里直接用 `_build/` 下面——stdlib 自己的
/// fs 测试也是这么放的，用它就不用自己造清理逻辑，也不会在仓库根留下文件。
fn p(name : String) -> String {
  "_build/loop54_" + name
}

///|
/// 删掉一个文件，但**文件不存在时不报错**
///
/// `@fs.remove` 对不存在的文件抛错，所以一个「先删掉再写」的习惯写法在一台
/// 刚 `moon clean` 过的机器上会失败。`moon test` 每次都清 `_build`，于是第一个
/// 跑这组测试的人会先撞上这个——所以守卫在这里，而不是每个调用点各判一次。
async fn drop(path : String) -> Unit {
  if @fs.exists(path) {
    @fs.remove(path)
  }
}

///|
/// 读回来，测试里省掉一次类型匹配
async fn text_of(path : String) -> String {
  match load(path) {
    Read(t) => t
    Missing => ""
    Unreadable(why) => abort("expected to read " + path + ", got: " + why)
  }
}

///|
async fn put(path : String, content : String) -> Unit {
  @fs.write_file(path, content)
}

///|
/// **The one that matters: appending must not truncate.**
///
/// `write_file`'s `create_mode` defaults to `CreateOrTruncate` while `append`
/// defaults to `false`, and those two defaults are safe together. Pass
/// `append=true` and leave the mode alone and every known_hosts the user has
/// ever built is truncated to zero and then one line is appended to nothing.
///
/// Nothing raises, nothing is logged, and the next connection reports the host
/// as unpinned -- which reads as "TOFU forgot again", the exact defect Loop #54
/// exists to remove, wearing a completely different cause. So this is asserted
/// directly rather than inferred from a later behaviour.
async test "append keeps everything that was already in the file" {
  let path = p("append_keeps.txt")
  let existing = "# a comment\nother.example.com ssh-ed25519 AAAAC3NzaC1lZDI1\n"
  put(path, existing)
  match append_terminated(path, "127.0.0.1 ssh-ed25519 AAAAdummy") {
    Appended => ()
    Failed(why) => abort("append failed: " + why)
  }
  let after = text_of(path)
  if !after.contains("other.example.com ssh-ed25519 AAAAC3NzaC1lZDI1") {
    abort("the pre-existing entry did not survive an append: " + after)
  }
  if !after.contains("127.0.0.1 ssh-ed25519 AAAAdummy") {
    abort("the new entry is not in the file: " + after)
  }
  if !after.contains("# a comment") {
    abort("the comment was dropped: " + after)
  }
}

///|
async test "load reports a missing file as Missing, not Unreadable" {
  let path = p("never_written.txt")
  drop(path)
  match load(path) {
    Missing => ()
    Read(t) => abort("a file that does not exist returned " + t)
    Unreadable(why) =>
      abort(
        "a file that does not exist was reported as unreadable (" + why +
        ") -- that would print a fault on every first-ever TOFU run",
      )
  }
}

///|
async test "load round-trips content, including a missing trailing newline" {
  let path = p("roundtrip.txt")
  put(path, "alpha\nbeta")
  match load(path) {
    Read(t) => {
      if t != "alpha\nbeta" {
        abort("round-trip changed the content: " + t)
      }
    }
    Missing => abort("an existing file was reported as missing")
    Unreadable(why) => abort("could not read a file we just wrote: " + why)
  }
}

///|
/// **A file whose last line has no newline must not fuse with the new line.**
///
/// Appending straight on produces `beta127.0.0.1 ssh-ed25519 ...`, which parses
/// as a single unparsable entry -- so the write-back silently does nothing. This
/// is the case a naive `append(line + "\n")` gets wrong, and it is reachable
/// because nothing enforces a trailing newline in a hand-edited known_hosts.
async test "an unterminated last line gets a separator, not a fusion" {
  let path = p("unterminated.txt")
  put(path, "alpha.example.com ssh-ed25519 AAAA")
  match append_terminated(path, "127.0.0.1 ssh-ed25519 BBBB") {
    Appended => ()
    Failed(why) => abort("append failed: " + why)
  }
  let after = text_of(path)
  if !after.contains("alpha.example.com ssh-ed25519 AAAA\n") {
    abort("the old line was not terminated: " + after)
  }
  if !after.contains("127.0.0.1 ssh-ed25519 BBBB\n") {
    abort("the new line is missing or fused: " + after)
  }
}

///|
async test "append creates the file when it does not exist yet" {
  let path = p("created_by_append.txt")
  drop(path)
  match append_terminated(path, "127.0.0.1 ssh-ed25519 CCCC") {
    Appended => ()
    Failed(why) => abort("append to a new file failed: " + why)
  }
  let after = text_of(path)
  if !after.contains("127.0.0.1 ssh-ed25519 CCCC\n") {
    abort("the new file does not hold the line: " + after)
  }
}

///|
/// **Unwritable is not the same as "no pin here".**
///
/// The driver has to be able to tell the user that their write-back did not
/// land. If this collapsed into a success the client would print `accepted`
/// and the pin would evaporate, which is the silent-accept defect Loop #52
/// closed on the browser side.
async test "an unwritable path is reported as Failed, not as success" {
  // A path whose parent is a *file*, not a directory. Portable in a way that
  // chmod is not: on Windows a read-only bit does not stop an owner from
  // writing, so a permission-based test would pass here and prove nothing.
  let blocker = p("blocker.txt")
  let path = p("blocked/inner.txt")
  put(blocker, "i am a file, not a directory")
  match append(path, "127.0.0.1 ssh-ed25519 DDDD\n") {
    Appended => abort("appending under a regular file reported success")
    Failed(_) => ()
  }
}

///|
/// **Unreadable is reachable, and here is how.**
///
/// The obvious portable way to make a file unreadable does not exist: on
/// Windows a read-only bit does not stop its owner from writing, so a
/// chmod-based test passes here and proves nothing. What does raise is
/// `Data::text` on bytes that are not valid UTF-8 -- and a known_hosts file is
/// not allowed to contain those anyway, so "present, opened, not decodable" is
/// exactly the state worth reporting rather than passing off as empty content.
///
///|
/// The empty content would be the dangerous version: `Read("")` under a
/// non-strict policy *accepts*. A file full of garbage must not be read as
/// "this host has no keys".
async test "undecodable bytes are Unreadable, never empty content" {
  let path = p("not_utf8.txt")
  // 0xFF is never valid UTF-8. A lone continuation byte, so it cannot be part
  // of a multi-byte sequence either.
  let raw = FixedArray::make(3, b'\xff')
  raw[1] = b'\xfe'
  raw[2] = b'A'
  @fs.write_file(path, Bytes::from_array(raw))
  match load(path) {
    Read(t) =>
      abort("undecodable bytes were reported as content (" + t + ")")
    Missing => abort("a file that exists was reported as Missing")
    Unreadable(_) => ()
  }
}

///|
/// **A path under a regular file is `Missing`, and that is the right answer.**
///
/// `@fs.exists` returns false for this rather than raising `ENOTDIR`, so `load`
/// never gets the chance to say "unreadable". Worth recording explicitly,
/// because the opposite was assumed while writing this file.
///
/// It is still correct: `Missing` and `Unreadable` both mean "no pin here" to
/// the policy, and both refuse under the default. They are distinguished in the
/// *transcript* -- so the user learns their file has a problem -- not in the
/// trust decision, where the two answers are deliberately the same.
async test "a path under a regular file is Missing, not Unreadable" {
  let blocker = p("blocker2.txt")
  let path = p("blocked2/inner.txt")
  put(blocker, "i am a file, not a directory")
  match load(path) {
    Read(t) => abort("a path that cannot exist read back as content: " + t)
    Missing => ()
    Unreadable(_) =>
      abort("exists() returned false, so Unreadable would mean the file was seen")
  }
}
