///| Is this argument a remote spec, and if so what are its three parts?
///
/// ## The rule, and why it is not just "contains a colon"
///
/// On every other platform `scp` decides remoteness by looking for a
/// colon.  On Windows that rule collides with drive letters, and the
/// collision is not hypothetical -- it was measured here first, because
/// the whole `-D` comparison bed depended on it:
///
///     scp a.txt h:/out.txt
///     The system cannot find the drive specified.      (exit 1)
///
/// `h:/out.txt` was **not** treated as a remote path.  `is_remote()` on
/// the Windows port refuses to call a single letter followed by a colon a
/// host, because that is a drive.  Every probe written for this loop had
/// to move to a multi-character host name once that was seen
/// (`.loop90/DESIGN.md` section 3).
///
/// The measured boundary, on both sides of it:
///
///     a.txt          -> local
///     C:\Windows\x   -> local   (drive)
///     h:x            -> local   (drive: one letter before the colon)
///     a:b:c          -> local   (the first colon is at 1, so it is a drive)
///     :x             -> local   (a leading colon is part of the name)
///     hh:x           -> remote  host=hh   path=x
///     host:x         -> remote  host=host path=x
///     host:          -> remote  host=host path=""  (it still connects)
///     host:a:b       -> remote  host=host path=a:b
///     1.2.3.4:x      -> remote
///     user@host:x    -> remote  user=user host=host path=x
///
/// Two cases are worth keeping in a test.  `a:b:c` shows the answer comes
/// from where the **first** colon is, not from how many there are.  And
/// `user@h:x` shows that an `@` defeats the drive-letter rule: the host
/// there is one letter, but it is a host, because a login name preceded
/// it.
///
/// ## What is not measured here
///
/// `/abs/host:x` was not measured: the probe that would have answered it
/// needs `scp` to reach the point of naming a host, and the run was
/// killed first.  This file treats it as remote (the colon is past offset
/// 1 and there is no `@`), which is what a plain "first colon wins" rule
/// gives; it is called out as unmeasured rather than presented as a fact.
///
/// ## The backslash question
///
/// A drive path may contain `\` and the drive rule already covers it.  A
/// *remote* spec's path half keeps its separators exactly as written: the
/// server is the one that interprets them, so nothing here rewrites them.

///|
/// One command-line argument, split.
pub(all) enum Spec {
  /// a path on this machine, usable as given
  Local(String)
  /// `[user@]host:path` -- the login name if one was given, the host, the
  /// path half exactly as written
  Remote(String?, String, String)
}

///|
/// `True` when the argument names a file on this machine.
///
/// Written as the negative of `split_spec` rather than as a second
/// implementation, so the two can never disagree.
pub fn is_local(spec : String) -> Bool {
  match split_spec(spec) {
    Local(_) => true
    Remote(_, _, _) => false
  }
}

///|
/// The index of the `:` that means "host", if there is one.
///
/// Three measured details:
///
/// * a **leading** colon never means a host (`:x` is local),
/// * a colon at offset **1** with no `@` before it is a **drive letter**,
///   and it settles the whole argument as local -- `a:b:c` is local even
///   though it has a second colon, because a drive path is a drive path,
/// * an `@` before the colon makes the host part whatever follows it and
///   by itself defeats the drive rule, so `user@h:x` is remote.
fn host_colon(s : String) -> Int32? {
  let n = s.length()
  if n == 0 || s[0] == ':' {
    return None
  }
  // `[::1]:x` -- the colons inside the brackets are address, not
  // separators, so the separator is the first `:` after `]`.
  if s[0] == '[' {
    let mut k = 0
    while k < n {
      if s[k] == ']' {
        if k + 1 < n && s[k + 1] == ':' {
          return Some(k + 1)
        }
        return None
      }
      k = k + 1
    }
    return None
  }
  let mut saw_at = false
  let mut i = 0
  while i < n {
    let c = s[i]
    if c == '@' {
      saw_at = true
    } else if c == ':' {
      if saw_at {
        return Some(i)
      }
      if i == 1 {
        // `X:` -- a drive letter, and therefore a local path, whatever
        // else the string contains.
        return None
      }
      return Some(i)
    }
    i = i + 1
  }
  None
}

///|
/// The path half of a spec, whichever kind it is.
///
/// Every message `scp` prints about a *remote* path names this half and
/// not the command-line argument: measured, `scp h:srv/nope.txt out.txt`
/// says `srv/nope.txt: No such file or directory` with the host stripped
/// (round 5 scenario 9).  So the stripping is a rule and lives here.
pub fn path_of(s : String) -> String {
  match split_spec(s) {
    Local(p) => p
    Remote(_, _, p) => p
  }
}

///|
/// Split one argument into local-or-remote.
pub fn split_spec(s : String) -> Spec {
  match host_colon(s) {
    None => Local(s)
    Some(at) => {
      let head = substring(s, 0, at)
      let path = substring(s, at + 1, s.length())
      let (user, host) = split_user_at(head)
      Remote(user, host, path)
    }
  }
}

///|
/// `user@host` -> `(Some(user), host)`; a bare `host` -> `(None, host)`.
///
/// The split is on the **last** `@`, because everything before it is the
/// login name and the rest is what ssh has to resolve.
fn split_user_at(head : String) -> (String?, String) {
  let n = head.length()
  let mut last = -1
  let mut i = 0
  while i < n {
    if head[i] == '@' {
      last = i
    }
    i = i + 1
  }
  if last < 0 {
    (None, head)
  } else {
    (Some(substring(head, 0, last)), substring(head, last + 1, n))
  }
}

///|
/// `[from, to)` of a string.
///
/// `String[i]` is a UTF-16 code unit (`UInt16`) under this toolchain, so
/// it has to be turned into a `Char` before it can be appended to a
/// builder -- the same drift documented at the top of `args.mbt`.
fn substring(s : String, from : Int32, to : Int32) -> String {
  let out = StringBuilder()
  let mut i = from
  while i < to && i < s.length() {
    out.write_char(Int32::unsafe_to_char(s[i].to_int()))
    i = i + 1
  }
  out.to_string()
}

///|
/// The last path component of a local path, accepting both separators.
///
/// `dir/ file` and `dir\ file` mean the same thing on Windows, and the
/// basename is what a directory target is built from.  Measured:
/// `-r local/t host:srv/upload` creates `upload/` holding **t's
/// contents**, not `upload/t/` (`.loop90/DESIGN.md` section 4).
pub fn basename_of(path : String) -> String {
  let n = path.length()
  let mut end = n
  // Trailing separators are not part of the name.
  while end > 0 && (path[end - 1] == '/' || path[end - 1] == '\\') {
    end = end - 1
  }
  let mut start = end
  while start > 0 && path[start - 1] != '/' && path[start - 1] != '\\' {
    start = start - 1
  }
  substring(path, start, end)
}

///|
/// Join a remote directory and a name the way the server will read it.
///
/// The remote side is POSIX-shaped in the tool's own messages (`srv/x`,
/// `srv/nodir/out.txt` in section 4 of the design note).
pub fn remote_join(dir : String, name : String) -> String {
  let n = dir.length()
  if n == 0 {
    name
  } else if dir[n - 1] == '/' || dir[n - 1] == '\\' {
    dir + name
  } else {
    dir + "/" + name
  }
}
