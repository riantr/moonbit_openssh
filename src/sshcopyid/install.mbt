///| Loop #103: the remote command, in the two shapes a server can run.
///
/// ## The POSIX shape is upstream's, byte for byte
///
/// Upstream builds one command with `tr '\t\n' ' '` over a here-document
/// and sends it as `exec sh -c '...'`.  The captured upstream bytes are:
///
///     exec sh -c ' cd; umask 077; AUTH_KEY_FILE=".ssh/authorized_keys"; [ -f /etc/openwrt_release ] && [ "$LOGNAME" = "root" ] && AUTH_KEY_FILE=/etc/dropbear/authorized_keys; AUTH_KEY_DIR=`dirname "${AUTH_KEY_FILE}"`; mkdir -p "${AUTH_KEY_DIR}" && { [ -z "`tail -1c "${AUTH_KEY_FILE}" 2>/dev/null`" ] || echo >> "${AUTH_KEY_FILE}" || exit 1; } && cat >> "${AUTH_KEY_FILE}" || exit 1; if type restorecon >/dev/null 2>&1; then restorecon -F "${AUTH_KEY_DIR}" "${AUTH_KEY_FILE}"; fi '
///
/// Note the space after `sh -c '` (the here-document's first line was
/// empty, and `tr` turned its newline into that space) and the trailing
/// `; fi '`.  Both are upstream's and both are reproduced.
///
/// ## The Windows shape is ours, and it was measured
///
/// A Windows `sshd` runs remote commands through `cmd.exe /c "<command>"`,
/// so `exec` is not a command there and upstream's one-liner cannot run --
/// measured on a real Windows server: upstream exits 0, prints "Number of
/// key(s) added: 1", and the key is never written.
///
/// The candidates were measured, one at a time, on a real Windows `sshd`
/// with the key on stdin:
///
///   * `findstr "^" >> file` -- `cmd.exe` eats the caret, the command
///     fails with "FINDSTR: Bad command line",
///   * `more >> file` -- works, but appends **two** CRLFs the input did not
///     have (176 bytes written for a 174-byte key),
///   * `echo <key> >> file` -- works, but the key is in the command line
///     instead of on stdin, and `echo` leaves a space before the redirect,
///   * `powershell -NoProfile -Command "$input | Add-Content ..."` -- the
///     pipe is eaten by `cmd.exe` before PowerShell sees it,
///   * `copy /b con file` -- blocks on the console device,
///   * **`powershell -NoProfile -EncodedCommand <base64>`** -- appends the
///     input byte for byte, and is what this package sends.
///
/// `-EncodedCommand` also removes the quoting problem entirely: the script
/// travels as base64, so `cmd.exe` never sees a `|`, a `>` or a quote.
pub fn install_command_posix(target : String) -> String {
  "exec sh -c ' cd; umask 077; AUTH_KEY_FILE=\"" +
  target +
  "\"; [ -f /etc/openwrt_release ] && [ \"$LOGNAME\" = \"root\" ] && AUTH_KEY_FILE=/etc/dropbear/authorized_keys; AUTH_KEY_DIR=`dirname \"${AUTH_KEY_FILE}\"`; mkdir -p \"${AUTH_KEY_DIR}\" && { [ -z \"`tail -1c \"${AUTH_KEY_FILE}\" 2>/dev/null`\" ] || echo >> \"${AUTH_KEY_FILE}\" || exit 1; } && cat >> \"${AUTH_KEY_FILE}\" || exit 1; if type restorecon >/dev/null 2>&1; then restorecon -F \"${AUTH_KEY_DIR}\" \"${AUTH_KEY_FILE}\"; fi '"
}

///|
/// The command that asks the far side what it is.
///
/// `echo %OS%` is the discriminator: on a Windows `cmd.exe` it answers
/// `Windows_NT`, and on a POSIX shell `%OS%` is not a variable, so it
/// answers `%OS%` -- a word that says "not Windows" and nothing more.
///
/// Measured on a real Windows server: `echo %OS%` -> `Windows_NT`,
/// `echo %USERPROFILE%` -> `C:\Users\hp`, `cd` -> `C:\Users\hp` (so the
/// session's working directory *is* the account's home), `echo $HOME` ->
/// `$HOME` (so there is no POSIX shell to expand it).
pub fn os_probe_command() -> String {
  "echo %OS%"
}

///|
/// Whether a probe answer means "the far side is a Windows machine".
pub fn probe_says_windows(answer : String) -> Bool {
  has_substring(answer, "Windows_NT")
}

///|
/// The Windows install command.
///
/// The script is the upstream POSIX one-liner's *meaning*, written for
/// PowerShell:
///
///   * make the directory if it is not there (upstream's `mkdir -p`),
///   * add a newline if the file does not end with one (upstream's
///     `tail -1c` test),
///   * append the key that arrived on stdin (upstream's `cat >>`).
///
/// The target path travels as base64 rather than inside the script, so the
/// script stays pure ASCII and a path with a non-ASCII name still works:
/// PowerShell's `-EncodedCommand` takes UTF-16LE, and UTF-16LE cannot be
/// built by asking for UTF-8 bytes.
pub fn install_command_windows(target : String) -> String {
  let path_b64 = base64_of(utf8_bytes_of(target))
  let script =
    "$t=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" +
    path_b64 +
    "'))" +
    windows_script_body()
  "powershell -NoProfile -EncodedCommand " + base64_of(utf16le_bytes_of(script))
}

///|
/// The body of the Windows install script, after the target path is
/// decoded.
///
/// Split out so a test can read it without decoding base64.
pub fn windows_script_body() -> String {
  "\n" +
  "$h=$env:USERPROFILE\n" +
  "if(-not $h){$h=[Environment]::GetFolderPath('UserProfile')}\n" +
  "$p=$t\n" +
  "if($h -and -not $t.StartsWith('/') -and -not $t.Contains(':')){$p=Join-Path $h $t}\n" +
  "$p=$p.Replace('/','\\')\n" +
  "$d=[IO.Path]::GetDirectoryName($p)\n" +
  "if(-not(Test-Path $d)){[IO.Directory]::CreateDirectory($d)|Out-Null}\n" +
  "if((Test-Path $p) -and (Get-Item $p).Length -gt 0){\n" +
  "  $f=[IO.File]::Open($p,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)\n" +
  "  $f.Seek(-1,[IO.SeekOrigin]::End)|Out-Null\n" +
  "  $b=$f.ReadByte()\n" +
  "  $f.Close()\n" +
  "  if($b -ne 10){[IO.File]::AppendAllText($p,[string][char]10)}\n" +
  "}\n" +
  "[IO.File]::AppendAllText($p,[Console]::In.ReadToEnd())\n"
}

///|
/// A string as UTF-8 bytes.
pub fn utf8_bytes_of(s : String) -> FixedArray[Byte] {
  let raw = @utf8.encode(s)
  let out : FixedArray[Byte] = FixedArray::make(raw.length(), b'\x00')
  for i in 0..<raw.length() {
    out[i] = raw[i]
  }
  out
}

///|
/// A string as UTF-16LE bytes, which is what PowerShell's
/// `-EncodedCommand` wants.
///
/// A MoonBit string is a sequence of UTF-16 code units, so each unit
/// becomes two bytes, low byte first.  Doing it from the code units rather
/// than from UTF-8 bytes keeps a surrogate pair intact.
pub fn utf16le_bytes_of(s : String) -> FixedArray[Byte] {
  let n = s.length()
  let out : FixedArray[Byte] = FixedArray::make(n * 2, b'\x00')
  for i in 0..<n {
    let unit = s[i].to_int()
    out[i * 2] = (unit & 0xff).to_byte()
    out[i * 2 + 1] = ((unit >> 8) & 0xff).to_byte()
  }
  out
}

///|
/// Standard base64, with padding.
pub fn base64_of(bytes : FixedArray[Byte]) -> String {
  @base64.encode(Bytes::from_array(bytes))
}

///|
/// Whether `s` contains `needle`.
pub fn has_substring(s : String, needle : String) -> Bool {
  let n = s.length()
  let m = needle.length()
  if m == 0 {
    return true
  }
  if m > n {
    return false
  }
  let mut i = 0
  while i + m <= n {
    let mut j = 0
    let mut same = true
    while j < m {
      if s[i + j] != needle[j] {
        same = false
        break
      }
      j = j + 1
    }
    if same {
      return true
    }
    i = i + 1
  }
  false
}
