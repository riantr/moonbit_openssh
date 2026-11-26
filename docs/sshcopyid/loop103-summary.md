# Loop #103 — `ssh-copy-id`

`ssh-copy-id` is the last OpenSSH tool in the goal list that was still missing,
and it is the one that behaves worst on Windows: the upstream script is a POSIX
shell program, and on a Windows server it **reports a key it never installed**.

This loop builds the tool, measures what upstream really does, and pins both to
bytes.

---

## 1. What upstream is, exactly

The upstream is OpenSSH's own `ssh-copy-id`, a `/bin/sh` script (368 lines). Git
for Windows ships it at `C:\Program Files\Git\usr\bin\ssh-copy-id`, so the
reference implementation is on this machine and can be run — which is the only
way to know what it prints.

Its shape:

| step | what it does |
|---|---|
| 1 | find the key(s): `-i`, or the newest `~/.ssh/id*.pub` (`-cert.pub` excluded) |
| 2 | unless `-f`: try to log in with them; if that works, they are already installed |
| 3 | say how many are left |
| 4 | unless `-n`: send **one** remote command that appends them |
| 5 | say how many were added |

The remote command is a here-document folded with `tr '\t\n' ' '` and sent as
`exec sh -c '...'`. Its bytes, captured from the real script's own argv:

```
exec sh -c ' cd; umask 077; AUTH_KEY_FILE=".ssh/authorized_keys"; [ -f /etc/openwrt_release ] && [ "$LOGNAME" = "root" ] && AUTH_KEY_FILE=/etc/dropbear/authorized_keys; AUTH_KEY_DIR=`dirname "${AUTH_KEY_FILE}"`; mkdir -p "${AUTH_KEY_DIR}" && { [ -z "`tail -1c "${AUTH_KEY_FILE}" 2>/dev/null`" ] || echo >> "${AUTH_KEY_FILE}" || exit 1; } && cat >> "${AUTH_KEY_FILE}" || exit 1; if type restorecon >/dev/null 2>&1; then restorecon -F "${AUTH_KEY_DIR}" "${AUTH_KEY_FILE}"; fi '
```

Note the space after `sh -c '` (the here-document's first line was empty) and
the trailing `; fi '`. Both are upstream's, and both are reproduced.

## 2. What upstream does on a Windows server — measured

Against the real OpenSSH `sshd.exe` this repository runs for its own tests:

- upstream **exits 0**;
- its stdout says **`Number of key(s) added: 1`**;
- its stderr says `'exec' is not recognized as an internal or external command`
  — the Windows shell cannot run `exec sh -c '...'`;
- `authorized_keys` **did not change**;
- the new key **does not authenticate**.

So the tool that exists to install a key reports having installed it, and the key
is not there. That is the difference this loop removes.

## 3. The Windows install command, measured one candidate at a time

A Windows `sshd` runs a remote command through `cmd.exe /c "<command>"`, so
upstream's one-liner cannot run at all. The candidates were measured on a real
Windows `sshd`, with the key on stdin:

| candidate | result |
|---|---|
| `findstr "^" >> file` | `cmd.exe` eats the caret → `FINDSTR: Bad command line` |
| `more >> file` | works, but appends **two** CRLFs the input did not have (176 bytes for a 174-byte key) |
| `echo <key> >> file` | works, but the key is in the command line, not on stdin |
| `powershell -NoProfile -Command "$input \| Add-Content ..."` | the pipe is eaten by `cmd.exe` before PowerShell sees it |
| `copy /b con file` | blocks on the console device |
| **`powershell -NoProfile -EncodedCommand <base64>`** | **appends the input byte for byte** |

`-EncodedCommand` also removes the quoting problem entirely: the script travels
as base64, so `cmd.exe` never sees a `|`, a `>` or a quote. The target path
travels as base64 *inside* the script, so the script stays pure ASCII and a path
with a non-ASCII name still works (`-EncodedCommand` takes UTF-16LE, and UTF-16LE
cannot be built by asking for UTF-8 bytes).

The far side is asked what it is first: `echo %OS%` answers `Windows_NT` on
Windows and the literal `%OS%` on a POSIX shell, so the tool knows which
command to send without guessing.

## 4. What this build does

`src/sshcopyid` holds the rules; `cmd/ssh_copy_id` translates them.

The sentences are upstream's own bytes, read out of the real script:

```
$prog: INFO: Source of key(s) to be installed: "newkey.pub"
$prog: INFO: attempting to log in with the new key(s), to filter out any that are already installed
$prog: INFO: 1 key(s) remain to be installed -- if you are prompted now it is to install the new keys
```

and the closing block on stdout:

```
Number of key(s) added: 1

Now try logging into the machine, with: "ssh -i ./newkey -p 22273 -o 'UserKnownHostsFile=...' 'hp@127.0.0.1'"
and check to make sure that only the key(s) you wanted were added.
```

Two upstream quirks are kept **on purpose**, because "better" is not the same as
"the same tool":

- `-f` empties the private key path, so upstream's closing sentence says
  `ssh -i  'user@host'` — with `-i`, a space, and no path;
- the "too many arguments" sentence ends with an empty list, because upstream
  prints `$SAVEARGS` and never assigns it.

### The one thing this build does that upstream does not

After the install, the tool **authenticates with the key it just installed**.

- the server **accepted** it → the install took effect;
- the server **refused** it → the key is not in the file the server reads, so the
  tool says so and exits 1 instead of claiming success;
- the check itself **failed** → nothing is known, and the tool says that too,
  but the install itself did succeed, so the status stays 0.

This is the whole point of the loop: upstream counts the keys it *wrote*, which
is why it can exit 0 on a server where nothing was written.

## 5. The gate

`host/verify_loop103.mjs` — **42 checks**, all green.

The oracle is the real upstream script, run twice:

- **with a stand-in `ssh`** (`host/copyid_probe.sh`): the script runs to
  completion and every byte it produces is captured — stdout, stderr, and the
  remote command it built;
- **with the real `ssh`** (`host/copyid_probe_real.sh`), against the same
  Windows `sshd` — where it fails while claiming success.

Both sides of every comparison get **the same arguments, from the same
directory**: a relative `-i newkey` gives `./newkey` on both sides (upstream's
private path is `dirname(pub) + "/" + basename(pub)`), so even the closing
sentence's quoted path comes out the same. The program name is the only thing
that cannot match — upstream prints `$0`, this build prints its own path — and
both are replaced by `<prog>` before the comparison.

What the gate asserts:

1. the install run, the dry run and the "already installed" run are byte for
   byte upstream's own output;
2. the POSIX remote command in the source is byte for byte the command upstream
   built in the same run;
3. the Windows command on the wire is the base64 form, and the visible part of
   the decoded script is the beginning of the script this build makes;
4. `authorized_keys` grew by exactly the `.pub` file's bytes, and those bytes
   are the `.pub` file's bytes;
5. the new key **authenticates** afterwards — with the real `ssh.exe`;
6. upstream, on the same server, claims the key was added, changes nothing, and
   the key does not authenticate.

### Two limits the gate states out loud

- **The dry-run block differs by one CR.** The block repeats the key text, and
  the key text comes from a `.pub` file that ends with CRLF on Windows. Upstream
  reads it with `cat` inside Git's bash, and that shell translates CRLF to LF
  (measured: upstream's own bytes carry `new\n`, ours carry `new\r\n`). The CR
  is dropped before the comparison, and the bytes this build *appends* are
  checked separately, against the `.pub` file's own bytes.
- **The sshd log truncates the command.** OpenSSH's logger keeps one line in a
  1024-byte buffer, and the command is base64 of UTF-16LE — about three times
  the length of the script. So the log can give the first few hundred
  characters, and the gate asserts that they are the beginning of the script
  this repository builds. The rest of the script is pinned by the unit test and
  by the effect.

## 6. What is still missing

- `-s` (install over sftp) is **refused**, with a sentence of our own. Upstream
  can do it; this build has no sftp install path, and pretending otherwise
  would be the same kind of lie this loop exists to remove.
- The host key is checked against `~/.ssh/known_hosts` when that file is there,
  and accepted without a check when it is not. Upstream asks the user; this
  build cannot ask, because its stdin is carrying the key.
- Of the `-o` options, only `UserKnownHostsFile=`, `StrictHostKeyChecking=` and
  `Port=` are honoured. The rest are passed to the closing sentence (as
  upstream prints them) and ignored.
