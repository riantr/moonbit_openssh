# riantr/moonbit_openssh

A hand-written SSH client **and server** in [MoonBit](https://docs.moonbitlang.com),
with no cryptography from any third-party SSH or TLS library.

Everything below the socket is implemented in this repository: the key
exchanges, the ciphers and MACs, signature verification (both directions),
host key pinning, `known_hosts` parsing, SFTP (client and server), userauth,
the OpenSSH certificate format, and the connection protocol that runs a
channel. The only dependency that carries weight is `moonbitlang/async`, for
filesystem and socket syscalls. `moonbit-community/proton*` is used by
`cmd/proton_gui` only -- no package under `src/` may import it.

- **Branch of record:** `loop41-m2-fault-console` (currently at Loop #95)
- **Loop history and every design decision:** [`AGENTS.md`](AGENTS.md) -- read
  this one, it is the actual documentation
- **License:** MIT -- see [`LICENSE`](LICENSE). Third-party reference code kept
  under `verify_c/` and `triple_check/` is NOT relicensed: those files carry
  their own upstream notices (BSD / public domain), which are left in place.
- **Mirrors:** [GitHub](https://github.com/riantr/moonbit_openssh) (tagged
  states only) and [Gitee](https://gitee.com/ren-yongxiang/moonbit_openssh)
  (the working remote, pushed continuously)

## Install from mooncakes.io

```powershell
moon add riantr/moonbit_openssh
```

The version on mooncakes.io is the one `moon.mod` names, and the release gate
refuses to create a git tag unless the two agree (`ci/publish.py --check`), so
a published version and a git tag name the same tested state by construction.

> This file is the module README, and `moon.mod` points `readme` at
> `README.mbt.md`. The repository-root `README.md` is a **symlink** to it (mode
> `120000` in git), so the two names are one file and editing either edits both.
> That is deliberate: a README that can drift from the one `moon.mod` ships is a
> README that will eventually be wrong.

## What the live client actually offers

This is the proposal `cmd/ssh_live` and `cmd/wt_ssh` send, read out of
`src/sshclient/live.mbt` rather than from memory:

| field | offered |
|---|---|
| key exchange | `diffie-hellman-group14-sha256` |
| host key | `ssh-ed25519`, `rsa-sha2-512`, `rsa-sha2-256`, `ecdsa-sha2-nistp256`, `ecdsa-sha2-nistp384` |
| host key, when a `@cert-authority` anchor exists | the above plus `ssh-ed25519-cert-v01@openssh.com` |
| cipher | `aes128-ctr` |
| MAC | `hmac-sha2-256` |
| compression | `none` |

Anything wider is **implemented and unit-tested but not offered in the live
proposal** -- `curve25519-sha256` (`src/kexc25519`),
`chacha20-poly1305@openssh.com` (`src/aead`, with RFC 8439 vectors),
`aes-*-gcm@openssh.com`, `hmac-sha2-512`. Those carry known-answer tests; what
is *proven against a peer* is the column above. Widening the proposal is a
one-line change and its own piece of work.

Also working, and proven against a real `sshd` or a man in the middle:

- publickey userauth
- interactive sessions: `pty-req` (columns before rows on the wire, which is
  the order the real server reads them in), `shell`, and `window-change` with
  `want_reply = FALSE`. A refused `pty-req` falls back to a session with no tty
  instead of failing.
- SFTP against `internal-sftp`, with window and max-packet clamping
- host key pinning: `known_hosts`, last-match-wins, `@revoked`, TOFU
- OpenSSH host certificates as a real trust anchor, with a genuine clock
- port forwarding, client half: `direct-tcpip`, the protocol layer of
  `ssh -L`, with the max-packet clamping and both failure modes. The local
  listener that turns a connection into a request, and the `ssh -R`
  direction that the server initiates, are not here yet.
- the SSH agent: `ssh_agent` holds keys, `ssh_add` talks to it, and the
  **real** `ssh-add` talks to our agent byte for byte. The transport is a
  Windows named pipe, because that is what the real client speaks.
- two transports, one set of rules

## The four targets

`host/verify.mjs` builds `cmd/main` for 4 targets x 2 modes (debug and
release) and asserts one SHA-256 across all eight outputs: x25519, KEXINIT,
wire framing and chacha20-poly1305 produce the same bytes on every backend.

What that covers, and what it deliberately does not:

| layer | packages | what is proven |
|---|---|---|
| protocol rules | `bpacket`, `kexflow`, `sshd` | built on all four by CI; `src/sshd`'s 23 unit tests pass on each |
| the demo | `cmd/main` | byte-exact on 4 targets x 2 modes; `host/main.wasm` is its wasm-gc build, instantiated and asserted in a browser |
| platform seams | `rng`, `tcp`, `subproc`, `sftpserver`, `scp`, `agentpipe`, `keyperm` | compile on all four: one file per backend, and the backend that lacks the platform says so instead of pretending |
| live native stack | `khfile`, `cmd/sshd`, `cmd/ssh_live`, `cmd/sftp_server` | native only -- files, sockets and child processes |
| live browser stack | `wt`, `wtlive`, `khstore`, `cmd/wt_ssh` | js only: `extern "js"`, and MoonBit's async does not cover the wasm backends |
| wasm sockets | `ws_socket`, `wt_socket` | `extern "wasm"`, so a host shim supplies send / recv / close |

So "runs on four targets" is a claim about the rules, not about a finished
client. The wasm backends have no entropy source at all -- `src/rng` reports
that rather than inventing bytes -- so a handshake there needs a host-provided
CSPRNG before it can start. What runs on wasm today is the protocol and crypto
kernel above, compared byte for byte; the product-shaped client and server run
on native and, in a browser, on js.

## The server

`cmd/sshd` is a real SSH server, not a test double: it completes the same
transport handshake as the client, accepts publickey userauth, and then speaks
RFC 4254 -- channel open/confirm, exec, stdout and stderr as separate streams,
EOF, exit-status, close. A real `ssh.exe` (OpenSSH 9.5p2) runs commands through
it, and the transcripts are compared byte for byte against the same commands
run through the **real** Windows `sshd` (OpenSSH 8.0): 18/18 cases identical on
exit code, stdout and stderr, including the two cases that are only visible to
a real client (`cmd.exe` keeps the trailing quote of `/c "..."`, and a server
that closes the socket before draining the peer's close loses the exit status
to a TCP reset).

The server does `exec` and nothing else yet. `shell`, `subsystem` and
`pty-req` are answered with `CHANNEL_FAILURE` rather than accepted and then
ignored; `env` is dropped without a reply, the way RFC 4254 §6.4 prescribes;
and the peer's stdin is counted against the window and discarded, because the
command runs with stdin closed (`src/sshd/channelserver.mbt`). The server half
of SFTP already exists as `src/sftpserver` -- the same requests and replies,
measured against the real `sftp-server.exe` -- but `cmd/sftp_server` drives it
over standard input and it is not yet wired to the channel layer. That wiring
is the next piece of work.

`host/verify_loop94.mjs` is the gate (49 checks), `host/loop94_mutations.py`
proves it would catch regressions (10/10 CAUGHT), and `host/loop94_oracle.py`
re-measures the real `sshd` whenever the claim needs re-grounding.

## Build and test

```powershell
# per-package unit tests
cmd /c "moon test src\knownhosts"
cmd /c "moon test src\hostkey"
cmd /c "moon test src\khfile --target native"   # native-only package

# live client, and the server
cmd /c "moon build cmd\ssh_live --target native"
cmd /c "moon build cmd\sshd --target native"
```

`moon check --target native` at the repository root is red by design; see
*Known gaps*.

### The local CI, the tag gate and publication

`ci/ci.py` runs everything as named steps and prints one summary line that
cannot disagree with the exit code:

```powershell
python ci\ci.py                                  # env,build,gates (the default)
python ci\ci.py --tiers env,build,gates,qa        # the release run
python ci\ci.py --self-check                     # tests the engine itself
python ci\ci.py --only loop94 --tiers gates       # one gate
```

Three rules are enforced by code rather than by intent:

- **No tag while CI is red.** `--tag` calls `ci/release.py`, which refuses to
  create a tag unless every step that ran passed -- including when asked
  directly, which is why it lives in a program and not in a habit. A tag only
  moves its final component (`v0.1.2` -> `v0.1.3`).
- **The published version and the tag are one fact.** `ci/release.py`'s
  `assert_version_matches_tag` refuses to create a tag whose name is not
  `moon.mod`'s `version`, and the release gate calls it before the tag exists
  -- after it, a disagreement could only be recorded as a mistake.
  `ci/publish.py --check --next-tag vX.Y.Z` asks the same question from the
  packaging side.
- **Publishing happens on GitHub, from the tag, with a stored credential.**
  A tag push triggers the `publish` job, and the workflow a tag push runs is the
  one in the tagged commit -- so the job that publishes is part of what the tag
  names. The runner restores `%USERPROFILE%\.moon\credentials.json` from the
  `MOONCAKES_RIANTR_TOKEN` secret -- measured to be a JSON object with one key,
  `token`, 32 characters -- and accepts either that whole file or the bare
  token, wrapping the latter into the file's own shape because a
  `credentials.json` that is not JSON is not a login,
  then asks `moon whoami` and reads the TEXT, because a stale login exits 0
  while printing "username is unavailable". It refuses to publish when the tag
  is not the version `moon.mod` names. A release that silently did not publish
  would be worse than a failed one.
- **The same gate runs locally, for the tag.** `--tag` still asks
  `ci/release.py`; `--publish` there refuses without a login rather than
  skipping, so the two paths cannot disagree about what "published" means.

```powershell
python ci\publish.py --check                      # offline: manifest + metadata
python ci\publish.py --check --next-tag v0.1.3    # ...and the version match
python ci\ci.py --tiers env,build,gates,qa --tag   # tags; the tag push publishes

# one-time: give the runner the login state that `moon login` wrote
Get-Content -Raw "$env:USERPROFILE\.moon\credentials.json" |
  gh secret set MOONCAKES_RIANTR_TOKEN
```

### Gates

The `host/verify_loop*.mjs` scripts are the real test suite. Each is a
self-contained run that starts its own man in the middle, drives the client
through it, and asserts on transcripts rather than on the client's own report.

```powershell
node host\verify_loop94.mjs    # 49 checks -- the server, against a real ssh.exe
node host\verify_loop93.mjs    # 28 checks -- the server: KEX + publickey auth
node host\verify_loop54.mjs    # 16 checks -- the TOFU write-back lands
node host\verify_loop53.mjs    # 26 checks -- host certificates, both transports
node host\verify_loop52.mjs    #  9 checks -- the pin survives the page going away
node host\verify_loop47.mjs    # 19 checks -- a peer that lies about its host key
node host\verify_loop45.mjs    # 51 checks -- fault vectors over a real socket
node host\verify_loop41.mjs    # 29 checks -- byte-identical to a Python oracle
node host\verify_loop89.mjs    # 81 checks -- the agent, against the REAL ssh-add
```

Mutation checks are separate, and are how a gate proves it would have caught
something:

```powershell
python host\loop54_mutations.py    # 3 CAUGHT, 0 MISSED
python host\loop53_mutations.py
python host\loop89_mutations.py    # 23 CAUGHT, 0 MISSED
```

**Never run two browser gates concurrently.** Each spawns Chromium, a static
server and a WS bridge; one gate's `moon clean` has deleted another gate's
freshly built `_build` mid-run, and the result reads like a protocol bug.

## Layout

```
src/
  sshwire/ kexflow/ kexdh/ kexc25519/   transport and key exchange
  aes/ chacha/ aead/ hmac/ poly1305/     ciphers and MACs, written here
  sha256/ sha512/ bigint/               primitives, written here
  ed25519/ ecdsa/ rsa/ x25519/          key types, written here
  blowfish/ bcrypt_pbkdf/               the legacy cipher and the key-file KDF
  hostkey/                              host keys, certificates, signatures
  knownhosts/                           known_hosts parsing and pinning rules
  khfile/ khstore/                      where a TOFU write-back goes
                                        (native file / browser IndexedDB)
  sftp/ sftpserver/ sftpdrive/ scp/     SFTP both ends, and scp
  bpacket/ channel/                     the packet and channel layer
  sshclient/ wtlive/                    the two transport adapters
  socket/ tcp/ ws_socket/ wt_socket/    byte-stream seams, one per target
  sshd/                                 the server: transport, connection protocol
  subproc/                              child processes, three pipes, deadlines
  userauth/ sshconfig/
  agent/ agentserver/ agentpipe/        the SSH agent: protocol, server, pipe
  keyfile/ keyperm/                     the OpenSSH private key file, its perms
  rng/                                  the platform CSPRNG, or the refusal
cmd/
  ssh_live/                             the native client
  sshd/                                 the server
  wt_ssh/                               the browser client
  ssh_agent/ ssh_add/                   the agent daemon and its client
  ssh_keygen/ ssh_keyscan/              make, read, rewrite, scan keys
  scp/ sftp_server/ sftp_mitm/          the scp and SFTP drivers the gates use
  main/                                 the 4-target byte-exact demo
  *_test/ *_kat/ *_probe/ bench_*/      known-answer, property and bench drivers
host/                                   python man in the middle + the gates
ci/                                     the step engine, the tag gate, publish
```

## The one rule

**A protocol rule lives in exactly one package, and both transports call it.**
`src/knownhosts` decides whether a host key is trusted; `src/hostkey` decides
whether a signature is valid; `src/sftp` owns framing. `src/sshclient` and
`src/wtlive` translate error types and nothing else. Two copies of a rule is
the duplication this repository has been paying for, repeatedly, and it is the
defect every recent loop was written to close.

## Known gaps

- The WebTransport path cannot be tested locally: Chromium rejects a
  locally-added certificate on the QUIC path (`QUIC_TLS_CERTIFICATE_UNKNOWN`).
  What is proven is everything above the transport, on a WebSocket carrier.
- The wasm backends have no entropy source and no async: `src/rng` reports the
  failure rather than inventing bytes, and MoonBit's async does not cover wasm.
  That is why the browser live path (`cmd/wt_ssh`) is pinned to `js`. What runs
  on wasm is the protocol and crypto kernel, byte for byte; the client and the
  server do not run there.
- `moon check --target native` at the repository root is red, correctly:
  `src/ws_socket`, `src/wt_socket` and the `cmd/wt_*` executables are
  js/wasm-only live packages. Check per package.
- The `pkg.generated.mbti` files in this repository are stale and are not an API
  surface. Read the `.mbt` sources in `.mooncakes`.
- `host/main.wasm` is a checked-in build artefact of `cmd/main`, not a source
  file. Regenerate it rather than editing it:

  ```powershell
  cmd /c "moon build --target wasm-gc --release cmd\main"
  # then copy _build\wasm-gc\release\build\cmd\main\main.wasm to host\main.wasm
  node host\browser_test.mjs     # asserts its output byte for byte
  ```

  It carries the module name in the `name` custom section behind a length
  prefix, so a search-and-replace inside it corrupts the file in a way
  `WebAssembly.validate` only sometimes reports: the renamed module
  `riantr/moonbit_openssh` is one byte shorter than the old one, and the stale
  prefix then reads one byte past the end of the string.
- Concurrent writers of one `known_hosts` can lose an entry; there is no lock.
- A certificate chain longer than one CA is not followed.
