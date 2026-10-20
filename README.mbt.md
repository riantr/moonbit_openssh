# openssh/openssh_moonbit

A hand-written SSH client in [MoonBit](https://docs.moonbitlang.com), with no
cryptography from any third-party SSH or TLS library.

Everything below the socket is implemented in this repository: the key
exchanges, the ciphers and MACs, signature verification, host key pinning,
`known_hosts` parsing, SFTP, userauth and the OpenSSH certificate format. The
only dependency that carries weight is `moonbitlang/async`, for filesystem and
socket syscalls. `moonbit-community/proton*` is used by `cmd/proton_gui` only
-- no package under `src/` may import it.

- **Branch of record:** `loop41-m2-fault-console` (currently at Loop #54)
- **Loop history and every design decision:** [`AGENTS.md`](AGENTS.md) -- read
  this one, it is the actual documentation
- **License:** Apache-2.0

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
- SFTP against `internal-sftp`, with window and max-packet clamping
- host key pinning: `known_hosts`, last-match-wins, `@revoked`, TOFU
- OpenSSH host certificates as a real trust anchor, with a genuine clock
- port forwarding, client half: `direct-tcpip`, the protocol layer of
  `ssh -L`, with the max-packet clamping and both failure modes. The local
  listener that turns a connection into a request, and the `ssh -R`
  direction that the server initiates, are not here yet.
- two transports, one set of rules

Four targets are built and compared byte for byte: `native`, `js`, `wasm`,
`wasm-gc`.

## Build and test

```powershell
# per-package unit tests
cmd /c "moon test src\knownhosts"
cmd /c "moon test src\hostkey"
cmd /c "moon test src\khfile --target native"   # native-only package

# live client
cmd /c "moon build cmd\ssh_live --target native"
```

### Gates

The `host/verify_loop*.mjs` scripts are the real test suite. Each is a
self-contained run that starts its own man in the middle, drives the client
through it, and asserts on transcripts rather than on the client's own report.

```powershell
node host\verify_loop54.mjs    # 16 checks -- the TOFU write-back lands
node host\verify_loop53.mjs    # 26 checks -- host certificates, both transports
node host\verify_loop52.mjs    #  9 checks -- the pin survives the page going away
node host\verify_loop47.mjs    # 19 checks -- a peer that lies about its host key
node host\verify_loop45.mjs    # 51 checks -- fault vectors over a real socket
node host\verify_loop41.mjs    # 29 checks -- byte-identical to a Python oracle
```

Mutation checks are separate, and are how a gate proves it would have caught
something:

```powershell
python host\loop54_mutations.py    # 3 CAUGHT, 0 MISSED
python host\loop53_mutations.py
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
  ed25519/ ecdsa/ rsa/ x25519/           key types, written here
  hostkey/                              host keys, certificates, signatures
  knownhosts/                           known_hosts parsing and pinning rules
  khfile/ khstore/                      where a TOFU write-back goes
                                        (native file / browser IndexedDB)
  sftp/ bpacket/ channel/               SFTP and the channel layer
  sshclient/ wtlive/                    the two transport adapters
  userauth/ sshconfig/
cmd/
  ssh_live/                             the native client
  wt_ssh/                               the browser client
  *_test/                               known-answer and property tests
host/                                   python man in the middle + the gates
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
- `moon check --target native` at the repository root is red, correctly:
  `src/ws_socket`, `src/wt_socket` and the `cmd/wt_*` executables are
  js/wasm-only live packages. Check per package.
- The `pkg.generated.mbti` files in this repository are stale and are not an API
  surface. Read the `.mbt` sources in `.mooncakes`.
- Concurrent writers of one `known_hosts` can lose an entry; there is no lock.
- A certificate chain longer than one CA is not followed.
