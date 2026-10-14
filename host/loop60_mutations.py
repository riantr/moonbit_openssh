"""Mutation check: Loop #60's invariant must bite, and must not over-reach.

Six mutations, each one a claim this loop makes for the first time.

  * **A: the EtM name is put back** into `kexflow::default_client`. This is the
    defect itself. It is harmless *today* -- the proposal's cipher is an AEAD,
    so the MAC is never computed -- which is exactly why it survived a dozen
    loops. Under the invariant it is now a hard failure.

  * **B: `is_runnable_mac` returns true unconditionally.** The whole predicate
    collapses. This one is why the gate keeps its *own* copy of the runnable set
    instead of trusting the emitter's `ok` / `NO-PATH` labels: both sides read
    the same mutated predicate and would agree on a wrong answer.

  * **C: chacha20-poly1305's `iv_len` becomes 16 instead of 0.** Cipher.c:176
    makes `cipher_ivlen` return the column verbatim under `CFLAG_CHACHAPOLY`;
    the nonce is the sequence number and no IV is derived. Passing 16 would
    make `derive_keys` consume an IV that must not exist.

  * **D: `authlen_for("aes128-ctr")` returns 32.** The original version of that
    function did exactly this and the gate caught it: OpenSSH's `auth_len`
    column is the AEAD tag only, and aes128-ctr's 32-byte MAC lives in
    `mac_len`. A quantity that "looks right" and is wrong.

  * **E: an equivalent mutant.** The cipher routing guard in `live.mbt` is
    short-circuited to `... && false`. Provably unobservable here: `live_proposal`
    offers only `aes128-ctr`, so the guard never fires either way. Reported as a
    finding rather than hidden -- it is dead defense on today's inputs, and only
    starts mattering the moment a second cipher becomes negotiable.

  * **F: the emitter stops emitting one client proposal.** Guards against the
    real drift risk: a new proposal source is added under the emitter and never
    checked, because nothing asserts the set is complete.

**Undo with the snapshot below, never with `git checkout`.**

Anchors are unique and **ASCII-only**: `str.replace` rewrites every occurrence,
and this workspace's `edit` tool cannot round-trip CJK in `old_string`, so an
anchor that fails an encoding round-trip reports `NOBUILD` -- which reads as
"nothing proven" rather than "the script is broken".

Edits to the same file **compose**: each is applied to what is on disk now, not
to the pristine text (Loop #56's mutation E).

Run:  python host/loop60_mutations.py          (all)
      python host/loop60_mutations.py A        (one, by label prefix)
"""

import io
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

PROPOSAL = os.path.join(ROOT, "src", "kexflow", "proposal.mbt")
RUNNABLE = os.path.join(ROOT, "src", "bpacket", "runnable.mbt")
LIVE = os.path.join(ROOT, "src", "sshclient", "live.mbt")
EMITTER = os.path.join(ROOT, "cmd", "proposal_kat", "main.mbt")
FILES = [PROPOSAL, RUNNABLE, LIVE, EMITTER]

MUTATIONS = [
    (
        "A: the EtM name is back in default_client",
        [(PROPOSAL,
          '    mac_ctos: "hmac-sha2-256",\n    mac_stoc: "hmac-sha2-256",',
          '    mac_ctos: "hmac-sha2-256-etm@openssh.com,hmac-sha2-256",\n'
          '    mac_stoc: "hmac-sha2-256-etm@openssh.com,hmac-sha2-256",')],
        "missed",
    ),
    (
        "B: is_runnable_mac accepts everything",
        [(RUNNABLE,
          "  for n in runnable_mac_names() {\n"
          "    if n == mac {\n"
          "      return true\n"
          "    }\n"
          "  }\n"
          "  false",
          "  true")],
        "missed",
    ),
    (
        "C: chacha20-poly1305 derives a 16-byte IV",
        [(RUNNABLE,
          "    Some(AeadChachaPoly1305) => (64, 8, 0, 0)",
          "    Some(AeadChachaPoly1305) => (64, 8, 16, 0)")],
        "missed",
    ),
    (
        "D: authlen_for counts the MAC as an auth tag",
        [(RUNNABLE,
          "    Some(AeadChachaPoly1305) => 16\n"
          "    Some(MacEncryptAes128CtrHmacSha256) => 0",
          "    Some(AeadChachaPoly1305) => 16\n"
          "    Some(MacEncryptAes128CtrHmacSha256) => 32")],
        "missed",
    ),
    (
        "E: the cipher routing guard is short-circuited away",
        [(LIVE,
          "  if !@bpacket.cipher_needs_mac(neg.cipher_ctos) {",
          "  if !@bpacket.cipher_needs_mac(neg.cipher_ctos) && false {")],
        "equivalent",
    ),
    (
        "F: the emitter stops emitting one client proposal",
        [(EMITTER,
          '  emit_client(\n'
          '    "sshclient.live_proposal_with_certs=false",\n'
          '    @sshclient.live_proposal_with_certs(false),\n'
          '  )\n',
          "")],
        "missed",
    ),
]


def read(path):
    with io.open(path, encoding="utf-8") as fh:
        return fh.read()


def write(path, text):
    with io.open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)


def restore(originals):
    for p, text in originals.items():
        write(p, text)


def run(argv, timeout=3600):
    return subprocess.run(
        argv, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        encoding="utf-8", errors="replace", timeout=timeout,
    )


def fails_for(out):
    labels = []
    for line in (out or "").split("\n"):
        s = line.strip()
        if s.startswith("FAIL ") and s not in labels:
            labels.append(s)
    return labels


def main():
    originals = {p: read(p) for p in FILES}
    only = sys.argv[1:] or None
    chosen = [m for m in MUTATIONS
              if only is None or any(m[0].startswith(pfx) for pfx in only)]
    if only and not chosen:
        print("no mutation matches %r" % (only,))
        return 1
    counts = {"CAUGHT": 0, "MISSED": 0, "NOBUILD": 0, "CRASH": 0, "EQUIVALENT": 0}
    try:
        for label, edits, expect in chosen:
            restore(originals)

            broken = None
            for path, frm, to in edits:
                src = originals[path]
                if frm not in src:
                    broken = "anchor not found in %s" % os.path.relpath(path, ROOT)
                    break
                if src.count(frm) != 1:
                    broken = ("anchor appears %d times in %s" % (
                        src.count(frm), os.path.relpath(path, ROOT)))
                    break
            if broken:
                print("NOBUILD  %s -- %s" % (label, broken))
                counts["NOBUILD"] += 1
                continue
            for path, frm, to in edits:
                write(path, read(path).replace(frm, to))

            run(["cmd", "/c", "moon", "clean"])
            proc = run(["node", os.path.join(ROOT, "host", "verify_loop60.mjs")])
            out = proc.stdout or ""

            if "failed when checking project" in out or (
                proc.returncode != 0 and "ALL PASS" not in out and "  FAIL " not in out
            ):
                print("NOBUILD  %s -- the mutated source did not compile/build" % label)
                counts["NOBUILD"] += 1
                continue
            if proc.returncode == 0:
                if expect == "equivalent":
                    print("EQUIVALENT  %s -- gate still ALL PASS, and this change "
                          "provably cannot be observed on these inputs" % label)
                    counts["EQUIVALENT"] += 1
                else:
                    print("MISSED  %s -- the gate still reported ALL PASS" % label)
                    counts["MISSED"] += 1
                continue
            fails = fails_for(out)
            if not fails and ("gate crashed" in out or "Traceback" in out):
                print("CRASH  %s -- %s" % (label, out.strip().split("\n")[0][:160]))
                counts["CRASH"] += 1
                continue
            print("CAUGHT  %s" % label)
            for f in fails[:4]:
                print("          " + f[:190])
            counts["CAUGHT"] += 1
    finally:
        restore(originals)
        drifted = [p for p in FILES if read(p) != originals[p]]
        if drifted:
            print("\nWARNING: not restored byte for byte: %s" % ", ".join(drifted))
            return 1

    print(
        "\n%d CAUGHT, %d MISSED, %d EQUIVALENT, %d NOBUILD, %d CRASH (of %d mutations)"
        % (counts["CAUGHT"], counts["MISSED"], counts["EQUIVALENT"],
           counts["NOBUILD"], counts["CRASH"], len(chosen))
    )
    return 0 if counts["MISSED"] == 0 and counts["CRASH"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())