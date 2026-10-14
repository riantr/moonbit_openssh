"""Mutation check: Loop #61's findings have to be load-bearing, and its two
false positives have to stay fixed.

Six mutations.

  * **A: the `derive_keys` argument swap comes back.** The defect that made
    `flow_on_reply` incapable of ever returning `Established`. Caught by a
    labelled source check, because both parameters are `FixedArray[Byte]` and no
    type system can see a swap -- and independently by `t12`.

  * **B: `FLOW_WE_NEED` comes back as a hardcoded 64.** The reason an unrunnable
    cipher could still produce a successful verdict.

  * **C: the strict-kex marker is treated as an algorithm.** This is the first
    false positive, re-introduced. It matters more than a normal mutation: the
    fix anyone reaches for under pressure is to delete the marker and turn off
    strict KEX, so a gate that demands its removal is a security regression
    wearing the costume of a failing test.

  * **D: certificate names are treated as unimplemented.** The second false
    positive. `live_proposal_with_certs(true)` exists precisely to let a client
    ask under a CA anchor; calling its name an over-promise says it cannot be
    written at all.

  * **E: `agrees_with_alg` goes back to inline literals.** The refactor that
    makes the host key names a union rather than a second list. Nothing is wrong
    with the *values* -- the mutation is caught by asserting the literal is gone
    from that function, which is the thing Loop #61 actually changed.

  * **F: an equivalent mutant.** `flow_on_reply`'s new cipher guard is
    short-circuited to `... && false`. Unobservable on today's inputs, because
    every client proposal offers only chacha20-poly1305, so an unrunnable cipher
    is never negotiated. Reported rather than hidden: it is dead defence today
    and live the moment a second cipher enters a proposal.

**Undo with the snapshot below, never with `git checkout`.**

Anchors are unique and **ASCII-only**. The `FLOW_WE_NEED` anchor is the whole
declaration line *including the following blank line*, because the string also
appears in comments -- and a textual mutation that hits a comment teaches nothing.

Run:  python host/loop61_mutations.py          (all)
      python host/loop61_mutations.py A        (one, by label prefix)
"""

import io
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

FLOW = os.path.join(ROOT, "src", "kexflow", "flow.mbt")
RUNNABLE = os.path.join(ROOT, "src", "kexflow", "runnable.mbt")
SIG = os.path.join(ROOT, "src", "hostkey", "sig_verify.mbt")
FILES = [FLOW, RUNNABLE, SIG]

MUTATIONS = [
    (
        "A: the derive_keys argument swap comes back",
        [(FLOW,
          "let keys = @kexc25519.derive_keys(h, shared_mpint, we_need)",
          "let keys = @kexc25519.derive_keys(shared_mpint, h, we_need)")],
        "missed",
    ),
    (
        "B: FLOW_WE_NEED is hardcoded again",
        [(FLOW,
          "  let (we_key, _we_block, _we_iv, we_mac) = @bpacket.transport_params(\n"
          "    neg.cipher_ctos,\n"
          "    neg.mac_ctos,\n"
          "  )\n"
          "  let mut we_need = we_key\n"
          "  if we_mac > we_need {\n"
          "    we_need = we_mac\n"
          "  }",
          "  let we_need : Int = 64")],
        "missed",
    ),
    (
        "C: the strict-kex marker counts as an algorithm",
        [(RUNNABLE,
          "  if is_pseudo_kex_alg(name) {\n      continue\n    }\n",
          "")],
        "missed",
    ),
    (
        "D: certificate names count as unimplemented",
        [(RUNNABLE,
          "    if is_cert_hostkey_alg(name) {\n"
          "      continue\n    }\n"
          "    if !is_runnable_hostkey(name) {",
          "    if !is_runnable_hostkey(name) {")],
        "missed",
    ),
    (
        "E: agrees_with_alg goes back to inline literals",
        [(SIG,
          "Ed25519Key(_) => ed25519_alg_names().contains(alg)\n"
          "    EcdsaKey(bits, _) =>\n"
          "      if bits == 256 {\n"
          "        ecdsa_p256_alg_names().contains(alg)\n"
          "      } else {\n"
          "        ecdsa_p384_alg_names().contains(alg)\n"
          "      }",
          'Ed25519Key(_) => alg == "ssh-ed25519"\n'
          "    EcdsaKey(bits, _) => {\n"
          "      let want = if bits == 256 {\n"
          '        "ecdsa-sha2-nistp256"\n'
          "      } else {\n"
          '        "ecdsa-sha2-nistp384"\n'
          "      }\n"
          "      alg == want\n"
          "    }")],
        "missed",
    ),
    (
        "F: flow_on_reply's cipher guard is short-circuited away",
        [(FLOW,
          "  if !@bpacket.cipher_needs_mac(neg.cipher_ctos) &&\n"
          "    !@bpacket.is_runnable_cipher(neg.cipher_ctos) {",
          "  if !@bpacket.cipher_needs_mac(neg.cipher_ctos) &&\n"
          "    !@bpacket.is_runnable_cipher(neg.cipher_ctos) && false {")],
        "equivalent",
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
            proc = run(["node", os.path.join(ROOT, "host", "verify_loop61.mjs")])
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