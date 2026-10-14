"""Mutation check: Loop #62's vectors have to be able to fail.

Six mutations. The vector set only means something if a wrong client fails it,
so most of these break the client rather than the vectors.

  * **A: the `derive_keys` argument swap comes back.** Loop #61 fixed it by
    inspection and a unit test; Loop #62 is the end-to-end version of the same
    claim. Caught here because the signature no longer verifies.

  * **C: host key verification is skipped.** The nastiest possible mutation:
    V1 and V2 would still report Established, V5 and V7 would report
    SignatureInvalid... which is the same verdict, so those cases pass too. This
    is the mutation that proves the negative cases carry weight.

    Note how it is caught: by the **build**, not by a verdict. Replacing the
    match arms with `_ => ()` leaves the scrutinee unbound, and MoonBit rejects
    it. A mutation caught by a compile error is not evidence that the vector set
    works, so this one is reported separately from the verdict-based catches
    rather than counted as if it proved something it did not.

  * **D: `session_id` is not checked against H.** The internal assertion Loop
    #61 left in place. Removing it is invisible to the vector set by
    construction, because the emitter only reports `Established` and both a
    correct and an incorrect session id produce that. Recorded as MISSED: the
    honest result, and a real limit of a verdict-based gate.

  * **B: `FLOW_WE_NEED` is hardcoded to 64 again.** Still correct for
    chacha20-poly1305, so V1 keeps passing. Same shape as D. Loop #61's gate
    catches it by reading the source; this one cannot, and pretending otherwise
    would be the wrong lesson.

  * **E: a vector's `expect` is changed** so the set still passes but a case no
    longer says what it says. The generator is re-run by the gate, so this can
    only work by editing the generator -- which is the point: it proves the
    drift check catches a hand-edited expectation.

  * **F: an equivalent mutant.** `flow_on_reply`'s `CipherNotRunnable` guard,
    short-circuited to `&& false`. Unobservable: V4's empty-cipher case is a
    *negotiation* failure (NoAgreement), never a negotiated-but-unrunnable
    cipher, so the guard cannot fire on any vector here.

**Undo with the snapshot below, never with `git checkout`.**

Anchors are unique and **ASCII-only**. `run(cmd /c moon clean)` before each,
because `flow_kat` is a native build and a stale binary reports the previous
tree's verdict -- which is how a mutation appears to pass.

Run:  python host/loop62_mutations.py          (all)
      python host/loop62_mutations.py A        (one, by label prefix)
"""

import io
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

FLOW = os.path.join(ROOT, "src", "kexflow", "flow.mbt")
VERIFY = os.path.join(ROOT, "src", "kexflow", "runnable.mbt")
GEN = os.path.join(ROOT, "host", "gen_flow62_vectors.py")
GATE = os.path.join(ROOT, "host", "verify_loop62.mjs")
VEC = os.path.join(ROOT, "verify_c", "kexflow", "flow_vectors.txt")
FILES = [FLOW, VERIFY, GEN, GATE]

# The generated vector file is part of the snapshot. The gate **regenerates** it
# as its first step, so a mutation of the generator rewrites it on disk -- and
# without restoring it here, the next mutation starts from a tree the previous
# one dirtied. That is not theoretical: mutation F was reported CAUGHT purely
# because E had left a wrong expectation behind, and it is a mutation that should
# be EQUIVALENT. Every mutation must start from the pristine tree, so the
# generated file is snapshotted alongside the sources.
SNAPSHOT = FILES + [VEC]

MUTATIONS = [
    (
        "A: the derive_keys argument swap comes back",
        [(FLOW,
          "let keys = @kexc25519.derive_keys(h, shared_mpint, we_need)",
          "let keys = @kexc25519.derive_keys(shared_mpint, h, we_need)")],
        "missed",
    ),
    (
        "B: the derivation length is hardcoded again",
        [(FLOW,
          "  let (we_key, _we_block, _we_iv, we_mac) = @bpacket.transport_params(\n"
          "    neg.cipher_ctos,\n"
          "    neg.mac_ctos,\n"
          "  )\n"
          "  let mut we_need = we_key\n"
          "  if we_mac > we_need {\n"
          "    we_need = we_mac\n"
          "  }",
          "  let we_need : Int = 64\n"
          "  let _unused_params = @bpacket.transport_params")],
        "missed",
    ),
    (
        "C: host key verification is skipped",
        # One line, and it still compiles. A client that never checks the
        # signature reports Established for V1/V2 and SignatureInvalid for
        # V5/V7 -- the same verdicts as a correct one, because a broken
        # signature and an unchecked one look identical from outside. If the
        # vector set cannot tell those apart, the negative cases are decoration.
        #
        # My first two attempts at this mutation were caught by the compiler
        # rather than by a verdict, which proves nothing about the gate. Both
        # rewrote the `match` into a `let` binding -- and MoonBit rejects a
        # multi-line argument list there even though it accepts one inside
        # `match`. Keep the original statement shape and change one arm.
        [(FLOW,
          "    _ => return Failed(SignatureInvalid)\n  }\n",
          "    _ => ()\n  }\n")],
        "missed",
    ),
    (
        "D: the session_id is not checked against H",
        [(FLOW,
          "  if !kf_bytes_eq(keys.session_id, h) {",
          "  if false && !kf_bytes_eq(keys.session_id, h) {")],
        "missed",
    ),
    (
        "E: a vector's expectation is quietly rewritten",
        [(GEN,
          'ENC, MAC, bytes(range(0x50, 0x60)), False, "", "SignatureInvalid",\n'
          '        "server signs a different exchange hash (substituted Q_S)",',
          'ENC, MAC, bytes(range(0x50, 0x60)), False, "", "Established",\n'
          '        "server signs a different exchange hash (substituted Q_S)",')],
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
    originals = {p: read(p) for p in SNAPSHOT if os.path.exists(p)}
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
            proc = run(["node", os.path.join(ROOT, "host", "verify_loop62.mjs")])
            out = proc.stdout or ""

            if "failed when checking project" in out or (
                proc.returncode != 0 and "ALL PASS" not in out and "  FAIL " not in out
            ):
                print("NOBUILD  %s -- the mutated source did not compile/build" % label)
                print("          NOT EVIDENCE: a mutation caught by the compiler "
                      "proves nothing about the gate.")
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
        drifted = [p for p in originals if read(p) != originals[p]]
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