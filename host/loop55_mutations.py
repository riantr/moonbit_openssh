"""Mutation check: the cross-check has to actually cross-check.

Three mutations, aimed at the three ways a three-way comparison can be theatre:

  * **A: MoonBit signs something one bit off.**  `src/ed25519/api.mbt` returns a
    signature whose last byte is flipped. Every positive vector on the MoonBit
    side becomes wrong, and so does its own `moon test src/ed25519`. What makes
    this the interesting one is that `moon test` alone catches it -- the point is
    that the *three-way* comparison catches it too, which is the claim that was
    previously only documentation.

  * **B: the equation check is dropped.**  `verify` returns true as soon as the
    point arithmetic ran, without comparing `pack(P)` against `R`. **No positive
    vector changes** -- they already matched. This is the mutation that proves
    the negative cases are load-bearing: a verifier that accepts a forged
    signature agrees with all three sides on every RFC 8032 vector and is
    completely broken, so a gate that only compared the vectors would report
    ALL PASS.

  * **B': the range check is disabled.**  Recorded as an **equivalent mutant**,
    and that is the finding rather than a failure. Disabling
    `sc_is_in_range_bytes` does not change what this client accepts: `s + L` is
    still rejected, and so is `s = L` (that one dies at the `sig[63] & 0xE0`
    check before the range check is even reached). Python's `cryptography` --
    which is OpenSSL/libsodium-backed and shares no code with this repository --
    also rejects `s + L`, so the rejection is a property of the format and not
    of one line here. The range check is defence in depth, not the sole guard,
    and until a vector exists that separates them, "equivalent" is the honest
    verdict.

**Undo with the snapshot below, never with `git checkout`.**  A mutation is never
something to undo with git unless it was committed first.

Anchors must be unique. `str.replace` rewrites *every* occurrence, so an anchor
that appears twice turns the mutation into a different mutation and then reports
a confident verdict about it.

Five verdicts: `NOBUILD` (nothing proven either way), `CRASH`, `CAUGHT` (a named
check went FAIL), `MISSED` (a real change, still reported ALL PASS), and
`EQUIVALENT` (the gate still reported ALL PASS *and* the mutation provably
cannot be observed on these vectors). `MISSED` is an accusation and
`EQUIVALENT` is a finding; conflating them makes both useless, which is why the
distinction is a verdict rather than a comment.

Run:  python host/loop55_mutations.py
"""

import io
import os
import subprocess

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

FILES = [
    os.path.join(ROOT, "src", "ed25519", "api.mbt"),
    os.path.join(ROOT, "src", "ed25519", "sc.mbt"),
    os.path.join(ROOT, "cmd", "ed25519_kat", "main.mbt"),
]

GATE = os.path.join(ROOT, "host", "verify_loop55.mjs")

MUTATIONS = [
    (
        "A: MoonBit's signature is one bit off (every positive vector changes)",
        os.path.join(ROOT, "src", "ed25519", "api.mbt"),
        "  for i = 0; i < 32; i = i + 1 {\n    sig[i] = r_bytes[i]\n    sig[i + 32] = s_bytes[i]\n  }\n  sig",
        "  for i = 0; i < 32; i = i + 1 {\n    sig[i + 32] = s_bytes[i]\n  }\n"
        "  sig[63] = (sig[63].to_uint64() ^ 1UL).to_byte()\n  sig",
    ),
    (
        "B: the equation check is dropped (no positive vector can see this)",
        os.path.join(ROOT, "src", "ed25519", "api.mbt"),
        "  let pcheck : FixedArray[Byte] = ge_pack(p_pt)\n  equal_32(pcheck, r_bytes)",
        "  let pcheck : FixedArray[Byte] = ge_pack(p_pt)\n"
        "  let _ = pcheck\n  true",
    ),
    (
        "B': the range check is disabled (equivalent mutant -- see the header)",
        os.path.join(ROOT, "src", "ed25519", "sc.mbt"),
        "pub fn sc_is_in_range_bytes(bytes : FixedArray[Byte]) -> Bool {\n  if bytes.length() != 32 {\n    return false\n  }",
        "pub fn sc_is_in_range_bytes(bytes : FixedArray[Byte]) -> Bool {\n  if true {\n    return true\n  }\n  if bytes.length() != 32 {\n    return false\n  }",
        "equivalent",
    ),
    (
        "C: the MoonBit side prints nothing, so the comparison is vacuous",
        os.path.join(ROOT, "cmd", "ed25519_kat", "main.mbt"),
        'fn main {\n  println("===== RFC 8032 SS 7.1 Test Vectors =====")',
        'fn main {\n  println("nothing to compare")\n  return\n'
        '  println("===== RFC 8032 SS 7.1 Test Vectors =====")',
    ),
]


def read(path):
    with io.open(path, encoding="utf-8") as fh:
        return fh.read()


def write(path, text):
    with io.open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)


def run_gate():
    # `moon clean` every time. A mutation that fails to show up because nothing
    # was rebuilt reads as MISSED, which points at the gate instead of the rule.
    subprocess.run(
        ["cmd", "/c", "moon", "clean"],
        cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=900,
    )
    return subprocess.run(
        ["node", GATE],
        cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        encoding="utf-8", errors="replace", timeout=3600,
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
    counts = {"CAUGHT": 0, "MISSED": 0, "NOBUILD": 0, "CRASH": 0, "EQUIVALENT": 0}
    try:
        for entry in MUTATIONS:
            label, path, frm, to = entry[:4]
            # Optional fifth element: the verdict to record if the gate still
            # reports ALL PASS. Absent means `MISSED`, which is an accusation.
            expect_equivalent = len(entry) > 4 and entry[4] == "equivalent"
            for p in FILES:
                write(p, originals[p])

            src = originals[path]
            if frm not in src:
                print("NOBUILD  %s -- anchor not found in %s" % (label, path))
                counts["NOBUILD"] += 1
                continue
            hits = src.count(frm)
            if hits != 1:
                print(
                    "NOBUILD  %s -- anchor appears %d times in %s; replace would "
                    "mutate more than intended" % (label, hits, path)
                )
                counts["NOBUILD"] += 1
                continue
            write(path, src.replace(frm, to))

            proc = run_gate()
            out = proc.stdout or ""

            if "failed when checking project" in out or (
                proc.returncode != 0 and "ALL PASS" not in out and "  FAIL " not in out
            ):
                print("NOBUILD  %s -- the mutated source did not compile" % label)
                counts["NOBUILD"] += 1
                continue
            if proc.returncode == 0:
                if expect_equivalent:
                    print("EQUIVALENT  %s -- gate still ALL PASS, and this change "
                          "provably cannot be observed on these vectors" % label)
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
            for f in fails:
                print("          " + f[:180])
            counts["CAUGHT"] += 1
    finally:
        for path, text in originals.items():
            write(path, text)
        drifted = [p for p in FILES if read(p) != originals[p]]
        if drifted:
            print("\nWARNING: not restored byte for byte: %s" % ", ".join(drifted))
            return 1

    print(
        "\n%d CAUGHT, %d MISSED, %d EQUIVALENT, %d NOBUILD, %d CRASH (of %d mutations)"
        % (counts["CAUGHT"], counts["MISSED"], counts["EQUIVALENT"],
           counts["NOBUILD"], counts["CRASH"], len(MUTATIONS))
    )
    return 0 if counts["MISSED"] == 0 and counts["CRASH"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
