"""Mutation check: `@cert-authority` must stay a question we cannot answer.

Loop #51's defect is a *silent* one in both directions, so the mutation set is
two halves of the same lie plus one adapter that ignores the answer:

  * **A: the CA entry becomes an ordinary entry again.**  `find_last_direct_match_v2`
    stops excluding `@cert-authority`, which is the fail-open itself -- a peer
    presenting the CA's own public key as its host key gets authenticated. This
    is what the code looked like before Loop #51 and what a one-character
    "simplification" would undo.

  * **B: the CA answer is downgraded to `Unknown`.**  Refusing still happens, so
    a gate that only checked yes/no would call this a pass -- and the user gets
    told to go and find a direct entry that this client can never produce. The
    damage of the false accusation is entirely in the *name*, which is why
    `verify_loop51.mjs` compares leaf names rather than outcomes.

  * **C: `src/wtlive` discards the verdict.**  The rule lives in one place, so
    one adapter can read it and ignore it. The native adapter is left standing on
    purpose: leaving one of the two up is what makes the next mutation say
    something about the other.

A and B both live in `src/knownhosts/check.mbt` because both are decisions about
what a `@cert-authority` line *means*. C is the transport that did not get there
on its own.

**Undo with the snapshot below, never with `git checkout`.**  See
`host/loop48_mutations.py` for the hour that cost. A mutation is never a thing to
undo with git unless it was committed first.

The whole tree is restored before each mutation, not in `finally` alone: A edits
`src/knownhosts/check.mbt` and C edits `src/wtlive/live.mbt`, and without that C
would run on top of A and report the native client failing under a mutation that
never touched it -- an invented dependency edge, and attribution is the entire
product here.

Four verdicts: `NOBUILD` (did not compile -- nothing proven either way), `CRASH`
(compiled and blew up), `CAUGHT` (a named check went FAIL), `MISSED` (ran and
everything still passed).

Run:  python host/loop51_mutations.py
"""

import io
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

FILES = [
    os.path.join(ROOT, "src", "knownhosts", "check.mbt"),
    os.path.join(ROOT, "src", "wtlive", "live.mbt"),
]

GATE = os.path.join(ROOT, "host", "verify_loop51.mjs")

MUTATIONS = [
    (
        "A: a @cert-authority entry is treated as an ordinary trust entry",
        os.path.join(ROOT, "src", "knownhosts", "check.mbt"),
        "    if e.marker != Marker::CertAuthority && entry_matches_spec(e, host_only, port_caller) {",
        "    if entry_matches_spec(e, host_only, port_caller) {",
    ),
    (
        "B: 'pinned via a CA' is reported as 'never pinned'",
        os.path.join(ROOT, "src", "knownhosts", "check.mbt"),
        "      if has_cert_authority_match(entries, host_only, port_caller) {\n        CertAuthority\n      } else {\n        Unknown\n      }",
        "      Unknown",
    ),
    (
        "C: src/wtlive discards the @cert-authority verdict",
        os.path.join(ROOT, "src", "wtlive", "live.mbt"),
        "    Some(@knownhosts.PinFailure::CertAuthority(h)) =>\n      return Failed(HostkeyCertAuthority(h))",
        "    Some(@knownhosts.PinFailure::CertAuthority(h)) => ()",
    ),
]


def read(path):
    with io.open(path, encoding="utf-8") as fh:
        return fh.read()


def write(path, text):
    with io.open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)


def run_gate():
    # `moon clean` every time. Loop #50 lost time to a stale binary that
    # `moon build` reported as "no work to do"; a mutation that fails to show up
    # because nothing was rebuilt reads as MISSED, which points at the gate.
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
    """Failing check labels, in order, deduplicated.

    The gate prints each failure twice -- once inline (indented) and once in its
    closing summary (not indented). Only the summary lines count, so that one
    check which failed once is not reported as two.
    """
    labels = []
    for line in (out or "").split("\n"):
        if line.startswith("FAIL ") and line.strip() not in labels:
            labels.append(line.strip())
    return labels


def main():
    originals = {p: read(p) for p in FILES}
    counts = {"CAUGHT": 0, "MISSED": 0, "NOBUILD": 0, "CRASH": 0}
    try:
        for label, path, frm, to in MUTATIONS:
            for p in FILES:
                write(p, originals[p])

            src = originals[path]
            if frm not in src:
                print("SKIP  %s -- anchor not found in %s" % (label, path))
                counts["NOBUILD"] += 1
                continue
            # An anchor that appears more than once is worse than a missing one:
            # `str.replace` rewrites *every* occurrence, so the mutation silently
            # becomes a different mutation and then reports a confident verdict
            # about it. Loop #52 lost three attempts to exactly this and called it
            # MISSED, which pointed at the gate.
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
                print("MISSED  %s -- the gate still reported ALL PASS" % label)
                counts["MISSED"] += 1
                continue
            fails = fails_for(out)
            if not fails and ("Panic" in out or "harness:" in out):
                print("CRASH  %s -- %s" % (label, out.strip().split("\n")[0][:160]))
                counts["CRASH"] += 1
                continue
            print("CAUGHT  %s" % label)
            for client in ("native", "browser"):
                caught_here = [f for f in fails if f.startswith("FAIL " + client + " ")]
                if caught_here:
                    print("        %-8s %s" % (client + ":", ", ".join(f.split()[2] for f in caught_here)))
            for f in fails:
                print("          " + f[:170])
            counts["CAUGHT"] += 1
    finally:
        for path, text in originals.items():
            write(path, text)
        drifted = [p for p in FILES if read(p) != originals[p]]
        if drifted:
            print("\nWARNING: not restored byte for byte: %s" % ", ".join(drifted))
            return 1

    print(
        "\n%d CAUGHT, %d MISSED, %d NOBUILD, %d CRASH (of %d mutations)"
        % (counts["CAUGHT"], counts["MISSED"], counts["NOBUILD"], counts["CRASH"], len(MUTATIONS))
    )
    with io.open(os.path.join(ROOT, ".loop51", "mutations.json"), "w", encoding="utf-8") as fh:
        json.dump(counts, fh, indent=2)
    return 0 if counts["MISSED"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
