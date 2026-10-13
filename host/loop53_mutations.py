"""Mutation check: host certificates must be a trust anchor that works, and only
that.

Three mutations, each aimed at one of the three ways this can quietly stop
working. They are deliberately spread across the layers, because a mutation set
that only touches one file proves only that one file is load-bearing:

  * **A: certificates are never trusted.**  `verify_cert` reports every certificate
    as rejected. This is Loop #51's behaviour re-introduced under a new name: the
    CA deployment is unusable again, and the gate's one authenticating case
    (`ca-signed-ok`) is the only thing standing between "works" and "silently
    refuses everything".

  * **B: the validity window is not checked.**  `expired` becomes `trusted`. The
    interesting part is that this is a *fail-open*, not a wrong message: an
    expired certificate is still a certificate anyone can replay forever, so
    removing the window check turns a pinned anchor into a permanent one.

  * **C: an untrusted certificate becomes `None`.**  `decide` stops reporting
    `CertUntrusted`. Everything else still works, the refusals are still refusals,
    and the peer that triggered it presented a *validly signed* certificate -- so
    the only observable difference is that a man in the middle with their own CA
    gets credentials. This is the one that most looks like a pass.

**Undo with the snapshot below, never with `git checkout`.**  A mutation is never
something to undo with git unless it was committed first.

The whole tree is restored before each mutation, not in `finally` alone: A and C
edit different files, and without that C would run on top of A and report the
native client failing under a mutation that never touched it. Attribution is the
entire product here.

Anchors must be unique. `str.replace` rewrites *every* occurrence, so an anchor
that appears twice turns the mutation into a different mutation and then reports
a confident verdict about it.

Four verdicts: `NOBUILD` (nothing proven either way), `CRASH`, `CAUGHT` (a named
check went FAIL), `MISSED` (everything still passed).

Run:  python host/loop53_mutations.py
"""

import io
import os
import subprocess

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

FILES = [
    os.path.join(ROOT, "src", "knownhosts", "policy.mbt"),
    os.path.join(ROOT, "src", "hostkey", "cert_verify.mbt"),
]

GATE = os.path.join(ROOT, "host", "verify_loop53.mjs")

MUTATIONS = [
    (
        "A: certificates are never trusted (Loop #51's behaviour under a new name)",
        os.path.join(ROOT, "src", "knownhosts", "policy.mbt"),
        "    Trusted => Accept",
        '    Trusted => CaRejected("untrusted")',
    ),
    (
        "B: the validity window is not checked (a pinned anchor becomes permanent)",
        os.path.join(ROOT, "src", "hostkey", "cert_verify.mbt"),
        "  if now > cert.valid_before {\n    return CertVerdict::Rejected(Expired)\n  }",
        "  if false {\n    return CertVerdict::Rejected(Expired)\n  }",
    ),
    (
        "C: an untrusted certificate is reported as acceptable",
        os.path.join(ROOT, "src", "knownhosts", "policy.mbt"),
        "    CertUntrusted(host) => Some(CertUntrusted(host))",
        "    CertUntrusted(host) => None",
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
        encoding="utf-8", errors="replace", timeout=7200,
    )


def fails_for(out):
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
                    print("        %-8s %s" % (
                        client + ":", ", ".join(f.split()[2] for f in caught_here)))
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
    return 0 if counts["MISSED"] == 0 and counts["CRASH"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())