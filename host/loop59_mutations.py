"""Mutation check: Loop #59's end-to-end wiring has to actually dial and pin.

Four mutations, each one a claim this loop makes for the first time.

  * **A: the known_hosts pin is keyed by the resolved `HostName`** instead of the
    alias the user typed. This is the one that would have been invisible: the
    connection still succeeds, the write-back still reports success, and the
    *next* connection by alias simply finds nothing and does TOFU again. Forever,
    silently. OpenSSH's `write_host_entry(f, host, NULL, ...)` passes `ip = NULL`
    (hostfile.c:476), so `HostName` never enters the key.

  * **B: the port from the config is ignored.** The client falls back to
    `find_port`, which finds nothing in Loop #59's step 1 and returns the 22222
    default. Nothing is listening there, so the connection fails.

  * **C: the user from the config is ignored** in `main` -- the pre-Loop-59 shape
    for `run_exec` / `run_shell`, which each re-parsed argv on their own and so
    never saw a config-resolved user. Step 1 asserts the user the client
    *reported*; the peer accepts any username, so that is the only part of it
    that is ours to get wrong.

  * **D: an equivalent mutant.** Dropping the `--proposal` assertion. The
    proposal is unaffected by this loop and already unchanged, so the assertion
    is not observable here. A finding, bounded to these inputs.

**What this gate does NOT claim, stated so nobody infers it.** Step 1's config
sets `HostName 127.0.0.1`, and the client hardcodes `127.0.0.1` as its fallback,
so step 1 cannot distinguish "dialed the configured host" from "dialed the
default host". The *port* is what proves the config drove the dial -- it is
absent from argv entirely. The host half is covered elsewhere: `--config-effective`
diffs it against `ssh -G` (Loop #58), and the alias-keying rule above is covered
by A. Inventing a hostname that resolves differently from 127.0.0.1 would have
made the check look stronger than it is.

**Undo with the snapshot below, never with `git checkout`.**

Anchors must be unique and **ASCII-only**: `str.replace` rewrites every
occurrence, and this workspace's `edit` tool cannot round-trip CJK in
`old_string`, so an anchor that fails on an encoding round-trip reports
`NOBUILD` -- which reads as "nothing proven" rather than "the script is broken".

Edits to the same file **compose**: each is applied to what is on disk now, not
to the pristine text (Loop #56's mutation E).

Run:  python host/loop59_mutations.py          (all)
      python host/loop59_mutations.py A        (one, by label prefix)
"""

import io
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

LIVE = os.path.join(ROOT, "cmd", "ssh_live", "main.mbt")
GATE = os.path.join(ROOT, "host", "verify_loop59.mjs")
FILES = [LIVE, GATE]

MUTATIONS = [
    (
        "A: the known_hosts pin is keyed by the resolved HostName",
        # The fixture's `HostName` is 127.0.0.1, so keying by the resolved name is
        # exactly "always 127.0.0.1" here. No helper needed, and the mutation
        # stays a one-line change that compiles -- a mutation caught by a broken
        # build is not evidence.
        [(LIVE,
          "    if target == \"\" { \"127.0.0.1\" } else { target }",
          "    if target == \"\" { \"127.0.0.1\" } else { \"127.0.0.1\" }")],
        "missed",
    ),
    (
        "B: the port from the config is ignored",
        [(LIVE,
          "  let port = if cfg.port != \"\" {\n    match parse_port(cfg.port, 0) {\n      0 => find_port(argv)\n      p => p\n    }\n  } else {\n    find_port(argv)\n  }",
          "  let port = find_port(argv)")],
        "missed",
    ),
    (
        "C: the user from the config is ignored (the pre-Loop-59 re-parse)",
        [(LIVE,
          "  let user = if cfg.user != \"\" { cfg.user } else { find_user(argv) }",
          "  let user = find_user(argv)")],
        "missed",
    ),
    (
        "D: the gate stops asserting --proposal is unchanged",
        [(GATE,
          '    if (prop.includes("kex_algs: diffie-hellman-group14-sha256") && prop.includes("enc_ctos: aes128-ctr")) {',
          '    if (true) {')],
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
            proc = run(["node", os.path.join(ROOT, "host", "verify_loop59.mjs")])
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