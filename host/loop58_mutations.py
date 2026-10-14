"""Mutation check: Loop #58's wiring has to actually apply OpenSSH's precedence.

Five mutations. Each one is a rule this loop introduced, so none of them is
Loop #57's resolver again -- that is already covered by `loop57_mutations.py`,
and re-testing it here would produce five CAUGHT lines that say nothing about
whether the client reads the resolver at all.

  * **A: `-o` loses to the config file.** Precedence inverted for the middle step
    of the chain. The override cases' `user` / `port` / `hostname` go wrong.

  * **B: `--config` is ignored.** `cfg_resolve` takes the no-config path
    unconditionally. Nothing else in the client can see this, and the value rule
    passes vacuously -- a client that resolves nothing has no wrong answers. Only
    the completeness rule catches it.

  * **C: `-o IdentityFile` replaces the file's list** instead of being obtained
    first and prepended. `IdentityFile` accumulates in OpenSSH, so this looks
    plausible and is wrong. A set comparison would not see it; the gate compares
    the ordered `|`-joined list.

  * **D: `--user` loses to `-o`.** The top of the chain. `ssh -G` has no
    `--user`, so this is asserted against the client's own rule -- which is why
    that assertion exists at all.

  * **E: an equivalent mutant.** The gate stops asserting that a run without
    `--config` resolves and invents nothing. The client does behave that way, so
    on this tree the assertion cannot be observed. A finding, bounded to these
    inputs.

**Undo with the snapshot below, never with `git checkout`.**

Anchors must be unique and **ASCII-only**: `str.replace` rewrites every
occurrence, and this workspace's `edit` tool cannot round-trip CJK in
`old_string`, so an anchor that fails on an encoding round-trip reports
`NOBUILD` -- which reads as "nothing proven" rather than "the script is broken".

Edits to the same file **compose**: each is applied to what is on disk now, not
to the pristine text. Writing every edit from the original let the second edit to
a file silently undo the first, and the mutation then reported a crisp CAUGHT
about something it never did (Loop #56, mutation E).

Run:  python host/loop58_mutations.py          (all)
      python host/loop58_mutations.py A        (one, by label prefix)
"""

import io
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

LIVE = os.path.join(ROOT, "cmd", "ssh_live", "main.mbt")
GATE = os.path.join(ROOT, "host", "verify_loop58.mjs")
FILES = [LIVE, GATE]

MUTATIONS = [
    (
        "A: -o loses to the config file (precedence inverted)",
        [(LIVE,
          "  let hostname = if hostname != \"\" { hostname } else { @sshconfig.resolved_value(target, sections, \"HostName\") }",
          "  let hostname = { @sshconfig.resolved_value(target, sections, \"HostName\") }\n"
          "  let hostname = if hostname.length() > 0 { hostname } else { hostname0 }"),
         (LIVE,
          "  let user = if user != \"\" { user } else { @sshconfig.resolved_value(target, sections, \"User\") }",
          "  let user = { @sshconfig.resolved_value(target, sections, \"User\") }\n"
          "  let user = if user.length() > 0 { user } else { user0 }"),
         (LIVE,
          "  let port = if port != \"\" { port } else { @sshconfig.resolved_value(target, sections, \"Port\") }",
          "  let port = { @sshconfig.resolved_value(target, sections, \"Port\") }\n"
          "  let port = if port.length() > 0 { port } else { port0 }"),
         (LIVE,
          "  let hostname = o_lookup(overrides, \"hostname\")",
          "  let hostname0 = o_lookup(overrides, \"hostname\")\n  let hostname = hostname0"),
         (LIVE,
          "  let port = o_lookup(overrides, \"port\")",
          "  let port0 = o_lookup(overrides, \"port\")\n  let port = port0"),
         (LIVE,
          "  let user = if explicit_user != \"<no-user-given>\" {\n    explicit_user\n  } else {\n    o_user\n  }",
          "  let user0 = if explicit_user != \"<no-user-given>\" {\n    explicit_user\n  } else {\n    o_user\n  }\n  let user = user0")],
        "missed",
    ),
    (
        "B: --config is ignored entirely (the no-config path always taken)",
        [(LIVE,
          "  let text = try { (@fs.read_file(path)).text() } catch { _ => abort(\"cannot read config \" + path) }",
          "  let text = \"\"")],
        "missed",
    ),
    (
        "C: -o IdentityFile is appended last instead of obtained first",
        # Move the push to after the file's values. Same set, wrong order --
        # which a set comparison would not see and which is the whole point of
        # comparing the `|`-joined list rather than membership.
        [(LIVE,
          "    ids.push(o_id)\n    let mut i = 0\n    while i < file_ids.length() {\n      ids.push(file_ids[i])\n      i = i + 1\n    }\n  } else {",
          "    let mut i = 0\n    while i < file_ids.length() {\n      ids.push(file_ids[i])\n      i = i + 1\n    }\n    ids.push(o_id)\n  } else {")],
        "missed",
    ),
    (
        "D: --user loses to -o (top of the precedence chain)",
        [(LIVE,
          "  let user = if explicit_user != \"<no-user-given>\" {\n    explicit_user\n  } else {\n    o_user\n  }",
          "  let user = if o_user != \"\" {\n    o_user\n  } else if explicit_user != \"<no-user-given>\" {\n    explicit_user\n  } else {\n    \"\"\n  }")],
        "missed",
    ),
    (
        "F: the gate stops asserting that a run without --config invents nothing",
        [(GATE,
          '  if (bareMap.get("config") === "(none)" && leaked.length === 0) {',
          '  if (true) {')],
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
            proc = run(["node", os.path.join(ROOT, "host", "verify_loop58.mjs")])
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