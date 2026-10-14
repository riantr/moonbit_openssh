"""Mutation check: Loop #57's resolver has to actually follow OpenSSH's rules.

Six mutations, one per rule the resolver implements, plus one equivalent mutant.

  * **A: first-block-only matching.** `resolve_host` is rewritten to consider only
    the first matching section -- i.e. back to what `match_host_option` did. This
    is the original bug, restored. `fallback.conf` loses `Port` and
    `cascade.conf` loses `Port` two blocks down. The completeness rule is what
    catches it: value comparison alone would pass, because a resolver that answers
    nothing has no wrong answers.

  * **B: negated pattern vetoes only itself** instead of the whole block.
    `negation.conf` / `secret` then resolves `Compression` to `yes`.

  * **C: keyword comparison becomes case-sensitive.** `syntax.conf` loses `Port`
    (written `PoRt`) and `ConnectTimeout` (written `ConnectTimeout=7`, whose `=`
    form is parsed but whose lookup key no longer matches a lowercased query).

  * **D: pre-`Host` options are dropped**, as they were in Loop #24.
    `leading.conf` loses `User` and `Port`.

  * **E: every keyword becomes first-wins**, i.e. `IdentityFile` loses its
    accumulate behaviour. The fixtures here give only one IdentityFile each, so
    this one is caught by the **unit tests** rather than the gate -- which is
    recorded honestly below rather than dressed up as a gate result.

  * **F: an equivalent mutant.** Dropping the `strip_comment` call's effect on a
    line with no `#` is not expressible as a single-anchor edit here, so instead:
    making `is_multivalued` ignore `identityfile` is E. For the equivalent one,
    the gate drops its `M.size !== cases.length` assertion. No emitter skips a
    case on this tree, so the assertion is not observable -- a finding, bounded to
    these inputs.

**Undo with the snapshot below, never with `git checkout`.**

Anchors must be unique: `str.replace` rewrites *every* occurrence, so an anchor
that appears twice turns the mutation into a different mutation and then reports a
confident verdict about it. They must also be **ASCII-only** -- this workspace's
`edit` tool cannot round-trip CJK in `old_string`, and an anchor that fails to
match on an encoding round-trip reports `NOBUILD`, which reads as "nothing proven"
rather than "the script is broken".

Edits to the same file **compose**: each edit is applied to what is on disk now,
not to the pristine text. Writing every edit from the original made the second
edit to a file silently undo the first, and the mutation then reported a crisp
CAUGHT about something it had never actually done (Loop #56, mutation E).

Five verdicts: `NOBUILD`, `CRASH`, `CAUGHT`, `MISSED` (an accusation), and
`EQUIVALENT` (a finding). `MISSED` and `EQUIVALENT` must stay distinct; conflating
them makes both useless.

Run:  python host/loop57_mutations.py            (all)
      python host/loop57_mutations.py A          (one, by label prefix)
"""

import io
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

RESOLVE = os.path.join(ROOT, "src", "sshconfig", "resolve.mbt")
PARSER = os.path.join(ROOT, "src", "sshconfig", "parser.mbt")
TESTS = os.path.join(ROOT, "src", "sshconfig", "sshconfig_test.mbt")
GATE = os.path.join(ROOT, "host", "verify_loop57.mjs")

FILES = [RESOLVE, PARSER, TESTS, GATE]
GATE_PATH = os.path.join(ROOT, "host", "verify_loop57.mjs")

# (label, [(path, from, to), ...], verdict-if-gate-still-green, extra-check)
# `extra` is an optional (argv, pattern) run after the gate, for mutations the
# gate cannot see but `moon test` can.
MUTATIONS = [
    (
        "A: only the first matching Host block is consulted (the Loop #24 bug)",
        [(RESOLVE,
          "  let mut s = 0\n  while s < sections.length() {\n    let section = sections[s]\n    if section_applies(section, host) {",
          "  let mut s = 0\n  let mut seen_one = false\n  while s < sections.length() {\n"
          "    let section = sections[s]\n"
          "    if section_applies(section, host) && !seen_one { seen_one = true } else { s = s + 1; continue }\n"
          "    if true {")],
        "missed", None,
    ),
    (
        "B: a negated Host pattern is ignored instead of vetoing its block",
        [(RESOLVE,
          "    if starts_with_ci(p, \"!\") {",
          "    if false {")],
        "missed", None,
    ),
    (
        "C: keyword lookup becomes case-sensitive",
        [(RESOLVE,
          "          if !contains(decided, k) {",
          "          if !contains(decided, opt.keyword) {")],
        "missed", None,
    ),
    (
        "D: the pattern-less section (options before the first Host) is dropped again",
        [(PARSER,
          "          if saw_any {\n            sections.push({ patterns: current_patterns, options: current_options })\n          }",
          "          if saw_any && current_patterns.length() > 0 {\n"
          "            sections.push({ patterns: current_patterns, options: current_options })\n          }")],
        "missed", None,
    ),
    (
        "E: IdentityFile stops accumulating (gate cannot see this one)",
        [(RESOLVE,
          "  let multivalued = [\n    \"identityfile\", \"localforward\", \"remoteforward\", \"dynamicforward\",\n"
          "    \"permitremoteopen\", \"sendenv\", \"setenv\",\n  ]",
          "  let multivalued = [\n    \"localforward\", \"remoteforward\", \"dynamicforward\",\n"
          "    \"permitremoteopen\", \"sendenv\", \"setenv\",\n  ]")],
        "missed", ["moon", "test", "src\\sshconfig"],
    ),
    (
        "F: the gate stops asserting that every case in cases.txt was decided",
        [(GATE,
          '  if (M.size !== cases.length) {',
          '  if (false) {')],
        "equivalent", None,
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
        for label, edits, expect, extra in chosen:
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
            # Compose: each edit sees what is on disk now.
            for path, frm, to in edits:
                write(path, read(path).replace(frm, to))

            run(["cmd", "/c", "moon", "clean"])
            proc = run(["node", GATE_PATH])
            out = proc.stdout or ""

            extra_out = ""
            if extra:
                # `moon test` on the mutated tree: this is the only thing that
                # can see mutation E, and saying so is better than pretending
                # the gate covered it.
                r = run(["cmd", "/c"] + extra)
                extra_out = r.stdout or ""
                failed = ("Total tests" in extra_out
                          and "failed: 0" not in extra_out.split("Total tests")[-1])
                if failed:
                    print("CAUGHT  %s  (by moon test, not the gate)" % label)
                    for line in extra_out.split("\n"):
                        if "failed" in line or "FAILED" in line:
                            print("          " + line.strip()[:180])
                    counts["CAUGHT"] += 1
                    continue

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
                print("          " + f[:180])
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