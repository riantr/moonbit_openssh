#!/usr/bin/env python3
"""Collect `moon check --deny-warn` diagnostics as structured JSON.

Three schema facts were established by inspection, and each one contradicts what
a regex-over-the-box-drawing approach assumes:

  * `--output-json` emits **NDJSON** -- one self-contained JSON object per line,
    each with `$message_type: "diagnostic"`. `json.loads` on the whole buffer
    fails with "Extra data".
  * There is no `kind` field. The warning class lives inside `message` as
    `Error Warning (<kind>): ...`. `loc` is a `"<line>:<col>-<line>:<col>"`
    string, not an object.
  * A package that fails to *compile* does not report its warnings. Loop #66 hit
    this: deleting `moonbitlang/async` from `src/khfile/moon.pkg` produced eight
    hard errors, and the `test_unqualified_package` warnings that came with them
    were cascade noise from a broken `async test` expansion -- not a property of
    the file. `collect()` therefore records the exit status per package so a
    failed check can never be read as a clean one.

Two earlier versions of this file were wrong in ways that hid real findings:

  * One parsed the human box-drawing output and reported 87 sites across 10
    files when the real figure is 76 across 8.
  * One called `moon check --output-json` with no path, which checks ONE
    package rather than the module, and reported the result as a repository-wide
    total. Three runs all said "7 files, 59 diagnostics" and looked stable, when
    each run had simply visited a different subset.

A third flaw was latent: results were keyed `path -> {line: kind}`, so two
warnings on one line silently collapsed into one. Sites are now a list.

Usage:
  python host/collect_warnings.py [--kind <warning_kind>] [--quiet]

Prints {"<relpath>": {"<line>": ["<kind>", ...]}} on stdout.
"""
import io
import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KIND_RE = re.compile(r"Warning \(([a-z_0-9]+)\)")
LOC_RE = re.compile(r"^(\d+):")

# `cmd /c` so a `.cmd`/`.bat` shim on PATH resolves the same way it does in an
# interactive shell. `subprocess` with a bare name does not search PATHEXT.
MOON = ["cmd", "/c", "moon"]


TARGETS = ("native", "js", "wasm", "wasm-gc")

# Warnings that are real but must stay, each with the evidence that established
# it. This is deliberately not a suppression list: `main()` reports them, and
# `verify_loop66` asserts that the reported set is *exactly* this table, so a
# new entry fails the gate and so does a stale one.
#
# The `unused_package` intersection below already removes the per-target-gated
# false positives. What is left here is the case the intersection cannot catch:
# an import whose consumer is a compiler expansion rather than any source text.
KNOWN_ACCEPTED = {
    ("src/khfile/moon.pkg", "13"): (
        "unused_package: `moonbitlang/async` is consumed by the compiler's "
        "`async test` expansion, which emits a call to "
        "`@moonbitlang/async.run_async_main`. The consumer is generated code, "
        "so no source line references the package and the unused-import "
        "analysis finds nothing. Loop #66 deleted the line and measured the "
        "result: 8 hard errors, one per `async test` block, reproducing the "
        "exact message the package comment predicted.\n"
        "NOT the same as `src/wtlive`, which Loop #67 measured separately: it "
        "has `async fn` but no `async test`, and removing the import there "
        "leaves `moon check --target js` and `moon build cmd/wt_ssh --target "
        "js` both green. Same warning, opposite verdict -- which is why the "
        "table is per-site evidence rather than a per-package rule."
    ),
    ("cmd/proton_gui/main.mbt", "101"): (
        "unused_async: `CommandRegistrar::bind` declares its handler type as "
        "`async fn`, so a handler is async whether or not its body awaits. "
        "`main.mbt:69` says so in the source: 'Every handler is `async` because "
        "`CommandRegistrar::bind` says ... dropping it would leave a handler "
        "whose *declared* type no longer says' what it is. The warning is about "
        "the body, the requirement is about the type."
    ),
    ("cmd/proton_gui/main.mbt", "114"): (
        "unused_async: same CommandRegistrar::bind signature requirement."
    ),
    ("cmd/proton_gui/main.mbt", "120"): (
        "unused_async: same CommandRegistrar::bind signature requirement."
    ),
}


def collect_one(path, target=None):
    """Return (diagnostics, ok) for one package. `ok` is False on a failed check."""
    cmd = MOON + ["check", path, "--deny-warn", "--output-json",
                  "--diagnostic-limit", "10000"]
    if target:
        cmd += ["--target", target]
    proc = subprocess.run(
        cmd,
        cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    raw = proc.stdout.decode("utf-8", "replace")
    docs = _parse(raw)
    # `--deny-warn` exits nonzero when it *finds* warnings, which is the normal
    # case here. What distinguishes "warned" from "failed to build" is whether
    # any diagnostic is a hard Error rather than a `Warning (...)` one.
    failed = any(_is_hard_error(d) for d in docs)
    return docs, (not failed)


def _is_hard_error(doc):
    """True for a diagnostic that is a build error rather than a warning.

    `level` cannot be used: under `--deny-warn` the toolchain reports warnings
    with `"level": "error"` as well. Nor can a prefix test on the message --
    Loop #67 found that `moon check cmd/wt_ssh --target js` reports

        The type @openssh/openssh_moonbit/src/wtlive.WtAuthReport has no field
        auth_method.

    with no "Error" prefix at all, and an earlier version of this function
    required one. It therefore called a package that does not compile "clean",
    which is the single worst thing this file can do: the Loop #66 fixpoint was
    measured with that bug in place, so "3 remaining warnings" was a statement
    about packages that happened to build.

    The discriminator is the message shape. Every compiler warning carries
    `Warning (<kind>):`; nothing else does.
    """
    msg = doc.get("message", "")
    if not msg:
        return False
    return not KIND_RE.search(msg)


def _sites(docs, kind):
    """{(relpath, line)} for one warning kind.

    `moon check` repeats the same diagnostic once per backend it builds, so a
    raw document list is not a site list. Keying by (path, line) collapses that
    back to one entry per place in the source.
    """
    out = set()
    for d in docs:
        m = KIND_RE.search(d.get("message", ""))
        if not m or m.group(1) != kind:
            continue
        loc = LOC_RE.match(d.get("loc", ""))
        if not loc:
            continue
        path = d.get("path", "")
        if path.startswith(ROOT):
            path = os.path.relpath(path, ROOT)
        out.add((path, loc.group(1)))
    return out


def unused_package_all_targets(path):
    """`unused_package` sites that fire on **every** target.

    A `moon.pkg` may gate files per target:

        options(targets: { "socket_js.mbt": [ "js" ], ... })

    When the files that use an import are gated away, the import is left with no
    textual reference and the compiler calls it unused -- even though the package
    is correct and the import is required the moment that target is built.
    Measured in Loop #66: `src/wt`, `src/khstore`, `src/khfile`,
    `cmd/wt_probe` and `cmd/knownhosts_kat` each report imports as unused on
    every target *except* the one they gate for, where they report nothing.

    So the honest test is the intersection across all four targets rather than
    the single default-target report. This is derived, not an allowlist: a
    genuinely dead import still fires everywhere, which is exactly how
    `src/tcp`'s `moonbitlang/core/bytes` was found and removed -- while
    `src/khfile`'s `moonbitlang/async`, whose absence produces eight hard
    errors, is correctly kept.

    Returns None when no target built, since a package that does not compile
    anywhere cannot contribute evidence either way. Targets the package does
    not declare are skipped rather than treated as clean -- see
    `evidence_targets`, which explains why silence is not evidence.
    """
    per_target = []
    for t in evidence_targets(path):
        docs, ok = collect_one(path, target=t)
        if not ok:
            continue
        per_target.append(_sites(docs, "unused_package"))
    common = set(per_target[0])
    for s in per_target[1:]:
        common &= set(s)
    return common


_TARGET_NAMES_RE = re.compile(r"\"([a-z][a-z0-9-]*)\"")


def _targets_in(text, key):
    """Target names listed in `key: { ... }` or `key: "+a, +b"`.

    The split is line-anchored because `targets:` is a substring of
    `supported_targets:`, and splitting on the bare key would read the wrong
    option on any package that carries both.
    """
    m = re.search(r"(?m)^\s*%s\s*:" % re.escape(key), text)
    if not m:
        return None
    tail = text[m.end():]
    names = set()
    # `targets: { "file.mbt": [ "js", "wasm" ] }` -- collect every quoted name
    # inside every bracket. File names have a dot and a target name never does,
    # so the character class separates them without a special case.
    for arr in re.finditer(r"\[\s*([^\]]*)\]", tail):
        for q in _TARGET_NAMES_RE.finditer(arr.group(1)):
            names.add(q.group(1))
    # `supported_targets: "+native"` -- the names carry a leading plus.
    if not names:
        for q in re.finditer(r"\+\s*\"?([a-z][a-z0-9-]*)\"?", tail.split("\n", 1)[0]):
            names.add(q.group(1))
    return names or None


def declared_targets(pkg):
    """Targets from the per-file `targets:` option, or None.

    This matters more than it looks. Loop #67 measured the case: `src/wtlive`
    gates both of its files to js, so on native it builds with **zero active
    files** and reports nothing at all. Intersecting `unused_package` across all
    four targets therefore intersects with an empty set on three of them, and
    the intersection is empty -- so a genuinely stray import in `src/wtlive` was
    classified as a false positive and filtered out of the report. The gate's
    own mutation M9 confirmed it: the tree carried the defect and the gate
    passed.

    **A target where a package has no files is silence, not evidence.** Only
    targets the package declares are evidence.
    """
    p = os.path.join(ROOT, pkg, "moon.pkg")
    if not os.path.exists(p):
        return None
    try:
        with io.open(p, encoding="utf-8") as fh:
            return _targets_in(fh.read(), "targets")
    except OSError:
        return None


def supported_targets(pkg):
    """Targets from `supported_targets: "+native"`, or None.

    `cmd/proton_gui` is the case that made this necessary. It is native-only,
    and bare `moon check` -- which has **no default target equal to native**,
    measured, not assumed -- reports nothing for it at all. A collector that
    consulted the default would have declared the package clean and lost its
    three `unused_async` warnings silently.
    """
    p = os.path.join(ROOT, pkg, "moon.pkg")
    if not os.path.exists(p):
        return None
    try:
        with io.open(p, encoding="utf-8") as fh:
            return _targets_in(fh.read(), "supported_targets")
    except OSError:
        return None


def is_target_gated(pkg):
    """True when the package's moon.pkg narrows the targets it supports.

    Such a package is not supposed to build everywhere: `cmd/wt_probe` declares
    `pkgtype(kind: "executable")` with `targets: { "main.mbt": ["js"] }`, so a
    default-target check can fail with [4067] "Missing main function" on a
    package that is perfectly correct. Treating that as "the package is broken"
    is the same class of mistake as judging an import dead on one target -- the
    Loop #66 lesson, one level up.
    """
    return declared_targets(pkg) is not None or supported_targets(pkg) is not None


def evidence_targets(pkg):
    """The targets whose diagnostics count as evidence for this package.

    Declared ones if the package declares any; otherwise all four, because bare
    `moon check` does not default to native and a package that only builds on
    one target would otherwise be reported as clean.
    """
    d = declared_targets(pkg) or supported_targets(pkg)
    if not d:
        return TARGETS
    ordered = [t for t in TARGETS if t in d]
    return tuple(ordered) or TARGETS


def collect_package(pkg):
    """Check one package on the targets it can actually build for.

    Returns (diagnostics, ok). `ok` is True when the package built on at least
    one target. Diagnostics are gathered only from targets that built, because a
    target that failed produces cascade noise -- `cmd/wt_ssh` once reported a
    wall of `test_unqualified_package` purely because its `async test` expansion
    had failed on a missing import.
    """
    targets = evidence_targets(pkg)
    docs = []
    built_any = False
    for t in targets:
        got, ok = collect_one(pkg, target=t)
        if ok:
            built_any = True
            docs.extend(got)
    return docs, built_any


def collect():
    """Return (all diagnostics, {package: ok})."""
    docs = []
    status = {}
    for pkg in packages():
        got, ok = collect_package(pkg)
        docs.extend(got)
        status[pkg] = ok
    return docs, status


def packages():
    out = []
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames
                       if d not in ("_build", ".mooncakes", "node_modules",
                                    "__pycache__", ".git", "ci")]
        if "moon.pkg" in filenames or "moon.pkg.json" in filenames:
            out.append(os.path.relpath(dirpath, ROOT))
    return sorted(out)


def _parse(raw):
    out = []
    for line in raw.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out


def accepted_sites():
    """KNOWN_ACCEPTED keyed the way the report is keyed (os.sep, str line)."""
    return {(p.replace("/", os.sep), ln): why
            for (p, ln), why in KNOWN_ACCEPTED.items()}


def _owner_pkg(rel_path, pkgs):
    """The package directory a site belongs to, or None."""
    best = None
    for p in pkgs:
        if rel_path == p or rel_path.startswith(p + os.sep):
            if best is None or len(p) > len(best):
                best = p
    return best


def confirm_unused_packages(docs, pkgs):
    """Intersect `unused_package` across targets.

    Returns (confirmed_sites, inconclusive_packages).
    """
    raw = set()
    for d in docs:
        m = KIND_RE.search(d.get("message", ""))
        if m and m.group(1) == "unused_package":
            raw |= _sites([d], "unused_package")
    if not raw:
        return set(), []
    confirmed = set()
    inconclusive = []
    for pkg in sorted({_owner_pkg(p, pkgs) for p, _ in raw} - {None}):
        common = unused_package_all_targets(pkg)
        if common is None:
            inconclusive.append(pkg)
            continue
        confirmed |= common
    return confirmed, inconclusive


def main():
    want = None
    if "--kind" in sys.argv:
        want = sys.argv[sys.argv.index("--kind") + 1]

    docs, status = collect()
    pkgs = packages()
    confirmed, inconclusive = confirm_unused_packages(docs, pkgs)

    result = {}
    for doc in docs:
        if doc.get("$message_type") != "diagnostic":
            continue
        m = KIND_RE.search(doc.get("message", ""))
        if not m:
            continue
        kind = m.group(1)
        if want and kind != want:
            continue
        path = doc.get("path", "")
        if not path:
            continue
        if path.startswith(ROOT):
            path = os.path.relpath(path, ROOT)
        loc = LOC_RE.match(doc.get("loc", ""))
        line = loc.group(1) if loc else "0"
        if kind == "unused_package":
            # Keep only what fired on every target. A package that would not
            # build on some target is kept wholesale and named on stderr --
            # "cannot tell" must never be reported as "clean".
            if (path, line) not in confirmed and _owner_pkg(path, pkgs) not in inconclusive:
                continue
        result.setdefault(path, {}).setdefault(line, []).append(kind)

    ordered = {}
    for k, v in sorted(result.items()):
        ordered[k] = {ln: sorted(set(ks)) for ln, ks in
                      sorted(v.items(), key=lambda kv: int(kv[0]))}

    print(json.dumps(ordered, indent=2, ensure_ascii=False))
    total = sum(len(v) for v in ordered.values())
    broken = sorted(p for p, ok in status.items() if not ok)
    msg = "files=%d sites=%d packages=%d" % (len(ordered), total, len(status))
    if inconclusive:
        msg += ("\nWARNING: %d package(s) could not be checked on every target, "
                "so their unused_package report is kept verbatim:\n  %s"
                % (len(inconclusive), "\n  ".join(sorted(inconclusive))))
    if broken:
        # Loudly, and on stderr, because this is the case that previously
        # presented itself as "clean".
        msg += "\nWARNING: %d package(s) failed to build; their warnings are NOT reliable:\n  %s" % (
            len(broken), "\n  ".join(broken))
    sys.stderr.write(msg + "\n")
    if (broken or inconclusive) and "--quiet" not in sys.argv:
        sys.exit(2)


if __name__ == "__main__":
    with io.open(os.devnull, "w"):
        pass
    main()
