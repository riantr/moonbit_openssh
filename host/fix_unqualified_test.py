#!/usr/bin/env python3
"""Fix `test_unqualified_package` using the compiler's own advice.

The compiler names both the bare identifier and the qualified form in each
message, so this never guesses at a package name:

    Error Warning (test_unqualified_package): `aead_encrypt` is implicitly
    imported in test. Use `@aead.aead_encrypt` instead.

Only identifiers the compiler itself flagged are rewritten, and only at the
columns it reported. A name that is already qualified, or one that belongs to
another package, is left alone -- which is why this is a scripted edit rather
than a search-and-replace for "add @ everywhere".

The edit is restricted to files under a `*_test.mbt` name or a `test` package;
a diagnostic in production code would mean something else entirely and must
not be "fixed" by adding a prefix.

Usage: python host/fix_unqualified_test.py [--dry-run]
"""
import io
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "host"))
import collect_warnings  # noqa: E402

MSG_RE = re.compile(
    r"Warning \(test_unqualified_package\): `(?P<bare>[A-Za-z_][\w]*)` "
    r"is implicitly imported in test\. Use `(?P<qualified>@[\w.]+)` instead\."
)
LOC_RE = re.compile(r"^(\d+):(\d+)-")


def collect_sites():
    """{relpath: {line: [(col_start, col_end, bare, qualified)]}}

    `collect_warnings.collect()` returns `(docs, per_package_ok)`. The status half
    is what stops a package that failed to build from being read as a clean one,
    so it is checked here too: a `test_unqualified_package` site reported by a
    package that did not compile is cascade noise, and writing a prefix into it
    would be editing a broken file.
    """
    sites = {}
    docs, status = collect_warnings.collect()
    broken = sorted(p for p, ok in status.items() if not ok)
    if broken:
        sys.stderr.write(
            "refusing to edit: %d package(s) failed to build, so their "
            "diagnostics are unreliable:\n  %s\n" % (len(broken), "\n  ".join(broken)))
        return None
    for doc in docs:
        if doc.get("$message_type") != "diagnostic":
            continue
        m = MSG_RE.search(doc.get("message", ""))
        if not m:
            continue
        loc = LOC_RE.match(doc.get("loc", ""))
        if not loc:
            continue
        path = doc.get("path", "")
        if path.startswith(ROOT):
            path = os.path.relpath(path, ROOT)
        sites.setdefault(path, {}).setdefault(int(loc.group(1)), set()).add(
            (int(loc.group(2)), m.group("bare"), m.group("qualified"))
        )
    # Sets have no order; hand back a list so the caller's right-to-left pass is
    # deterministic.
    return {p: {ln: sorted(v) for ln, v in d.items()} for p, d in sites.items()}


def main():
    dry = "--dry-run" in sys.argv
    sites = collect_sites()
    if sites is None:
        return 2
    total = sum(len(v) for f in sites.values() for v in f.values())

    changed_files = 0
    for rel, lines in sorted(sites.items()):
        path = os.path.join(ROOT, rel)
        # A diagnostic outside a test file means our understanding is wrong.
        # Refuse rather than touch production code.
        base = os.path.basename(rel)
        if not (base.endswith("_test.mbt") or "_test" in rel.split(os.sep)):
            sys.stderr.write("refusing non-test file: %s\n" % rel)
            return 2
        with io.open(path, "r", encoding="utf-8", newline="") as fh:
            text = fh.read()
        nl = "\r\n" if "\r\n" in text else "\n"
        body = text.replace("\r\n", "\n")
        src = body.split("\n")
        edits = 0
        for lineno, cols in lines.items():
            idx = lineno - 1
            if idx >= len(src):
                sys.stderr.write("line %d out of range in %s\n" % (lineno, rel))
                return 2
            line = src[idx]
            # Apply right-to-left so earlier columns stay valid.
            for col, bare, qualified in sorted(cols, key=lambda t: -t[0]):
                start = col - 1
                end = start + len(bare)
                actual = line[start:end]
                if actual != bare:
                    sys.stderr.write(
                        "column drift in %s:%d -- expected %r, found %r\n"
                        % (rel, lineno, bare, actual))
                    return 2
                line = line[:start] + qualified + line[end:]
                edits += 1
            src[idx] = line
        print("%-42s %3d sites" % (rel, edits))
        if edits == 0:
            continue
        changed_files += 1
        if not dry:
            out = nl.join(src)
            if nl == "\r\n":
                out = out.replace("\n", "\r\n")
            with io.open(path, "w", encoding="utf-8", newline="") as fh:
                fh.write(out)
    print("---")
    print("files=%d sites=%d dry_run=%s" % (changed_files, total, dry))
    return 0


if __name__ == "__main__":
    sys.exit(main())
