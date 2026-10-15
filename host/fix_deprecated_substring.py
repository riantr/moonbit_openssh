#!/usr/bin/env python3
"""Rewrite deprecated `.substring(start=A, end=B)` calls to slice syntax.

The toolchain reports:

    Error Warning (deprecated): Use `str[:]` or `str[:].to_string()` instead

and points at the `substring` token. This script does not search for `substring`
by text -- it starts from the column the compiler named, verifies that is where
the token actually is, then scans the argument list with a paren-depth counter
so that an argument containing a call (`end=s.length()`) is not truncated at its
first `)`.

`substring` returns an owned `String`; `s[a:b]` returns a `StringView`. The
rewrite therefore ends in `.to_owned()`, which is what the second half of the
compiler's own message asks for. Verified against `src/hostkey/cert.mbt`:
`name.substring(start=0, end=n)` -> `name[:n].to_owned()`.

Usage: python host/fix_deprecated_substring.py [--dry-run]
"""
import io
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "host"))
import collect_warnings  # noqa: E402

MSG_RE = re.compile(r"Warning \(deprecated\): Use `str\[:\]`")
LOC_RE = re.compile(r"^(\d+):(\d+)-")
TOKEN = "substring"


def _split_top_level(inner):
    """Split `start=0, end=s.length()` on top-level commas only."""
    parts, depth, cur = [], 0, []
    for ch in inner:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    parts.append("".join(cur))
    return [p.strip() for p in parts if p.strip()]


def _match_paren(src, open_idx):
    """Index of the ')' matching the '(' at `open_idx`, or -1."""
    depth = 0
    for i in range(open_idx, len(src)):
        c = src[i]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i
    return -1


def _parse_args(args):
    """Return (start_expr, end_expr) from positional or named arguments."""
    start = end = None
    for a in args:
        if "=" in a:
            k, v = a.split("=", 1)
            k, v = k.strip(), v.strip()
            if k == "start":
                start = v
            elif k == "end":
                end = v
            else:
                return None
        else:
            if start is None:
                start = a
            elif end is None:
                end = a
            else:
                return None
    return start, end


def collect_sites():
    docs, status = collect_warnings.collect()
    broken = sorted(p for p, ok in status.items() if not ok)
    if broken:
        sys.stderr.write(
            "refusing to edit: %d package(s) failed to build:\n  %s\n"
            % (len(broken), "\n  ".join(broken)))
        return None
    sites = {}
    for doc in docs:
        if doc.get("$message_type") != "diagnostic":
            continue
        if not MSG_RE.search(doc.get("message", "")):
            continue
        loc = LOC_RE.match(doc.get("loc", ""))
        if not loc:
            continue
        path = doc.get("path", "")
        if path.startswith(ROOT):
            path = os.path.relpath(path, ROOT)
        sites.setdefault(path, set()).add((int(loc.group(1)), int(loc.group(2))))
    return sites


def main():
    dry = "--dry-run" in sys.argv
    sites = collect_sites()
    if sites is None:
        return 2

    total = 0
    for rel, locs in sorted(sites.items()):
        path = os.path.join(ROOT, rel)
        with io.open(path, "r", encoding="utf-8", newline="") as fh:
            text = fh.read()
        nl = "\r\n" if "\r\n" in text else "\n"
        src = text.replace("\r\n", "\n").split("\n")

        edits = 0
        # Right-to-left across the file so earlier coordinates stay valid.
        for lineno, col in sorted(locs, reverse=True):
            idx = lineno - 1
            if idx >= len(src):
                sys.stderr.write("line %d out of range in %s\n" % (lineno, rel))
                return 2
            line = src[idx]
            at = col - 1
            if line[at:at + len(TOKEN)] != TOKEN:
                sys.stderr.write(
                    "column drift in %s:%d -- expected %r, found %r\n"
                    % (rel, lineno, TOKEN, line[at:at + len(TOKEN)]))
                return 2
            # The receiver expression runs back to the '.' immediately before
            # the token; the rewrite replaces ".substring(...)" in place.
            dot = at - 1
            if dot < 0 or line[dot] != ".":
                sys.stderr.write("no receiver '.' at %s:%d\n" % (rel, lineno))
                return 2
            open_paren = at + len(TOKEN)
            if open_paren >= len(line) or line[open_paren] != "(":
                sys.stderr.write("expected '(' at %s:%d\n" % (rel, lineno))
                return 2
            close = _match_paren(line, open_paren)
            if close < 0:
                sys.stderr.write("unbalanced '(' at %s:%d\n" % (rel, lineno))
                return 2
            args = _parse_args(_split_top_level(line[open_paren + 1:close]))
            if args is None or args[0] is None or args[1] is None:
                sys.stderr.write("cannot parse args at %s:%d: %r\n"
                                 % (rel, lineno, line[open_paren:close + 1]))
                return 2
            start, end = args
            src[idx] = line[:dot] + "[%s:%s].to_owned()" % (start, end) + line[close + 1:]
            edits += 1

        total += edits
        print("%-42s %3d sites" % (rel, edits))
        if edits and not dry:
            out = nl.join(src)
            if nl == "\r\n":
                out = out.replace("\n", "\r\n")
            with io.open(path, "w", encoding="utf-8", newline="") as fh:
                fh.write(out)

    print("---")
    print("sites=%d dry_run=%s" % (total, dry))
    return 0


if __name__ == "__main__":
    sys.exit(main())
