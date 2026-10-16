"""Delete or replace a line range located by unique ASCII anchor lines.

The `edit` tool repeatedly failed to match multi-line blocks in this repository
-- across AGENTS.md, ci/qa.py, cmd/flow_kat/main.mbt and others -- on invisible
byte differences alone. Matching on two short unique ASCII lines and rewriting
the span between them sidesteps the whole problem, and the uniqueness check
makes a drifted file fail loudly instead of patching the wrong site.

Usage:
  python host/patch_span.py <file> <start-marker> <end-marker> [replacement]

Markers are whole lines (compared stripped). The span is [start, end] inclusive
and is replaced by `replacement` (default: removed, along with one following
blank line).

An end marker of the form `until:<text>` is EXCLUSIVE -- the span stops just
before the line matching `<text>`, and that line is kept. It exists because a
closing `}` is rarely unique in MoonBit source: `cmd/flow_kat/main.mbt` has 74
of them.
"""
import io
import sys


def find(lines, marker, after=0):
    hits = [i for i, l in enumerate(lines) if l.strip() == marker]
    if not hits:
        raise SystemExit("marker not found: %r" % marker)
    if len(hits) > 1:
        raise SystemExit("marker occurs %d times: %r" % (len(hits), marker))
    if hits[0] < after:
        raise SystemExit("marker is before the expected position: %r" % marker)
    return hits[0]


def main():
    path, start_marker, end_marker = sys.argv[1], sys.argv[2], sys.argv[3]
    replacement = sys.argv[4] if len(sys.argv) > 4 else None
    exclusive = end_marker.startswith("until:")
    if exclusive:
        end_marker = end_marker[len("until:"):]

    raw = io.open(path, encoding="utf-8", newline="").read()
    nl = "\r\n" if "\r\n" in raw else "\n"
    lines = raw.replace("\r\n", "\n").split("\n")

    a = find(lines, start_marker)
    b = find(lines, end_marker, after=a)
    if b < a:
        raise SystemExit("end marker precedes start marker")
    if exclusive:
        b -= 1
        # Also drop the blank separator immediately before the kept line, so the
        # deletion leaves one blank line rather than two.
        while b > a and lines[b].strip() == "":
            b -= 1

    tail = b + 1
    if replacement is None and not exclusive and tail < len(lines) and lines[tail].strip() == "":
        tail += 1
    removed = b - a + 1
    new = lines[:a] + ([replacement] if replacement is not None else []) + lines[tail:]

    out = nl.join(new)
    io.open(path, "w", encoding="utf-8", newline="").write(out)
    print("%s: replaced lines %d..%d (%d lines removed)%s"
          % (path, a + 1, tail, removed,
             "" if replacement is not None else " with nothing"))


if __name__ == "__main__":
    main()
