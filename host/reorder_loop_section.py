"""Move one Loop section so the sequence reads newest-first.

AGENTS.md's loop sections are meant to read 67, 66, 65, 64, ... Two
insertions have each anchored on the wrong heading and left the order wrong:
Loop #66 anchored on `### Loop #64`, so it landed after Loop #65; Loop #67 then
anchored on `### Loop #66` and inherited the mistake.

    python host/reorder_loop_section.py <moving-heading-prefix> <anchor-heading-prefix>

The section runs from its own heading up to the next heading at the same or
higher level. Both headings must exist exactly once, and the move is a cut and
splice of the original lines -- the text is never regenerated, so it cannot
drift from what a loop actually wrote.
"""
import io
import re
import sys

PATH = "AGENTS.md"


def headings(lines):
    return [i for i, l in enumerate(lines) if re.match(r"^#{2,3} ", l)]


def one(lines, prefix):
    hits = [i for i, l in enumerate(lines) if l.startswith(prefix)]
    if len(hits) != 1:
        raise SystemExit("%r found %d times, expected 1" % (prefix, len(hits)))
    return hits[0]


def section_end(lines, start):
    hs = headings(lines)
    for i in hs:
        if i > start:
            return i
    return len(lines)


def main():
    if len(sys.argv) < 3:
        raise SystemExit(__doc__)
    moving, anchor = sys.argv[1], sys.argv[2]
    lines = io.open(PATH, encoding="utf-8", newline="").read().split("\n")

    a = one(lines, moving)
    b = one(lines, anchor)
    end = section_end(lines, a)
    block = lines[a:end]

    rest = lines[:a] + lines[end:]
    target = [i for i, l in enumerate(rest) if l.startswith(anchor)]
    if len(target) != 1:
        raise SystemExit("anchor moved unexpectedly")
    at = target[0]

    out = rest[:at] + block + rest[at:]
    io.open(PATH, "w", encoding="utf-8", newline="").write("\n".join(out))
    print("moved %d lines: %r now precedes %r" % (len(block), moving, anchor))


if __name__ == "__main__":
    main()
