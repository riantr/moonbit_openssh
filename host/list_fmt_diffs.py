"""List the files `moon fmt --check` reports, from a captured run.

    python host/list_fmt_diffs.py <capture-file>

`moon fmt --check` prints a unified diff whose header names both sides, so the
files are recoverable from the `diff --git a/<path>` lines. The capture has to
be made with `cmd /c "... > file"`: PowerShell's `>` writes UTF-16 and its
`2>&1 | Out-String` interleaves stderr into stdout, either of which corrupts
the parse.
"""
import re
import sys

path = sys.argv[1] if len(sys.argv) > 1 else "fmtcap.txt"
t = open(path, encoding="utf-8", errors="replace").read()

files = set()
files |= set(re.findall(r"no-index\s+(\S+)\s", t))
files |= set(re.findall(r'a/(E:[^"]+?\.(?:mbt|pkg|moon))', t))

rel = sorted(p.replace("\\", "/").replace("E:/src/moon/openssh_moonbit/", "")
             for p in files)
print("files with diffs: %d" % len(rel))
for p in rel:
    print("  " + p)
