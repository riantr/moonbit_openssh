"""List the files `moon fmt --check` reports, from a captured run.

    python host/list_fmt_diffs.py <capture-file>

`moon fmt --check` prints a unified diff whose header names both sides, so the
files are recoverable from the `diff --git a/<path>` lines. The capture has to
be made with `cmd /c "... > file"`: PowerShell's `>` writes UTF-16 and its
`2>&1 | Out-String` interleaves stderr into stdout, either of which corrupts
the parse.
"""
import os
import re
import sys

path = sys.argv[1] if len(sys.argv) > 1 else "fmtcap.txt"
t = open(path, encoding="utf-8", errors="replace").read()

# Loop #71: this used to be `a/(E:[^"]+?...)` plus a hardcoded
# `replace("E:/src/moon/openssh_moonbit/", "")`. Both baked in one machine's
# drive and one developer's checkout root, so on any other clone the tool
# printed paths that had no leading directory at all rather than saying it had
# recognised nothing. The drive letter is now a pattern and the root is
# stripped only if the capture actually mentions this checkout.
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROOT_FWD = ROOT.replace("\\", "/").rstrip("/") + "/"

files = set()
files |= set(re.findall(r"no-index\s+(\S+)\s", t))
files |= set(re.findall(r'a/([A-Za-z]:[^"]+?\.(?:mbt|pkg|moon))', t))

rel = sorted(p.replace("\\", "/").replace(ROOT_FWD, "") for p in files)
print("files with diffs: %d" % len(rel))
for p in rel:
    print("  " + p)
