#!/usr/bin/env python3
"""Snapshot every CJK run in the repository's MoonBit sources.

Loop #67 measured that `moon fmt` in write mode does NOT damage CJK comments
on `moon 0.1.20261012` -- 373 runs across 12 reformatted files, byte-identical
before and after -- contradicting the standing note in AGENTS.md. That claim
deserves better than a one-off check, so this snapshot exists to be taken before
any whole-tree format and compared after it.

Usage:
  python host/cjk_snapshot.py save  <file>
  python host/cjk_snapshot.py check <file>

`check` reports the first differing file plus the runs it lost, and exits 1. It
is a content check, not a byte check: reformatting legitimately moves lines, and
a formatter that silently eats a CJK character would show up here as a run that
exists in the snapshot and not in the tree.
"""
import io
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKIP = {"_build", ".mooncakes", "node_modules", ".git", "__pycache__", ".fmtbak"}
SUFFIX = (".mbt", ".moon", ".pkg")

# CJK ideographs, CJK punctuation, and fullwidth forms. Comments in this
# repository are Chinese; an ASCII-only comment cannot be damaged by a
# character-dropping formatter and does not need to be in the snapshot.
CJK = re.compile(r"[\u3000-\u9fff\u3400-\u4dbf\uff00-\uffef\u3040-\u30ff\uac00-\ud7af]+")


def walk():
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames if d not in SKIP]
        for f in sorted(filenames):
            if f.endswith(SUFFIX):
                yield os.path.join(dirpath, f)


def collect():
    snap = {}
    for p in walk():
        rel = os.path.relpath(p, ROOT).replace(os.sep, "/")
        with io.open(p, encoding="utf-8") as fh:
            runs = CJK.findall(fh.read())
        if runs:
            snap[rel] = runs
    return snap


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    mode, target = sys.argv[1], sys.argv[2]
    snap = collect()
    if mode == "save":
        with io.open(target, "w", encoding="utf-8", newline="") as fh:
            json.dump(snap, fh, ensure_ascii=False, indent=1, sort_keys=True)
        total = sum(len(v) for v in snap.values())
        print("saved %d files / %d CJK runs -> %s" % (len(snap), total, target))
        return 0
    if mode == "check":
        with io.open(target, encoding="utf-8") as fh:
            before = json.load(fh)
        changed = []
        added = []
        removed = []
        for rel, runs in before.items():
            now = snap.get(rel)
            if now is None:
                removed.append(rel)
                continue
            if runs == now:
                continue
            missing = [r for r in runs if r not in now]
            extra = [r for r in now if r not in runs]
            if missing or extra:
                changed.append((rel, missing[:5], extra[:5]))
        for rel in snap:
            if rel not in before:
                added.append(rel)
        total_before = sum(len(v) for v in before.values())
        total_now = sum(len(v) for v in snap.values())
        print("CJK runs: snapshot=%d  tree=%d  files=%d/%d"
              % (total_before, total_now, len(before), len(snap)))
        for rel, missing, extra in changed:
            print("  CHANGED %s lost=%s gained=%s" % (rel, missing, extra))
        # A file that gained or lost CJK entirely is legitimate editing -- a new
        # Chinese comment, or a deletion that removed one along with the code it
        # documented. The guard is for *character-level* damage inside a file
        # that still exists, which is what a character-dropping formatter does
        # and what nothing else here does.
        for rel in added:
            print("  NOTE    %s has CJK and is not in the snapshot" % rel)
        for rel in removed:
            print("  NOTE    %s was in the snapshot and no longer exists" % rel)
        if changed:
            print("a formatter that changes CJK content is the failure this exists for")
            return 1
        print("CJK content identical in every file present in both")
        return 0
    sys.exit("unknown mode %r" % mode)


if __name__ == "__main__":
    sys.exit(main())
