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
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKIP = {"_build", ".mooncakes", "node_modules", ".git", "__pycache__", ".fmtbak"}
SUFFIX = (".mbt", ".moon", ".pkg")

# CJK ideographs, CJK punctuation, and fullwidth forms. Comments in this
# repository are Chinese; an ASCII-only comment cannot be damaged by a
# character-dropping formatter and does not need to be in the snapshot.
CJK = re.compile(r"[\u3000-\u9fff\u3400-\u4dbf\uff00-\uffef\u3040-\u30ff\uac00-\ud7af]+")


def walk():
    """Every TRACKED file that carries one of SUFFIX.

    The snapshot is a committed artefact, so it has to describe the tree a
    *checkout* produces -- which is what `git ls-files` enumerates, not what
    happens to be lying in somebody's working directory.

    Loop #89 measured the difference. The committed snapshot carried an entry
    for `src/test_nested/nested_test.mbt`, a path that `git log --all` shows
    has never been tracked: it was picked up by walking the filesystem on the
    machine that saved the snapshot. On CI the file cannot exist, so every run
    printed `NOTE ... was in the snapshot and no longer exists` -- noise that
    is indistinguishable from a real staleness signal, in a gate whose whole
    job is to notice when CJK content moves.

    A tracked file that is currently deleted in the working tree is skipped
    rather than crashing: that is a normal state halfway through an edit, and
    the entry simply is not in the snapshot this run.
    """
    out = subprocess.run(
        ["git", "ls-files", "-z"], cwd=ROOT,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    if out.returncode != 0:
        sys.exit("git ls-files failed in %s: %s"
                 % (ROOT, out.stderr.decode("utf-8", "replace").strip()))
    for rel in out.stdout.decode("utf-8").split("\0"):
        if not rel.endswith(SUFFIX):
            continue
        full = os.path.join(ROOT, rel.replace("/", os.sep))
        if os.path.exists(full):
            yield full


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
