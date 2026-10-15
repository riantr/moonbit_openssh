#!/usr/bin/env python3
"""ci/sandbox.py -- run a step against a throwaway copy of the tree.

## Why

Mutation harnesses edit the working tree and restore it in a `finally`. That
is correct and it is not enough: a `finally` does not run when the process is
killed. This repository already paid for that. `verify_loop40` ran for 44
minutes, was interrupted, and left `src/channel/channel.mbt` with the `env`
name/value pair swapped -- a real protocol file, silently mutated, with the
harness reporting nothing because it never got to report.

`subprocess.run(..., timeout=...)` kills on timeout, so the engine can cause
exactly this. The fix is not a better `finally`; it is to not mutate the tree
that matters.

## How

A `git worktree` at HEAD, with the current uncommitted state applied on top:

  * `git worktree add --detach <dir> HEAD` -- a clean, independent checkout
  * `git diff --binary HEAD | git apply` -- so the step sees what the developer
    has in front of them, including this loop's uncommitted work
  * copy every untracked file `git status` reports, because `git diff` does not
    include them and the harness would otherwise fail on a missing package

`git checkout --` is never used; the developer's tree is only read.
"""

import os
import shutil
import subprocess
import sys
import tempfile

SKIP_DIRS = {"_build", ".mooncakes", "node_modules", "__pycache__", ".pytest_cache"}


def _run(argv, cwd, pipe_stdout_to=None):
    if pipe_stdout_to is None:
        return subprocess.run(argv, cwd=cwd, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE)
    with open(pipe_stdout_to, "wb") as fh:
        return subprocess.run(argv, cwd=cwd, stdout=fh, stderr=subprocess.PIPE)


def _untracked(root):
    r = subprocess.run(["git", "status", "--porcelain"], cwd=root,
                       stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    out = []
    for line in r.stdout.decode("utf-8", "replace").splitlines():
        if line.startswith("?? "):
            out.append(line[3:].strip().strip('"'))
    return out


def make_sandbox(root):
    """Create an isolated copy. Returns its path, or raises RuntimeError."""
    path = tempfile.mkdtemp(prefix="openssh_moonbit_sandbox_")
    target = os.path.join(path, "tree")
    r = subprocess.run(["git", "worktree", "add", "--detach", target, "HEAD"],
                       cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if r.returncode != 0:
        shutil.rmtree(path, ignore_errors=True)
        raise RuntimeError("git worktree add failed: %s"
                           % r.stderr.decode("utf-8", "replace").strip())

    # Uncommitted tracked changes, binary-safe.
    diff_file = os.path.join(path, "worktree.patch")
    r = _run(["git", "diff", "--binary", "HEAD"], root, pipe_stdout_to=diff_file)
    if r.returncode == 0 and os.path.getsize(diff_file) > 0:
        subprocess.run(["git", "apply", "--whitespace=nowarn", diff_file],
                       cwd=target, stdout=subprocess.DEVNULL,
                       stderr=subprocess.PIPE)

    # `git diff` does not see untracked files, and a missing package would make
    # the harness fail for a reason that has nothing to do with the mutation.
    for rel in _untracked(root):
        src = os.path.join(root, rel)
        dst = os.path.join(target, rel)
        if os.path.isdir(src):
            if any(part in SKIP_DIRS for part in rel.split(os.sep)):
                continue
            shutil.copytree(src, dst, dirs_exist_ok=True,
                            ignore=shutil.ignore_patterns(*SKIP_DIRS))
        elif os.path.isfile(src):
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy2(src, dst)
    return target


def drop_sandbox(root, target):
    subprocess.run(["git", "worktree", "remove", "--force", target],
                   cwd=root, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["git", "worktree", "prune"], cwd=root,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    parent = os.path.dirname(target)
    if parent and os.path.isdir(parent):
        shutil.rmtree(parent, ignore_errors=True)


def self_check(root):
    """The sandbox must reproduce the tree, or it is worse than no sandbox."""
    bad = []
    target = None
    try:
        target = make_sandbox(root)
        for rel in ("src", "scripts", "host", "moon.mod"):
            if not os.path.exists(os.path.join(target, rel)):
                bad.append("sandbox is missing %s" % rel)
        # An untracked file must be present: without it the loop under test
        # would fail for a reason the report would misattribute.
        for rel in _untracked(root):
            if not os.path.exists(os.path.join(target, rel)):
                bad.append("untracked file not carried over: %s" % rel)
        # A tracked, uncommitted edit must be present too.
        diff = subprocess.run(["git", "diff", "--name-only", "HEAD"], cwd=root,
                              stdout=subprocess.PIPE).stdout.decode(
                                  "utf-8", "replace").split()
        for rel in diff:
            if os.path.isfile(os.path.join(root, rel)):
                if not os.path.exists(os.path.join(target, rel)):
                    bad.append("modified tracked file not carried over: %s" % rel)
    except Exception as exc:  # noqa: BLE001 - report, do not mask
        bad.append("sandbox creation raised: %s" % exc)
    finally:
        if target:
            drop_sandbox(root, target)
    # The developer's tree must be untouched by all of the above.
    after = set(_untracked(root))
    if after != set(_untracked(root)):
        bad.append("untracked set changed while making and dropping a sandbox")
    return bad


if __name__ == "__main__":
    root = sys.argv[1] if len(sys.argv) > 1 else os.getcwd()
    problems = self_check(root)
    for p in problems:
        print("  FAIL %s" % p)
    print("sandbox self-check: %s" % ("OK" if not problems else "FAILED"))
    sys.exit(1 if problems else 0)
