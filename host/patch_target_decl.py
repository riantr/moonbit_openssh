"""Convert a per-file `targets:` gate on a cmd executable into a package-level
`supported_targets` declaration.

Why this exists -- measured, not assumed. Loop #68 asked why
`moon coverage analyze` fails in a workspace whose gates are otherwise green.
The command has no `--target` flag, so it builds every package for the DEFAULT
target. Seven executables under `cmd/` gate their only source file with

    options(targets: { "main.mbt": [ "js" ] })

which is a *file* filter: on any other target the package still exists, it just
has no `main.mbt` left, and the compiler answers

    Error: [4067] Missing main function in the main package.

The same information expressed as a package-level

    options(supported_targets: "+js")

makes the toolchain REFUSE the build as a declared impossibility instead of
attempting it and failing. `cmd/proton_gui` and `cmd/sftp_mitm` already say it
that way, and neither appears in the coverage run's diagnostics -- measured in
Loop #68 by converting `cmd/wt_ssh` alone and watching its error disappear while
the other six stayed.

Per-file `targets:` remains the right tool for the library packages under `src/`
and is deliberately left alone there: `src/khstore/moon.pkg` and
`src/khfile/moon.pkg` document why -- a package-level declaration would block
downstream consumers, so a wasm-wanting consumer fails loudly at its own compile
instead of silently inside the library. The executables under `cmd/` are leaves;
nothing imports them, so the reason does not apply and only the honesty does.

`cmd/ssh_live` is the other half and is a genuine defect, not a gate artefact: it
declares no target at all, yet it consumes `src/khfile` and `src/tcp`, both
native-only, so it cannot build on js, wasm or wasm-gc. Measured in Loop #68:
native 0 errors, js 8, wasm 7, wasm-gc 9.

Usage:
  python host/patch_target_decl.py            # apply, then verify every package
  python host/patch_target_decl.py --check    # verify only, non-zero on drift

Verification after patching is not a formality: every touched package is
re-checked on every target, and the script fails if a package became *less*
buildable than the declaration claims.
"""
from __future__ import annotations

import io
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TARGETS = ("native", "js", "wasm", "wasm-gc")

# Per-file `targets:` gate -> the single target it names. Only packages whose
# ONLY gated file is the executable's own main are listed: a package that gated
# a second file is a different animal and must be looked at by hand.
CONVERT = {
    "cmd/flow_kat": "native",
    "cmd/knownhosts_kat": "native",
    "cmd/sshconfig_kat": "native",
    "cmd/probe_async_wall": "js",
    "cmd/wt_net": "js",
    "cmd/wt_probe": "js",
    "cmd/wt_ssh": "js",
}

# Declares nothing, builds on exactly one target. See module docstring.
ADD = {
    "cmd/ssh_live": "native",
}

OPTIONS_RE = re.compile(r"^options\($")
TARGETS_LINE_RE = re.compile(
    r'^(\s*)targets:\s*\{\s*"main\.mbt":\s*\[\s*"([a-z-]+)"\s*\],?\s*\},?\s*$'
)
SUPPORTED_RE = re.compile(r'^\s*supported_targets:\s*"\+([a-z-]+)"', re.M)


def read(path):
    with io.open(path, encoding="utf-8", newline="") as fh:
        return fh.read()


def write(path, text):
    with io.open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)


def newline_of(text):
    return "\r\n" if "\r\n" in text else "\n"


def convert(pkg, target):
    """Rewrite one package's gate. Returns True if the file changed."""
    path = os.path.join(ROOT, pkg, "moon.pkg")
    raw = read(path)
    nl = newline_of(raw)
    lines = raw.replace("\r\n", "\n").split("\n")
    out, changed = [], False
    for line in lines:
        m = TARGETS_LINE_RE.match(line)
        if m and out and OPTIONS_RE.match(out[-1]):
            out.append('%ssupported_targets: "+%s",' % (m.group(1), target))
            changed = True
        else:
            out.append(line)
    if changed:
        write(path, nl.join(out))
    return changed


def add(pkg, target):
    """Give a package that declares nothing the declaration it should have had."""
    path = os.path.join(ROOT, pkg, "moon.pkg")
    raw = read(path)
    if SUPPORTED_RE.search(raw):
        return False
    nl = newline_of(raw)
    lines = raw.replace("\r\n", "\n").split("\n")
    # Append after the last non-blank line, keeping one trailing newline.
    while lines and lines[-1].strip() == "":
        lines.pop()
    lines += ["", "options(", '  supported_targets: "+%s",' % target, ")", ""]
    write(path, nl.join(lines))
    return True


def declared(pkg):
    path = os.path.join(ROOT, pkg, "moon.pkg")
    m = SUPPORTED_RE.search(read(path))
    return m.group(1) if m else None


def builds(pkg, target):
    """True when `moon check --target <target> -p <pkg>` exits 0.

    A `supported_targets` package answers a non-zero exit with NO diagnostics on
    a target it does not support -- that is the toolchain declining, and it is
    counted as "builds here is false" without being an error.
    """
    proc = subprocess.run(
        ["moon", "check", "--target", target, "-p", pkg],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        encoding="utf-8",
        errors="replace",
    )
    return proc.returncode == 0


def main():
    check_only = "--check" in sys.argv
    problems = []

    if not check_only:
        for pkg, target in CONVERT.items():
            if convert(pkg, target):
                print("%s: targets{} -> supported_targets \"+%s\"" % (pkg, target))
            else:
                print("%s: already converted (no change)" % pkg)
        for pkg, target in ADD.items():
            if add(pkg, target):
                print("%s: added supported_targets \"+%s\"" % (pkg, target))
            else:
                print("%s: already declared (no change)" % pkg)

    for pkg, target in sorted(list(CONVERT.items()) + list(ADD.items())):
        got = declared(pkg)
        if got != target:
            problems.append("%s: declares %r, expected %r" % (pkg, got, target))
            continue
        ok = [t for t in TARGETS if builds(pkg, t)]
        if ok != [target]:
            problems.append("%s: declares \"%s\" but builds on %s"
                            % (pkg, target, ok or "nothing"))
        else:
            print("%s: OK -- declares %s, builds only on %s" % (pkg, target, ok))

    if problems:
        sys.stderr.write("PROBLEMS:\n  " + "\n  ".join(problems) + "\n")
        return 1
    print("all %d packages declare exactly the target they build on"
          % (len(CONVERT) + len(ADD)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
