#!/usr/bin/env python3
"""ci/publish.py -- the mooncakes.io publication gate.

## What this file exists to prevent

A tag and a mooncakes release are two records of the same claim ("this exact
tree is the tested state"), and nothing in either toolchain checks that they
agree. So the two failure modes worth engineering against are:

  1. **The two versions drift.** `git tag v0.1.3` next to `version = "0.1.2"`
     in `moon.mod` publishes a package whose version nobody can match back to a
     commit. `--check` refuses that, and `ci.py --tag` calls it before it is
     allowed to create a tag.
  2. **What gets published is not what was tested.** `moon package` decides the
     file set from `moon.mod` and the package layout; a stray scratch directory
     or a build artefact entering that set would ship something no gate ever
     looked at. The manifest assertions below name the things that must be in
     and the things that must not be.

## Why the credentials are not this file's problem

`moon publish` needs a login, and a login is a browser interaction: it cannot
be automated here and must not be faked. So `--check` and `--dry-run` are
credential-free and always runnable, while the real `--publish` refuses loudly
when the identity cannot be established, printing the one command the human
must run. A gate that silently skipped publication when logged out would report
a green release that never happened.

## The identity rule, measured rather than assumed

`moon whoami` on this machine answers, with exit code 0:

    Logged in, but username is unavailable. Please run `moon login` again.

Exit code 0 while the username is missing is exactly the kind of "looks fine"
that a naive `returncode == 0` check would accept. So the decision is made on
the *text*: a username is required, and the "username is unavailable" answer is
treated as "not authenticated for publishing".
"""

import io
import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MOD_FILE = os.path.join(ROOT, "moon.mod")

# The publication identity the package must declare. Kept here rather than read
# back out of moon.mod so that a typo in moon.mod is a gate failure instead of a
# silently different package.
EXPECT_NAME = "riantr/moonbit_openssh"

# Lines `moon package` must not include: build output, loop scratch state, CI
# artefacts. Matched as path prefixes or substrings, in either separator style.
FORBIDDEN_IN_MANIFEST = (
    "_build/",
    ".loop",
    "ci/artifacts/",
    ".git/",
    ".mooncakes/",
)

SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")

# Box-drawing characters that appear in `moon check` diagnostics. They matter
# because a line like `───╯` contains NO whitespace, so a whitespace filter
# alone would keep it as if it were a manifest path. Measured: filtering by
# "no whitespace" alone yields 992 lines where the manifest has 953; the
# difference is exactly these fragments.
BOX_CHARS = "│╭╰─┬┴┼╮╯"


def run(argv, timeout=600, merge_stderr=True):
    """Run a command from the repository root and return (rc, stdout+stderr).

    Same convention as ci/ci.py: on Windows the toolchain is reached through
    cmd.exe, so the argv lists passed in here already carry their own prefix.
    """
    rc, out, err = run_split(argv, timeout=timeout, merge_stderr=merge_stderr)
    return rc, out + err


def run_split(argv, timeout=600, merge_stderr=False):
    """(rc, stdout, stderr), kept apart.

    `merge_stderr=False` exists because `moon package` writes its diagnostics to
    stderr and the file manifest to stdout: measured, `moon package --list`
    emitted 1,109 lines of which the first ~30 were `Warning: [0029]` blocks
    from the check it runs first. Parsing merged output would be parsing
    warnings -- but a failing command still has to be diagnosable, so the two
    streams are returned separately rather than one being discarded.
    """
    try:
        proc = subprocess.run(
            argv, cwd=ROOT, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT if merge_stderr else subprocess.PIPE,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return 127, "", "could not run %s: %s" % (" ".join(argv), exc)
    out = proc.stdout.decode("utf-8", "replace")
    if merge_stderr:
        return proc.returncode, out, ""
    return proc.returncode, out, proc.stderr.decode("utf-8", "replace")


def read_mod():
    """Parse the top-level `key = value` fields of moon.mod.

    Deliberately not a TOML parser: moon.mod is a flat list of scalar fields
    plus one `import { ... }` block, and the values this gate needs are all
    scalars. A malformed file shows up as a missing key, which is a failure
    here exactly as it would be for `moon` itself.
    """
    with io.open(MOD_FILE, encoding="utf-8") as fh:
        text = fh.read()
    fields = {}
    for line in text.splitlines():
        m = re.match(r'^\s*([a-z_]+)\s*=\s*(.+?)\s*$', line)
        if m:
            fields[m.group(1)] = m.group(2).strip().strip('"')
    return fields


def check_name(problems):
    fields = read_mod()
    got = fields.get("name")
    if got != EXPECT_NAME:
        problems.append("moon.mod name is %r, expected %r" % (got, EXPECT_NAME))
    return fields


def check_version(problems, fields, next_tag):
    """The mooncakes version must equal the git tag, minus the `v`.

    Two records of one claim; if they disagree, a reader cannot tell which
    commit a published version came from.
    """
    version = fields.get("version", "")
    if not SEMVER_RE.match(version):
        problems.append("moon.mod version %r is not X.Y.Z" % version)
        return version
    if next_tag:
        wanted = next_tag[1:] if next_tag.startswith("v") else next_tag
        if version != wanted:
            problems.append(
                "moon.mod version is %r but the next tag is %r; a published "
                "version must name the commit it came from" % (version, next_tag)
            )
    return version


def check_package_metadata(problems, fields):
    """Everything mooncakes.io shows on the package page must be filled in.

    An empty `description`, `repository` or `keywords` is not a build error, so
    nothing in the toolchain would ever complain -- which is precisely why it
    is checked here. Measured before this gate existed: description, repository
    and keywords were all empty, and `moon publish` warned about none of them.
    `license` was the one field already filled in.
    """
    if not fields.get("description"):
        problems.append("moon.mod description is empty")
    if not fields.get("repository"):
        problems.append("moon.mod repository is empty")
    if not fields.get("license"):
        problems.append("moon.mod license is empty")
    keywords = fields.get("keywords", "")
    if keywords in ("", "[", "[]", "[ ]"):
        problems.append("moon.mod keywords is empty")

    readme = fields.get("readme")
    if not readme:
        problems.append("moon.mod names no readme")
    elif not os.path.isfile(os.path.join(ROOT, readme.replace("/", os.sep))):
        problems.append("moon.mod readme %r does not exist" % readme)


# The pre-rename module path, assembled from parts ON PURPOSE.
#
# This gate greps the whole tracked tree for the old path, and this file is in
# that tree. Written as a literal, the check would match itself and fail always;
# this repository already paid for that lesson once, when a QA evidence string
# reintroduced the token it was describing. Joining the halves keeps the check
# exact while leaving nothing for it to find.
#
# THREE forms, not one, and the reason is a measured miss: the first version of
# this check looked only for the plain `publisher/package` spelling and reported
# the rename complete. `host/verify_loop64.mjs` spelled it inside a RegExp
# literal, where the separators are escaped, so the plain search could not see
# it -- and that gate then failed with "src/transport imports src/tcp", a red
# that had nothing to do with the contract it asserts. A rename check that
# cannot see the form a JS regex writes is not a complete check.
_OLD_PUB, _OLD_PKG = "openssh", "openssh_" + "moonbit"
OLD_MODULE_FORMS = (
    _OLD_PUB + "/" + _OLD_PKG,        # a plain import path
    _OLD_PUB + "\\/" + _OLD_PKG,      # inside a JS RegExp literal
    _OLD_PUB + "\\\\/" + _OLD_PKG,    # inside a JS string holding a path
)
OLD_MODULE = OLD_MODULE_FORMS[0]


def check_rename_is_complete(problems):
    """No tracked file may still name the old module path, in any spelling.

    The module was renamed across 111 files. A single missed `moon.pkg` import
    resolves to nothing at build time, but a missed *documentation* line
    resolves to a reader's wasted afternoon, and neither shows up in a build.
    `git grep` answers for the whole tracked tree, including the files no gate
    compiles -- which is also why the tokens above are assembled rather than
    spelled out.
    """
    for form in OLD_MODULE_FORMS:
        rc, out = run(["cmd", "/c", "git", "grep", "-l", "-F", form, "--", "."])
        if rc == 0:
            stale = [line for line in out.splitlines() if line.strip()]
            if stale:
                problems.append(
                    "%d tracked file(s) still name the old module path as %r: %s"
                    % (len(stale), form, ", ".join(stale[:5]))
                )
        elif rc != 1:
            # Exit 1 means "no match", which is what we want. Anything else
            # means the question could not be asked, and an unaskable question
            # is not a pass.
            problems.append(
                "git grep failed while checking for the old module path as %r"
                % form)


def parse_manifest(text):
    """(entries, zip_line) from the text `moon package --list` writes to stderr.

    Pure, so `--self-check` can pin the rule with a fixture instead of a
    toolchain. That matters here more than usual: the manifest shares a stream
    with `moon check` diagnostics, so the rule is "recognise an entry by its
    shape", and a rule that cannot be tested is a rule that silently returns
    zero entries while exiting 0 -- which is what this function's first
    incarnation did, by reading the wrong stream.
    """
    entries = []
    zip_line = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("Package to "):
            zip_line = line[len("Package to "):].strip()
            continue
        if re.search(r"\s", line):
            continue
        if any(ch in BOX_CHARS for ch in line):
            continue
        entries.append(line.replace("\\", "/"))
    return entries, zip_line


def package_list(timeout=3600):
    """(rc, entries, zip_line, err) for the file set `moon publish` would ship.

    Measured on `moon 0.1.20261102`, and the measurement contradicts the
    obvious reading twice over:

      * **the file manifest goes to STDERR.** stdout is empty (0 bytes) while
        stderr carries the whole 1,091-line report. Parsing stdout returns zero
        entries and exit code 0 -- a clean-looking "nothing to publish". The
        first version of this function did exactly that, and it was the release
        run's own packaging row that would have caught it;
      * the manifest is INTERLEAVED with `moon check`'s diagnostics, because the
        command runs the check first and prints both to one stream: a
        `Running moon check ...` preamble, `Warning: [0029]` blocks drawn with
        box characters, and blank lines.

    So an entry is recognised by shape, not by position: a non-empty line with
    no whitespace and no box-drawing character. Measured against today's output
    that separates 953 entries from 137 diagnostic lines. The artefact line
    (`Package to ...`, which does contain spaces) is handled separately.

    A fourth fact, which cost an edit: no drive letter is written down here on
    purpose. `host/verify_loop71.mjs` fails a tracked file that asserts a
    machine-specific absolute path, and a docstring inside a `.py` file is a
    tracked file -- that gate caught the previous wording of this paragraph on
    its first run, with the file and line.

    `--dry-run` is NOT implemented for `package` ("dry-run is not implemented
    for package", exit 1), so `--list` is the inspection command, and the zip
    it writes lands under the gitignored `_build/`.
    `--frozen` keeps dependency syncing (and therefore the network) out of it.
    """
    rc, _out, err = run_split(
        ["cmd", "/c", "moon", "package", "--list", "--frozen"], timeout=timeout)
    entries, zip_line = parse_manifest(err)
    return rc, entries, zip_line, err


def check_manifest(problems):
    """`moon package` decides what ships. Assert it ships the right things.

    Searched both ways: the module file and the sources must be present, and
    build output, loop scratch state and CI artefacts must not be. The artefact
    name is checked too, because it is derived from the module name and version
    and is the last chance to notice that the two disagree before a release.
    """
    rc, entries, zip_line, err = package_list()
    if rc != 0:
        tail = " ".join(err.strip().splitlines()[-4:])[:400]
        problems.append("`moon package --list` exited %d%s"
                        % (rc, (": " + tail) if tail else ""))
        return []

    if not entries:
        problems.append("`moon package --list` listed no files")
        return []

    if "moon.mod" not in entries:
        problems.append("the package does not include moon.mod")
    if not any(e.startswith("src/") and e.endswith(".mbt") for e in entries):
        problems.append("the package includes no src/**/*.mbt files")
    mbt = [e for e in entries if e.endswith(".mbt")]
    if len(mbt) < 100:
        problems.append(
            "the package lists only %d .mbt files; this repository has "
            "hundreds, so the manifest is not describing this module" % len(mbt)
        )
    for bad in FORBIDDEN_IN_MANIFEST:
        hits = [e for e in entries if bad in e]
        if hits:
            problems.append(
                "%d entr(ies) under %r would be published, e.g. %s"
                % (len(hits), bad, hits[0])
            )

    # The artefact name encodes identity: `riantr-moonbit_openssh-0.1.2.zip`.
    fields = read_mod()
    want = ("%s-%s.zip" % (EXPECT_NAME.replace("/", "-"),
                           fields.get("version", "")))
    if not zip_line:
        problems.append("`moon package --list` named no artefact")
    elif not zip_line.replace("\\", "/").endswith(want):
        problems.append("the artefact is %r, expected it to end with %r"
                        % (zip_line.replace("\\", "/").rsplit("/", 1)[-1], want))
    return entries


def whoami():
    """(ok, detail) for 'is there a publishing identity on this machine'.

    Decided on the text, not the exit code. Measured on
    `moon 0.1.20261102`: with no usable login, `moon whoami` exits 0 and prints
    "Logged in, but username is unavailable. Please run `moon login` again."
    """
    rc, out = run(["cmd", "/c", "moon", "whoami"], timeout=120)
    text = out.strip()
    if rc != 0:
        return False, "`moon whoami` exited %d: %s" % (rc, text[:200])
    if "unavailable" in text.lower():
        return False, text
    if not text:
        return False, "`moon whoami` printed nothing"
    return True, text.splitlines()[0]


def dry_run():
    """Ask the toolchain to validate publication without releasing anything.

    `--frozen` keeps dependency syncing out of it; the registry check that the
    dry run exists to perform still happens.
    """
    rc, out = run(["cmd", "/c", "moon", "publish", "--dry-run", "--frozen"],
                  timeout=1800)
    return rc, out


def cmd_check(argv):
    """Credential-free: everything that must be true before a tag is allowed."""
    next_tag = None
    if "--next-tag" in argv:
        next_tag = argv[argv.index("--next-tag") + 1]

    problems = []
    fields = check_name(problems)
    version = check_version(problems, fields, next_tag)
    check_package_metadata(problems, fields)
    check_rename_is_complete(problems)
    entries = check_manifest(problems)

    print("publish check: %s version %s" % (fields.get("name"), version))
    if next_tag:
        print("  next tag       : %s" % next_tag)
    print("  manifest files : %d (%d .mbt)"
          % (len(entries), len([e for e in entries if e.endswith(".mbt")])))
    ok, detail = whoami()
    print("  identity       : %s" % ("ok -- " + detail if ok
                                     else "NOT USABLE -- " + detail))
    print("  (the identity does not block a tag; it blocks `--publish`)")
    if problems:
        print("")
        for p in problems:
            print("  FAIL %s" % p)
        return 1
    print("")
    print("  PASS every packaging assertion held")
    return 0


def cmd_dry_run():
    rc, out = dry_run()
    print(out.rstrip())
    if rc != 0:
        print("")
        print("  the toolchain refused the dry run; the release would fail")
        return 1
    print("")
    print("  the toolchain accepted the package for publication (nothing released)")
    return 0


def tags_on_head():
    """The tags that point at HEAD, as a list. Empty list if git cannot say."""
    rc, out = run(["cmd", "/c", "git", "tag", "--points-at", "HEAD"])
    if rc != 0:
        return None
    return [line.strip() for line in out.splitlines() if line.strip()]


def cmd_publish():
    """The real thing. Refuses loudly rather than skipping silently.

    Three refusals, in the order they can save a wrong release: an identity that
    cannot be named (a browser login this file cannot and must not perform), a
    version that does not name a tag on HEAD (so a release can never come from a
    tree that was not tagged and therefore was not the one CI verified), and a
    dry run the toolchain rejects.
    """
    fields = read_mod()
    version = fields.get("version", "")

    tags = tags_on_head()
    if tags is None:
        print("REFUSED: `git tag --points-at HEAD` failed, so this file cannot")
        print("  tell whether the tree it would publish is a tagged one.")
        return 1
    wanted = "v" + version
    if wanted not in tags:
        print("REFUSED: moon.mod says version %s, but %s is not a tag on HEAD."
              % (version, wanted))
        print("  Tags on HEAD: %s" % (", ".join(tags) if tags else "(none)"))
        print("")
        print("  A release must come from the exact tree a tag names, because the")
        print("  tag is what the CI green run verified. Tag first:")
        print("      python ci/ci.py --tiers env,build,gates,qa --tag")
        print("  Nothing was published.")
        return 1

    ok, detail = whoami()
    if not ok:
        print("REFUSED: no usable mooncakes.io identity on this machine.")
        print("  moon whoami said: %s" % detail)
        print("")
        print("  Run this once, by hand, in a terminal (it opens a browser):")
        print("      moon login")
        print("  Then publish the tag that already exists, WITHOUT re-tagging")
        print("  (a second --tag run would compute the NEXT tag and refuse):")
        print("      python ci/publish.py --publish")
        print("")
        print("  Nothing was published, and no tag was affected.")
        return 1

    print("publishing %s %s as %s" % (fields.get("name"), version, detail))
    print("  tag on HEAD : %s" % wanted)
    rc, out = dry_run()
    print(out.rstrip())
    if rc != 0:
        print("")
        print("REFUSED: the dry run failed, so the real publish was not attempted.")
        return 1
    rc, out = run(["cmd", "/c", "moon", "publish"], timeout=1800)
    print(out.rstrip())
    if rc != 0:
        print("")
        print("FAILED: `moon publish` exited %d" % rc)
        return 1
    print("")
    print("PUBLISHED %s %s" % (fields.get("name"), fields.get("version")))
    return 0


def self_check_cases():
    """The checks that can be decided without the network.

    Each case is a pure function over text, so it runs with no login, no
    registry and no repository state -- and it is the reason the real check can
    be trusted to refuse later. Returns a list of problems rather than printing
    them, so `ci.py --self-check` can account for these cases in its own total
    instead of them being a separate, skippable run.
    """
    bad = []

    # A version equal to the tag is accepted; a drifting one is refused.
    def version_of(text):
        fields = {"version": text}
        problems = []
        return problems, check_version(problems, fields, "v0.1.2")

    problems, _ = version_of("0.1.2")
    if problems:
        bad.append("version matching the tag was rejected: %s" % problems)
    problems, _ = version_of("0.1.3")
    if not problems:
        bad.append("a version that drifts from the tag was accepted")
    problems, _ = version_of("0.1")
    if not problems:
        bad.append("a non-X.Y.Z version was accepted")

    # A tag without the leading v is still recognised.
    problems = []
    check_version(problems, {"version": "0.1.2"}, "0.1.2")
    if problems:
        bad.append("an unprefixed tag was not matched: %s" % problems)

    # Empty package metadata is a failure, not a default.
    problems = []
    check_package_metadata(problems, {"description": "", "repository": "",
                                      "license": "", "keywords": "[]",
                                      "readme": "nope.md"})
    if len(problems) < 4:
        bad.append("empty metadata produced %d problems, wanted >= 4"
                   % len(problems))

    # The manifest parser, against a fixture shaped like the real output: a
    # preamble, a warning block drawn with box characters, indented source
    # lines, then the paths, then the artefact line. The bug this pins is real
    # and was shipped once -- parsing the OTHER stream returned zero entries
    # and exit code 0.
    fixture = "\n".join([
        "Running moon check ...",
        "Warning: [0029]",
        "   ╭─[ <repo>/src/agentpipe/moon.pkg:2:3 ]",
        "   │",
        ' 2 │   "moonbitlang/core/encoding/utf8",',
        "   │   ────────────────┬───────────────",
        "   │                   ╰── Warning (unused_package)",
        "───╯",
        "moon.mod",
        "src/sha256/api.mbt",
        "verify_c\\x25519_harness.c",
        "Package to \\\\?\\<abs>\\_build\\publish\\riantr-moonbit_openssh-0.1.2.zip",
    ])
    entries, zip_line = parse_manifest(fixture)
    want_entries = ["moon.mod", "src/sha256/api.mbt", "verify_c/x25519_harness.c"]
    if entries != want_entries:
        bad.append("manifest parser returned %r, wanted %r"
                   % (entries, want_entries))
    if not zip_line.endswith("riantr-moonbit_openssh-0.1.2.zip"):
        bad.append("manifest parser lost the artefact line: %r" % zip_line)
    # Negative control: box-drawing fragments carry no whitespace, so a
    # whitespace-only rule would keep them as if they were paths.
    for fragment in ("│", "───╯"):
        if fragment in entries:
            bad.append("box fragment %r was parsed as a path" % fragment)

    return bad


self_check_count = 7


def self_check():
    bad = self_check_cases()
    total = self_check_count
    print("self-check: %d/%d cases passed" % (total - len(bad), total))
    for b in bad:
        print("  FAIL %s" % b)
    return 0 if not bad else 1


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if "--self-check" in argv:
        return self_check()
    if "--check" in argv:
        return cmd_check(argv)
    if "--dry-run" in argv:
        return cmd_dry_run()
    if "--publish" in argv:
        return cmd_publish()
    sys.stderr.write(
        "usage: python ci/publish.py --check [--next-tag vX.Y.Z]\n"
        "       python ci/publish.py --dry-run\n"
        "       python ci/publish.py --publish\n"
        "       python ci/publish.py --self-check\n"
    )
    return 2


if __name__ == "__main__":
    sys.exit(main())
