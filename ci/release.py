#!/usr/bin/env python3
"""ci/release.py -- the tag / push gate.

## The rule this file enforces

* **No tag while the local CI is not fully green.** Not even on request.
  The owner has explicitly asked for this because they know they will forget:
  "在本地CI未全绿之前禁止打tag，即便是我要求的". A tag is the one artefact that
  says "this is the tested state of the project", so it must be the *last*
  thing produced, never an exception.
* **A tag only moves its final component.** `v0.1.0` -> `v0.1.1` -> `v0.1.2`.
  Nothing else about the tag changes, so a series of tags reads as a series of
  tested states rather than a series of renames. This holds until the owner
  says otherwise.
* **Gitee may be pushed at any time.** It is the working remote.
* **GitHub is pushed only when the local CI is green and a tag exists.**
  The GitHub remote exists (added 2026-10-19), so this half of the rule has
  something to act on: `git push github main --follow-tags` after the tag.
* **mooncakes.io is published only when CI is green, the tag exists, and
  `moon.mod`'s `version` equals that tag.** The version/tag agreement is
  enforced by `assert_version_matches_tag` below, and the publication itself
  by `ci/publish.py`, which refuses loudly when no identity is logged in
  rather than skipping.

`next_tag` is deliberately a pure function so `--self-check` can test the
numbering without a repository, a tag, or a network. `assert_version_matches_tag`
is pure for the same reason.
"""

import re

# A tag ending in digits. The digits are moved; everything before them is
# kept verbatim. So `v0.1.0` becomes `v0.1.1`, and a date-shaped
# `release-2026-10` becomes `release-2026-11` -- which is the same rule, "only
# the trailing number moves", applied to a different naming scheme. A tag with
# no trailing digits (`nightly`) cannot be advanced this way and is refused
# rather than guessed at.
VERSION_TAG_RE = re.compile(r"^(?P<head>.+?)(?P<last>\d+)$")

# The shape `moon.mod` must declare before it can be compared with a tag. Three
# numeric components, nothing else: mooncakes.io treats the string as an
# ordered version, and a version it cannot order is a version a user cannot
# pin.
VERSION_STRING_RE = re.compile(r"^\d+\.\d+\.\d+$")


class TagError(Exception):
    """The requested tag cannot be produced, or must not be."""


def next_tag(existing):
    """The tag that follows the newest one, moving only the trailing number.

    Raises TagError when there is nothing to move: no tags at all, or a newest
    tag with no trailing digits. Guessing a numbering scheme here would produce
    a tag nobody can interpret.
    """
    if not existing:
        raise TagError(
            "no tag exists yet; refusing to invent a numbering scheme. "
            "Create the first tag by hand once, then the gate takes over."
        )
    newest = max(existing)
    m = VERSION_TAG_RE.match(newest)
    if not m:
        raise TagError(
            "newest tag %r does not end in a number, so 'change only the last "
            "digit' is undefined. Ask the owner instead of guessing." % newest
        )
    head = m.group("head")
    nxt = int(m.group("last")) + 1
    # Preserve the zero padding of the component we are replacing, so a project
    # that uses v1.09 does not silently become v1.10 while we only meant v1.10.
    width = len(m.group("last"))
    return "%s%s" % (head, str(nxt).zfill(width))


def assert_version_matches_tag(version, tag):
    """The published version and the git tag must be the same claim.

    A tag says "this exact tree was verified". `moon.mod`'s `version` says what
    a `moon add` user receives. When they disagree, a published version cannot
    be traced back to a commit -- and nothing in either toolchain checks it, so
    it is checked here, before the tag exists.

    `v` is stripped from the tag but not invented: a tag of `v0.1.2` must match
    a version of `0.1.2`, and a tag without the prefix is accepted as-is.
    """
    if not VERSION_STRING_RE.match(version or ""):
        raise TagError(
            "moon.mod version %r is not X.Y.Z, so it cannot be compared with a "
            "tag" % (version,)
        )
    wanted = tag[1:] if tag.startswith("v") else tag
    if version != wanted:
        raise TagError(
            "moon.mod version is %r but the next tag is %r. Publishing %r would "
            "release a version that names no commit. Bump `version` in moon.mod "
            "to %r as part of the change being tagged." %
            (version, tag, version, wanted)
        )
    return True


def assert_tag_allowed(failed_steps, ran_steps, skipped_tiers):
    """Refuse to tag unless every step that ran passed.

    `skipped_tiers` is reported rather than treated as failure: some tiers
    (peer-gates, mutations) are excluded by design and take hours. Hiding that
    would make the green meaningless, so it is printed at the moment the tag
    is granted.
    """
    problems = []
    if not ran_steps:
        problems.append("no steps ran, so nothing was verified")
    if failed_steps:
        names = ", ".join(s if isinstance(s, str) else s.name for s in failed_steps)
        problems.append("%d step(s) failed: %s" % (len(failed_steps), names))
    if problems:
        raise TagError("; ".join(problems))
    return True
