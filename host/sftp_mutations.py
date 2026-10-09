"""Mutation check: every Loop #39 design decision must turn the KAT red.

Each mutation below is one of the decisions that were actually argued about
while writing `src/sftp`, turned into the plausible mistake on the other side
of it.  A KAT that stays green under all of them is not testing anything, so
this script is part of the loop's evidence rather than a one-off.

The ones worth reading twice:

  * the reply numbers.  `FXP_STATUS = 101, HANDLE = 102, DATA = 103,
    NAME = 104, ATTRS = 105` is the wire order.  The draft lists the same five
    numbers sorted by name -- 101 DATA, 102 HANDLE, 103 NAME, 104 ATTRS,
    105 STATUS -- which is exactly what you write down from memory, and it
    makes every reply parse as some other reply.  Capturing a real
    `internal-sftp` is the only reason this repo is on the right side of it.

  * VERSION's trailing extension pairs.  A parser that wants end-of-packet
    after the version number dies on the first byte a real server sends.

  * STATUS's language tag.  Same shape: `expect_end` before reading it turns
    every STATUS into a parse failure, including the `FX_EOF` that ends a
    read and the `SSH2_FX_NO_SUCH_FILE` a negative test expects.

  * READ's offset accumulating, and a short chunk not being EOF.

Run:  python host/sftp_mutations.py
"""

import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# Loop #39 touched five files under src/sftp; all of them have to be restored
# together or a failed run leaves the tree mutated.
FILES = [
    os.path.join(ROOT, "src", "sftp", "proto.mbt"),
    os.path.join(ROOT, "src", "sftp", "attrs.mbt"),
    os.path.join(ROOT, "src", "sftp", "build.mbt"),
    os.path.join(ROOT, "src", "sftp", "parse.mbt"),
    os.path.join(ROOT, "src", "sftp", "stream.mbt"),
    os.path.join(ROOT, "src", "sftp", "session.mbt"),
]

# (label, original, mutated, a check name that must go FAIL)
MUTATIONS = [
    # ---- the wire numbers ------------------------------------------------
    (
        "swap DATA and ATTRS: the draft's by-name order, not the wire order",
        "pub const FXP_DATA : Int = 103",
        "pub const FXP_DATA : Int = 104",
        "live_readfile_eof_status",
    ),
    (
        "swap NAME and ATTRS",
        "pub const FXP_ATTRS : Int = 105",
        "pub const FXP_ATTRS : Int = 103",
        "live_realpath_stat",
    ),
    (
        "swap STATUS and HANDLE",
        "pub const FXP_STATUS : Int = 101",
        "pub const FXP_STATUS : Int = 102",
        "negative_missing_stat",
    ),

    # ---- VERSION ---------------------------------------------------------
    (
        "demand end-of-packet right after the version number",
        "  Parsed(SftpReply::Version({ version: v, extensions: n }))",
        "  match c.err {\n    Some(_) => return Rejected(SftpError::TrailingData)\n"
        "    None => ()\n  }\n"
        "  Parsed(SftpReply::Version({ version: v, extensions: 0 }))",
        "live_realpath_stat",
    ),

    # ---- STATUS ----------------------------------------------------------
    (
        "stop before STATUS's language tag",
        "  let msg = c.string()\n  let lang = c.string()\n  c.expect_end()",
        "  let msg = c.string()\n  c.expect_end()\n"
        "  let lang = c.string()\n  let _ = lang",
        "live_listdir_eof",
    ),

    # ---- framing ---------------------------------------------------------
    (
        "include the length prefix in the length itself",
        "pub fn sftp_frame(body : FixedArray[Byte]) -> FixedArray[Byte] {",
        "pub fn sftp_frame(body : FixedArray[Byte]) -> FixedArray[Byte] {\n"
        "  // sftp-client.c:151-173 -- the count excludes itself\n"
        "  return sftp_cat([put_u32i(body.length() + 4), body])",
        "live_realpath_stat",
    ),
    (
        "allocate for the claimed length before bounding it",
        "    if n < 0 || n > SFTP_MAX_MSG_LENGTH {",
        "    if n < 0 {",
        "negative_length_over_max",
    ),
    (
        "consume the bytes of a refused packet anyway",
        "      self.failed = Some(Unexpected(n))\n      return None",
        "      self.failed = Some(Unexpected(n))\n"
        "      self.drop(4)\n      return None",
        "length_over_max_refused",
    ),

    # ---- stream reassembly ----------------------------------------------
    (
        "drop the partial packet when a read comes up short",
        "  if self.buf.length() < self.want {\n    return None\n  }",
        "  if self.buf.length() < self.want {\n"
        "    self.drop(self.buf.length())\n    return None\n  }",
        "boundary_data_split_mid",
    ),
    (
        "hand back one packet and stop, losing the rest of the buffer",
        "  let mut again = true\n  while again {\n    match self.take() {",
        "  let mut again = false\n  while again {\n    match self.take() {",
        "two_packets_one_feed",
    ),

    # ---- attributes ------------------------------------------------------
    (
        "read size unconditionally, ignoring the flag word",
        "  if (flags & ATTR_SIZE) != 0 {\n    out.size = Some(self.u64())",
        "  if true {\n    out.size = Some(self.u64())",
        "live_realpath_stat",
    ),
    (
        "read a directory flag as if it were the file type's low byte",
        "  match a.permissions {\n    Some(p) => (p & 0xF000) == 0x4000",
        "  match a.permissions {\n    Some(p) => (p & 0xF000) == 0x8000",
        "live_listdir_eof",
    ),

    # ---- the scripted session -------------------------------------------
    (
        "restart the READ offset every round instead of accumulating",
        "          self.offset = self.offset + d.data.length().to_uint64()",
        "          self.offset = 0",
        "boundary_data_split_mid",
    ),
    (
        "end a read on the first short chunk",
        "          if d.data.length() == 0 {",
        "          if d.data.length() < 32768 {",
        "live_readfile_eof_status",
    ),
    (
        "end a directory listing on a short name list instead of on STATUS(EOF)",
        "        Name(nm) => {\n          for i = 0; i < nm.names.length(); i = i + 1 {",
        "        Name(nm) => {\n          if nm.names.length() < 32 {\n"
        "            self.flush_listing()\n            self.send_close()\n"
        "            return\n          }\n"
        "          for i = 0; i < nm.names.length(); i = i + 1 {",
        "live_listdir_eof",
    ),
    (
        "treat a wrong-id reply as fatal instead of ignoring it",
        "    WantStat(id) => {\n      if reply_id(r) != id {\n        return\n      }",
        "    WantStat(id) => {\n      if reply_id(r) != id {\n"
        "        self.phase = PH_FAILED\n"
        "        self.failure = Some(\"wrong id\")\n        return\n      }",
        "negative_wrong_id_ignored",
    ),
    (
        "carry on after an unreadable reply",
        "        self.phase = PH_FAILED\n"
        "        self.failure = Some(\"unparsable reply: \" + sftp_error_name(e))\n"
        "        return",
        "        return",
        "negative_unparsable_is_fatal",
    ),
    (
        "ignore a framing failure and keep waiting for a reply",
        "    Some(e) => {\n      self.phase = PH_FAILED\n"
        "      self.failure = Some(\"framing: \" + sftp_error_name(e))\n"
        "      return\n    }",
        "    Some(_) => ()\n"
        "    None => ()",
        "negative_length_over_max",
    ),
    (
        "number requests from 0, so the first real request and 'nothing sent' "
        "look the same",
        "    next_id: 1,",
        "    next_id: 0,",
        "live_realpath_stat",
    ),
]


def read():
    state = {}
    for p in FILES:
        with open(p, encoding="utf-8") as fh:
            state[p] = fh.read()
    return state


def write(state):
    for p, text in state.items():
        with open(p, "w", encoding="utf-8", newline="") as fh:
            fh.write(text)


def run_kat():
    # `moon` emits UTF-8 box-drawing diagnostics on Windows consoles whose
    # active code page is GBK, and `text=True` would decode them as GBK and
    # raise.  Read bytes and decode explicitly.
    r = subprocess.run(
        ["moon", "run", "cmd/sftp_test", "--target", "native"],
        cwd=ROOT, capture_output=True,
    )
    return (r.stdout + r.stderr).decode("utf-8", "replace")


def main():
    original = read()
    failures = []
    try:
        for label, old, new, must_fail in MUTATIONS:
            target = None
            for p, text in original.items():
                if text.count(old) == 1:
                    target = p
                    break
            if target is None:
                counts = {os.path.basename(p): t.count(old)
                          for p, t in original.items()}
                print("SKIP  %s -- anchor count %s" % (label, counts))
                failures.append(label)
                continue
            state = dict(original)
            state[target] = state[target].replace(old, new)
            write(state)
            out = run_kat()
            caught = ("FAIL " + must_fail) in out or (must_fail + ":") in out
            print("%s  %s" % ("CAUGHT" if caught else "MISSED", label))
            if not caught:
                failures.append(label)
                for line in out.splitlines():
                    if "FAIL" in line:
                        print("        " + line.strip())
    finally:
        write(original)

    print()
    if failures:
        print("MUTATION CHECK FAILED: %d of %d not caught"
              % (len(failures), len(MUTATIONS)))
        return 1
    print("all %d mutations turned the KAT red" % len(MUTATIONS))
    return 0


if __name__ == "__main__":
    sys.exit(main())