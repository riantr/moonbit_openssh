#!/usr/bin/env python3
"""Emit cmd/proton_gui/fault_vectors.mbt from the oracle's JSON.

The JSON is the artifact the oracle checked itself against; this file only
transcribes it into MoonBit syntax, so there is exactly one place where the
expected bytes are written down and a second (independent) place where they
are derived.
"""

import io
import json
import sys

HEADER = '''///| GENERATED FILE -- do not edit by hand.
///|
/// Regenerate: python host/gen_fault_vectors.py host/sftp_fault_oracle.py-out.json
///
/// Every inbound payload and every expected request below comes from
/// `host/sftp_fault_oracle.py`, which is an independent implementation
/// written from the SFTP v3 draft and OpenSSH's error branches with no
/// reference to `src/sftp`.  The oracle refuses to emit this file unless its
/// own run of each scenario agrees with the hand-written expectation, so a
/// scenario cannot silently become "whatever the implementation does".
///
/// These are the replies a *well-behaved* server never sends.  The Loop #39
/// KAT and the live sshd round trip both prove the happy path against real
/// bytes; nothing in either of them can reach "STATUS before VERSION" or
/// "a length prefix over the maximum", because OpenSSH does not emit them.
/// That is the whole reason this console exists.

pub(all) struct Op {
  /// 0 realpath, 1 stat, 4 writefile, 9 rename
  kind : Int
  path : String
  ///| the rename target, or the hex payload of a writefile
  arg : String
}

pub(all) struct FaultCase {
  name : String
  intent : String
  ops : Array[Op]
  ///| inbound CHANNEL_DATA payloads, as hex
  feeds : Array[String]
  ///| the requests we must emit, as hex
  requests : Array[String]
  ///| one rendered line per result, the way `cmd/sftp_test` renders them
  results : Array[String]
  expect_done : Bool
  expect_failed : Bool
  expect_reason : String
}

pub let fault_cases : Array[FaultCase] = [
'''

FOOTER = ''']
'''


def mbt_str(s):
    return '"' + s.replace('\\', '\\\\').replace('"', '\\"') + '"'


def render_result(r):
    kind = r[0]
    if kind == "realpath":
        return "realpath=" + r[1].encode("latin-1").hex()
    if kind == "attrs":
        return "attrs="
    if kind == "changed":
        return "changed"
    if kind == "wrote":
        return "wrote=" + str(r[1])
    if kind == "contents":
        return "contents=" + r[1].hex()
    if kind == "failed":
        return (
            "failed=code="
            + str(r[1])
            + ":msg="
            + r[2].encode("latin-1").hex()
        )
    raise SystemExit("unknown result kind " + kind)


KIND = {"realpath": 0, "stat": 1, "writefile": 4, "rename": 9}


def main():
    src = sys.argv[1]
    dst = sys.argv[2]
    data = json.load(io.open(src, encoding="utf-8"))
    out = [HEADER]
    for c in data:
        out.append("  {\n")
        out.append("    name: " + mbt_str(c["name"]) + ",\n")
        out.append("    intent: " + mbt_str(c["intent"]) + ",\n")
        ops = []
        for o in c["ops"]:
            if len(o) > 2 and o[0] != "rename":
                arg = o[2]
            else:
                arg = o[2] if len(o) > 2 else ""
            ops.append(
                "{ kind: "
                + str(KIND[o[0]])
                + ", path: "
                + mbt_str(o[1])
                + ", arg: "
                + mbt_str(arg)
                + " }"
            )
        out.append("    ops: [" + ", ".join(ops) + "],\n")
        out.append(
            "    feeds: ["
            + ", ".join(mbt_str(f) for f in c["feeds"])
            + "],\n"
        )
        out.append(
            "    requests: ["
            + ", ".join(mbt_str(q) for q in c["requests"])
            + "],\n"
        )
        out.append(
            "    results: ["
            + ", ".join(mbt_str(render_result(r)) for r in c["results"])
            + "],\n"
        )
        out.append("    expect_done: " + ("true" if c["done"] else "false") + ",\n")
        out.append(
            "    expect_failed: " + ("true" if c["failed"] else "false") + ",\n"
        )
        out.append(
            "    expect_reason: " + mbt_str(c["failure_reason"]) + ",\n"
        )
        out.append("  },\n")
    out.append(FOOTER)
    io.open(dst, "w", encoding="utf-8", newline="\n").write("".join(out))
    print(f"wrote {dst}: {len(data)} cases")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
