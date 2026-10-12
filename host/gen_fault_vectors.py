#!/usr/bin/env python3
"""Emit a MoonBit vector table from the oracle's JSON.

The JSON is the artifact the oracle checked itself against; this file only
transcribes it into MoonBit syntax, so there is exactly one place where the
expected bytes are written down and a second (independent) place where they
are derived.

Four consumers exist and all four read the same table, so `host/verify_loop41.mjs`
checks that their copies agree rather than trusting it.
"""

import io
import json
import sys

HEADER = '''///| GENERATED FILE -- do not edit by hand.
///
/// Regenerate: python host/gen_fault_vectors.py <oracle.json> <out.mbt>
///
/// Every inbound payload and every expected request below comes from
/// `host/sftp_fault_oracle.py`, which is an independent implementation
/// written from the SFTP v3 draft and OpenSSH's error branches with no
/// reference to `src/sftp`.  The oracle refuses to emit this file unless its
/// own run of each scenario agrees with the hand-written expectation, so a
/// scenario cannot silently become "whatever the implementation does".
///
/// Four copies of this table are generated from that one JSON, and they must
/// stay identical -- same scenarios, same expectations -- so that a difference
/// between two layers is a transport bug and not two different test sets:
///
///   cmd/proton_gui/fault_vectors.mbt  fed straight to `SftpSession`
///   cmd/sftp_fault/vectors.mbt        re-sliced through the channel layer
///   cmd/sftp_mitm/vectors.mbt         over a real socket, behind a MITM
///   cmd/wt_ssh/fault_vectors.mbt      in a browser Worker, over WebSocket

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
  ///| CHANNEL_DATA cut points the channel-layer driver must reproduce this
  ///| case at. Re-slicing the inbound stream must not change the answer --
  ///| that is the invariant `src/sftp/stream.mbt` exists to hold.
  chop_sizes : Array[Int]
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
        out.append("    expect_failed: " + ("true" if c["failed"] else "false") + ",\n")
        out.append(
            "    expect_reason: " + mbt_str(c["failure_reason"]) + ",\n"
        )
        chop = c.get("chop_sizes") or []
        out.append(
            "    chop_sizes: [" + ", ".join(str(n) for n in chop) + "],\n"
        )
        out.append("  },\n")
    out.append(FOOTER)
    io.open(dst, "w", encoding="utf-8", newline="\n").write("".join(out))
    print(f"wrote {dst}: {len(data)} cases")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())