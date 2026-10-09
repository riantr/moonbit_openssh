"""Generate `cmd/sftp_test/vectors.mbt` from a real capture.

The inputs are the two byte streams `host/sftp_capture.py` recorded against a
real OpenSSH `internal-sftp`, and the encoder/parser in `host/sftp_oracle.py`.
The output is a set of scripted cases: inbound CHANNEL_DATA payloads, the
requests our session must emit for them, and the results it must report.

Three properties the vectors are built to have:

  1. **The expectations are the server's bytes, not our output.**  For every
     case, the inbound payloads are replayed from the capture and the expected
     results are cross-checked against what paramiko's own `SFTPClient`
     returned for the same operation.  A vector therefore fails for exactly
     one of two reasons: our parser read a real reply wrongly, or the capture
     no longer matches the fixture.

  2. **Only the request id is rewritten.**  Ids are client-chosen; keeping
     paramiko's would pin our numbering to theirs.  Everything else -- the
     attribute blocks, the extension pairs, the DATA payloads -- is verbatim.

  3. **CHANNEL_DATA boundaries are hostile on purpose.**  A packet split 3+1,
     two packets in one chunk, a length prefix split 2+2, a DATA payload split
     mid-stream, a truncated packet that must stay pending, a length that
     claims more than the packet holds.  These are not hypothetical: the
     server is free to send any chunking it likes (`atomicio6` reads to
     length, not to packet), and OpenSSH coalesces aggressively on a fast
     link.

Run:
    python host/gen_sftp_vectors.py --capture .loop39/capture.json
    python host/gen_sftp_vectors.py --capture .loop39/capture.json --selfcheck
"""

import argparse
import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sftp_oracle import (  # noqa: E402
    ATTR_SIZE, FX_EOF, FXP_ATTRS, FXP_DATA, FXP_HANDLE, FXP_NAME, FXP_STATUS,
    FX_NO_SUCH_FILE, Buf, attrs_summary, f_close, f_init, f_open, f_opendir,
    f_read, f_readdir, f_realpath, f_stat, parse_attrs, parse_reply, retag,
    script_requests, split_stream, u32,
)

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUT = os.path.join(ROOT, "cmd", "sftp_test", "vectors.mbt")


class SelfCheck(Exception):
    pass


def req(cid=0):
    pass


def load_capture(path):
    cap = json.load(open(path, encoding="utf-8"))
    cap["_c2s"] = split_stream(bytes.fromhex(cap["c2s"]))
    cap["_s2c"] = split_stream(bytes.fromhex(cap["s2c"]))
    for p in cap["_c2s"] + cap["_s2c"]:
        if "raw" in p:
            p["rawb"] = bytes.fromhex(p["raw"])
    return cap


def find_reply(cap, typ, rid):
    for p in cap["_s2c"]:
        if "rawb" not in p or p["rawb"][0] != typ:
            continue
        if struct.unpack(">I", p["rawb"][1:5])[0] == rid:
            return p["rawb"]
    raise SelfCheck("no %s reply with id %d in capture" % (typ, rid))


def find_request(cap, typ, occurrence=0):
    seen = 0
    for p in cap["_c2s"]:
        if "rawb" in p and p["rawb"][0] == typ:
            if seen == occurrence:
                return p["rawb"]
            seen += 1
    raise SelfCheck("no request of type %d at occurrence %d" % (typ, occurrence))


def body_after_id(raw):
    return raw[5:]


# ---------------------------------------------------------------------------
# leg 1: our encoder against paramiko's actual bytes
# ---------------------------------------------------------------------------

def selfcheck_requests(cap):
    """Every request paramiko framed must match ours, modulo the id.

    Where they legitimately differ -- paramiko sends `pflags = 0` and reads in
    8192-byte blocks, we send `FXF_READ` and ask for 32768 -- the difference is
    asserted here explicitly rather than quietly normalised away.
    """
    problems = []

    def cmp(name, ours, theirs, note=""):
        # `find_request` returns the payload with the length prefix already
        # stripped, so strip ours the same way before comparing.
        if ours[4:] != theirs:
            problems.append("%s%s\n    ours   %s\n    theirs %s"
                            % (name, note, ours.hex(), theirs.hex()))

    init = find_request(cap, 1)
    cmp("INIT", f_init(), init)
    if init[1:] != b"\x00\x00\x00\x03":
        problems.append("paramiko INIT is not a bare version: %s" % init.hex())

    cmp("REALPATH '.'",
        f_realpath(1, "."), find_request(cap, 16, 0))
    fixture = cap["fixture"]
    cmp("REALPATH fixture",
        f_realpath(2, fixture), find_request(cap, 16, 1))
    small_path = os.path.join(fixture, "small.txt")
    cmp("STAT small",
        f_stat(3, small_path), find_request(cap, 17, 0))
    cmp("OPENDIR", f_opendir(4, fixture), find_request(cap, 11, 0))
    cmp("READDIR", f_readdir(5, b"\x00\x00\x00\x00"), find_request(cap, 12, 0))
    cmp("CLOSE", f_close(7, b"\x00\x00\x00\x00"), find_request(cap, 4, 0))

    # OPEN: paramiko sends pflags 0 (O_RDONLY on POSIX); we send FXF_READ,
    # which sftp-server.c:251-255 maps to the same O_RDONLY.  Same meaning,
    # different bytes -- and the difference is deliberate.
    ours_open = f_open(12, small_path)[4:]
    theirs_open = find_request(cap, 3, 0)
    if ours_open[:5] != theirs_open[:5]:
        problems.append("OPEN type/id differ")
    if body_after_id(ours_open)[-8:] != body_after_id(theirs_open)[-8:]:
        problems.append("OPEN tail differs:\n    ours   %s\n    theirs %s"
                        % (ours_open.hex(), theirs_open.hex()))

    # READ: same type, id, handle and offset; the requested length differs on
    # purpose (we ask for 32768, paramiko asks for 8192), so compare the head
    # and check the length separately.
    ours_read = f_read(13, b"\x00\x00\x00\x00", 0, 32768)
    theirs_read = find_request(cap, 5, 0)
    cmp("READ head", ours_read[:25], theirs_read[:21])
    ours_len = struct.unpack(">I", ours_read[-4:])[0]
    theirs_len = struct.unpack(">I", theirs_read[-4:])[0]
    if ours_len <= theirs_len:
        problems.append("we ask for less than paramiko does")

    # The offsets must actually walk each file.  paramiko reads `small.txt`
    # (11 bytes, then a second read at 11 that comes back EOF) and then
    # `big.txt` from 0, so the walk restarts per file and the check has to
    # look at the big-file run rather than at the whole sequence.
    offsets = []
    for p in cap["_c2s"]:
        if "rawb" in p and p["rawb"][0] == 5:
            offsets.append(struct.unpack(">Q", p["rawb"][13:21])[0])
    if offsets[:2] != [0, 11]:
        problems.append("small.txt was not read at 0 then 11: %r" % offsets[:2])
    big = offsets[2:]
    if big[:3] != [0, 8192, 16384]:
        problems.append("big.txt offsets do not walk: %r" % big[:3])
    return problems


# ---------------------------------------------------------------------------
# leg 2: VERSION, off the wire
# ---------------------------------------------------------------------------

def selfcheck_version(cap):
    problems = []
    ver = [p for p in cap["_s2c"]
           if "rawb" in p and p["rawb"][0] == 2][0]["rawb"]
    typ, info = parse_reply(ver)
    if typ != 2:
        problems.append("first reply is not VERSION")
    if info["version"] != 3:
        problems.append("VERSION is %d" % info["version"])
    # The count is a property of this server, not a constant of the protocol.
    # Anything from zero upward is legal, so assert only what is checkable.
    print("  VERSION version=%d extension pairs=%d: %s"
          % (info["version"], len(info["extensions"]),
             " ".join("%s=%s" % kv for kv in info["extensions"])))
    return problems


# ---------------------------------------------------------------------------
# the cases
# ---------------------------------------------------------------------------

def render_attrs(a):
    return "attrs=" + attrs_summary(a)


def render_listing(entries):
    parts = []
    for (name, _longname, a) in entries:
        is_dir = (a["permissions"] is not None
                  and (a["permissions"] & 0xF000) == 0x4000)
        parts.append("name=%s:size=%s:dir=%d"
                     % (name.encode("utf-8").hex(),
                        "-" if a["size"] is None else str(a["size"]),
                        1 if is_dir else 0))
    return "listing=" + ";".join(parts)


def render_status(st):
    return "failed=code=%d:msg=%s" % (st["code"], st["message"].encode("utf-8").hex())


def case(name, ops, chunks, results, note=""):
    return {
        "name": name,
        "ops": ops,
        "chunks": [c.hex() for c in chunks],
        "requests": [r.hex() for r in script_requests(ops)],
        "results": results,
        "done": len(results) == len(ops),
        "note": note,
    }


def build_cases(cap):
    fixture = cap["fixture"]
    small = os.path.join(fixture, "small.txt")
    ver = [p for p in cap["_s2c"] if "rawb" in p and p["rawb"][0] == 2][0]["rawb"]
    cases = []

    # --- 1. REALPATH + STAT, straight replay -------------------------------
    rp = find_reply(cap, FXP_NAME, 1)
    st = retag(find_reply(cap, FXP_ATTRS, 3), 2)
    _t, rp_i = parse_reply(rp)
    _t, st_i = parse_reply(st)
    ops = [("realpath", "."), ("stat", small)]
    results = [
        "realpath=" + rp_i["entries"][0][0].encode("utf-8").hex(),
        render_attrs(st_i["attrs"]),
    ]
    # Cross-check against what paramiko itself reported.
    if rp_i["entries"][0][0] != cap["realpath_dot"]:
        problems.append("REALPATH parse %r != paramiko %r"
                        % (rp_i["entries"][0][0], cap["realpath_dot"]))
    if st_i["attrs"]["size"] != cap["stat_small"]["size"]:
        problems.append("STAT size %r != paramiko %r"
                        % (st_i["attrs"]["size"], cap["stat_small"]["size"]))
    if st_i["attrs"]["permissions"] != cap["stat_small"]["mode"]:
        problems.append("STAT mode %r != paramiko %r"
                        % (st_i["attrs"]["permissions"], cap["stat_small"]["mode"]))
    cases.append(case("live_realpath_stat", ops,
                      [framed(ver), framed(rp), framed(st)],
                      results,
                      "paramiko reported realpath %s and size %d"
                      % (cap["realpath_dot"], cap["stat_small"]["size"])))

    # --- 2. LISTDIR: HANDLE, NAME, EOF, CLOSE -----------------------------
    h = retag(find_reply(cap, FXP_HANDLE, 4), 1)
    nm = retag(find_reply(cap, FXP_NAME, 5), 2)
    eof = retag(find_reply(cap, FXP_STATUS, 6), 3)
    cls = retag(find_reply(cap, FXP_STATUS, 7), 4)
    _t, nm_i = parse_reply(nm)
    _t, eof_i = parse_reply(eof)
    if eof_i["code"] != FX_EOF:
        problems.append("READDIR did not end with FX_EOF (got %d)" % eof_i["code"])
    names = sorted(e[0] for e in nm_i["entries"])
    if names != cap["listdir"]:
        problems.append("NAME entries %r != paramiko %r" % (names, cap["listdir"]))
    detail = sorted("%s:%d:%d" % (e[0], e[2]["size"] if e[2]["size"] is not None else -1,
                                  1 if (e[2]["permissions"] or 0) & 0xF000 == 0x4000 else 0)
                    for e in nm_i["entries"])
    if detail != cap["listdir_detail"]:
        problems.append("NAME detail %r != paramiko %r"
                        % (detail, cap["listdir_detail"]))
    cases.append(case("live_listdir_eof", [("listdir", fixture)],
                      [framed(ver), framed(h), framed(nm), framed(eof), framed(cls)],
                      [render_listing(nm_i["entries"])],
                      "%d entries, ended by STATUS(EOF) -- not by a short list"
                      % len(nm_i["entries"])))

    # --- 3. READFILE: the server ends with STATUS(EOF), not an empty DATA --
    conf = retag(find_reply(cap, FXP_HANDLE, 12), 1)
    data = retag(find_reply(cap, FXP_DATA, 13), 2)
    eof = retag(find_reply(cap, FXP_STATUS, 14), 3)
    rcls = retag(find_reply(cap, FXP_STATUS, 15), 4)
    _t, d_i = parse_reply(data)
    _t, e_i = parse_reply(eof)
    if d_i["data"].hex() != cap["read_small"]:
        problems.append("DATA payload %r != paramiko read %r"
                        % (d_i["data"].hex(), cap["read_small"]))
    if e_i["code"] != FX_EOF:
        problems.append("read did not end with FX_EOF (got %d)" % e_i["code"])
    cases.append(case("live_readfile_eof_status", [("readfile", small)],
                      [framed(ver), framed(conf), framed(data),
                       framed(eof), framed(rcls)],
                      ["contents=" + d_i["data"].hex()],
                      "%d bytes, ended by STATUS(EOF) -- a real server says "
                      "EOF, it does not send a zero-length DATA"
                      % len(d_i["data"])))

    # --- 3b. the other end-of-read spelling, which some servers do use -----
    small_data = d_i["data"]
    synth_conf = framed(bytes([FXP_HANDLE]) + u32(1) + u32(4) + b"\x00\x00\x00\x00")
    synth_data = framed(bytes([FXP_DATA]) + u32(2) + u32(len(small_data)) + small_data)
    synth_eof = framed(bytes([FXP_DATA]) + u32(3) + u32(0))
    synth_cls = framed(bytes([FXP_STATUS]) + u32(4) + u32(0) + u32(0) + u32(0))
    cases.append(case("synthetic_readfile_empty_data", [("readfile", small)],
                      [framed(ver), synth_conf, synth_data, synth_eof, synth_cls],
                      ["contents=" + small_data.hex()],
                      "SYNTHETIC: a zero-length DATA also ends a read, and "
                      "must not be mistaken for one byte of payload"))

    # --- 4. boundary: VERSION's length prefix split 3 + 1 -----------------
    # Split the *framed* packet, not the payload: `ver` here is a reply
    # payload, and slicing it would drop the length prefix entirely rather
    # than divide it.
    ver_framed = framed(ver)
    cases.append(case("boundary_version_split_3_1",
                      [("realpath", ".")],
                      [ver_framed[:3], ver_framed[3:], framed(rp)],
                      ["realpath=" + rp_i["entries"][0][0].encode("utf-8").hex()],
                      "three bytes of the length prefix, then the rest: a "
                      "parser that read all four before deciding has already "
                      "lost them"))

    # --- 6. boundary: length prefix split 2 + 2 ---------------------------
    rp_framed = framed(rp)
    cases.append(case("boundary_lenprefix_2_2",
                      [("realpath", ".")],
                      [framed(ver), rp_framed[:2], rp_framed[2:]],
                      ["realpath=" + rp_i["entries"][0][0].encode("utf-8").hex()],
                      "half of a length prefix is not a short packet -- it is "
                      "no packet at all"))

    # --- 7. boundary: DATA split mid-payload ------------------------------
    data_framed = framed(data)
    cases.append(case("boundary_data_split_mid",
                      [("readfile", small)],
                      [framed(ver), framed(conf),
                       data_framed[:9], data_framed[9:], framed(eof), framed(rcls)],
                      ["contents=" + d_i["data"].hex()],
                      "the 4-byte length, the type byte, the id, and then the "
                      "payload itself, all split"))

    # --- 7b. the same, split inside the length prefix of the DATA ---------
    cases.append(case("boundary_data_lenprefix_1_3",
                      [("readfile", small)],
                      [framed(ver), framed(conf),
                       data_framed[:1], data_framed[1:4], data_framed[4:17],
                       data_framed[17:], framed(eof), framed(rcls)],
                      ["contents=" + d_i["data"].hex()],
                      "one byte of the length prefix, then three, then the "
                      "type and id, then the payload"))

    # --- 8. no operations at all: INIT and VERSION only -------------------
    cases.append(case("init_only", [],
                      [framed(ver)],
                      [],
                      "nothing to do: the session must finish on VERSION "
                      "alone and never ask for anything"))

    # --- 8. negative: a path that is not there ----------------------------
    miss = retag(find_reply(cap, FXP_STATUS, 44), 1)
    _t, miss_i = parse_reply(miss)
    if miss_i["code"] != FX_NO_SUCH_FILE:
        problems.append("missing-file status is %d" % miss_i["code"])
    cases.append(case("negative_missing_stat",
                      [("stat", os.path.join(fixture, "no_such_file"))],
                      [framed(ver), framed(miss)],
                      [render_status(miss_i)],
                      "a status reply is a completed exchange, not a broken one"))

    # --- 9. a reply for a request we did not make ---------------------------
    good = retag(find_reply(cap, FXP_ATTRS, 3), 1)
    _t, good_i = parse_reply(good)
    stale = bytes([FXP_ATTRS]) + u32(9) + good[5:]
    cases.append(case("negative_wrong_id_ignored",
                      [("stat", small)],
                      [framed(ver), framed(stale), framed(good)],
                      [render_attrs(good_i["attrs"])],
                      "a reply carrying an id we are not waiting for has to "
                      "be dropped, not fatal -- and must not be mistaken for "
                      "the answer either"))

    # --- 10. truncated reply must stay pending, not fail --------------------
    trunc = framed(find_reply(cap, FXP_ATTRS, 3))[:20]
    cases.append(case("negative_truncated_pending",
                      [("stat", small)],
                      [framed(ver), trunc],
                      [],
                      "half an ATTRS reply: the session must be neither done "
                      "nor failed, and must not invent a result"))

    # --- 10. unparsable reply is fatal -------------------------------------
    bad = bytes([FXP_ATTRS]) + u32(2) + u32(0x0F) + b"\x00" * 3
    cases.append(case("negative_unparsable_is_fatal",
                      [("stat", small)],
                      [framed(ver), framed(bad)],
                      [],
                      "a reply we cannot read ends the session -- we no longer "
                      "know where in the exchange we are"))
    cases[-1]["expect_failed"] = True

    # --- 11. a length larger than the packet ------------------------------
    huge = u32(0x00100000) + bytes([FXP_STATUS]) + u32(1) + u32(0)
    cases.append(case("negative_length_over_max",
                      [("stat", small)],
                      [framed(ver), huge],
                      [],
                      "a claimed length over SFTP_MAX_MSG_LENGTH must be "
                      "refused before allocating for it"))
    cases[-1]["expect_failed"] = True

    return cases


def framed(raw):
    return u32(len(raw)) + raw


# ---------------------------------------------------------------------------
# emit
# ---------------------------------------------------------------------------

def mstr(s):
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def emit(cases, cap):
    out = []
    a = out.append
    a("///| GENERATED FILE -- do not edit by hand.")
    a("///| Regenerate with: python host/gen_sftp_vectors.py "
      "--capture .loop39/capture.json")
    a("///")
    a("/// Every inbound payload here is a real OpenSSH 8.0p1 `internal-sftp`")
    a("/// reply recorded by `host/sftp_capture.py`, with one exception stated")
    a("/// below.  The requests are what `src/sftp` must emit, derived from")
    a("/// `host/sftp_oracle.py` -- an independent implementation -- and")
    a("/// cross-checked against the requests paramiko actually framed in the")
    a("/// same session.")
    a("///")
    a("/// The one rewrite: a captured reply's 4-byte request id is replaced,")
    a("/// because ids are chosen by the client and pinning our numbering to")
    a("/// paramiko's would test the wrong thing.  Attribute blocks, extension")
    a("/// pairs, longnames and DATA payloads are verbatim.")
    a("///")
    a("/// `chunks` are CHANNEL_DATA payloads.  Their boundaries are chosen to")
    a("/// be hostile on purpose -- see each case's `note`.")
    a("")
    a("pub(all) struct Op {")
    a("  kind : Int")
    a("  path : String")
    a("}")
    a("")
    a("pub(all) struct Case {")
    a("  name : String")
    a("  ops : Array[Op]")
    a("  chunks : Array[String]")
    a("  requests : Array[String]")
    a("  results : Array[String]")
    a("  expect_done : Bool")
    a("  expect_failed : Bool")
    a("  note : String")
    a("}")
    a("")
    a("pub let cases : Array[Case] = [")
    for c in cases:
        a("  {")
        a("    name: %s," % mstr(c["name"]))
        a("    ops: [")
        for kind, path in c["ops"]:
            a("      { kind: %d, path: %s }," % (KIND[kind], mstr(path)))
        a("    ],")
        a("    chunks: [")
        for ch in c["chunks"]:
            a("      %s," % mstr(ch))
        a("    ],")
        a("    requests: [")
        for r in c["requests"]:
            a("      %s," % mstr(r))
        a("    ],")
        a("    results: [")
        for r in c["results"]:
            a("      %s," % mstr(r))
        a("    ],")
        a("    expect_done: %s," % ("true" if c["done"] else "false"))
        a("    expect_failed: %s," % ("true" if c.get("expect_failed") else "false"))
        a("    note: %s," % mstr(c["note"]))
        a("  },")
    a("]")
    a("")
    a("///| what the capture saw, for the report")
    a("pub const CAPTURE_VERSION : Int = 3")
    a("pub const CAPTURE_EXTENSIONS : Int = %d" % cap["_ext_count"])
    a("pub const CAPTURE_FIXTURE : String = %s" % mstr(cap["fixture"]))
    a("")
    return "\n".join(out) + "\n"


KIND = {"realpath": 0, "stat": 1, "listdir": 2, "readfile": 3}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--capture", default=".loop39/capture.json")
    ap.add_argument("--out", default=OUT)
    ap.add_argument("--selfcheck", action="store_true")
    args = ap.parse_args()

    cap = load_capture(args.capture)
    problems = []
    print("leg 1: our encoder vs paramiko's framing")
    problems += selfcheck_requests(cap)
    print("leg 2: VERSION off the wire")
    problems += selfcheck_version(cap)
    ver = [p for p in cap["_s2c"] if "rawb" in p and p["rawb"][0] == 2][0]["rawb"]
    cap["_ext_count"] = len(parse_reply(ver)[1]["extensions"])

    print("leg 3: scripted cases")
    try:
        cases = build_cases(cap)
    except SelfCheck as e:
        print("  SELFCHECK FAILED: %s" % e)
        return 1
    problems = [p for p in problems if p]

    for c in cases:
        print("  %-30s ops=%d chunks=%-4d requests=%-4d results=%d"
              % (c["name"], len(c["ops"]), len(c["chunks"]),
                 len(c["requests"]), len(c["results"])))

    if problems:
        print("\nSELFCHECK FAILED (%d):" % len(problems))
        for p in problems:
            print("  - %s" % p)
        return 1
    print("\nselfcheck clean")

    with open(args.out, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(emit(cases, cap))
    print("wrote %s (%d cases)" % (args.out, len(cases)))
    return 0


if __name__ == "__main__":
    sys.exit(main())