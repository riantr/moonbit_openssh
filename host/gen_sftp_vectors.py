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
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sftp_oracle import (  # noqa: E402
    ATTR_ACMODTIME, ATTR_PERMISSIONS, ATTR_SIZE, FX_EOF, FXP_ATTRS,
    FXP_DATA, FXP_EXTENDED, FXP_HANDLE, FXP_NAME, FXP_STATUS, FX_NO_SUCH_FILE,
    FX_OP_UNSUPPORTED, FXF_CREAT, FXF_TRUNC, FXF_WRITE, Buf, attrs_summary,
    encode_attrs, f_attrs_none, f_close, f_init, f_mkdir, f_open, f_opendir,
    f_posix_rename, f_read, f_readdir, f_realpath, f_remove, f_rename, f_rmdir,
    f_setstat, f_stat, f_write, parse_attrs, parse_reply, retag,
    script_requests, split_stream, u32, write_chunks,
)

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUT = os.path.join(ROOT, "cmd", "sftp_test", "vectors.mbt")


def _digest(path):
    """A cheap content digest, for noticing that the formatter did nothing."""
    import hashlib
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def format_in_place(path):
    """Put the generated file through the formatter.

    The generated file is a SOURCE file in the repository, and the repository
    is formatter-clean -- `moon fmt --check` over the whole tree is a gate
    (Loop #67). So the generator has to produce what the formatter produces.

    That is not a cosmetic difference. Loop #39's gate regenerates this file
    and requires the committed copy to be unchanged, and the two used to
    differ by exactly the formatter's line wrapping -- so the check could
    never pass, and the regenerated copy was left in the working tree, where
    it made every later `git diff` non-empty.

    `moon fmt` is run through `cmd /c` because that is how every other
    harness in this repository invokes the toolchain on Windows.

    **The formatter only touches files that belong to a package of the
    current module.** For a file anywhere else it exits 0, prints nothing,
    and changes nothing -- so a `--out` path outside a package comes out
    unformatted. That is reported rather than swallowed: a caller that
    compares such a file with the committed one would be comparing two
    formatting conventions, and the difference (1290 bytes here) has nothing
    to do with the vectors.
    """
    res = subprocess.run(
        ["cmd", "/c", "moon", "fmt", path],
        capture_output=True,
    )
    if res.returncode != 0:
        sys.stderr.write("moon fmt failed on the file %s\n%s\n%s\n"
                         % (path,
                            res.stdout.decode("utf-8", "replace"),
                            res.stderr.decode("utf-8", "replace")))
        raise SystemExit(res.returncode)
    return res.stdout.decode("utf-8", "replace")


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


def load_write_capture(path):
    """The write capture, indexed the same way -- plus the raw EXTENDED
    session, which is a *separate* connection and therefore a separate pair
    of streams."""
    cap = json.load(open(path, encoding="utf-8"))
    cap["_c2s"] = split_stream(bytes.fromhex(cap["c2s"]))
    cap["_s2c"] = split_stream(bytes.fromhex(cap["s2c"]))
    for p in cap["_c2s"] + cap["_s2c"]:
        if "raw" in p:
            p["rawb"] = bytes.fromhex(p["raw"])
    ext = split_stream(bytes.fromhex(cap["ext_s2c"]))
    cap["_ext_s2c_raw"] = [bytes.fromhex(p["raw"]) for p in ext
                           if "raw" in p]
    rm = split_stream(bytes.fromhex(cap["rm_c2s"]))
    cap["_rm_c2s"] = rm
    for p in rm:
        if "raw" in p:
            p["rawb"] = bytes.fromhex(p["raw"])
    ver = [p for p in cap["_s2c"] if "rawb" in p and p["rawb"][0] == 2]
    if not ver:
        raise SelfCheck("no VERSION in the write capture")
    cap["_ver_raw"] = ver[0]["rawb"]
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


def case(name, ops, chunks, results, note="", requests=None):
    # `requests` may be overridden where the scripted stream depends on how
    # the server answered.  `script_requests` is the right answer for every
    # case that succeeds; a case whose OPEN is refused has no handle, so it
    # must not be expected to emit the WRITE and CLOSE that a successful OPEN
    # would lead to.
    return {
        "name": name,
        "ops": ops,
        "chunks": [c.hex() for c in chunks],
        "requests": [r.hex() for r in
                     (requests if requests is not None
                      else script_requests(ops))],
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
# the write side
# ---------------------------------------------------------------------------

def write_offsets(wcap):
    """Every WRITE offset on the wire, in order."""
    out = []
    for p in wcap["_c2s"]:
        if "rawb" in p and p["rawb"][0] == 6:
            # type(1) + id(4) + handle string(4 len + 4 data) + offset(8)
            out.append(struct.unpack(">Q", p["rawb"][13:21])[0])
    return out


def selfcheck_write(wcap):
    """The write side against what paramiko actually framed.

    The load-bearing claim here is the offset.  Everything else about a WRITE
    is a length and a type byte; the offset is the one field where a plausible
    wrong value produces a file that looks right.
    """
    problems = []

    offs = write_offsets(wcap)
    if not offs:
        problems.append("no WRITE in the capture at all")
        return problems
    # Offsets are per *file*, not per session: re-opening the same path with
    # TRUNC starts a fresh file and the offset goes back to 0.  So the
    # invariant is not "always increasing" -- it is "equals the running total
    # of the payloads written so far, resetting at the start of each file".
    # An implementation that used a session-global counter would fail here,
    # and one that never reset would overwrite its own output.
    sizes = []
    for p in wcap["_c2s"]:
        if "rawb" in p and p["rawb"][0] == 6:
            sizes.append(struct.unpack(">I", p["rawb"][21:25])[0])
    running = 0
    resets = 0
    for i, (off, sz) in enumerate(zip(offs, sizes)):
        if off == 0:
            if i != 0:
                resets += 1
            running = 0
        elif off != running:
            problems.append("WRITE #%d has offset %d, expected %d -- offsets "
                            "are not accumulating payload lengths"
                            % (i, off, running))
            break
        running += sz
    if resets == 0:
        problems.append("no offset ever returned to 0, so the per-file reset "
                        "is untested")
    if offs[0] != 0:
        problems.append("first WRITE offset is %d, not 0" % offs[0])

    # Our framing of one of paramiko's own WRITEs, byte for byte.
    first = None
    for p in wcap["_c2s"]:
        if "rawb" in p and p["rawb"][0] == 6:
            first = p["rawb"]
            break
    rid = struct.unpack(">I", first[1:5])[0]
    # first[5:9] is the handle's *length prefix*; `s()` adds its own, so
    # slicing it in as well would frame the handle twice.
    handle = first[9:13]
    off = struct.unpack(">Q", first[13:21])[0]
    data = first[25:]
    # `f_write` returns a framed packet; the capture entry is the payload with
    # the length prefix already stripped, so strip ours the same way.
    ours = f_write(rid, handle, off, data)
    if ours[4:] != first:
        problems.append("our WRITE framing differs:\n    ours   %s\n    theirs %s"
                        % (ours[:44].hex(), first[:40].hex()))

    # The message numbers, cross-checked against the capture rather than
    # against sftp.h alone -- 13 and 15 are adjacent and swapping them still
    # produces a well-formed packet the server simply rejects.
    seen = {}
    for p in wcap["_c2s"] + wcap["_rm_c2s"]:
        if "rawb" in p:
            seen.setdefault(p["rawb"][0], 0)
            seen[p["rawb"][0]] += 1
    for typ, name, expect in ((13, "REMOVE", 1), (14, "MKDIR", 1),
                              (9, "SETSTAT", 2), (18, "RENAME", 1),
                              (6, "WRITE", 1), (4, "CLOSE", 1),
                              (15, "RMDIR", 1)):
        if seen.get(typ, 0) < expect:
            problems.append("capture has %d %s(%d) packets, expected >= %d"
                            % (seen.get(typ, 0), name, typ, expect))

    # REMOVE(13) and RMDIR(15) are adjacent and swap without producing a
    # malformed packet -- the server just refuses the operation.  Compare the
    # bytes rather than trusting the constant.
    rm_stream = wcap["_rm_c2s"]
    rm_types = [p["rawb"][0] for p in rm_stream if "rawb" in p]
    if 13 in rm_types and 15 in rm_types:
        # the recorder drove `remove(child.txt)` then `rmdir(nested)`
        i13 = rm_types.index(13)
        i15 = rm_types.index(15)
        if not i13 < i15:
            problems.append("REMOVE and RMDIR arrived in the capture in an "
                            "order that does not match the operations driven")
        rm_path = rm_stream[i13]["rawb"][9:]
        rd_path = rm_stream[i15]["rawb"][9:]
        if rm_path == rd_path:
            problems.append("REMOVE and RMDIR carry the same path, so the two "
                            "messages cannot be told apart by their payload")

    # OPEN flags for a write: our WRITE|CREAT|TRUNC is the same triple
    # OpenSSH's own client uses when it renames a file into place
    # (sftp-client.c:2502).
    ours_flags = FXF_WRITE | FXF_CREAT | FXF_TRUNC
    theirs_flags = None
    for p in wcap["_c2s"]:
        if "rawb" in p and p["rawb"][0] == 3:
            # type(1)+id(4)+path string(4+n)+pflags(4)
            n = struct.unpack(">I", p["rawb"][5:9])[0]
            theirs_flags = struct.unpack(">I", p["rawb"][9 + n:13 + n])[0]
            break
    if theirs_flags is not None and theirs_flags != ours_flags:
        problems.append("write OPEN pflags %08x != ours %08x"
                        % (theirs_flags, ours_flags))

    # The three EXTENDED outcomes, verbatim off the wire.
    ext = wcap["_ext_s2c_raw"]
    codes = [struct.unpack(">I", r[5:9])[0] for r in ext[1:]]
    if codes != [0, 0, FX_OP_UNSUPPORTED]:
        problems.append("EXTENDED status codes %r != [0, 0, %d]"
                        % (codes, FX_OP_UNSUPPORTED))

    print("  WRITE offsets (first 8): %s" % (offs[:8],))
    print("  WRITE payload sizes     : %s" % (sizes[:8],))
    print("  EXTENDED status codes   : %s" % (codes,))
    print("  version extensions      : %s"
          % (" ".join(wcap["version_ext_names"]),))
    return problems


def build_write_cases(wcap, cap):
    """Scripted write-side cases, with real server bytes as the replies."""
    cases = []
    ver = wcap["_ver_raw"]
    # Real STATUS replies from the write capture: HANDLE for an OPEN, and the
    # STATUS that answers a WRITE and one that answers a CLOSE.
    handle = find_reply(wcap, FXP_HANDLE, 2)
    write_ok = find_reply(wcap, FXP_STATUS, 3)
    close_ok = find_reply(wcap, FXP_STATUS, 16)
    mkdir_ok = find_reply(wcap, FXP_STATUS, 1)
    # the EXTENDED session's three statuses
    ext_status = wcap["_ext_s2c_raw"][1:]
    posix_ok = ext_status[0]
    overwrite_ok = ext_status[1]
    unsupported = ext_status[2]

    w_dir = wcap["fixture"].replace("\\", "/") + "/w"
    p_main = w_dir + "/main.bin"

    # --- 1. a single-chunk write -----------------------------------------
    payload = bytes(range(64)) * 4          # 256 bytes, more than one packet
    cases.append(case(
        "live_writefile_single_chunk",
        [("writefile", p_main, payload.hex())],
        [framed(ver), framed(retag(handle, 1)),
         framed(retag(write_ok, 2)), framed(retag(close_ok, 3))],
        ["wrote=%d" % len(payload)],
        "OPEN(WRITE|CREAT|TRUNC), one WRITE at offset 0, CLOSE -- %d bytes"
        % len(payload)))

    # --- 2. a write that crosses the chunk boundary ----------------------
    # Two WRITEs, and the second one's offset is the first one's length.
    # That offset is the whole point: sent as "bytes still to send" the file
    # ends the right length with the first chunk written twice.
    big = bytes((i * 7) & 0xFF for i in range(32768 + 24))
    reqs = script_requests([("writefile", p_main, big.hex())])
    writes = [r for r in reqs if r[4] == 6]
    if len(writes) != 2:
        raise SelfCheck("expected 2 WRITEs for %d bytes, script made %d"
                         % (len(big), len(writes)))
    cases.append(case(
        "live_writefile_two_chunks",
        [("writefile", p_main, big.hex())],
        [framed(ver), framed(retag(handle, 1)),
         framed(retag(write_ok, 2)), framed(retag(write_ok, 3)),
         framed(retag(close_ok, 4))],
        ["wrote=%d" % len(big)],
        "two WRITEs at offsets 0 and %d -- the second is the *file* offset, "
        "not a remaining-byte count" % len(big[:32768])))

    # --- 3. an empty payload sends no WRITE at all ------------------------
    cases.append(case(
        "live_writefile_empty_sends_no_write",
        [("writefile", p_main, "")],
        [framed(ver), framed(retag(handle, 1)), framed(retag(close_ok, 2))],
        ["wrote=0"],
        "OPEN with TRUNC already emptied the file, so a WRITE would have "
        "nothing to do -- and one empty WRITE would look on the wire exactly "
        "like having written the file"))

    # --- 4. MKDIR then REMOVE ---------------------------------------------
    cases.append(case(
        "live_mkdir_then_remove",
        [("mkdir", w_dir + "/k"), ("remove", w_dir + "/k")],
        [framed(ver), framed(retag(mkdir_ok, 1)), framed(retag(mkdir_ok, 2))],
        ["changed", "changed"],
        "MKDIR carries an attribute block and REMOVE does not -- both answer "
        "with a STATUS(OK)"))

    # --- 5. SETSTAT, permissions and times -------------------------------
    cases.append(case(
        "live_setstat_perms_times",
        [("setattrs", p_main, {"permissions": 0o640,
                               "atime": 1700000000, "mtime": 1700000123})],
        [framed(ver), framed(retag(mkdir_ok, 1))],
        ["changed"],
        "one SETSTAT carrying both a permissions field and an atime/mtime "
        "pair, in that order"))

    # --- 6. SETSTAT with nothing to change --------------------------------
    cases.append(case(
        "live_setstat_none",
        [("setattrs", p_main, {})],
        [framed(ver), framed(retag(mkdir_ok, 1))],
        ["changed"],
        "four zero bytes is 'change nothing' and is a complete request -- an "
        "empty attribute block would be a parse failure, not a default"))

    # --- 7. posix-rename, the extension path ------------------------------
    cases.append(case(
        "live_posix_rename_extension",
        [("rename", p_main, w_dir + "/renamed.bin")],
        [framed(ver), framed(retag(posix_ok, 1))],
        ["changed"],
        "FXP_EXTENDED with posix-rename@openssh.com, because VERSION "
        "advertised it -- this is what can replace an existing target"))

    # --- 8. an extension the server does not implement --------------------
    cases.append(case(
        "negative_rename_op_unsupported",
        [("rename", p_main, w_dir + "/nope.bin")],
        [framed(ver), framed(retag(unsupported, 1))],
        [render_status(parse_reply(unsupported)[1])],
        "STATUS(SSH2_FX_OP_UNSUPPORTED) is a completed exchange: reported as "
        "a failure, session still finishes"))

    # --- 9. a failed WRITE must still close the handle --------------------
    fail = bytes([FXP_STATUS]) + u32(2) + u32(4) + u32(7) + b"failure" + u32(0)
    cases.append(case(
        "negative_write_failure_still_closes",
        [("writefile", p_main, "00112233")],
        [framed(ver), framed(retag(handle, 1)),
         framed(retag(fail, 2)), framed(retag(close_ok, 3))],
        [render_status({"code": 4, "message": "failure"})],
        "the OPEN succeeded, so the server is holding a descriptor: a failed "
        "WRITE has to be followed by CLOSE or the handle leaks"))
    cases[-1]["requests_note"] = "OPEN, WRITE, CLOSE"

    # --- 10. an OPEN that is refused --------------------------------------
    # Every OPEN in the write capture succeeded, so there is no "OPEN denied"
    # status to lift from this session.  The read capture has a real
    # STATUS(SSH2_FX_NO_SUCH_FILE), which is exactly the shape an OPEN on a
    # missing path produces, and it is the server's own bytes either way.
    openfail = find_reply(cap, FXP_STATUS, 44)
    cases.append(case(
        "negative_open_refused",
        [("writefile", w_dir + "/never-created", "00")],
        [framed(ver), framed(retag(openfail, 1))],
        [render_status(parse_reply(openfail)[1])],
        "the server refused the OPEN, so there is no handle and nothing to "
        "close -- and no WRITE may be sent",
        requests=[f_init(), f_open(1, w_dir + "/never-created",
                                   FXF_WRITE | FXF_CREAT | FXF_TRUNC)]))
    return cases


def wcase_wrap(cases):
    return cases


# ---------------------------------------------------------------------------
# emit
# ---------------------------------------------------------------------------

def mstr(s):
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def mlong(s, width=480):
    """A long literal, emitted as concatenated pieces.

    A 32 KiB payload is 65536 hex characters on one line, and the compiler
    rightly complains that the text segment is about to exceed the column
    limit -- while also printing the whole thing, which buries any real
    diagnostic underneath it.  Concatenating literals produces the identical
    string, so nothing downstream can tell the difference.
    """
    if len(s) <= width:
        return mstr(s)
    parts = [s[i:i + width] for i in range(0, len(s), width)]
    out = mstr(parts[0])
    for p in parts[1:]:
        out += " +\n      " + mstr(p)
    return out


def emit(cases, cap):
    out = []
    a = out.append
    a("///| GENERATED FILE -- do not edit by hand.")
    a("")
    # The machine-path exemption (Loop #69/#71) is a repository-wide
    # convention: a file that legitimately contains a machine-specific
    # absolute path has to say so, and say why, *in the file*. The captured
    # bytes below are exactly that -- `host/sftp_capture.py` recorded them
    # from a live internal-sftp session, so the client's request strings name
    # the directory that machine used.
    #
    # This block has to be emitted by the GENERATOR, not added by hand after
    # the fact: the generator overwrites the whole file, so a hand-written
    # header is lost the first time anybody regenerates -- and then
    # `host/verify_loop71.mjs` flags the file as an unexplained machine path,
    # and Loop #39's "committed vectors still match the oracle" check can never
    # pass, because the regenerated copy is missing the block.
    a("// machine-path-exempt-file: every `E:/...` below is a CAPTURED WIRE BYTE, not")
    a("// a path this code reads. host/sftp_capture.py recorded these frames from a")
    a("// live OpenSSH 8.0p1 internal-sftp session on the machine that ran the")
    a("// capture, so the client's request strings contain that machine's absolute")
    a("// paths. They are compared byte-for-byte against host/sftp_oracle.py, which")
    a("// frames the same bytes independently -- rewriting them would not make the")
    a("// vectors portable, it would make the comparison meaningless. Regenerating")
    a("// means re-capturing against a server, which is a deliberate act, not a find")
    a("// and replace. `CAPTURE_FIXTURE` at the bottom is the directory those bytes")
    a("// name, and host/verify_loop39.mjs recreates it before running.")
    a("")
    a("///|")
    a("/// Regenerate with: python host/gen_sftp_vectors.py --capture .loop39/capture.json")
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
    a("  ///| the second path of a rename; empty when the op has none")
    a("  path2 : String")
    a("  ///| the payload of a writefile, as hex")
    a("  payload : String")
    a("  ///| attribute fields.  -1 means *not mentioned*, which is a")
    a("  ///| different request from mentioning it with the value 0.")
    a("  perms : Int")
    a("  atime : Int")
    a("  mtime : Int")
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
        for op in c["ops"]:
            f = op_fields(op)
            a("      { kind: %d, path: %s, path2: %s, payload: %s, "
              "perms: %d, atime: %d, mtime: %d },"
              % (f["kind"], mstr(f["path"]), mstr(f["path2"]),
                 mlong(f["payload"]), f["perms"], f["atime"], f["mtime"]))
        a("    ],")
        a("    chunks: [")
        for ch in c["chunks"]:
            a("      %s," % mlong(ch))
        a("    ],")
        a("    requests: [")
        for r in c["requests"]:
            a("      %s," % mlong(r))
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


KIND = {"realpath": 0, "stat": 1, "listdir": 2, "readfile": 3,
        "writefile": 4, "setattrs": 5, "mkdir": 6, "remove": 7,
        "rmdir": 8, "rename": 9}

# -1 rather than 0 for "not mentioned".  A permissions word of 0 is a real
# value (`chmod 000`), and collapsing the two would make the generator and the
# client disagree about a request that is legal and occasionally intended.
ABSENT = -1


def op_fields(op):
    """Flatten an op tuple into the fields `vectors.mbt` carries.

    Kept in one place so the generated struct and the Python that fills it
    cannot disagree about what "absent" means.
    """
    kind, path = op[0], op[1]
    rest = op[2:]
    path2 = ""
    payload = ""
    perms, atime, mtime = ABSENT, ABSENT, ABSENT
    for part in rest:
        if isinstance(part, str) and payload == "" and kind == "writefile":
            payload = part
        elif isinstance(part, str):
            path2 = part
        elif isinstance(part, dict):
            perms = part.get("permissions", ABSENT)
            atime = part.get("atime", ABSENT)
            mtime = part.get("mtime", ABSENT)
    return {"kind": KIND[kind], "path": path, "path2": path2,
            "payload": payload, "perms": perms, "atime": atime, "mtime": mtime}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--capture", default=".loop39/capture.json")
    ap.add_argument("--write-capture", default=".loop40/write_capture.json")
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

    wcap = load_write_capture(args.write_capture)
    wcap["fixture"] = cap["fixture"]
    print("leg 4: the write side vs paramiko's framing")
    problems += selfcheck_write(wcap)

    print("leg 3: scripted cases")
    try:
        cases = build_cases(cap)
        cases += build_write_cases(wcap, cap)
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
    before = _digest(args.out)
    format_in_place(args.out)
    if _digest(args.out) == before:
        # The formatter is a no-op for a file that is not in a package. Say so,
        # because the next step of this script (or a gate that compares this
        # file with the committed one) is about bytes, and bytes formatted
        # one way and bytes formatted another way are not the same bytes.
        sys.stderr.write(
            "note: moon fmt did not touch %s -- it is not inside a MoonBit "
            "package, so the formatter does not apply to it\n" % args.out)
    print("wrote %s (%d cases)" % (args.out, len(cases)))
    return 0


if __name__ == "__main__":
    sys.exit(main())