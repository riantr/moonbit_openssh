"""Mutation check: every Loop #82 defect must turn the gate red.

A gate that stays green under a set of mutations is not testing anything, so
this script is part of the loop's evidence rather than a one-off.

Each mutation below is one of the ways this code could plausibly be wrong, and
each one names the gate check that has to go red because of it.

Three rules this script keeps, all learned elsewhere in this repository:

  * **A compile failure is not evidence.**  A mutation that does not compile
    proves nothing about the gate, so it gets its own verdict (INVALID)
    instead of being counted as caught or missed.  A *warning* counts the same
    way: `moon run` exits non-zero when the build prints a warning, so a
    mutation that leaves a variable unused cannot even be measured.

  * **The anchor has to hit exactly once, in exactly one file.**  An anchor
    that has drifted (the formatter rewrapped the line, say) is reported as
    SKIP and counted as "not caught" -- which points the finger at the gate
    rather than at the thing that actually moved.

  * **A mutation that cannot fail is not evidence either.**  A mutation whose
    check never goes red is worse than no mutation at all, because it looks
    like coverage.

The interesting ones in this list are the pair about the *name* of the key.
The known_hosts line says `ssh-rsa` while the key exchange negotiated
`rsa-sha2-512` (RFC 8332): the line carries the name **inside the key blob**,
not the name that was negotiated.  The server's own log proves which one it
logged -- the mutation harness relies on that, because it is the difference
between a line OpenSSH would accept and one it would reject.

The other one worth naming is the SERVICE_REQUEST.  A scan that asked for the
`ssh-userauth` service would still send no credentials, so "no userauth in the
server's log" would not notice it.  The gate therefore also counts the
service request itself, and only when a positive control says the server
logs packet types at all -- otherwise the count would pass vacuously.

Run:  python host/loop82_mutations.py            # all of them
      python host/loop82_mutations.py --only 5   # just one, for settling a
                                                 # disagreement with the gate
"""

import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Every file a mutation may touch. They are restored together, because a
# failed run must not leave the tree mutated.
FILES = [
    os.path.join(ROOT, "src", "knownhosts", "render.mbt"),
    os.path.join(ROOT, "src", "sshclient", "live.mbt"),
    os.path.join(ROOT, "src", "sshclient", "keyscan.mbt"),
    os.path.join(ROOT, "cmd", "ssh_keyscan", "main.mbt"),
]

SCAN_TYPES_BLOCK = (
    '  [\n'
    '    ScanType::{ name: "rsa", algs: "rsa-sha2-512,rsa-sha2-256", },\n'
    '    ScanType::{\n'
    '      name: "ecdsa",\n'
    '      algs: "ecdsa-sha2-nistp256,ecdsa-sha2-nistp384",\n'
    '    },\n'
    '    ScanType::{ name: "ed25519", algs: "ssh-ed25519", },\n'
    '  ]\n'
)

SCAN_TYPES_ENTRIES = (
    '    ScanType::{ name: "rsa", algs: "rsa-sha2-512,rsa-sha2-256", },\n'
    '    ScanType::{\n'
    '      name: "ecdsa",\n'
    '      algs: "ecdsa-sha2-nistp256,ecdsa-sha2-nistp384",\n'
    '    },\n'
    '    ScanType::{ name: "ed25519", algs: "ssh-ed25519", },\n'
)

# (label, original, mutated, a check name that must go FAIL)
MUTATIONS = [
    (
        # The known_hosts line carries the type name **inside the key blob**
        # (`ssh-rsa`), not the name that was negotiated (`rsa-sha2-512`).
        # OpenSSH writes the blob's name, and OpenSSH also *reads* a known_hosts
        # line by the blob's name -- so a line that says `rsa-sha2-512` is a
        # line OpenSSH would not match against the key it just saw.
        "the known_hosts line uses the negotiated algorithm name",
        "            r.hostkey_type,",
        "            r.hostkey_alg,",
        "the keys come out in the order they were requested: rsa, ecdsa, ed25519",
    ),
    (
        # `put_host_port` brackets a non-default port.  The brackets are not
        # decoration: without them `::1:2222` reads as an address, not as an
        # address and a port.
        "the hosts field loses its brackets",
        '    "[" + host + "]:" + port.to_string()',
        '    host + ":" + port.to_string()',
        "KAT line 3 == oracle",
    ),
    (
        # Port 22 is the default port, and the default port is written as the
        # bare host name.  Treating 22 as an ordinary port writes
        # `host:22` for every default-port host.
        "port 22 is not treated as the default port",
        "  if port == 0 || port == 22 {",
        "  if port == 0 {",
        "KAT line 2 == oracle",
    ),
    (
        # Port 0 means "the default port" too -- OpenSSH's own `put_host_port`
        # treats 0 and 22 the same way.
        "port 0 is not treated as the default port",
        "  if port == 0 || port == 22 {",
        "  if port == 22 {",
        "KAT line 1 == oracle",
    ),
    (
        # OpenSSH's `lowercase` folds ASCII upper-case letters.  Dropping the
        # fold leaves the host name as it was typed, and the known_hosts line
        # no longer matches the one OpenSSH writes.
        "the host name is not lower-cased",
        "      sb.write_char(Int32::unsafe_to_char(c + 32))",
        "      sb.write_char(Int32::unsafe_to_char(c))",
        "KAT line 6 == oracle",
    ),
    (
        # The composition -- `lowercase` applied to `put_host_port` -- is what
        # the tool writes.  Lowercasing only the host and not the whole field
        # looks the same on every host that has no letters in its port, which
        # is every host this client can even reach.
        "the composed field skips the lower-casing",
        "  lowercase_ascii(host_field(host, port))",
        "  host_field(host, port)",
        "KAT line 9 == oracle",
    ),
    (
        # The line is `host keytype base64(blob)`, in that order.  The field
        # order is the whole format: a line whose first field is a key type
        # is a line OpenSSH parses as a host pattern.
        "the known_hosts line puts the key type first",
        '  host_field + " " + key_type + " " + base64_encode(blob)',
        '  key_type + " " + host_field + " " + base64_encode(blob)',
        "the hosts field carries the port",
    ),
    (
        # A key exchange negotiates exactly ONE host key, so a scan of three
        # key types needs three connections.  Proposing all of them at once
        # yields one key -- and one line.
        "all key types are proposed in one connection",
        SCAN_TYPES_BLOCK,
        '  [\n'
        '    ScanType::{\n'
        '      name: "all",\n'
        '      algs: "rsa-sha2-512,rsa-sha2-256,ecdsa-sha2-nistp256,'
        'ecdsa-sha2-nistp384,ssh-ed25519",\n'
        '    },\n'
        '  ]\n',
        "the scan printed three keys -- one per key type",
    ),
    (
        # OpenSSH prints the keys in its own type order (RSA, ECDSA, Ed25519).
        # The order is the order of `ssh-keyscan.c`'s keytypes array, and the
        # line order is what a user diffing two scans compares.
        "the key types are scanned in the wrong order",
        SCAN_TYPES_ENTRIES,
        '    ScanType::{ name: "ed25519", algs: "ssh-ed25519", },\n'
        '    ScanType::{\n'
        '      name: "ecdsa",\n'
        '      algs: "ecdsa-sha2-nistp256,ecdsa-sha2-nistp384",\n'
        '    },\n'
        '    ScanType::{ name: "rsa", algs: "rsa-sha2-512,rsa-sha2-256", },\n',
        "the keys come out in the order they were requested: rsa, ecdsa, ed25519",
    ),
    (
        # The client proposes the host key algorithms in its own preference
        # order, and the server picks the first one it also has.  Putting
        # ed25519 first makes every connection get the ed25519 key, so three
        # connections print three copies of the same key.
        #
        # The parameter stays **used**: dropping it would leave it unused, the
        # build would print a warning, and `moon run` exits non-zero on a
        # warning -- so the mutation would be reported INVALID instead of
        # measured.
        "ed25519 is preferred for every connection",
        '    kex_algs: "diffie-hellman-group14-sha256",\n    hostkey_algs,',
        '    kex_algs: "diffie-hellman-group14-sha256",\n'
        '    hostkey_algs: "ssh-ed25519," + hostkey_algs,',
        "the keys come out in the order they were requested: rsa, ecdsa, ed25519",
    ),
    (
        # The whole point of the tool: it looks at a host's keys BEFORE
        # deciding whether to trust it, so it must not authenticate.  Asking
        # for the `ssh-userauth` service sends no credentials -- but it is
        # the step right before credentials would go, and a scan that took it
        # would be one refactor away from taking the next one too.
        "the scan asks for the ssh-userauth service as well",
        "  let (res, _st) = handshake_to_session_with_proposal(conn, x, kh, my)",
        "  let (res, st) = handshake_to_session_with_proposal(conn, x, kh, my)\n"
        "  match st {\n"
        "    Some(v) => {\n"
        "      let _ = request_userauth_service(conn, v)\n"
        "    }\n"
        "    None => ()\n"
        "  }",
        "the scan did not even request the ssh-userauth service",
    ),
    (
        # The comment line says which server answered ("# host:port
        # SSH-2.0-...").  It is the tool's output too -- OpenSSH prints the
        # same line, and a scan that named the wrong thing would be a scan
        # whose report cannot be trusted.
        "the comment line names the wrong thing",
        '          eprintln("# " + host + ":" + port.to_string() + " " + r.server_ident)',
        '          eprintln("# " + host + ":" + port.to_string() + " " + r.hostkey_alg)',
        "the comment line agrees with",
    ),
]


def read():
    return {p: open(p, "r", encoding="utf-8", newline="").read() for p in FILES}


def write(state):
    for p, text in state.items():
        with open(p, "w", encoding="utf-8", newline="") as fh:
            fh.write(text)


def run_gate():
    # The regression section is skipped: it runs the gates of Loop #78, #79,
    # #80 and #81, which take minutes and cannot be affected by a change to
    # the key-scan files.  What is left is the part this loop is about.
    r = subprocess.run(
        ["node", os.path.join("host", "verify_loop82.mjs"), "--skip-regression"],
        cwd=ROOT, capture_output=True,
        # text=True alone would decode the gate's output with the locale
        # codec (cp936 here), and one box-drawing character would raise
        # UnicodeDecodeError *inside* the batch loop -- the child would die
        # after the last flushed line, looking exactly like "0 caught, 12
        # missed" with no traceback in the captured stderr.  Explicit utf-8
        # with replacement cannot raise, whatever the gate prints.
        encoding="utf-8", errors="replace", text=True,
        timeout=3600,
    )
    return r.stdout + r.stderr


def selected():
    """The mutations to run, in order.

    `--only N` runs a single one.  That is not a convenience: this list went
    through a round where the author's expectation and the measurement
    disagreed, and the way to settle such a disagreement is to run that one
    mutation and read the gate's output, not to re-run the whole batch and
    hope.
    """
    if len(sys.argv) < 3 or sys.argv[1] != "--only":
        return list(enumerate(MUTATIONS))
    idx = int(sys.argv[2])
    if idx < 0 or idx >= len(MUTATIONS):
        print("--only takes 0..%d" % (len(MUTATIONS) - 1))
        sys.exit(2)
    return [(idx, MUTATIONS[idx])]


def main():
    original = read()
    failures = []
    chosen = selected()
    try:
        for idx, (label, old, new, must_fail) in chosen:
            # The file that contains the anchor -- and it has to contain it
            # EXACTLY once, in exactly one file.  An anchor that appears
            # twice is a mutation that might hit the wrong place.
            hits = {os.path.basename(p): t.count(old) for p, t in original.items()}
            targets = [p for p, t in original.items() if t.count(old) == 1]
            if len(targets) != 1 or sum(hits.values()) != 1:
                print("SKIP  %s -- anchor hits %s" % (label, hits), flush=True)
                failures.append(label)
                continue
            target = targets[0]
            state = dict(original)
            state[target] = state[target].replace(old, new)
            write(state)
            out = run_gate()
            if "FAIL  cmd/ssh_keyscan builds for native" in out or \
               "FAIL  cmd/keyscan_kat runs on 4 target x 2 mode" in out:
                # A mutation that does not build proves nothing about the
                # gate.  It is neither caught nor missed; it is a broken
                # mutation, and it has to be fixed.
                #
                # "does not build" covers a warning as well as an error:
                # `moon run` exits non-zero when the build prints a warning,
                # so a mutation that leaves a variable unused cannot even be
                # measured.
                print("INVALID  %s -- the mutation does not build cleanly" % label, flush=True)
                failures.append(label)
                continue
            caught = ("FAIL  %s" % must_fail) in out
            print("%s  [%d] %s" % ("CAUGHT" if caught else "MISSED", idx, label),
                  flush=True)
            if not caught:
                failures.append(label)
                for line in out.splitlines():
                    if line.startswith("  FAIL"):
                        print("        " + line.strip(), flush=True)
    finally:
        write(original)

    print()
    if failures:
        print("MUTATION CHECK FAILED: %d of %d not caught"
              % (len(failures), len(chosen)))
        return 1
    print("all %d mutations turned the gate red" % len(chosen))
    return 0


if __name__ == "__main__":
    sys.exit(main())
