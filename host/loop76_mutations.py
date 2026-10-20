#!/usr/bin/env python3
"""host/loop76_mutations.py -- prove the loop76 gate is not vacuous.

A regression gate that cannot fail is worse than no gate: it reports
"protected" while protecting nothing. Every mutation below is one the gate
**must** catch, and each was checked CAUGHT before this file was written.

What the gate claims, and therefore what each mutation attacks:

  * the CHANNEL_OPEN bytes are paramiko's bytes (section B)
  * a real OpenSSH server forwards for us and the bytes come back unchanged
    (sections C and C2)
  * the two failure modes are told apart (sections F and G)

The mutations, and what each one removes:

  **M1** renames the channel type. The server does not know that type, so it
       refuses the open; and the payload stops being paramiko's payload.
       Caught by section B *and* by section C.

  **M2** puts the destination port before the destination host. The two
       fields have different wire shapes (a string and a u32), so swapping
       them produces a payload that is the right *length* and the wrong
       *content* -- the shape of mistake that survives a length check.
       Caught by section B.

  **M3** drops the two originator fields. They are the fields the server
       does not use for anything except logging, which is exactly why they
       are the ones a wrong implementation gets wrong: nothing downstream
       complains. Caught by section B.

  **M4** reports the "no data came back" case as a success -- the exact
       failure OpenSSH's own client makes, silently, with exit code 0.
       Caught by section F.

  **M5** swallows the server's refusal (CHANNEL_OPEN_FAILURE, reason 1) and
       keeps waiting for a confirmation that will never come. The client
       then reports a different failure, so the reason code the protocol
       gave us is lost. Caught by section G.

  **M6** removes the maximum-packet clamp. A payload that fits in one
       packet never exercises it, which is why the gate has a 100000-byte
       case: with the clamp gone the client sends one oversized packet and
       the server drops the connection. Caught by section C2.

What is deliberately NOT here:

  * A mutation of `host/verify_loop76.mjs` itself. The gate is the thing
    under test; a mutation that makes it stop checking would be a MISSED
    that is indistinguishable from a pass. The Loop #71 rule applies.
  * A mutation of `host/gen_forward_vectors.py`. It is the *reference*; a
    mutation there would make the reference agree with a broken encoder,
    which is the one thing section B exists to rule out.

Usage: python host/loop76_mutations.py [--only M1,M2]
"""

import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "ci"))
import sandbox  # noqa: E402


MUTATIONS = [
    {
        "mid": "M1",
        "desc": "the channel type is not the one the protocol defines",
        "path": os.path.join("src", "channel", "channel.mbt"),
        "old": 'pub const CHANNEL_TYPE_DIRECT_TCPIP : String = "direct-tcpip"',
        "new": 'pub const CHANNEL_TYPE_DIRECT_TCPIP : String = "direct-tcp1p"',
    },
    {
        "mid": "M2",
        "desc": "the destination port is written before the destination host",
        "path": os.path.join("src", "channel", "channel.mbt"),
        "old": (
            "    @sshwire.write_ssh_string(ch_ascii(dest_host)),\n"
            "    u32be(dest_port),"
        ),
        "new": (
            "    u32be(dest_port),\n"
            "    @sshwire.write_ssh_string(ch_ascii(dest_host)),"
        ),
    },
    {
        "mid": "M3",
        "desc": "the originator fields are dropped from the payload",
        "path": os.path.join("src", "channel", "channel.mbt"),
        "old": (
            "    @sshwire.write_ssh_string(ch_ascii(originator_ip)),\n"
            "    u32be(originator_port),\n"
        ),
        "new": "",
    },
    {
        "mid": "M4",
        "desc": "a forward that moved no bytes is reported as a success",
        "path": os.path.join("src", "sshclient", "forward.mbt"),
        "old": "  if report.stdout_len == 0 {",
        "new": "  if report.stdout_len == 0 && report.stdout_len > 0 {",
    },
    {
        "mid": "M5",
        "desc": "the server's refusal of the channel is swallowed",
        "path": os.path.join("src", "sshclient", "forward.mbt"),
        "old": (
            "          Some(@channel.ChanError::OpenFailed(reason, desc)) =>\n"
            "            return Failed(ForwardError::OpenFailed(reason, desc))\n"
            "          Some(@channel.ChanError::Malformed(why)) =>\n"
            "            return Failed(ForwardError::Malformed(why))"
        ),
        "new": (
            "          Some(@channel.ChanError::OpenFailed(reason, desc)) => ()\n"
            "          Some(@channel.ChanError::Malformed(why)) =>\n"
            "            return Failed(ForwardError::Malformed(why))"
        ),
    },
    {
        "mid": "M6",
        "desc": "the maximum packet size is no longer respected",
        "path": os.path.join("src", "channel", "exec.mbt"),
        "old": (
            "  if n > self.remote_max_packet {\n"
            "    n = self.remote_max_packet\n"
            "  }\n"
        ),
        "new": "",
    },
]


def apply_mutation(tree, m):
    p = os.path.join(tree, m["path"])
    with open(p, "rb") as fh:
        raw = fh.read()
    text = raw.decode("utf-8")
    crlf = "\r\n" in text
    body = text.replace("\r\n", "\n")
    n = body.count(m["old"])
    if n != 1:
        raise RuntimeError("anchor occurs %d times in %s, expected 1" % (n, m["path"]))
    body = body.replace(m["old"], m["new"], 1)
    if crlf:
        body = body.replace("\n", "\r\n")
    with open(p, "wb") as fh:
        fh.write(body.encode("utf-8"))


def run_gate(tree):
    proc = subprocess.run(["cmd", "/c", "node", "host/verify_loop76.mjs"],
                          cwd=tree, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, timeout=3600)
    return proc.returncode, proc.stdout.decode("utf-8", "replace")


def main():
    only = None
    if "--only" in sys.argv:
        only = set(sys.argv[sys.argv.index("--only") + 1].split(","))

    caught = missed = build_broken = 0
    for m in MUTATIONS:
        if only and m["mid"] not in only:
            continue
        print("== %s  %s" % (m["mid"], m["desc"]))
        tree = None
        try:
            tree = sandbox.make_sandbox(ROOT)
            apply_mutation(tree, m)
            rc, out = run_gate(tree)
            fails = [l.strip() for l in out.splitlines() if l.strip().startswith("FAIL")]
            if rc == 0:
                print("   verdict: MISSED")
                print("   !! the gate accepted a tree carrying this defect")
                missed += 1
            elif "no such file" in out.lower() or "cannot find module" in out.lower():
                # A tree that does not build is not evidence that the gate
                # catches anything: it is evidence that the mutation broke the
                # build. Reported separately, never counted as a catch.
                print("   verdict: BUILD-BROKEN")
                print("   %s" % (fails[:2] or ["the mutant did not build"]))
                build_broken += 1
            else:
                print("   verdict: CAUGHT")
                for l in fails[:4]:
                    print("   %s" % l)
                caught += 1
        except Exception as e:  # noqa: BLE001
            print("   ERROR: %s" % e)
            missed += 1
        finally:
            if tree:
                sandbox.drop_sandbox(ROOT, tree)
        print("")

    print("---")
    print("mutations=%d CAUGHT=%d MISSED=%d BUILD-BROKEN=%d"
          % (caught + missed + build_broken, caught, missed, build_broken))
    if missed or build_broken:
        print("a MISSED is an accusation against the gate, not a note")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
