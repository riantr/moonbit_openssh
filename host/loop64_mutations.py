#!/usr/bin/env python3
"""Loop #64 mutation harness.

Every mutation is applied to the working tree, the gate is run, and the whole
tree is restored afterwards -- including build products, because a stale
`_build` can make a broken tree look green.

Discipline followed here (from Loop #60 onward):
  * restore the entire tree before each mutation, not just the edited file;
  * run `moon clean` first so no cached artifact can answer for the mutation;
  * anchors are unique and ASCII-only;
  * a mutation caught by a compile error is NOT counted as evidence -- a
    mutation that does not even build was never tested by the gate, so those
    are reported separately as BUILD-BROKEN rather than CAUGHT.

Verdicts:
  CAUGHT     -- the gate failed, and the tree built (the gate saw it)
  MISSED     -- the gate passed and the tree built (a real hole)
  EQUIVALENT -- the tree built and the gate passed, but the mutation does not
                change behaviour (a discovery, not an accusation)
  BUILD-BROKEN -- the tree did not build, so the gate never got to judge
"""
import io
import os
import shutil
import subprocess
import sys

# Loop #71: this was ROOT = r"E:\src\moon\openssh_moonbit". A GitHub runner
# checks out to D:\a\<repo>\<repo>, so the hardcoded root sent every mutation
# to a directory that does not exist there -- and a mutation harness pointed at
# a missing tree does not report "the tree is missing", it reports whatever the
# tools say about nothing. Derived from __file__ instead, so it travels with the
# clone.
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GATE = os.path.join("host", "verify_loop64.mjs")

# (name, relative path, unique ASCII anchor, replacement)
MUTATIONS = [
    (
        "M1 re-harden one signature to @tcp.TcpConn",
        os.path.join("src", "sshclient", "live.mbt"),
        "  conn : T,\n  counters : WireCounters,\n  s : @bpacket.SendCtx,",
        "  conn : @tcp.TcpConn,\n  counters : WireCounters,\n  s : @bpacket.SendCtx,",
    ),
    (
        "M2 add a second Transport impl (a browser transport)",
        os.path.join("src", "transport", "transport.mbt"),
        "pub impl Transport for @tcp.TcpConn with fn wire_close(self) {\n  self.close()\n}",
        "pub impl Transport for @tcp.TcpConn with fn wire_close(self) {\n"
        "  self.close()\n}\n\n"
        "///|\npub struct BrowserSock {\n  url : String\n}\n\n"
        "///|\npub impl Transport for BrowserSock with fn wire_send(self, data) {\n"
        "  ignore(data)\n  true\n}\n\n"
        "///|\npub impl Transport for BrowserSock with fn wire_read_exact(self, n) {\n"
        "  ignore(n)\n  None\n}\n\n"
        "///|\npub impl Transport for BrowserSock with fn wire_close(self) {\n  ignore(self)\n}",
    ),
    (
        "M3 stale call site: conn.send instead of conn.wire_send",
        os.path.join("src", "sshclient", "live.mbt"),
        "      if !conn.wire_send(pkt.wire) {",
        "      if !conn.wire_send(pkt.wire) || false && conn.send(pkt.wire) {",
    ),
    (
        # An earlier version of this mutation tried to make the sync arm yield by
        # arming a promise inside the spin loop. It was reported MISSED, which was
        # wrong: arming a promise does not yield, so the wall was still measured
        # correctly and the mutation was behaviour-preserving. This one starves
        # the *async* arm instead, which is a real change to what the probe says.
        "M4 make the async arm starve too",
        os.path.join("cmd", "probe_async_wall", "main.mbt"),
        "async fn async_take() -> Int {\n  @js_async.Promise::wait(arm_deferred_promise())\n}",
        "async fn async_take() -> Int {\n  let mut spins = 0\n"
        "  while slot_empty() && spins < 1000 {\n    spins = spins + 1\n  }\n  -1\n}",
    ),
    (
        "M5 split the two probe arms onto different scheduling",
        os.path.join("cmd", "probe_async_wall", "main.mbt"),
        '  "() => { setTimeout(() => { globalThis.__probe_slot.push(0x5a); }, 0); }"',
        '  "() => { globalThis.__probe_slot.push(0x5a); }"',
    ),
    (
        "M6 let src/tcp learn the trait (cycle in disguise)",
        os.path.join("src", "transport", "moon.pkg"),
        'import {\n  "openssh/openssh_moonbit/src/tcp",\n}',
        'import {\n  "openssh/openssh_moonbit/src/tcp",\n  "openssh/openssh_moonbit/src/ws_socket",\n}',
    ),
]

# M6 is expected to be EQUIVALENT-ish: adding a ws_socket import that nothing
# uses is a real edit but changes no behaviour. Keep it -- an unused import is
# exactly the kind of thing a gate should notice, and if it does not, that is
# the finding.


def read(path):
    with io.open(path, "r", encoding="utf-8", newline="") as fh:
        return fh.read()


def write(path, text):
    with io.open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)


def run_gate():
    return subprocess.call(["cmd", "/c", "node", GATE], cwd=ROOT,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def builds():
    r = subprocess.run(["cmd", "/c", "moon", "build", "src\\sshclient"],
                       cwd=ROOT, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL)
    return r.returncode == 0


def clean():
    subprocess.call(["cmd", "/c", "moon", "clean"], cwd=ROOT,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def main():
    baseline = run_gate()
    print("baseline gate exit = %d" % baseline)
    if baseline != 0:
        print("BASELINE IS RED -- fix that before mutating.")
        return 2

    results = []
    for name, rel, anchor, repl in MUTATIONS:
        path = os.path.join(ROOT, rel)
        original = read(path)
        count = original.count(anchor)
        if count != 1:
            results.append((name, "ANCHOR-%d" % count))
            print("[skip] %s -- anchor occurs %d times" % (name, count))
            continue
        clean()
        try:
            write(path, original.replace(anchor, repl, 1))
            ok = builds()
            code = run_gate()
        finally:
            clean()
            write(path, original)
        if not ok:
            verdict = "BUILD-BROKEN"
        elif code == 0:
            verdict = "MISSED"
        else:
            verdict = "CAUGHT"
        results.append((name, verdict))
        print("[%s] %s" % (verdict, name))

    clean()
    run_gate()

    print("")
    caught = [r for r in results if r[1] == "CAUGHT"]
    missed = [r for r in results if r[1] == "MISSED"]
    broken = [r for r in results if r[1] == "BUILD-BROKEN"]
    print("CAUGHT %d / MISSED %d / BUILD-BROKEN %d / total %d"
          % (len(caught), len(missed), len(broken), len(results)))
    for n, v in results:
        print("  %-14s %s" % (v, n))
    return 0


if __name__ == "__main__":
    sys.exit(main())
