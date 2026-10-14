"""Mutation check: Loop #63's negative findings must stay true until proved false.

Six mutations. This gate asserts a set of things that are *absent* -- an
unreachable host, a discarded handshake, a client bound to the wrong transport --
so the mutations mostly add those things back and require the gate to notice.

  * **A: the browser binary stops discarding the server's REPLY.** It stores the
    payload in a name. The gate's "discarded reads" count collapses, which is
    the whole point of the check.

  * **B: `ssh_full_ws` starts negotiating.** A `negotiate` call appears. This
    is the change that would most improve the demo, and it is also the one that
    must not pass silently: negotiating is not verifying, and a gate that only
    asked "does it negotiate?" would report a browser client where there is
    still no signature check.

  * **C: the verified client gains a WebSocket transport.** `live.mbt` stops
    being bound to `@tcp.TcpConn` and starts importing `ws_socket`. If this
    mutation ever became *desirable*, the gate is what should object first --
    which is exactly why it is written to fail while the client is TCP-only.

  * **D: the orphan host gains a caller.** A gate starts spawning
    `node_host_wasm.mjs`. Caught by the caller scan.

  * **E: wasm-gc grows an export.** Not a source mutation -- this one edits the
    * gate's own view of the world by pointing the probe at a nonexistent
    artifact, so the export assertion cannot be made. It proves the assertion is
    load-bearing: no artifact, no claim.

  * **F: an equivalent mutant.** `ws_wait_for_bytes` is renamed. Nothing calls
    it, so nothing changes. Reported, because "dead code that is correct" is the
    only harmless kind of dead code and this one documents a real limitation.

**Undo with the snapshot below, never with `git checkout`.**

Run:  python host/loop63_mutations.py          (all)
      python host/loop63_mutations.py A        (one, by label prefix)
"""

import io
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DEMO = os.path.join(ROOT, "cmd", "ssh_full_ws", "main.mbt")
LIVE = os.path.join(ROOT, "src", "sshclient", "live.mbt")
HOSTJS = os.path.join(ROOT, "host", "node_host_wasm.mjs")
OTHER = os.path.join(ROOT, "host", "verify_loop24.mjs")
GATE = os.path.join(ROOT, "host", "verify_loop63.mjs")
FILES = [DEMO, LIVE, HOSTJS, OTHER, GATE]


def read(path):
    with io.open(path, encoding="utf-8") as fh:
        return fh.read()


def write(path, text):
    with io.open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)


def restore(originals):
    for p, text in originals.items():
        write(p, text)


def run(argv, timeout=3600):
    return subprocess.run(
        argv, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        encoding="utf-8", errors="replace", timeout=timeout,
    )


def fails_for(out):
    labels = []
    for line in (out or "").split("\n"):
        s = line.strip()
        if s.startswith("FAIL ") and s not in labels:
            labels.append(s)
    return labels


MUTATIONS = [
    (
        "A: the browser binary stops discarding the server's REPLY",
        [(DEMO,
          "  let _ = sock.read_n(make_server_kexdh_reply_reply().length())",
          "  let discarded_reply = sock.read_n(make_server_kexdh_reply_reply().length())\n"
          "  let _ = discarded_reply")],
        "missed",
    ),
    (
        "B: ssh_full_ws starts negotiating",
        [(DEMO,
          "  let prop = @kexflow.Proposal::default_client(false)",
          "  let prop = @kexflow.Proposal::default_client(false)\n"
          "  let _negotiated = @kexflow.negotiate")],
        "missed",
    ),
    (
        "C: the verified client gains a WebSocket transport",
        # One occurrence, chosen by context. `conn : @tcp.TcpConn,` appears 19
        # times in live.mbt; the anchor below is the *first* parameter of the
        # public handshake entry point, which is the one that would actually
        # change what the transport is.
        [(LIVE,
          "pub fn live_handshake(\n  conn : @tcp.TcpConn,",
          "pub fn live_handshake(\n  conn : @ws_socket.Socket,")],
        "missed",
    ),
    (
        "D: the orphan host gains a caller",
        # A real spawn, not a comment mentioning it. The first version appended
        # `// node_host_wasm.mjs is now wired in` and the gate reported MISSED --
        # correctly, because the caller scan strips comments and a comment runs
        # nothing. A mutation that does not change behaviour cannot test a
        # behaviour check, and reporting that as a miss would have been my
        # error rather than the gate's.
        [(OTHER,
          "const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');",
          "const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');\n"
          "const spawned = execSync('node host/node_host_wasm.mjs',\n"
          "  { cwd: ROOT, encoding: 'utf8' });")],
        "missed",
    ),
    (
        "E: the export probe cannot be built",
        [(GATE,
          'const built = run("cmd", ["/c", "moon build cmd\\\\probe_export --target wasm-gc"], { cwd: root });',
          'const built = { code: 0, out: "" }; // pretend the probe built')],
        "missed",
    ),
    (
        "F: the dead host helper is renamed",
        [(HOSTJS,
          "async function ws_wait_for_bytes(handle, n, timeoutMs = 5000) {",
          "async function ws_wait_for_bytes_renamed(handle, n, timeoutMs = 5000) {")],
        "equivalent",
    ),
]


def main():
    originals = {p: read(p) for p in FILES}
    only = sys.argv[1:] or None
    chosen = [m for m in MUTATIONS
              if only is None or any(m[0].startswith(pfx) for pfx in only)]
    if only and not chosen:
        print("no mutation matches %r" % (only,))
        return 1
    counts = {"CAUGHT": 0, "MISSED": 0, "NOBUILD": 0, "CRASH": 0, "EQUIVALENT": 0}
    try:
        for label, edits, expect in chosen:
            restore(originals)

            broken = None
            for path, frm, to in edits:
                src = originals[path]
                if frm not in src:
                    broken = "anchor not found in %s" % os.path.relpath(path, ROOT)
                    break
                if src.count(frm) != 1:
                    broken = ("anchor appears %d times in %s" % (
                        src.count(frm), os.path.relpath(path, ROOT)))
                    break
            if broken:
                print("NOBUILD  %s -- %s" % (label, broken))
                counts["NOBUILD"] += 1
                continue
            for path, frm, to in edits:
                write(path, read(path).replace(frm, to))

            run(["cmd", "/c", "moon", "clean"])
            proc = run(["node", os.path.join(ROOT, "host", "verify_loop63.mjs")])
            out = proc.stdout or ""

            if "failed when checking project" in out or (
                proc.returncode != 0 and "ALL PASS" not in out and "  FAIL " not in out
            ):
                print("NOBUILD  %s -- the mutated source did not compile/build" % label)
                print("          NOT EVIDENCE: a mutation caught by the compiler "
                      "proves nothing about the gate.")
                counts["NOBUILD"] += 1
                continue
            if proc.returncode == 0:
                if expect == "equivalent":
                    print("EQUIVALENT  %s -- gate still ALL PASS" % label)
                    counts["EQUIVALENT"] += 1
                else:
                    print("MISSED  %s -- the gate still reported ALL PASS" % label)
                    counts["MISSED"] += 1
                continue
            fails = fails_for(out)
            if not fails and ("gate crashed" in out or "Traceback" in out):
                print("CRASH  %s -- %s" % (label, out.strip().split("\n")[0][:160]))
                counts["CRASH"] += 1
                continue
            print("CAUGHT  %s" % label)
            for f in fails[:4]:
                print("          " + f[:190])
            counts["CAUGHT"] += 1
    finally:
        restore(originals)
        drifted = [p for p in FILES if read(p) != originals[p]]
        if drifted:
            print("\nWARNING: not restored byte for byte: %s" % ", ".join(drifted))
            return 1

    print(
        "\n%d CAUGHT, %d MISSED, %d EQUIVALENT, %d NOBUILD, %d CRASH (of %d mutations)"
        % (counts["CAUGHT"], counts["MISSED"], counts["EQUIVALENT"],
           counts["NOBUILD"], counts["CRASH"], len(chosen))
    )
    return 0 if counts["MISSED"] == 0 and counts["CRASH"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())