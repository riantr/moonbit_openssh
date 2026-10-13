"""Mutation check: a pin that is not written is not a pin.

Loop #52's claim is narrow and easy to fake: "the write-back survives the page".
Three mutations, one per link in the chain, because each can break on its own and
the two obvious ones look identical from outside:

  * **A: nothing is written.**  The TOFU path stops saving. This is the original
    defect restored: the connection succeeds, the client prints `tofu: stored`,
    and every later connection starts from nothing. Case 1 has a line that says
    it stored, which is exactly why the gate asserts the *line* and not just the
    authentication.

  * **B: nothing is read.**  The policy stops consulting storage. Then A's write
    still lands and A's case still passes -- a store that is written to and never
    read is a write-only log, and only case 2 catches it.

  * **C: forgetting also authenticates.**  `kh_forget` keeps going and connects,
    turning "remove this pin" into a silent accept of whatever the peer presents
    next. This is the fail-open Loop #51 closed, re-entered through a different
    door, and it is why the gate's step 4 is two connections rather than one.

    The first attempt at this mutation read `cfg("auth")` into an unused
    variable, which changed nothing at all -- the mode still returned, the gate
    still passed, and the driver reported **MISSED**. A mutation that does not
    mutate is indistinguishable from a gate with a hole in it, and the tally
    looked like the gate's fault. It is the same shape as Loop #43's bad fixture
    and Loop #49's marker loss: an assertion that cannot fail.

A and B are the pair worth having together. Each alone leaves the other half of
the feature intact, so a gate that only checked "did it store" would call B a
pass, and one that only checked "did it remember" would call A a pass. A third
gap showed up when A was first run: step 1 asserted the client's own
`tofu: stored` line, and A is `let stored = true` -- the self-report agreed with
itself and passed. The gate now reads the same IndexedDB from its own side, so a
client that says it stored something and did not fails at step 1.

**Undo with the snapshot below, never with `git checkout`.**  See
`host/loop48_mutations.py` for the hour that cost. The tree is also restored
*before* each mutation, not in `finally` alone: A and B edit the same file and C
edits it too, so without that the mutations would stack and a later one would
report a check failing that it never touched.

`moon clean` before every run, for the reason Loop #50 learned the hard way: a
stale artifact reads as a MISSED mutation, which points at the gate rather than
at the tree.

Run:  python host/loop52_mutations.py
"""

import io
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

FILES = [
    os.path.join(ROOT, "cmd", "wt_ssh", "main.mbt"),
]

GATE = os.path.join(ROOT, "host", "verify_loop52.mjs")

MUTATIONS = [
    (
        "A: TOFU stops writing the pin",
        os.path.join(ROOT, "cmd", "wt_ssh", "main.mbt"),
        "  let stored = @khstore.save(host, written)",
        "  let stored = true",
    ),
    (
        "B: the policy stops reading the store",
        os.path.join(ROOT, "cmd", "wt_ssh", "main.mbt"),
        "    text = @khstore.load(host)",
        '    text = ""',
    ),
    (
        # The mutation has to remove the completion signal **as well as** the
        # `return`. Four earlier attempts got this wrong, each in a way that read
        # as a different problem:
        #
        #  1. an anchor containing a Chinese comment, which drifts when the
        #     comment is edited;
        #  2. a short anchor that appears **five times** in `main.mbt`, so
        #     `str.replace` rewrote all five and the mutation became "every mode
        #     carries on" -- whose behaviour at the one measured path happened to
        #     be unchanged. Reported MISSED, pointing at the gate;
        #  3. a one-line anchor whose mutation only *added* a statement, leaving
        #     the `return` in place;
        #  4. removing only the `return`, keeping `wt_finish(true, "done")`. That
        #     one is the subtle one: the harness takes "finished" from that call,
        #     so the mode signalled completion *before* the authentication it was
        #     supposed to perform, and the gate correctly read a clean forget.
        #
        # The failure mode in (4) is worth naming: a mutation that produces the
        # right answer for a reason that has nothing to do with the mutation is
        # indistinguishable, from the outside, from a gate with a hole.
        #
        # Removing both lines is what finally reaches the fail-open: forget the
        # pin, then accept whatever the peer presents, under an explicit
        # `kh_tofu` -- Loop #51's downgrade entered through a different door.
        "C: kh_forget forgets and then accepts under kh_tofu",
        os.path.join(ROOT, "cmd", "wt_ssh", "main.mbt"),
        '    println("forget: " + host)\n'
        '    // 必须发完成信号。Worker harness 靠 `__wt_finish` 判定「跑完了」,而每个\n'
        '    // 模式都自己发——这一处一开始漏了,于是 `kh_forget` 打印了正确的一行然后\n'
        '    // 静默挂死,门禁只看到一个 timeout 和一段完整 transcript。那种失败读起来像\n'
        '    // 存储有问题,实际上什么都没发生。\n'
        '    wt_finish(true, "done")\n'
        '    return',
        '    println("forget: " + host)',
    ),
]


def read(path):
    with io.open(path, encoding="utf-8") as fh:
        return fh.read()


def write(path, text):
    with io.open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)


def run_gate():
    subprocess.run(
        ["cmd", "/c", "moon", "clean"],
        cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=900,
    )
    return subprocess.run(
        ["node", GATE],
        cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        encoding="utf-8", errors="replace", timeout=3600,
    )


def fails_for(out):
    """Failing check labels, in order, deduplicated.

    The gate prints each failure twice -- once inline (indented) and once in its
    closing summary. Only the summary lines count, so that one check which failed
    once is not reported as two.
    """
    labels = []
    for line in (out or "").split("\n"):
        if line.startswith("FAIL ") and line.strip() not in labels:
            labels.append(line.strip())
    return labels


def main():
    originals = {p: read(p) for p in FILES}
    counts = {"CAUGHT": 0, "MISSED": 0, "NOBUILD": 0, "CRASH": 0}
    try:
        for label, path, frm, to in MUTATIONS:
            for p in FILES:
                write(p, originals[p])

            src = originals[path]
            if frm not in src:
                print("SKIP  %s -- anchor not found in %s" % (label, path))
                counts["NOBUILD"] += 1
                continue
            # An anchor that appears more than once is the failure mode that cost
            # three attempts here: `str.replace` rewrites *every* occurrence, so
            # the mutation silently becomes a different mutation and reports a
            # confident verdict about it. NOBUILD, not MISSED -- nothing was
            # proven, and calling it MISSED would point at the gate.
            hits = src.count(frm)
            if hits != 1:
                print("NOBUILD  %s -- anchor appears %d times in %s; a replace would "
                      "mutate more than intended" % (label, hits, path))
                counts["NOBUILD"] += 1
                continue
            write(path, src.replace(frm, to))

            proc = run_gate()
            out = proc.stdout or ""

            if "failed when checking project" in out or (
                proc.returncode != 0 and "ALL PASS" not in out and "  FAIL " not in out
            ):
                print("NOBUILD  %s -- the mutated source did not compile" % label)
                counts["NOBUILD"] += 1
                continue
            if proc.returncode == 0:
                print("MISSED  %s -- the gate still reported ALL PASS" % label)
                counts["MISSED"] += 1
                continue
            fails = fails_for(out)
            if not fails and ("Panic" in out or "harness:" in out):
                print("CRASH  %s -- %s" % (label, out.strip().split("\n")[0][:160]))
                counts["CRASH"] += 1
                continue
            print("CAUGHT  %s" % label)
            for f in fails:
                print("          " + f[:170])
            counts["CAUGHT"] += 1
    finally:
        for path, text in originals.items():
            write(path, text)
        drifted = [p for p in FILES if read(p) != originals[p]]
        if drifted:
            print("\nWARNING: not restored byte for byte: %s" % ", ".join(drifted))
            return 1

    print(
        "\n%d CAUGHT, %d MISSED, %d NOBUILD, %d CRASH (of %d mutations)"
        % (counts["CAUGHT"], counts["MISSED"], counts["NOBUILD"], counts["CRASH"], len(MUTATIONS))
    )
    with io.open(os.path.join(ROOT, ".loop52", "mutations.json"), "w", encoding="utf-8") as fh:
        json.dump(counts, fh, indent=2)
    return 0 if counts["MISSED"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())