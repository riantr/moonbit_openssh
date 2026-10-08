"""Mutation check: each Loop #35 bug must turn the KAT red.

Every mutation below is one of the three defects that actually existed in
src/channel while it was being written.  A KAT that stays green under all of
them is not testing anything, so this script is part of the loop's evidence
rather than a one-off.

Run:  python host/channel_mutations.py
"""

import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXEC = os.path.join(ROOT, "src", "channel", "exec.mbt")

# (label, original, mutated, a check name that must go FAIL)
MUTATIONS = [
    (
        "drop the window when no adjust is due",
        "    None => ({ ..st, window: w }, [])",
        "    None => (st, [])",
        "chan_sessions",
    ),
    (
        "send WINDOW_ADJUST with 0 bytes (read amount after take_adjust)",
        "channel_window_adjust_payload(st.remote_id, w.adjust_amount())",
        "channel_window_adjust_payload(st.remote_id, w2.adjust_amount())",
        "chan_sessions",
    ),
    (
        "treat an inbound recipient as the peer's channel id",
        "          if who != st.local_channel {\n"
        "            (st, none, Some(ChanError::Malformed(\"data_wrong_channel\")))",
        "          if who != st.remote_id {\n"
        "            (st, none, Some(ChanError::Malformed(\"data_wrong_channel\")))",
        "chan_sessions",
    ),
    (
        "make exit-status report 0 instead of the SSH 255 fallback",
        "    exit_status: if self.exit_status < 0 { 255 } else { self.exit_status },",
        "    exit_status: if self.exit_status < 0 { 0 } else { self.exit_status },",
        "chan_sessions",
    ),
]


def read():
    with open(EXEC, "r", encoding="utf-8", newline="") as fh:
        return fh.read()


def write(text):
    with open(EXEC, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)


def run_kat():
    r = subprocess.run(
        ["moon", "run", "cmd/channel_test", "--target", "native"],
        cwd=ROOT, capture_output=True, text=True,
    )
    return r.stdout + r.stderr


def main():
    original = read()
    failures = []
    try:
        for label, old, new, must_fail in MUTATIONS:
            if original.count(old) != 1:
                print("SKIP  %s -- anchor found %d times"
                      % (label, original.count(old)))
                failures.append(label)
                continue
            write(original.replace(old, new))
            out = run_kat()
            caught = ("%s: FAIL" % must_fail) in out
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
