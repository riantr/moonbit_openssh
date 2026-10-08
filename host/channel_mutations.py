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
# Loop #35 mutated src/channel/exec.mbt; Loop #36 added the interactive
# builders to src/channel/channel.mbt, so both files have to be restored
# together or a failed run leaves the tree mutated.
FILES = [
    os.path.join(ROOT, "src", "channel", "exec.mbt"),
    os.path.join(ROOT, "src", "channel", "channel.mbt"),
]

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
        "pub fn ChanState::report(self : ChanState) -> ExecReport {\n"
        "  {\n"
        "    remote_id: self.remote_id,\n"
        "    local_channel: self.local_channel,\n"
        "    stdout: ch_cat_all(self.stdout),\n"
        "    stderr: ch_cat_all(self.stderr),\n"
        "    exit_status: if self.exit_status < 0 { 255 } else { self.exit_status },",
        "pub fn ChanState::report(self : ChanState) -> ExecReport {\n"
        "  {\n"
        "    remote_id: self.remote_id,\n"
        "    local_channel: self.local_channel,\n"
        "    stdout: ch_cat_all(self.stdout),\n"
        "    stderr: ch_cat_all(self.stderr),\n"
        "    exit_status: if self.exit_status < 0 { 0 } else { self.exit_status },",
        "chan_sessions",
    ),
    # ---- Loop #36 --------------------------------------------------------
    (
        "swap cols and rows in pty-req",
        "      @sshwire.write_ssh_string(ch_ascii(term)),\n"
        "      u32be(cols),\n"
        "      u32be(rows),",
        "      @sshwire.write_ssh_string(ch_ascii(term)),\n"
        "      u32be(rows),\n"
        "      u32be(cols),",
        "chan_pty_payloads",
    ),
    (
        "send the tty modes unwrapped (forget the outer string)",
        "      u32be(pixel_height),\n"
        "      @sshwire.write_ssh_string(modes),",
        "      u32be(pixel_height),\n"
        "      modes,",
        "chan_pty_payloads",
    ),
    (
        "drop the TTY_OP_END terminator from the modes string",
        "    FixedArray::from_array([TTY_OP_OSPEED]),\n"
        "    u32be(baud),\n"
        "    FixedArray::from_array([TTY_OP_END]),",
        "    FixedArray::from_array([TTY_OP_OSPEED]),\n"
        "    u32be(baud),",
        "chan_pty_payloads",
    ),
    (
        "ask for a reply to window-change, which the server never sends",
        "    recipient,\n"
        "    \"window-change\",\n"
        "    false,",
        "    recipient,\n"
        "    \"window-change\",\n"
        "    true,",
        "chan_pty_payloads",
    ),
    (
        "ignore exit-signal again",
        "          } else if rtype == \"exit-signal\" {",
        "          } else if rtype == \"exit-signal-never-matches\" {",
        "chan_shell_sessions",
    ),
    (
        "treat a refused pty-req as fatal instead of falling back",
        "      if st.interactive {",
        "      if false {",
        "chan_shell_sessions",
    ),
]


def read():
    return {p: open(p, "r", encoding="utf-8", newline="").read() for p in FILES}


def write(state):
    for p, text in state.items():
        with open(p, "w", encoding="utf-8", newline="") as fh:
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
            # find the file that contains the anchor
            target = None
            for p, text in original.items():
                if text.count(old) == 1:
                    target = p
                    break
            if target is None:
                counts = {os.path.basename(p): t.count(old)
                          for p, t in original.items()}
                print("SKIP  %s -- anchor count %s" % (label, counts))
                failures.append(label)
                continue
            state = dict(original)
            state[target] = state[target].replace(old, new)
            write(state)
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
