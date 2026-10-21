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
        # The trailing comma after `w` is the formatter's (Loop #67 ran `moon fmt`
        # over the tree), and the anchor without it stopped matching then. A
        # mutation whose anchor has drifted is not a mutation: it is reported
        # as SKIP and counted as "not caught", which points at the KAT instead
        # of at the thing that actually moved. The anchor has to be the text
        # that is in the file now.
        "drop the window when no adjust is due",
        "    None => ({ ..st, window: w, }, [])",
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
        # Same story as the anchor above: the formatter split the one-line
        # `if` across four lines, so the anchor stopped matching in Loop #67.
        # The mutated text keeps the same shape, because a mutation that
        # changes the *layout* as well as the behaviour would be measuring
        # two things at once.
        "make exit-status report 0 instead of the SSH 255 fallback",
        "pub fn ChanState::report(self : ChanState) -> ExecReport {\n"
        "  {\n"
        "    remote_id: self.remote_id,\n"
        "    local_channel: self.local_channel,\n"
        "    stdout: ch_cat_all(self.stdout),\n"
        "    stderr: ch_cat_all(self.stderr),\n"
        "    exit_status: if self.exit_status < 0 {\n"
        "      255\n"
        "    } else {\n"
        "      self.exit_status\n"
        "    },",
        "pub fn ChanState::report(self : ChanState) -> ExecReport {\n"
        "  {\n"
        "    remote_id: self.remote_id,\n"
        "    local_channel: self.local_channel,\n"
        "    stdout: ch_cat_all(self.stdout),\n"
        "    stderr: ch_cat_all(self.stderr),\n"
        "    exit_status: if self.exit_status < 0 {\n"
        "      0\n"
        "    } else {\n"
        "      self.exit_status\n"
        "    },",
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
        "} else if st.interactive {\n"
        "        // 交互式流程:CHANNEL_FAILURE 只说明「这个请求被拒了」。最常见的是服务端",
        "} else if false {\n"
        "        // 交互式流程:CHANNEL_FAILURE 只说明「这个请求被拒了」。最常见的是服务端",
        "chan_shell_sessions",
    ),
    # ---- Loop #37 --------------------------------------------------------
    (
        "ask for a reply to env, which RFC 4254 6.4 says never comes",
        '    "env",\n    false,',
        '    "env",\n    true,',
        "chan_env_payloads",
    ),
    (
        "swap the env variable name and value",
        "      @sshwire.write_ssh_string(ch_ascii(name)),\n"
        "      @sshwire.write_ssh_string(ch_ascii(value)),",
        "      @sshwire.write_ssh_string(ch_ascii(value)),\n"
        "      @sshwire.write_ssh_string(ch_ascii(name)),",
        "chan_env_payloads",
    ),
    (
        "clamp stdin to max_packet but ignore the peer's window",
        "  if n > self.remote_window {\n    n = self.remote_window\n  }\n",
        "",
        "chan_stdin_clamp",
    ),
    (
        "clamp stdin to the window but ignore max_packet",
        "  if n > self.remote_max_packet {\n    n = self.remote_max_packet\n  }\n",
        "",
        "chan_stdin_clamp",
    ),
    (
        "pretend a stalled stdin went out in full",
        "  if n <= 0 {\n    return (self, None, pending)\n  }",
        "  if n <= 0 {\n    return (self, None, FixedArray::make(0, b'\\x00'))\n  }",
        "chan_stdin_clamp",
    ),
    (
        "address CHANNEL_EOF to our own channel instead of the peer's",
        "    Some(Send(0x60, channel_bare_payload(self.remote_id))),",
        "    Some(Send(0x60, channel_bare_payload(self.local_channel))),",
        "chan_eof_action",
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
        cwd=ROOT, capture_output=True,
        # text=True alone would decode moon's output with the locale codec
        # (cp936 here), and one box-drawing character the compiler prints on
        # some paths would raise UnicodeDecodeError *inside* the batch loop.
        # The child would die after the last flushed line -- looking exactly
        # like "5 caught, 0 missed" with no traceback in the captured stderr,
        # which is what the nested Loop #42 run showed. Explicit utf-8 with
        # replacement cannot raise, whatever moon decides to print.
        encoding="utf-8", errors="replace", text=True,
        timeout=1200,
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
            print("%s  %s" % ("CAUGHT" if caught else "MISSED", label),
                  flush=True)
            if not caught:
                failures.append(label)
                for line in out.splitlines():
                    if "FAIL" in line:
                        print("        " + line.strip(), flush=True)
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
