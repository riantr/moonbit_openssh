"""Mutation check: every Loop #80 defect must turn the gate red.

A gate that stays green under a set of mutations is not testing anything, so
this script is part of the loop's evidence rather than a one-off.

Each mutation below is one of the ways this code could plausibly be wrong, and
each one names the gate check that has to go red because of it.

Three rules this script keeps, all learned elsewhere in this repository:

  * **A compile failure is not evidence.**  A mutation that does not compile
    proves nothing about the gate, so it gets its own verdict (INVALID)
    instead of being counted as caught or missed.

  * **The anchor has to hit exactly once, in exactly one file.**  An anchor
    that has drifted (the formatter rewrapped the line, say) is reported as
    SKIP and counted as "not caught" -- which points the finger at the gate
    rather than at the thing that actually moved.

  * **A mutation that cannot fail is not evidence either.**  A mutation whose
    check never goes red is worse than no mutation at all, because it looks
    like coverage.

The interesting one in this list is the last pair.  "The probe comes first" is
a claim about *ordering*, and no amount of inspecting a successful transcript
can establish it: a successful run signs exactly once whether or not the probe
happened.  So the gate runs a second agent holding a key the server rejects,
and asserts that this agent was never asked to sign.  The mutation "sign
before you probe" therefore has to be caught by that counter, and it is.

Run:  python host/loop80_mutations.py            # all of them
      python host/loop80_mutations.py --only 5   # just one, for settling a
                                                 # disagreement with the gate
"""

import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Every file a mutation may touch. They are restored together, because a
# failed run must not leave the tree mutated.
FILES = [
    os.path.join(ROOT, "src", "agent", "agent.mbt"),
    os.path.join(ROOT, "src", "userauth", "userauth.mbt"),
    os.path.join(ROOT, "src", "sshclient", "agentauth.mbt"),
]

# (label, original, mutated, a check name that must go FAIL)
MUTATIONS = [
    (
        # The framing: `uint32 length` + `byte type` + payload, where the
        # length counts the type byte and the payload but NOT itself.
        #
        # OpenSSH writes it with `POKE_U32(buf, sshbuf_len(request))` and the
        # request already holds the type byte, so the length is the length of
        # everything that follows the length field.  Counting the length
        # field itself makes every message one byte too long, and the peer
        # reads the type byte as the first payload byte.
        "the frame length counts the length field itself",
        "  let body = ag_cat(FixedArray::from_array([msg_type]), payload)\n"
        "  let len = body.length()",
        "  let body = ag_cat(FixedArray::from_array([msg_type]), payload)\n"
        "  let len = body.length() + 4",
        "KAT frame_request_identities == oracle frame_request_identities_hex",
    ),
    (
        # The SIGN_REQUEST payload is `string key blob` + `string data` +
        # `uint32 flags` (authfd.c, ssh_agent_sign).  Swapping the first two
        # makes the agent read the key blob as the data to sign -- so it signs
        # the public key instead of the authentication request, and the server
        # rejects the signature.
        "the sign request puts the data before the key blob",
        "    @sshwire.write_ssh_string(key_blob),\n"
        "    ag_cat(\n"
        "      @sshwire.write_ssh_string(data),",
        "    @sshwire.write_ssh_string(data),\n"
        "    ag_cat(\n"
        "      @sshwire.write_ssh_string(key_blob),",
        "KAT sign_request_payload == oracle sign_request_payload_hex",
    ),
    (
        # The IDENTITIES_ANSWER payload is `uint32 count` + per entry
        # `string blob` + `string comment` (authfd.c, deserialise_identity2).
        # Swapping the two fields means every comment is read as a key and
        # every key as a comment.
        "the identities answer puts the comment before the key blob",
        "    out = ag_cat(out, @sshwire.write_ssh_string(entries[i].key_blob))\n"
        "    out = ag_cat(out, @sshwire.write_ssh_string(ag_ascii(entries[i].comment)))",
        "    out = ag_cat(out, @sshwire.write_ssh_string(ag_ascii(entries[i].comment)))\n"
        "    out = ag_cat(out, @sshwire.write_ssh_string(entries[i].key_blob))",
        "KAT identities_payload == oracle identities_payload_hex",
    ),
    (
        # The same two fields, but on the *reading* side.  The writer can be
        # right and the reader wrong, and then the client believes the agent
        # holds a key whose "name" is a blob of bytes.
        "the identity parser reads the comment before the key blob",
        "    let (blob, next) = match ag_read_string(payload, off) {\n"
        "      None => return None\n"
        "      Some(v) => v\n"
        "    }\n"
        "    let (comment, next2) = match ag_read_string(payload, next) {",
        "    let (comment, next) = match ag_read_string(payload, off) {\n"
        "      None => return None\n"
        "      Some(v) => v\n"
        "    }\n"
        "    let (blob, next2) = match ag_read_string(payload, next) {",
        "the parsed identity keeps its comment",
    ),
    (
        # The reply length is a u32 **given by the peer**.  Taking it at face
        # value means one bad agent can make the client allocate 4 GiB.  This
        # is OpenSSH's `MAX_AGENT_REPLY_LEN`, and the check has to happen
        # before the allocation, not after.
        "the reply length limit is not enforced",
        "  if len > MAX_REPLY_LEN {",
        "  if len > 0x7FFFFFF0 {",
        "the KAT refuses a bad reply limit",
    ),
    (
        # The identity count is a u32 given by the peer too, and the same
        # argument applies: an agent claiming to hold four billion keys must
        # not make the client loop four billion times.  OpenSSH's
        # `MAX_AGENT_IDENTITIES` is 2048.
        "the identity count limit is not enforced",
        "  if num > MAX_IDENTITIES {",
        "  if num > 0x7FFFFFF0 {",
        "the KAT refuses a bad identities count limit",
    ),
    (
        # The probe is the RFC 4252 section 7 request with the boolean set to
        # FALSE.  A probe that claims a signature follows is a *signed*
        # request that carries no signature, and the server reads the next
        # field as the signature -- which is not there.
        "the probe claims a signature follows",
        "          FixedArray::from_array([SSH_BOOL_FALSE]),",
        "          FixedArray::from_array([SSH_BOOL_TRUE]),",
        "KAT probe_payload == oracle probe_payload_hex",
    ),
    (
        # The probe has to name the public key it wants to use, and it has to
        # name it **in the right order**: `string algorithm name` and then
        # `string public key blob` (RFC 4252 section 7).  Swap them and the
        # server reads the blob as an algorithm name, finds nothing it
        # recognises, and says "no" -- a rejection that has nothing to do
        # with the key.
        #
        # This mutation swaps rather than deletes, and that is deliberate: an
        # earlier version dropped the public key blob, which left the
        # `pubkey_blob` parameter unused, and `moon run` treats a warning as a
        # failure -- so the mutation came back INVALID (the build "failed")
        # instead of as evidence about the gate.  A mutation that cannot
        # build is not a mutation.
        "the probe puts the algorithm name after the public key blob",
        "          ua_concat(\n"
        "            @sshwire.write_ssh_string(ua_ascii(key_type)),\n"
        "            @sshwire.write_ssh_string(pubkey_blob),\n"
        "          ),",
        "          ua_concat(\n"
        "            @sshwire.write_ssh_string(pubkey_blob),\n"
        "            @sshwire.write_ssh_string(ua_ascii(key_type)),\n"
        "          ),",
        "KAT probe_payload == oracle probe_payload_hex",
    ),
    (
        # The bytes that get signed (RFC 4252 section 7) are
        #     string session identifier
        #     byte   SSH_MSG_USERAUTH_REQUEST
        #     string user name
        #     string service name
        #     string "publickey"
        #     boolean TRUE
        #     string public key algorithm name
        #     string public key blob
        # and the order is part of the contract: the server rebuilds them in
        # exactly this order and verifies the signature against the result.
        # Swapping two of the fields still produces a perfectly valid ECDSA
        # signature -- over the wrong bytes -- and the server says
        # "signature unverified" and nothing more.
        #
        # Note that this mutation keeps every variable **used**.  An earlier
        # version of it deleted the session identifier outright, which left
        # the parameter unused -- and `moon run` treats a warning as a
        # failure, so the mutation came back as INVALID (the build "failed")
        # rather than as evidence about the gate.  A mutation that cannot
        # build is not a mutation.
        "the signed blob swaps the user and the service",
        "        @sshwire.write_ssh_string(ua_ascii(user)),\n"
        "        ua_concat(\n"
        "          @sshwire.write_ssh_string(ua_ascii(service)),",
        "        @sshwire.write_ssh_string(ua_ascii(service)),\n"
        "        ua_concat(\n"
        "          @sshwire.write_ssh_string(ua_ascii(user)),",
        "KAT signed_blob == oracle signed_blob_hex",
    ),
    (
        # The agent hands back a signature; the client is supposed to put it
        # into the request unchanged.  Asking the agent to sign the wrong
        # bytes produces a valid signature over nothing at all.
        "the agent signs the wrong bytes",
        "  let sig = match @agent.agent_sign(agent, identity.key_blob, to_sign) {",
        "  let sig = match @agent.agent_sign(\n"
        "    agent,\n"
        "    identity.key_blob,\n"
        "    FixedArray::make(0, b'\\x00'),\n"
        "  ) {",
        "result: USERAUTH_SUCCESS",
    ),
    (
        # The SIGN_RESPONSE payload is `string signature` -- the signature is
        # *inside* a string.  Handing the whole payload to the request puts
        # the length prefix into the signature, and the server reads a
        # signature blob that starts with four zero bytes.
        "the signature is not taken out of its string",
        "  let (sig, _) = match ag_read_string(payload, 0) {\n"
        "    None => return None\n"
        "    Some(v) => v\n"
        "  }\n"
        "  Some(sig)",
        "  Some(payload)",
        "result: USERAUTH_SUCCESS",
    ),
    (
        # **The ordering claim.**  The probe exists so that a key the server
        # will not accept never reaches the agent -- a real agent may ask the
        # user to confirm, and a confirmation prompt for a key that was
        # always going to be refused is pure harassment.
        #
        # This mutation signs before it probes.  A successful run cannot
        # detect it (it signs once either way), so the gate runs a second
        # agent holding a key the server rejects and asserts that this agent
        # was never asked to sign.  Here it is asked once, before the probe
        # has any answer -- which is exactly the defect.
        "sign before you probe",
        "  if ids.length() == 0 {\n"
        "    return (AgentFailed(AgentAuthError::NoIdentity), None)\n"
        "  }",
        "  if ids.length() == 0 {\n"
        "    return (AgentFailed(AgentAuthError::NoIdentity), None)\n"
        "  }\n"
        "  let _early = @agent.agent_sign(\n"
        "    agent,\n"
        "    ids[0].key_blob,\n"
        "    FixedArray::make(0, b'\\x00'),\n"
        "  )",
        "the agent served exactly one identity and one signature",
    ),
]


def read():
    return {p: open(p, "r", encoding="utf-8", newline="").read() for p in FILES}


def write(state):
    for p, text in state.items():
        with open(p, "w", encoding="utf-8", newline="") as fh:
            fh.write(text)


def run_gate():
    # The regression section is skipped: it runs the gates of Loop #78 and
    # #79, which take minutes and cannot be affected by a change to the
    # agent's own files.  What is left is the part this loop is about.
    r = subprocess.run(
        ["node", os.path.join("host", "verify_loop80.mjs"), "--skip-regression"],
        cwd=ROOT, capture_output=True,
        # text=True alone would decode the gate's output with the locale
        # codec (cp936 here), and one box-drawing character would raise
        # UnicodeDecodeError *inside* the batch loop -- the child would die
        # after the last flushed line, looking exactly like "0 caught, 7
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
            if "FAIL  cmd/agent_kat runs on 4 target x 2 mode" in out or \
               "FAIL  cmd/ssh_live builds for native" in out:
                # A mutation that does not build proves nothing about the
                # gate.  It is neither caught nor missed; it is a broken
                # mutation, and it has to be fixed.
                #
                # "does not build" covers a warning as well as an error:
                # `moon run` exits non-zero when the build prints a warning,
                # so a mutation that leaves a variable unused cannot even be
                # measured.  (That is how the first version of the
                # session-identifier mutation was rejected: it deleted the
                # parameter's only use, the KAT's build started warning, and
                # the run "failed" for a reason that had nothing to do with
                # the gate.)
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
