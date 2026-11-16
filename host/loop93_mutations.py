"""Mutation check: every Loop #93 defect must turn the gate red.

A gate that stays green under a set of mutations is not testing anything, so
this script is part of the loop's evidence rather than a one-off.  Each entry
is one of the ways this code could plausibly be wrong, and each names the
`host/verify_loop93.mjs` check that has to go red because of it.

Three rules, all inherited from earlier loops because all three were learned
the hard way:

  * **A compile failure is not evidence.**  A mutation that does not build
    proves nothing about the gate, so it gets its own verdict (INVALID)
    instead of being counted as caught or missed.

  * **The anchor has to hit exactly once, in exactly one file.**  A drifted
    anchor is reported as SKIP and counted as not caught -- which points at
    the gate rather than at the thing that actually moved.

  * **The check name is matched EXACTLY, not as a prefix.**

What this list is about
-----------------------

Three of the mutations below are the defects this loop actually found, and
they are the interesting ones.  All three were invisible to "does the server
answer correctly", because in all three the server answered a perfectly
well-formed message that the peer refused to read:

  * The `SSH_MSG_KEX_ECDH_REPLY` signature field was written without the
    outer `string`.  The CONTENT was right -- 83 bytes, the same 83 bytes the
    real sshd sends -- and the FRAMING was wrong, so the peer read an
    11-byte "signature" and found 68 bytes it did not expect.  The peer
    said `unexpected bytes remain after decoding` and hung up.

  * The `SSH_MSG_CHANNEL_OPEN` was read with one `string` too many, so the
    window size was taken for the channel number and the refusal was
    addressed to channel 2097152 -- a channel that does not exist.

  * The `SSH_MSG_CHANNEL_OPEN_FAILURE` left out the language tag, so the
    peer had one field fewer to read than the format says.

The rest are the ways this server could be wrong without the real client
noticing, and each one is aimed at a check that DOES notice.

Run:
    python host/loop93_mutations.py                  # all of them
    python host/loop93_mutations.py --only 0,1       # a few, after a cancel
    python host/loop93_mutations.py --restore        # put back a killed run
"""
import os
import re
import sys
import json
import time
import subprocess

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

FILES = [
    os.path.join(ROOT, "src", "sshd", "kexserver.mbt"),
    os.path.join(ROOT, "src", "sshd", "server.mbt"),
    os.path.join(ROOT, "src", "sshd", "authserver.mbt"),
    os.path.join(ROOT, "src", "kexflow", "proposal.mbt"),
    os.path.join(ROOT, "cmd", "sshd", "main.mbt"),
]

BACKUP = os.path.join(ROOT, ".loop93", "mutation_backup.json")

# Output of `verify_loop93.mjs` that means "the tree did not build".
#
# **Only the build check belongs here.**  A mutation aimed at a rule the unit
# tests already pin makes both red, and the verdict must be decided by the
# named gate check first.
INVALID_MARKERS = (
    "FAIL  cmd/sshd does not build",
    "FAIL  our server built",
)

MUTATIONS = [
    (
        # The defect this loop was found by.  The signature field is a string
        # whose CONTENT is the signature blob, so the blob is wrapped in a
        # string ONE more time.  Written unwrapped, the peer reads an 11-byte
        # "signature" and refuses the connection before it ever sends
        # NEWKEYS.
        "the signature field loses its outer string",
        "    @sshwire.write_ssh_string(sig_blob),",
        "    sig_blob,",
        "the client authenticates with publickey",
    ),
    (
        # The host key's signature over the exchange hash.  A peer checks it
        # before it trusts anything else about the server, so zeroing it
        # stops the handshake at the signature.
        "the host key is not signed",
        "  let sig = @hostkey.sign(h, hostkey_sec)",
        "  let sig = FixedArray::make(64, b'\\x00')",
        "the client verified our host key",
    ),
    (
        # The two directions' traffic keys.  The server sends with the
        # `stoc` key and receives with the `ctos` key; swapping them does
        # not fail loudly, it decrypts the peer's stream into noise.
        "the two directions' keys are swapped",
        "  send_ctx.set_mode(@bpacket.MacEncrypt(stoc))\n"
        "  recv_ctx.set_mode(@bpacket.MacEncrypt(ctos))",
        "  send_ctx.set_mode(@bpacket.MacEncrypt(ctos))\n"
        "  recv_ctx.set_mode(@bpacket.MacEncrypt(stoc))",
        "the client authenticates with publickey",
    ),
    (
        # The signature the client made over the session identifier.  The
        # session identifier is the exchange hash H -- the one value both
        # ends computed and neither end sent.
        "the authentication signature is checked against the wrong session id",
        "        if verify_publickey(req, kex.session_id, authorized) {",
        "        if verify_publickey(req, FixedArray::make(32, b'\\x00'), authorized) {",
        "the client authenticates with publickey",
    ),
    (
        # The `authorized_keys` list.  A key that is not on it has to be
        # refused even when the signature over it is perfect -- and it IS
        # perfect, because the client signed with its own private key.
        #
        # This mutation is aimed at the ONE implementation of the rule that
        # both the probe and the signed request call.  There used to be two
        # comparisons, one in each, and the gate could not see either one
        # being broken: the real client always sends the probe first, so
        # breaking only the signed request's comparison left the probe's
        # refusal standing, and breaking only the probe's comparison left the
        # signed request's refusal standing.  The rule is written once now,
        # and this is where the mutation goes.
        "the authorized keys list is not consulted",
        "    if k.blob == blob {\n      return true\n    }",
        "    if k.blob != blob {\n      return true\n    }",
        "an unauthorized key is refused",
    ),
    (
        # A key with options in `authorized_keys`.  This server does not
        # implement `command=` or `no-pty`, so accepting the key without
        # honouring them would silently drop the restrictions the file
        # asked for.
        "a key with options in authorized_keys is accepted",
        "    if type_at > 0 {\n"
        "      // Options are present and this server does not implement them.\n"
        "      continue\n"
        "    }\n",
        "",
        "a key with options in authorized_keys is refused",
    ),
    (
        # The methods the peer may continue with.  An empty list is a
        # different answer from "publickey", and the peer prints it.
        "the failure payload lists no methods",
        "    @sshwire.write_ssh_string(sd_ascii(@userauth.AUTH_METHOD_PUBLICKEY)),",
        "    @sshwire.write_ssh_string(FixedArray::make(0, b'\\x00')),",
        "the client is told which methods may continue",
    ),
    (
        # The key exchange algorithm.  This is the one the real sshd and
        # the real client negotiated, and it is the one the server's
        # transcript can be compared field by field with.
        "the server proposes a different key exchange",
        '    kex_algs: "diffie-hellman-group14-sha256",',
        '    kex_algs: "curve25519-sha256",',
        "the client negotiated the measured algorithms",
    ),
    (
        # The identification string.  A peer reads it before anything else
        # and prints it.
        "the identification string is not ours",
        '  let mut ident = "SSH-2.0-MoonBit_sshd_0.1"',
        '  let mut ident = "SSH-2.0-MoonBit_sshd_0.2"',
        "the identification string is ours",
    ),
    (
        # The channel the refusal names.  RFC 4254 §5.4: the "recipient
        # channel" is the number the PEER opened.  A constant addresses the
        # refusal to a channel that does not exist, and the peer says so.
        "the refusal names a channel of our own choosing",
        "            @sshwire.write_u32(peer_channel),",
        "            @sshwire.write_u32(1U),",
        "the channel refusal is addressed to the channel the peer opened",
    ),
    (
        # The `SSH_MSG_CHANNEL_OPEN` payload is four fields -- there is no
        # `string sender channel` between the type and the number.  Reading
        # one takes the window size for the channel number.
        "the channel open is read with one string too many",
        "  let (_type_b, off1) = match sd_read_string(payload, 0) {\n"
        "    None => return None\n"
        "    Some(v) => v\n"
        "  }\n"
        "  sd_read_u32(payload, off1)",
        "  let (_type_b, off1) = match sd_read_string(payload, 0) {\n"
        "    None => return None\n"
        "    Some(v) => v\n"
        "  }\n"
        "  let (_sender_b, off2) = match sd_read_string(payload, off1) {\n"
        "    None => return None\n"
        "    Some(v) => v\n"
        "  }\n"
        "  sd_read_u32(payload, off2)",
        "the channel refusal is addressed to the channel the peer opened",
    ),
    (
        # The language tag of the refusal.  The payload is FOUR fields; a
        # peer reading three runs out of message in the wrong place.
        "the refusal leaves out the language tag",
        "            sd_cat2(\n"
        "              @sshwire.write_ssh_string(\n"
        "                sd_ascii(\"channels are not implemented by this server yet\"),\n"
        "              ),\n"
        "              // the language tag: present, and empty\n"
        "              @sshwire.write_ssh_string(FixedArray::make(0, b'\\x00')),\n"
        "            ),",
        "            @sshwire.write_ssh_string(\n"
        "              sd_ascii(\"channels are not implemented by this server yet\"),\n"
        "            ),",
        "the channel refusal says why",
    ),
    (
        # The reason code of the refusal: 1 is
        # SSH_OPEN_ADMINISTRATIVELY_PROHIBITED, and the peer prints it.
        "the refusal gives the wrong reason",
        "            @sshwire.write_u32(1U),",
        "            @sshwire.write_u32(2U),",
        "the channel refusal says why",
    ),
]


def read():
    return {p: open(p, "r", encoding="utf-8", newline="").read()
            for p in FILES if os.path.exists(p)}


def write(state):
    for p, text in state.items():
        with open(p, "w", encoding="utf-8", newline="") as fh:
            fh.write(text)


def save_backup(state):
    os.makedirs(os.path.dirname(BACKUP), exist_ok=True)
    with open(BACKUP, "w", encoding="utf-8") as fh:
        json.dump(state, fh)


def restore_leftovers():
    """Put back a run that was cancelled before its `finally`.

    A run that is cancelled never reaches its `finally`, so the working
    tree can be left with one mutation applied.  This is its own command
    (`--restore`) because a second full run would write its own backup over
    the good one first.
    """
    if not os.path.exists(BACKUP):
        return []
    with open(BACKUP, "r", encoding="utf-8", newline="") as fh:
        state = json.load(fh)
    restored = []
    current = read()
    for p, text in state.items():
        if current.get(p) != text:
            restored.append(os.path.relpath(p, ROOT))
    write(state)
    os.remove(BACKUP)
    return restored


def run_gate():
    r = subprocess.run(
        ["node", os.path.join("host", "verify_loop93.mjs")],
        cwd=ROOT, capture_output=True,
        encoding="utf-8", errors="replace", text=True,
        timeout=3600,
    )
    return r.stdout + r.stderr


def selected():
    if len(sys.argv) >= 2 and sys.argv[1] == "--restore":
        return None
    if len(sys.argv) < 3 or sys.argv[1] != "--only":
        return list(enumerate(MUTATIONS))
    picked = []
    for part in sys.argv[2].split(","):
        part = part.strip()
        if not part:
            continue
        idx = int(part)
        if idx < 0 or idx >= len(MUTATIONS):
            raise SystemExit("no mutation %d (there are %d)" % (idx, len(MUTATIONS)))
        picked.append((idx, MUTATIONS[idx]))
    return picked


def check_failed(out, name):
    """Whether the gate reported THIS check as failed, whole line only."""
    pattern = re.compile(r"^\s*FAIL\s+" + re.escape(name) + r"\s*$", re.MULTILINE)
    return pattern.search(out) is not None


def main():
    restored = restore_leftovers()
    if restored:
        print("RESTORED  a previous run was interrupted; put back: %s"
              % ", ".join(restored), flush=True)
    chosen = selected()
    if chosen is None:
        print("nothing to run; the tree is as it was")
        return 0
    original = read()
    caught, missed, invalid, skipped = [], [], [], []
    save_backup(original)
    try:
        for idx, (label, old, new, must_fail) in chosen:
            hits = {os.path.relpath(p, ROOT): t.count(old)
                    for p, t in original.items() if t.count(old)}
            targets = [p for p, t in original.items() if t.count(old) == 1]
            if len(targets) != 1 or sum(hits.values()) != 1:
                print("SKIP  %d %s -- anchor hits %s" % (idx, label, hits), flush=True)
                skipped.append(label)
                continue
            target = targets[0]
            state = dict(original)
            state[target] = state[target].replace(old, new)
            write(state)
            started = time.time()
            out = run_gate()
            elapsed = time.time() - started
            if check_failed(out, must_fail):
                # The named gate check is the evidence this loop is after,
                # so it is consulted before anything else.
                print("CAUGHT   %d %s -> %s (%.0fs)"
                      % (idx, label, must_fail, elapsed), flush=True)
                caught.append(label)
            elif any(marker in out for marker in INVALID_MARKERS):
                print("INVALID  %d %s -- the tree did not build (%.0fs)"
                      % (idx, label, elapsed), flush=True)
                invalid.append(label)
            else:
                print("MISSED   %d %s -- `%s` stayed green (%.0fs)"
                      % (idx, label, must_fail, elapsed), flush=True)
                missed.append(label)
            write(original)
    finally:
        write(original)
        if os.path.exists(BACKUP):
            os.remove(BACKUP)

    print("")
    print("---")
    print("loop93 mutations: %d caught, %d missed, %d invalid, %d skipped"
          % (len(caught), len(missed), len(invalid), len(skipped)))
    if missed:
        for label in missed:
            print("  MISSED  %s" % label)
    if invalid:
        for label in invalid:
            print("  INVALID %s" % label)
    if skipped:
        for label in skipped:
            print("  SKIP    %s" % label)
    if missed or invalid or skipped:
        return 1
    print("ALL CAUGHT")
    return 0


if __name__ == "__main__":
    sys.exit(main())
