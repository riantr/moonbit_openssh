"""Mutation check: every Loop #89 defect must turn the gate red.

A gate that stays green under a set of mutations is not testing anything, so
this script is part of the loop's evidence rather than a one-off.

Each mutation below is one of the ways this code could plausibly be wrong, and
each one names the gate check that has to go red because of it.

Three rules this script keeps, all learned elsewhere in this repository:

  * **A compile failure is not evidence.**  A mutation that does not compile
    proves nothing about the gate, so it gets its own verdict (INVALID)
    instead of being counted as caught or missed.  A *warning* counts the same
    way: the build prints a warning and the gate's own build check turns
    red, so a mutation that leaves a variable unused cannot even be measured.

  * **The anchor has to hit exactly once, in exactly one file.**  An anchor
    that has drifted (the formatter rewrapped the line, say) is reported as
    SKIP and counted as "not caught" -- which points the finger at the gate
    rather than at the thing that actually moved.

  * **A mutation that cannot fail is not evidence either.**  A mutation whose
    check never goes red is worse than no mutation at all, because it looks
    like coverage.

**The check name is matched EXACTLY, not as a prefix.**  The gate has checks
whose names start with one another's ("full lifecycle: -l one" and "full
lifecycle: -l after -d"), and a prefix match would call the second one a hit
for the first.  A mutation that is caught by the wrong check is a mutation
whose evidence says less than it appears to, so the matcher here is a whole-
line regular expression.

What this list is actually about
--------------------------------

Loop #89 makes the SSH agent work on Windows: a named-pipe transport, a
server that holds keys, and a client that talks to it.  The ways that can be
wrong are not all the same kind of wrong:

  * **The protocol is ASYMMETRIC.**  `ADD_IDENTITY` carries the key with NO
    outer length prefix; `REMOVE_IDENTITY` carries it WITH one.  That is
    not a typo -- it is what OpenSSH does, because the add path serializes
    the key field by field (`sshkey_private_serialize`) and the remove path
    writes one blob (`sshkey_puts`, which is `sshbuf_put_string`).  A
    server that reads both the same way gets exactly one of them right,
    and the one it gets wrong is the one that "works" against a mock agent.

  * **The FRAME is `u32 length` + `type` + payload, and the length counts
    the type byte.**  Get that off by one and every message is one byte
    short, which shows up as a hang or a garbage reply rather than as a
    clean failure.

  * **An identity is TWO strings, not one.**  The list answer is `u32 count`
    then per identity `string key blob` + `string comment`.  The real
    `ssh-add` reads two; one string and it says "incomplete message".

  * **The server refuses a duplicate key.**  OpenSSH's
    `process_add_identity` returns `SSH_AGENT_FAILURE` for a key it already
    holds.  A server that accepts it holds two copies of one key, and
    nothing in the protocol says that is wrong -- so it takes a decision
    the gate has to state out loud.

  * **The client's SENTENCES are the tool's contract.**  Which stream they
    go to (stdout vs stderr) and what the exit status is are all part of
    what a script can see.  "The agent has no identities." goes to STDOUT
    and exits 1; "Error connecting to agent: No such file or directory"
    goes to STDERR and exits 2.

  * **The client's own bytes have to match the real client's bytes.**  The
    gate compares the two request FRAMES byte for byte against a stub
    agent, which is the only thing that can tell a protocol shape from a
    sentence.

  * **An option letter that already means something must not be given a
    new meaning.**  `ssh-add -s` is a PKCS#11 provider (measured: it
    BLOCKS without a terminal), and the first version of this loop used
    `-s <socket>` to mean "the agent is here" -- so `ssh-add -s pkcs11`
    typed at it SUCCEEDED as a no-op.  The other end of the same mistake
    is answering "unknown option" to a REAL OpenSSH option, which turns a
    fact about this tool into a fact about the user.  Three mutations pin
    the three honest behaviours: refuse the smartcard family and say
    what it is, say "a real option this tool does not implement" for the
    rest, and keep "unknown" for things that are not options at all.

Run:  python host/loop89_mutations.py            # all of them
      python host/loop89_mutations.py --only 5   # just one, for settling a
                                                 # disagreement with the gate
      python host/loop89_mutations.py --restore  # put back a tree that a
                                                 # CANCELLED run left mutated
"""

import os
import re
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Every file a mutation may touch.  They are restored together, because a
# failed run must not leave the tree mutated.
FILES = [
    os.path.join(ROOT, "src", "agent", "agent.mbt"),
    os.path.join(ROOT, "src", "agentserver", "store.mbt"),
    os.path.join(ROOT, "src", "agentserver", "server.mbt"),
    os.path.join(ROOT, "src", "agentpipe", "agentpipe.c"),
    os.path.join(ROOT, "cmd", "ssh_add", "main.mbt"),
    os.path.join(ROOT, "cmd", "ssh_agent", "main.mbt"),
    os.path.join(ROOT, "src", "keyfile", "blob.mbt"),
]

# A run that is killed -- a timeout, a Ctrl-C, a runner that goes away --
# never reaches the `finally` at the bottom, and the tree is left MUTATED.
# The pristine state is therefore written to disk before anything is
# changed, and a run that finds its predecessor's leftovers puts them back
# before it starts.
#
# The backup lives under .loop89/, which is gitignored.
BACKUP_DIR = os.path.join(ROOT, ".loop89", "mutation_backup")
RUNNING = "RUNNING"


def _backup_path(name):
    return os.path.join(BACKUP_DIR, name)


def _backup_name(p):
    """A backup file name that is unique per FILE, not per basename.

    Two of the files under test are called `main.mbt` -- `cmd/ssh_add/
    main.mbt` and `cmd/ssh_agent/main.mbt`.  A backup keyed by the
    basename has the second one overwrite the first, and the restore
    would then put `cmd/ssh_agent`'s content into `cmd/ssh_add` --
    which is a **silent** corruption of the tree, and one that a gate
    would report as "the code is wrong".

    So the backup name is the path with the separators turned into
    something that cannot appear in a file name.
    """
    rel = os.path.relpath(p, ROOT)
    return rel.replace(os.sep, "__").replace(":", "_")


def save_backup(state):
    os.makedirs(BACKUP_DIR, exist_ok=True)
    for p, text in state.items():
        with open(_backup_path(_backup_name(p)), "w", encoding="utf-8",
                  newline="") as fh:
            fh.write(text)
    with open(_backup_path(RUNNING), "w", encoding="utf-8", newline="") as fh:
        fh.write("a mutation run was interrupted\n")


def drop_backup():
    if not os.path.isdir(BACKUP_DIR):
        return
    for name in os.listdir(BACKUP_DIR):
        try:
            os.remove(os.path.join(BACKUP_DIR, name))
        except OSError:
            pass
    try:
        os.rmdir(BACKUP_DIR)
    except OSError:
        pass


def restore_leftovers():
    """Put back a tree that a killed run left mutated.

    **This has to be callable on its own**, not just at the start of a
    run.  A run that is CANCELLED -- not crashed, CANCELLED -- does not
    reach its `finally`, and the tree is then left with one mutation
    applied.  That happened once here: the batch was cancelled while it
    was on mutation #14, and `src/keyfile/blob.mbt` was left with that
    mutation applied, which silently removed a space from the `ssh-add
    -L` output and turned two gate checks red for a reason that had
    nothing to do with the code.

    The backup is on disk precisely so that this can be undone from
    outside the process that wrote it.
    """
    marker = _backup_path(RUNNING)
    if not os.path.exists(marker):
        return []
    restored = []
    for p in FILES:
        b = _backup_path(_backup_name(p))
        if os.path.exists(b):
            with open(b, "r", encoding="utf-8", newline="") as fh:
                text = fh.read()
            with open(p, "w", encoding="utf-8", newline="") as fh:
                fh.write(text)
            restored.append(os.path.relpath(p, ROOT))
    drop_backup()
    return restored


MUTATIONS = [
    (
        # **The asymmetry.**  ADD_IDENTITY carries the key field by field
        # and has NO outer length prefix.  Wrapping the whole payload in
        # one more string is the single most likely way to get this
        # wrong -- it is what every OTHER agent message looks like, so
        # the mistake is natural.
        #
        # The check that catches it is the WIRE comparison: the two
        # clients' frames are compared byte for byte, and ours grows by
        # four bytes.
        "the ADD_IDENTITY payload gets an outer length prefix",
        "  let payload = ag_cat(\n"
        "    key_blob,\n"
        "    ag_cat(private_blob, @sshwire.write_ssh_string(ag_utf8(comment))),\n"
        "  )\n",
        "  let payload = @sshwire.write_ssh_string(ag_cat(\n"
        "    key_blob,\n"
        "    ag_cat(private_blob, @sshwire.write_ssh_string(ag_utf8(comment))),\n"
        "  ))\n",
        "the ADD_IDENTITY frame is the same",
    ),
    (
        # **The other half of the asymmetry.**  REMOVE_IDENTITY carries
        # `string <the 51-byte public key blob>` -- ONE length prefix,
        # around the blob.  Dropping it and sending the bare blob is the
        # mirror image of the mistake above, and it is just as likely:
        # a reader that expects the blob raw will read the first four
        # bytes of it (`00 00 00 0b` = 11) as a length.
        "the REMOVE_IDENTITY payload loses its length prefix",
        "      AGENTC_REMOVE_IDENTITY,\n"
        "      @sshwire.write_ssh_string(key_blob),\n",
        "      AGENTC_REMOVE_IDENTITY,\n"
        "      key_blob,\n",
        "the REMOVE_IDENTITY frame is the same",
    ),
    (
        # The frame is `u32 length` + `type` + payload, and the length
        # counts the TYPE byte and the payload but not the length
        # itself.  That is OpenSSH's `POKE_U32(buf, len)` where
        # `len = sshbuf_len(request)` and the request already holds the
        # type byte.
        #
        # Off by one here and every single message is one byte short.
        # The wire check sees it on all four message types.
        "the frame length does not count the type byte",
        "  let body = ag_cat(FixedArray::from_array([msg_type]), payload)\n"
        "  let len = body.length()\n",
        "  let body = ag_cat(FixedArray::from_array([msg_type]), payload)\n"
        "  let len = payload.length()\n",
        "the REQUEST_IDENTITIES frame is the same",
    ),
    (
        # An identity is TWO strings: the key blob and the comment.  The
        # real `ssh-add` reads two, and one string and it says
        # "incomplete message".
        #
        # The count is a u32 in NETWORK order.  Byte-swapping it is the
        # quiet version of this bug: with one key the count becomes
        # 16777216 and the client tries to read sixteen million
        # identities.
        "the identity count is not in network order",
        "fn u32_bytes(v : Int32) -> FixedArray[Byte] {\n"
        "  FixedArray::from_array([\n"
        "    ((v >> 24) & 0xFF).to_byte(),\n"
        "    ((v >> 16) & 0xFF).to_byte(),\n"
        "    ((v >> 8) & 0xFF).to_byte(),\n"
        "    (v & 0xFF).to_byte(),\n"
        "  ])\n"
        "}\n",
        "fn u32_bytes(v : Int32) -> FixedArray[Byte] {\n"
        "  FixedArray::from_array([\n"
        "    (v & 0xFF).to_byte(),\n"
        "    ((v >> 8) & 0xFF).to_byte(),\n"
        "    ((v >> 16) & 0xFF).to_byte(),\n"
        "    ((v >> 24) & 0xFF).to_byte(),\n"
        "  ])\n"
        "}\n",
        "full lifecycle: -l one",
    ),
    (
        # The comment of an identity is the SECOND string.  Dropping it
        # leaves the client printing an empty comment -- a key with no
        # name, which is exactly what a user typed a key for.
        #
        # **This one is INVISIBLE to G2.**  In G2 both clients talk to
        # our agent, so both get an empty comment and both print the
        # same line -- the comparison is happy and the key has lost its
        # name.  It is caught by the check that reads what the agent
        # HOLDS, with the real client doing the reading.
        "the identity list drops the comment",
        "    body = cat(body, @sshwire.write_ssh_string(utf8_bytes(k.comment)))\n",
        "    body = cat(body, @sshwire.write_ssh_string(utf8_bytes(\"\")))\n",
        "the agent gives back the comment it was given",
    ),
    (
        # **The key's two halves have to be the same key.**  The private
        # blob is `seed || public key`; the public blob is the public
        # key.  A server that holds a mismatched pair signs something
        # the client cannot verify, and the client sees a mysterious
        # authentication failure.
        #
        # Comparing the wrong half of the secret is the quiet version:
        # the seed is 32 bytes and the public key is 32 bytes, so the
        # comparison still RUNS and still returns false -- for every
        # key, including the good ones.
        #
        # **Invisible to G2** for the same reason as the comment: both
        # clients get the same refusal and agree about it.
        "the key consistency check compares the seed",
        "  bytes_equal_from(sk, 32, pk, 0, 32)\n",
        "  bytes_equal_from(sk, 0, pk, 0, 32)\n",
        "adding a new key succeeds",
    ),
    (
        # The agent refuses a key whose two halves disagree.  Inverting
        # the test refuses every GOOD key and accepts every bad one --
        # the worst of both, and it is invisible until a key is added.
        #
        # **Invisible to G2**: both clients get the same refusal.
        "the key consistency check is inverted",
        "  if !key_is_consistent(key) {\n"
        "    // 这句话是给**看 agent 的人**的",
        "  if key_is_consistent(key) {\n"
        "    // 这句话是给**看 agent 的人**的",
        "adding a new key succeeds",
    ),
    (
        # **OpenSSH's agent refuses a duplicate key**
        # (`process_add_identity`).  A server that accepts it holds two
        # copies of one key, and the protocol has no way to say that is
        # wrong -- so the gate has to say it out loud.
        #
        # This one is INVISIBLE to the "our client vs the real client"
        # comparison, because both clients talk to OUR agent and would
        # agree perfectly about a wrong answer.  It is caught by the
        # section that asks the REAL client what the server decided.
        "the agent accepts a duplicate key",
        "  if self.find(key.key_blob) is Some(_) {\n"
        "    return false\n"
        "  }\n",
        "  if self.find(key.key_blob) is Some(_) && self.keys.length() > 100 {\n"
        "    return false\n"
        "  }\n",
        "adding the same key again is refused",
    ),
    (
        # Removing all the keys SUCCEEDS even when there are none:
        # "removed zero keys" is still "removed them all".  Answering
        # FAILURE instead makes `ssh-add -D` say "Failed to remove all
        # identities." on an agent that never had anything.
        "removing all from an empty agent fails",
        "pub fn remove_all(store : AgentStore) -> (Byte, FixedArray[Byte]) {\n"
        "  store.remove_all()\n"
        "  (@agent.AGENT_SUCCESS, FixedArray::make(0, b'\\x00'))\n"
        "}\n",
        "pub fn remove_all(store : AgentStore) -> (Byte, FixedArray[Byte]) {\n"
        "  store.remove_all()\n"
        "  (@agent.AGENT_FAILURE, FixedArray::make(0, b'\\x00'))\n"
        "}\n",
        "removing all from an empty agent succeeds",
    ),
    (
        # An agent that does not understand a request says so.  Saying
        # "success" instead is the worst kind of quiet: the client goes
        # away believing something happened.
        "an unknown request is answered with success",
        "  } else {\n"
        "    (@agent.AGENT_FAILURE, FixedArray::make(0, b'\\x00'))\n"
        "  }\n"
        "}\n",
        "  } else {\n"
        "    (@agent.AGENT_SUCCESS, FixedArray::make(0, b'\\x00'))\n"
        "  }\n"
        "}\n",
        "src/agentserver's tests pass on native",
    ),
    (
        # The private blob of an ed25519 key is `u32 64` + 64 bytes, and
        # the 64 bytes are `seed || public key`.  A check that wants a
        # different length refuses every key.
        "the secret key length check is wrong",
        "  if sk.length() != 64 {\n"
        "    return None\n"
        "  }\n",
        "  if sk.length() != 65 {\n"
        "    return None\n"
        "  }\n",
        "src/agentserver's tests pass on native",
    ),
    (
        # **Which stream a sentence goes to is part of the contract.**
        # "The agent has no identities." is a `printf` in OpenSSH --
        # stdout -- and the exit status is still 1.
        "the empty-agent sentence goes to stderr",
        '    println("The agent has no identities.")\n',
        '    eprintln("The agent has no identities.")\n',
        "empty agent -l: -l empty",
    ),
    (
        # **The exit status of "there is no agent" is 2**, not 1.  A
        # script that reads 1 as "the agent said no" and 2 as "there is
        # no agent" cannot tell the two apart otherwise.
        "the no-agent exit status is 1",
        "  let pipe = match @agentpipe.agent_pipe_connect(sock) {\n"
        "    None => {\n"
        "      eprintln(\"Error connecting to agent: No such file or directory\")\n"
        "      @env.exit(2)\n",
        "  let pipe = match @agentpipe.agent_pipe_connect(sock) {\n"
        "    None => {\n"
        "      eprintln(\"Error connecting to agent: No such file or directory\")\n"
        "      @env.exit(1)\n",
        "no agent: -l",
    ),
    (
        # The fingerprint line is `<bits> <fingerprint> <comment>
        # (<type>)`.  The bit count is the FIRST thing on the line, and
        # it is the number of bits in the key: 256 for ed25519.
        "the fingerprint line has no bit count",
        '        "256 " +\n'
        "        @keyfile.fingerprint_of_blob(id.key_blob) +\n",
        "        @keyfile.fingerprint_of_blob(id.key_blob) +\n",
        "full lifecycle: -l one",
    ),
    (
        # **`-L` prints the public key line and then a SPACE and the
        # comment.**  The space is unconditional -- OpenSSH prints the
        # key line, then prints `" " + comment`.  The `.pub` FILE has no
        # trailing space when the comment is empty, but `ssh-add -L` does.
        # The two are different things and the gate compares the latter.
        "the -L line has no space before the comment",
        '  KEY_TYPE + " " + b64 + " " + comment\n',
        '  KEY_TYPE + " " + b64 + comment\n',
        "full lifecycle: -L one",
    ),
    (
        # "All identities removed." goes to STDERR.  OpenSSH's
        # `delete_all` is `fprintf(stderr, ...)`.
        "the remove-all sentence goes to stdout",
        '    eprintln("All identities removed.")\n',
        '    println("All identities removed.")\n',
        "full lifecycle: -D remove all",
    ),
    (
        # The path of the key file is IN the sentence.  A tool that says
        # "Identity added" without saying WHICH file it added is a tool
        # a script cannot use when it adds several files at once.
        "the added sentence does not name the file",
        '    eprintln("Identity added: " + path + " (" + key.comment_text + ")")\n',
        '    eprintln("Identity added: (" + key.comment_text + ")")\n',
        "full lifecycle: add",
    ),
    (
        # The type of the key is IN the removal sentence:
        # `Identity removed: <path> <TYPE> (<comment>)`.  OpenSSH prints
        # the key type there, and it is how a user tells an ed25519 key
        # from an RSA one without running `-l`.
        "the removed sentence names the wrong key type",
        '        key_type: "ED25519",\n',
        '        key_type: "ED25519X",\n',
        "full lifecycle: -d remove",
    ),
    (
        # `-q` means quiet.  Printing the sentence anyway makes `-q`
        # useless, and `-q` exists because scripts use it.
        "the quiet flag is ignored when adding",
        '  if !quiet {\n'
        '    eprintln("Identity added: " + path + " (" + key.comment_text + ")")\n'
        "  }\n",
        '  eprintln("Identity added: " + path + " (" + key.comment_text + ")")\n',
        "quiet add: add -q",
    ),
    (
        # The agent can be GIVEN a key at startup (`ssh_agent -a <file>`).
        # An agent that loads the key and then drops it is an agent whose
        # startup option does nothing.
        "the agent drops the key it was given at startup",
        "        if !store.add(key) {\n"
        '          eprintln("ssh_agent: " + f + " is already in the agent")\n'
        "          @env.exit(1)\n"
        "        }\n",
        "        if !store.add(key) {\n"
        '          eprintln("ssh_agent: " + f + " is already in the agent")\n'
        "          @env.exit(1)\n"
        "        }\n"
        "        store.remove_all()\n",
        "the real client sees the key the agent was given at startup",
    ),
    (
        # The client opens the pipe READ-WRITE.  Opening it read-only
        # means it cannot send a request, and the failure shows up as
        # "no agent" -- a sentence about the wrong thing entirely.
        "the client opens the pipe read-only",
        "\t\tGENERIC_READ | GENERIC_WRITE,\n",
        "\t\tGENERIC_READ,\n",
        "the ADD_IDENTITY frame is the same",
    ),
    (
        # **An option a tool does not implement must say so.**
        #
        # OpenSSH's `ssh-add -s <provider>` means "add keys from a
        # PKCS#11 provider", and it BLOCKS without a terminal (measured:
        # killed at 6s, no output).  This tool has no smartcard support,
        # so the honest answer is a sentence that names the meaning and
        # the absence -- exit 1, and it must not hang.
        #
        # The tempting alternative is to take the letter and give it a
        # DIFFERENT meaning, which is what the first version of this
        # loop did (`-s <socket>` = "the agent is here").  Then
        # `ssh-add -s pkcs11` typed at our tool SUCCEEDS as a no-op --
        # the worst answer available, because the user is told the card
        # was added.
        #
        # Falling through to "unknown option" is the second-worst: it is
        # a lie about the INTERFACE, since `-s` is a real OpenSSH option.
        "the client treats -s as an unknown option",
        "    } else if a == \"-s\" || a == \"-e\" || a == \"-S\" {\n",
        "    } else if a == \"--smartcard-unsupported\" {\n",
        "our ssh_add refuses '-s' as a smartcard option",
    ),
    (
        # **The other half of the same distinction.**
        #
        # `-c` `-t` `-k` `-K` `-X` `-x` `-E` `-T` `-v` are REAL `ssh-add`
        # options -- they are in the real tool's own usage line -- and
        # this tool does not implement them.  Answering "unknown option"
        # makes a fact about US sound like a fact about the USER.
        #
        # A mutation that drops one option out of the list makes the
        # client call a REAL option "unknown" -- a fact about us
        # reported as a fact about the user, which is the exact
        # behaviour this loop is about not having.
        "the client calls a real unimplemented option an unknown one",
        '  a == "-c" ||\n',
        '  a == "-%c" ||\n',
        "our ssh_add says '-c' is a real option it does not implement",
    ),
    (
        # **"You did not finish the word" is not "you said a wrong word".**
        #
        # `--socket` at the end of the command line means the user knows
        # what they want and stopped typing.  The sentence has to say
        # THAT, and not "unexpected argument", which blames a word that
        # was spelled right.
        #
        # The mutation changes the sentence rather than deleting the
        # guard: deleting it would make the read go past the end of
        # `argv` and turn the answer into a crash, and a crash is
        # platform behaviour rather than this tool's contract.
        "the agent blames the user for an unfinished option",
        "        eprintln(\"ssh_agent: \" + a + \" requires an argument\")\n",
        "        eprintln(\"ssh_agent: unexpected argument: \" + a)\n",
        "our ssh_agent says an option needs its argument",
    ),
]


def read():
    return {p: open(p, "r", encoding="utf-8", newline="").read() for p in FILES}


def write(state):
    for p, text in state.items():
        with open(p, "w", encoding="utf-8", newline="") as fh:
            fh.write(text)


def run_gate():
    r = subprocess.run(
        ["node", os.path.join("host", "verify_loop89.mjs")],
        cwd=ROOT, capture_output=True,
        # text=True alone would decode the gate's output with the locale
        # codec (cp936 here), and one box-drawing character would raise
        # UnicodeDecodeError *inside* the batch loop -- the child would
        # die after the last flushed line, looking exactly like "0 caught,
        # 21 missed" with no traceback in the captured stderr.  Explicit
        # utf-8 with replacement cannot raise, whatever the gate prints.
        encoding="utf-8", errors="replace", text=True,
        timeout=3600,
    )
    return r.stdout + r.stderr


def selected():
    """The mutations to run, in order.

    `--only N` runs a single one, and `--only 17,18,19` runs a few.  That
    is not a convenience: this list went through a round where the
    author's expectation and the measurement disagreed, and the way to
    settle such a disagreement is to run that one mutation and read the
    gate's output, not to re-run the whole batch and hope.

    **The comma form exists because a batch can be CANCELLED.**  A
    twenty-four mutation run takes about twenty-six minutes, and this one
    was cancelled at 17 of 24 when the session went away overnight --
    the tree was left mutated AND the last seven mutations had no
    evidence at all.  Running the remainder as a short list means the
    next interruption costs minutes rather than the whole run.

    `--restore` runs nothing: it puts back a tree that a killed run left
    mutated, and exits.  **A run that is CANCELLED does not reach its
    `finally`**, so the tree can be left with one mutation applied --
    and the next full run would restore it anyway, but only after
    writing its own backup over the good one.  So the restore has to be
    its own command.
    """
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
            print("--only takes 0..%d" % (len(MUTATIONS) - 1))
            sys.exit(2)
        picked.append((idx, MUTATIONS[idx]))
    if not picked:
        print("--only got no indexes")
        sys.exit(2)
    return picked


# The checks that mean "the tree did not build" -- a mutation that lands on
# one of these is INVALID rather than caught or missed.
BUILD_FAILURES = [
    "FAIL  src/agentpipe compiles on native",
    "FAIL  src/agentserver compiles on native",
    "FAIL  src/keyfile compiles on native",
    "FAIL  cmd/ssh_agent compiles on native",
    "FAIL  cmd/ssh_add compiles on native",
    "FAIL  cmd/ssh_agent builds",
    "FAIL  cmd/ssh_add builds",
    "FAIL  the built ssh_agent is there",
    "FAIL  the built ssh_add is there",
]


def check_failed(out, name):
    """Whether the gate reported THIS check as failed.

    The whole line, and not a prefix: the gate has checks whose names
    start with one another's ("full lifecycle: -l one" and "full lifecycle:
    -l after -d"), and a prefix match would call the second one a hit for
    the first.
    """
    pattern = re.compile(r"^\s*FAIL\s+" + re.escape(name) + r"\s*(--.*)?$",
                         re.MULTILINE)
    return pattern.search(out) is not None


def main():
    # A run that was killed leaves the tree mutated.  Put it back before
    # anything else, and say so loudly -- a tree that is quietly wrong
    # measures nothing.
    restored = restore_leftovers()
    if restored:
        print("RESTORED  a previous run was interrupted; put back: %s"
              % ", ".join(restored), flush=True)
    chosen = selected()
    if chosen is None:
        print("nothing to run; the tree is as it was")
        return 0
    original = read()
    failures = []
    save_backup(original)
    try:
        for idx, (label, old, new, must_fail) in chosen:
            # The file that contains the anchor -- and it has to contain it
            # EXACTLY once, in exactly one file.  An anchor that appears
            # twice is a mutation that might hit the wrong place.
            #
            # **The keys are paths, not basenames.**  Two of the files
            # under test are called `main.mbt` -- `cmd/ssh_add/main.mbt`
            # and `cmd/ssh_agent/main.mbt` -- and a dict keyed by the
            # basename has the second one overwrite the first.  That
            # hides a hit, and a hidden hit reads as "the anchor drifted"
            # when it did not: every anchor that lives in `cmd/ssh_add`
            # came back as a SKIP.
            hits = {os.path.relpath(p, ROOT): t.count(old)
                    for p, t in original.items() if t.count(old)}
            targets = [p for p, t in original.items() if t.count(old) == 1]
            if len(targets) != 1 or sum(hits.values()) != 1:
                print("SKIP  %s -- anchor hits %s" % (label, hits), flush=True)
                failures.append(label)
                continue
            target = targets[0]
            state = dict(original)
            state[target] = state[target].replace(old, new)
            write(state)
            started = time.time()
            out = run_gate()
            elapsed = time.time() - started
            if any(f in out for f in BUILD_FAILURES):
                # A mutation that does not build proves nothing about the
                # gate.  It is neither caught nor missed; it is a broken
                # mutation, and it has to be fixed.
                #
                # "does not build" covers a warning as well as an error:
                # the gate's own build check turns red on a warning, so a
                # mutation that leaves a variable unused cannot even be
                # measured.
                print("INVALID  %s -- the mutation does not build cleanly" % label, flush=True)
                failures.append(label)
                continue
            caught = check_failed(out, must_fail)
            print("%s  [%d] %s  (%.0fs)"
                  % ("CAUGHT" if caught else "MISSED", idx, label, elapsed),
                  flush=True)
            if not caught:
                failures.append(label)
                for line in out.splitlines():
                    if line.startswith("  FAIL"):
                        print("        " + line.strip(), flush=True)
    finally:
        write(original)
        drop_backup()

    print()
    if failures:
        print("MUTATION CHECK FAILED: %d of %d not caught"
              % (len(failures), len(chosen)))
        return 1
    print("all %d mutations turned the gate red" % len(chosen))
    return 0


if __name__ == "__main__":
    sys.exit(main())
