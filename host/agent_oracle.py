#!/usr/bin/env python3
"""Loop #80 KAT oracle: the SSH agent protocol, and the publickey probe.

Reference implementation for the agent wire format. MoonBit is checked against
this, so nothing here was copied out of the MoonBit side.

Three things are pinned:

  1. The **framing**: `uint32 length` + `byte type` + payload, where the
     length counts the type byte and the payload but not itself. This is
     OpenSSH's `ssh_request_reply` (authfd.c:137-175) exactly: it writes
     `POKE_U32(buf, len)` with `len = sshbuf_len(request)`, and the request
     already contains the type byte.

  2. The **payloads**, from authfd.c:
       * IDENTITIES_ANSWER: `uint32 count`, then `count` times
         `string key blob` + `string comment`  (deserialise_identity2)
       * SIGN_REQUEST:  `string key blob` + `string data` + `uint32 flags`
         (ssh_agent_sign)
       * SIGN_RESPONSE: `string signature`

  3. The **publickey probe** (RFC 4252 section 7, boolean FALSE) -- the request
     that asks "may I use this key?" without asking anyone to sign anything.

The message numbers come from OpenSSH's authfd.h:

    SSH2_AGENTC_REQUEST_IDENTITIES  11
    SSH2_AGENT_IDENTITIES_ANSWER    12
    SSH2_AGENTC_SIGN_REQUEST        13
    SSH2_AGENT_SIGN_RESPONSE        14
    SSH2_AGENT_FAILURE              30

Usage:
    python host/agent_oracle.py                # human-readable
    python host/agent_oracle.py --json         # JSON for the verifier
"""

import argparse
import json
import os
import sys
from collections import OrderedDict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ecdsa_auth_oracle import (  # noqa: E402
    KEY_TYPE,
    SERVICE,
    mpint,
    pubkey_blob,
    sign,
    sig_blob,
    signed_blob,
    ssh_string,
)

AGENTC_REQUEST_IDENTITIES = 11
AGENT_IDENTITIES_ANSWER = 12
AGENTC_SIGN_REQUEST = 13
AGENT_SIGN_RESPONSE = 14
AGENT_FAILURE = 30

MAX_AGENT_REPLY_LEN = 256 * 1024
MAX_AGENT_IDENTITIES = 2048

SSH_MSG_USERAUTH_REQUEST = 0x32

# The identity the agent holds: the RFC 6979 A.2.5 key, same as Loop #34.
COMMENT = "loop80@agent"

# This loop's own account name. The value is irrelevant to the protocol -- the
# user name is a plain SSH string -- but keeping it distinct from Loop #34's
# makes it obvious which vector a mismatch belongs to.
USER = b"loop80"

# The bytes the agent is asked to sign.  Anything works; a fixed one makes the
# signature reproducible (RFC 6979) and therefore comparable byte for byte.
DATA = bytes(range(0xA0, 0xC0))


def u32(v):
    return v.to_bytes(4, "big")


def agent_frame(msg_type, payload=b""):
    """`uint32 length` + `byte type` + payload.

    The length counts the type byte and the payload, but not the length
    itself -- OpenSSH's `POKE_U32(buf, sshbuf_len(request))`.
    """
    body = bytes([msg_type]) + payload
    return u32(len(body)) + body


def identities_answer_payload(entries):
    """`uint32 count` + per entry `string blob` + `string comment`."""
    out = u32(len(entries))
    for blob, comment in entries:
        out += ssh_string(blob) + ssh_string(comment)
    return out


def sign_request_payload(key_blob, data, flags=0):
    """`string key blob` + `string data` + `uint32 flags`."""
    return ssh_string(key_blob) + ssh_string(data) + u32(flags)


def sign_response_payload(signature):
    """`string signature` -- the SSH-shaped signature blob."""
    return ssh_string(signature)


def probe_payload(user=USER, service=SERVICE, key_type=KEY_TYPE, blob=None):
    """The RFC 4252 section 7 probe: boolean FALSE, and no signature field.

    Same fields as the signed request, in the same order, except that the
    boolean is FALSE and the trailing `string signature` is absent.
    """
    if blob is None:
        blob = pubkey_blob()
    return (
        ssh_string(user)
        + ssh_string(service)
        + ssh_string(b"publickey")
        + b"\x00"  # boolean FALSE: no signature follows
        + ssh_string(key_type)
        + ssh_string(blob)
    )


def build():
    blob = pubkey_blob()
    entries = [(blob, COMMENT.encode("ascii"))]
    sig = sig_blob(sign(DATA))
    return OrderedDict(
        [
            ("comment", COMMENT),
            ("key_type", KEY_TYPE.decode("ascii")),
            ("data_hex", DATA.hex()),
            ("pubkey_blob_hex", blob.hex()),
            ("frame_request_identities_hex", agent_frame(AGENTC_REQUEST_IDENTITIES).hex()),
            ("identities_payload_hex", identities_answer_payload(entries).hex()),
            ("frame_sign_request_hex",
             agent_frame(AGENTC_SIGN_REQUEST, sign_request_payload(blob, DATA, 0)).hex()),
            ("sign_request_payload_hex", sign_request_payload(blob, DATA, 0).hex()),
            ("sign_response_payload_hex", sign_response_payload(sig).hex()),
            ("sig_blob_hex", sig.hex()),
            ("probe_payload_hex", probe_payload().hex()),
            # The signed blob over the same session id, for the record: the
            # agent path and the local-key path must sign the same bytes.
            ("signed_blob_hex", signed_blob(bytes(range(0xA0, 0xC0)), user=USER).hex()),
        ]
    )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    doc = build()
    if args.json:
        print(json.dumps(doc, indent=1))
        return 0

    print("SSH agent protocol -- reference wire format")
    print("")
    for k, v in doc.items():
        print("%-28s %s" % (k, v))
    return 0


if __name__ == "__main__":
    sys.exit(main())
