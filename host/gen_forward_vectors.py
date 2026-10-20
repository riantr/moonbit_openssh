#!/usr/bin/env python3
"""Generate the expected direct-tcpip CHANNEL_OPEN bytes -- Loop #76.

The expected bytes are produced by **paramiko's own encoder**, not by a
transcription of our own MoonBit code. That distinction is the whole reason
this file exists: a wire format is a contract with other implementations, and
"our encoder agrees with our encoder" proves nothing.

paramiko builds this message in `Transport.open_channel()`:

    msg.add_string('direct-tcpip')
    msg.add_int(self._next_channel())
    msg.add_int(self.local_window)
    msg.add_int(self.local_maximum_packet_size)
    msg.add_string(dest_addr)
    msg.add_int(dest_port)
    msg.add_string(src_addr)
    msg.add_int(src_port)

which is RFC 4254 section 7.2 field for field. The class used here,
`paramiko.message.Message`, is paramiko's own encoder, so the bytes below are
the bytes a working SSH implementation puts on the wire.

Usage:
    python host/gen_forward_vectors.py
"""

import sys

from paramiko.message import Message

CASES = [
    # label, sender, window, max_packet, dest_host, dest_port, orig_ip, orig_port
    ("C1", 0, 2097152, 32768, "127.0.0.1", 24000, "127.0.0.1", 0),
    ("C2", 7, 64, 32, "example.com", 65535, "10.0.0.1", 12345),
    ("C3", 0, 2097152, 32768, "::1", 0, "127.0.0.1", 0),
    ("C4", 3, 4096, 8192, "a-very-long-destination-name.example.com", 443,
     "192.0.2.1", 65534),
]


def direct_tcpip_open_payload(sender, window, max_packet, dest_host, dest_port,
                              originator_ip, originator_port) -> bytes:
    m = Message()
    m.add_string("direct-tcpip")
    m.add_int(sender)
    m.add_int(window)
    m.add_int(max_packet)
    m.add_string(dest_host)
    m.add_int(dest_port)
    m.add_string(originator_ip)
    m.add_int(originator_port)
    return m.asbytes()


def main() -> int:
    for (label, sender, window, max_packet, dest_host, dest_port,
         orig_ip, orig_port) in CASES:
        blob = direct_tcpip_open_payload(sender, window, max_packet, dest_host,
                                         dest_port, orig_ip, orig_port)
        print("OPEN %s %s" % (label, blob.hex()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
