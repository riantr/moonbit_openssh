#!/usr/bin/env python3
"""Generate cmd/ctrmac_test/vectors.mbt from the KAT oracle.

Hand-transcribing 14 long hex strings into MoonBit source is a transcription
risk with no upside, so the vectors are generated straight from the JSON that
`host/ssh_ctrhmac_oracle.py` already proved correct against paramiko.

Run:
    python host/gen_ctrmac_vectors.py
"""

import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUT = os.path.join(ROOT, "cmd", "ctrmac_test", "vectors.mbt")


def main():
    raw = subprocess.run(
        [sys.executable, os.path.join(HERE, "ssh_ctrhmac_oracle.py"), "--json"],
        capture_output=True, check=True,
    ).stdout.decode("utf-8")
    doc = json.loads(raw)

    lines = []
    a = lines.append
    a("///| GENERATED FILE -- do not edit by hand.")
    a("///| Regenerate with: python host/gen_ctrmac_vectors.py")
    a("///|")
    a("///| Every hex string below comes from host/ssh_ctrhmac_oracle.py, which")
    a("///| refuses to emit anything unless its own from-spec implementation and")
    a("///| paramiko's Packetizer agree byte for byte. Padding is zeroed on both")
    a("///| sides so the comparison is a true byte diff.")
    a("")
    a("///| AES-128 encryption key (letter 'C')")
    a('pub const KAT_KEY_HEX : String = "%s"' % doc["key"])
    a("")
    a("///| client-to-server counter seed (letter 'A')")
    a('pub const KAT_IV_HEX : String = "%s"' % doc["iv_ctos"])
    a("")
    a("///| server-to-client counter seed (letter 'B')")
    a('pub const KAT_IV_STOC_HEX : String = "%s"' % doc["iv_stoc"])
    a("")
    a("///| hmac-sha2-256 key (letter 'E')")
    a('pub const KAT_MAC_KEY_HEX : String = "%s"' % doc["mac_key"])
    a("")
    a("///| One KAT case: `count` identical messages sent back to back on the")
    a("///| same connection.")
    a("///|")
    a("///| Sending several in a row is deliberate -- it exercises CTR counter")
    a("///| continuity across packets. An implementation that re-seeds the")
    a("///| counter from the IV for every packet still gets packet 0 right, so")
    a("///| this is exactly the bug a single-packet test cannot see.")
    a("pub(all) struct KatCase {")
    a("  name : String")
    a("  msg_type : Byte")
    a("  payload_hex : String")
    a("  frames : Array[String]")
    a("  wires : Array[String]")
    a("}")
    a("")
    a("pub fn KatCase::new(")
    a("  name : String,")
    a("  msg_type : Byte,")
    a("  payload_hex : String,")
    a("  frames : Array[String],")
    a("  wires : Array[String],")
    a(") -> KatCase {")
    a("  { name, msg_type, payload_hex, frames, wires, }")
    a("}")
    a("")
    a("///| All KAT cases")
    a("pub fn kat_cases() -> Array[KatCase] {")
    a("  [")
    for c in doc["cases"]:
        frames = ", ".join('"%s"' % f for f in c["frames"])
        wires = ", ".join('"%s"' % w for w in c["wires"])
        a("    KatCase::new(")
        a('      "%s",' % c["name"])
        a("      b'\\x%02x'," % c["msg_type"])
        a('      "%s",' % c["payload"])
        a("      [%s]," % frames)
        a("      [%s]," % wires)
        a("    ),")
    a("  ]")
    a("}")
    a("")

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines))
    print("wrote %s (%d cases, %d bytes)"
          % (os.path.relpath(OUT, ROOT), len(doc["cases"]), os.path.getsize(OUT)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
