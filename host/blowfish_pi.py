"""Extract the Blowfish P-array and S-boxes, and PROVE they are pi.

Blowfish's initial state is the hexadecimal expansion of the fractional part
of pi: the P-array is the first 18 words of it and the four S-boxes are the
next 1024.  That is a property of the algorithm, not of any one
implementation -- OpenBSD's blowfish.c says so in a comment ("P-box and S-box
tables initialized with digits of Pi") and so does the original Blowfish
paper.

So the constants are not "whatever OpenSSH's C file says".  They are pi, and
that can be CHECKED.  This script does two independent things and compares:

  1. it reads the constants out of OpenSSH's openbsd-compat/blowfish.c, and
  2. it computes pi to enough hex digits to hold all 1042 words (8336 hex
     digits of the fractional part) with mpmath, and takes the digits from
     THERE.

If the two agree, the constants are pi -- which is a much stronger claim than
"the file and our port agree", because it does not depend on OpenSSH being
right.

Usage:  python host/blowfish_pi.py --check          # verify and print a summary
        python host/blowfish_pi.py --emit <file>     # emit the MoonBit source
"""

import io
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import openssh_src

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

P_WORDS = 18
S_WORDS = 256
S_BOXES = 4
TOTAL_WORDS = P_WORDS + S_BOXES * S_WORDS          # 1042
HEX_DIGITS = TOTAL_WORDS * 8                       # 8336


def from_openssh():
    """The 1042 words as OpenSSH's blowfish.c spells them, in PI ORDER.

    The file's struct is `typedef struct BlowfishContext { u_int32_t S[4][256];
    u_int32_t P[BLF_N + 2]; } blf_ctx;` -- the S-boxes come FIRST in the
    layout and therefore first in the initializer -- while pi's order is the
    P-array first and the S-boxes after it.  So the file order is not the pi
    order, and reading it as if it were would compare the wrong words.
    """
    path = os.path.join(
        openssh_src.find_or_die("blowfish_pi.py"), "openbsd-compat", "blowfish.c"
    )
    with io.open(path, "r", encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    start = text.index("static const blf_ctx initstate")
    end = text.index("} };", start)
    body = text[start:end]
    words = [int(m, 16) for m in re.findall(r"0x([0-9a-fA-F]{8})", body)]
    if len(words) != TOTAL_WORDS:
        return words
    s_boxes = words[:S_BOXES * S_WORDS]        # file order: S[0..3][0..255]
    p_array = words[S_BOXES * S_WORDS:]        # file order: P[0..17]
    # Pi order: P[0..17] then S[0..3][0..255].
    return p_array + s_boxes


def from_pi():
    """The same 1042 words, computed from pi itself.

    The fractional part of pi is scaled by 16**8336 and truncated once, which
    is exact as long as the working precision is high enough -- 8336 hex
    digits are 8336 * log10(16) ~= 10038 decimal digits, so mpmath needs
    that many plus a margin.

    (A digit-at-a-time loop looks tempting and is wrong here: each
    multiplication rounds at the working precision, and the rounding
    compounds until the digits come out as zeros.  Measured: the loop gave
    zeros from word 265 on.)
    """
    import mpmath
    need = int(HEX_DIGITS * 1.20412) + 64          # hex digits -> decimal digits
    mpmath.mp.dps = need
    frac = mpmath.mpf(mpmath.pi) - 3
    scaled = int(mpmath.floor(frac * mpmath.mpf(16) ** HEX_DIGITS))
    hexstr = "%0*x" % (HEX_DIGITS, scaled)
    return [int(hexstr[i * 8:(i + 1) * 8], 16) for i in range(TOTAL_WORDS)]


def emit_moonbit(words):
    """The MoonBit source for the constants.

    MoonBit's `pub const` can only hold immutable primitives, so the table is
    a function returning a fresh array -- the same shape `src/keyfile` uses
    for its magic bytes.
    """
    out = []
    out.append("///|")
    out.append("/// The Blowfish P-array and S-boxes: the hexadecimal expansion of the")
    out.append("/// fractional part of pi.")
    out.append("///")
    out.append("/// This is a property of the algorithm, not of one implementation: the")
    out.append("/// P-array is the first 18 words of pi's fraction and the four S-boxes")
    out.append("/// are the next 1024.  The table below was therefore CHECKED against pi")
    out.append("/// computed to 8336 hex digits, not copied out of a C file on trust --")
    out.append("/// see `host/blowfish_pi.py --check`.")
    out.append("///")
    out.append("/// It is a function rather than a constant because MoonBit's constants")
    out.append("/// must be immutable primitives, and a table of 1042 words is not one.")
    # The `U` suffix matters: MoonBit's `Int` is 32 bits, and words above
    # 0x7fffffff (there are plenty -- 0x9e1f9b5e is one) do not fit in it.
    # Without the suffix the literal is an Int and the array does not type
    # check, so the suffix is not decoration.
    out.append("pub fn pi_words() -> FixedArray[UInt32] {")
    out.append("  [")
    for i, w in enumerate(words):
        if i % 6 == 0:
            out.append("   ")
        out.append(" 0x%08xU," % w)
        if i % 6 == 5:
            out.append("")
    out.append("  ]")
    out.append("}")
    return "\n".join(out) + "\n"


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "--check"
    ours = from_openssh()
    theirs = from_pi()
    if len(ours) != TOTAL_WORDS:
        print("parsed %d words from OpenSSH, expected %d" % (len(ours), TOTAL_WORDS))
        return 1
    bad = [(i, ours[i], theirs[i]) for i in range(TOTAL_WORDS) if ours[i] != theirs[i]]
    if bad:
        print("MISMATCH in %d word(s):" % len(bad))
        for i, a, b in bad[:5]:
            print("  [%d] openssh 0x%08x  pi 0x%08x" % (i, a, b))
        return 1
    print("OK  %d words agree with pi (computed to %d hex digits)" % (TOTAL_WORDS, HEX_DIGITS))
    print("    P[0]=0x%08x P[17]=0x%08x" % (ours[0], ours[17]))
    print("    S[0][0]=0x%08x S[3][255]=0x%08x" % (ours[P_WORDS], ours[-1]))
    if mode == "--emit":
        dest = sys.argv[2]
        with io.open(dest, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(emit_moonbit(ours))
        print("wrote %s" % dest)
    return 0


if __name__ == "__main__":
    sys.exit(main())
