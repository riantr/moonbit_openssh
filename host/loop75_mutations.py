#!/usr/bin/env python3
"""host/loop75_mutations.py -- prove the loop75 gate is not vacuous.
#
# The gate asserts that the knownhosts C harness survives a poisoned stack.
# If the fix were reverted, the harness would fail 12 assertions under
# `-ftrivial-auto-var-init=pattern` -- and the gate MUST go red.
#
# A regression gate that cannot fail is worse than no gate: it reports
# "protected" while protecting nothing. This is the same rule the other
# mutation harnesses in this repository follow.
"""

import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HARNESS = os.path.join(ROOT, "verify_c", "knownhosts_harness.c")

# The fixed decoder, from the padding block to the end of the function.
# Matched as ONE region so that a mutant which restores the original
# decoder (which differs in both halves) can be spliced in as one piece.
# Two separate regexes would leave the code BETWEEN them duplicated.
FIXED_RE = re.compile(
    r"    padded\[slen\] = '\\0';\n"
    r"    int r = slen % 4;\n"
    r"    if \(r != 0\) \{\n"
    r"(?:        /\*.*?\*/\n)?"          # the explanatory comment, optional
    r"        int pad = 4 - r;\n"
    r"        if \(slen \+ pad >= \(int\)sizeof\(padded\)\) return -1;\n"
    r"        for \(int k = 0; k < pad; k\+\+\) padded\[slen \+ k\] = '=';\n"
    r"        padded\[slen \+ pad\] = '\\0';\n"
    r"    \}\n"
    r"    s = padded;\n"
    r"    slen = \(int\)strlen\(s\);\n"
    r"\n"
    r"    int i = 0;\n"
    r"    while \(i < slen\) \{\n"
    r"        int got = 0;\n"
    r"        while \(got < 4 && i < slen\) \{\n"
    r"            char c = s\[i\];\n"
    r"            if \(c == '='\) \{\n"
    r"                i\+\+;\n"
    r"                while \(i < slen && s\[i\] == '='\) i\+\+;\n"
    r"                break;\n"
    r"            \}\n"
    r"            int x = b64_val\(\(unsigned char\)c\);\n"
    r"            if \(x < 0\) return -1;\n"
    r"            v\[got\+\+\] = x;\n"
    r"            i\+\+;\n"
    r"        \}\n"
    r"(?:        /\*.*?\*/\n)?"        # the explanatory comment, optional
    r"        int nbytes = \(got \* 6\) / 8;\n"
    r"        while \(got < 4\) v\[got\+\+\] = 0;\n"
    r"        if \(\(size_t\)n_out \+ nbytes > out_max\) return -1;\n"
    r"        if \(nbytes > 0\) out\[n_out\+\+\] = \(uint8_t\)\(\(v\[0\] << 2\) \| \(v\[1\] >> 4\)\);\n"
    r"        if \(nbytes > 1\) out\[n_out\+\+\] = \(uint8_t\)\(\(v\[1\] << 4\) \| \(v\[2\] >> 2\)\);\n"
    r"        if \(nbytes > 2\) out\[n_out\+\+\] = \(uint8_t\)\(\(v\[2\] << 6\) \| v\[3\]\);\n"
    r"    \}\n"
    r"    return n_out;\n"
    r"\}\n",
    re.DOTALL,
)

# Mutant 1: the ORIGINAL decoder, restored in full.
#
# The original had two defects at once: the buffer was never terminated after
# the memcpy, and the padding count was re-measured with strlen. The fixed
# code also changed the group-commit block (it now emits `sextets * 6 / 8`
# bytes rather than always three), so the mutant has to replace BOTH blocks
# and the code between them -- otherwise the spliced text does not compile,
# and a build break is not evidence that anything was caught.
MUTANT_MEASURE = """    int r = slen % 4;
    if (r != 0) {
        if (slen + 3 >= (int)sizeof(padded)) return -1;
        while ((int)strlen(padded) % 4 != 0) padded[strlen(padded)] = '=';
    }
    padded[strlen(padded)] = '\\0';
    s = padded;
    slen = (int)strlen(s);

    int i = 0;
    while (i < slen) {
        int got = 0;
        while (got < 4 && i < slen) {
            char c = s[i];
            if (c == '=') {
                while (got < 4) v[got++] = 0;
                i++;
                while (i < slen && s[i] == '=') i++;
                goto commit;
            }
            int x = b64_val((unsigned char)c);
            if (x < 0) return -1;
            v[got++] = x;
            i++;
        }
        while (got < 4) v[got++] = 0;
        commit:
        if ((size_t)n_out + 3 > out_max) return -1;
        out[n_out++] = (v[0] << 2) | (v[1] >> 4);
        out[n_out++] = (v[1] << 4) | (v[2] >> 2);
        out[n_out++] = (v[2] << 6) | v[3];
    }
    return n_out;
}
"""

# Mutant 2: the padding is computed correctly, but the buffer is never
# NUL-terminated after the memcpy, so the very first strlen() of it reads
# uninitialised memory. The group-commit half stays FIXED.
MUTANT_UNTERMINATED_PADDING = """    int r = slen % 4;
    if (r != 0) {
        int pad = 4 - r;
        if (slen + pad >= (int)sizeof(padded)) return -1;
        for (int k = 0; k < pad; k++) padded[slen + k] = '=';
        padded[slen + pad] = '\\0';
    }
"""

# The fixed padding block on its own, for M2 to replace.
FIXED_PADDING_RE = re.compile(
    r"    padded\[slen\] = '\\0';\n"
    r"    int r = slen % 4;\n"
    r"    if \(r != 0\) \{\n"
    r"(?:        /\*.*?\*/\n)?"          # the explanatory comment, optional
    r"        int pad = 4 - r;\n"
    r"        if \(slen \+ pad >= \(int\)sizeof\(padded\)\) return -1;\n"
    r"        for \(int k = 0; k < pad; k\+\+\) padded\[slen \+ k\] = '=';\n"
    r"        padded\[slen \+ pad\] = '\\0';\n"
    r"    \}\n",
    re.DOTALL,
)

# Mutant 3: the decoder emits three bytes for every group of four sextets,
# whatever the group's real content is. That is the original behaviour, and
# it disagrees with OpenSSH's b64_pton for any input whose length is not a
# multiple of four -- which the harness compensated for at ONE call site and
# not the other.
MUTANT_ALWAYS_THREE = """    int i = 0;
    while (i < slen) {
        int got = 0;
        while (got < 4 && i < slen) {
            char c = s[i];
            if (c == '=') {
                while (got < 4) v[got++] = 0;
                i++;
                while (i < slen && s[i] == '=') i++;
                goto commit;
            }
            int x = b64_val((unsigned char)c);
            if (x < 0) return -1;
            v[got++] = x;
            i++;
        }
        while (got < 4) v[got++] = 0;
        commit:
        if ((size_t)n_out + 3 > out_max) return -1;
        out[n_out++] = (v[0] << 2) | (v[1] >> 4);
        out[n_out++] = (v[1] << 4) | (v[2] >> 2);
        out[n_out++] = (v[2] << 6) | v[3];
    }
    return n_out;
}
"""

# The fixed group-commit block, matched by a regex so the comment above it
# can change without breaking the harness.
FIXED_GROUP_RE = re.compile(
    r"    int i = 0;\n"
    r"    while \(i < slen\) \{\n"
    r"        int got = 0;\n"
    r"        while \(got < 4 && i < slen\) \{\n"
    r"            char c = s\[i\];\n"
    r"            if \(c == '='\) \{\n"
    r"                i\+\+;\n"
    r"                while \(i < slen && s\[i\] == '='\) i\+\+;\n"
    r"                break;\n"
    r"            \}\n"
    r"            int x = b64_val\(\(unsigned char\)c\);\n"
    r"            if \(x < 0\) return -1;\n"
    r"            v\[got\+\+\] = x;\n"
    r"            i\+\+;\n"
    r"        \}\n"
    r"(?:        /\*.*?\*/\n)?"        # the explanatory comment, optional
    r"        int nbytes = \(got \* 6\) / 8;\n"
    r"        while \(got < 4\) v\[got\+\+\] = 0;\n"
    r"        if \(\(size_t\)n_out \+ nbytes > out_max\) return -1;\n"
    r"        if \(nbytes > 0\) out\[n_out\+\+\] = \(uint8_t\)\(\(v\[0\] << 2\) \| \(v\[1\] >> 4\)\);\n"
    r"        if \(nbytes > 1\) out\[n_out\+\+\] = \(uint8_t\)\(\(v\[1\] << 4\) \| \(v\[2\] >> 2\)\);\n"
    r"        if \(nbytes > 2\) out\[n_out\+\+\] = \(uint8_t\)\(\(v\[2\] << 6\) \| v\[3\]\);\n"
    r"    \}\n"
    r"    return n_out;\n"
    r"\}\n",
    re.DOTALL,
)

MUTANTS = [
    ("M1", "the original decoder, unterminated buffer and strlen-measured padding",
     MUTANT_MEASURE, "whole"),
    ("M2", "the buffer is never NUL-terminated after the memcpy",
     MUTANT_UNTERMINATED_PADDING, "padding"),
    ("M3", "the decoder always emits three bytes per quad",
     MUTANT_ALWAYS_THREE, "group"),
]


def run(cmd, cwd=None):
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True,
                          encoding="utf-8", errors="replace")


def compilers():
    out = []
    for name in ("clang", "gcc"):
        r = run(["cmd", "/c", f"where {name}"])
        for line in (r.stdout or "").splitlines():
            p = line.strip()
            if p and p.lower().endswith(".exe"):
                out.append((name, p))
    return out


def main():
    src = open(HARNESS, encoding="utf-8").read()
    m = FIXED_RE.search(src)
    if not m:
        print("MUTATION TARGET NOT FOUND: the fixed block is not in the harness")
        print("The mutation harness has to be updated when the fix changes shape.")
        return 2
    fixed_block = m.group(0)

    work = tempfile.mkdtemp(prefix="loop75-mut-")
    mutants = []
    for mid, desc, new, target in MUTANTS:
        if target == "whole":
            # M1 restores the entire decoder, so it replaces the padding block,
            # the group-commit block, and everything between them in one
            # splice.
            mutants.append((mid, desc, src[:m.start()] + new + src[m.end():]))
        elif target == "padding":
            p = FIXED_PADDING_RE.search(src)
            if not p:
                print("MUTATION TARGET NOT FOUND: the padding block is not in the harness")
                return 2
            mutants.append((mid, desc, src[:p.start()] + new + src[p.end():]))
        else:
            g = FIXED_GROUP_RE.search(src)
            if not g:
                print("MUTATION TARGET NOT FOUND: the group-commit block is not in the harness")
                return 2
            mutants.append((mid, desc, src[:g.start()] + new + src[g.end():]))

    ccs = compilers()
    if not ccs:
        print("no C compiler on PATH: cannot run the mutation")
        return 2

    caught = 0
    missed = 0
    build_broken = 0

    for mid, desc, mutant_src in mutants:
        mutant_path = os.path.join(work, "knownhosts_harness.c")
        with open(mutant_path, "w", encoding="utf-8", newline="\n") as f:
            f.write(mutant_src)
        # The harness includes "_knownhosts_kat.h" by relative path, so the
        # generated header has to travel with the mutant. Without this the
        # mutant does not compile, and a build break is NOT evidence that the
        # gate catches anything -- it is just a broken build. Copying the
        # header is what makes the mutation a real test.
        shutil.copy(os.path.join(ROOT, "verify_c", "_knownhosts_kat.h"),
                    os.path.join(work, "_knownhosts_kat.h"))
        exe = os.path.join(work, f"mut_{mid}.exe")
        worked = False
        for cname, cpath in ccs:
            b = run([cpath, "-O2", "-ftrivial-auto-var-init=pattern",
                     "-o", exe, mutant_path, "-lm"], cwd=work)
            if b.returncode != 0:
                continue
            r = run([exe], cwd=work)
            out = (r.stdout or "") + (r.stderr or "")
            m = re.search(r"Total:\s*(\d+)/(\d+)\s+passed", out)
            if not m:
                continue
            worked = True
            passed, total = int(m.group(1)), int(m.group(2))
            if passed == total:
                print(f"  MISSED  {mid}  ({desc}) -- the poisoned build still passed {passed}/{total}")
                missed += 1
            else:
                print(f"  CAUGHT  {mid}  ({desc}) -- poisoned build gave {passed}/{total}")
                caught += 1
            break
        if not worked:
            print(f"  BUILD-BROKEN  {mid}  ({desc}) -- no toolchain produced a runnable mutant")
            build_broken += 1

    shutil.rmtree(work, ignore_errors=True)
    print("")
    print(f"loop75 mutations: {caught} CAUGHT, {missed} MISSED, {build_broken} BUILD-BROKEN")
    if missed or build_broken:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
