#!/usr/bin/env python3
"""host/loop53_fixture_mutations.py -- prove the loop53 fixture generator's own
self-check is not vacuous.

The generator (`host/gen_loop53_fixtures.mjs`) now parses every certificate it
produces and asserts the type, the inner key, the principals and the signing
CA.  That check is the only thing standing between a wrong fixture set and a
16-minute CI run, so it has to be able to fail.

This harness swaps the USER certificate for the HOST one -- same CA, same file
name, but the type and the inner key are both wrong -- and requires the
generator to notice, to name the file, and to say which property is wrong.

That is the exact shape of the defect Loop #74 shipped: the generator signed
the user certificate over `host.pub` instead of `userhost.pub`, so the
MITM's handshake signature did not verify and the client reported
`SignatureInvalid` where the contract says `HostkeyCertAuthority`.

Usage: python host/loop53_fixture_mutations.py
"""

import json
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GEN = os.path.join("host", "gen_loop53_fixtures.mjs")


def run(args, cwd=ROOT):
    proc = subprocess.run(
        ["node", os.path.join(ROOT, GEN)] + args,
        cwd=cwd, capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=300,
    )
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def main():
    checks = 0
    failures = 0

    def ok(name, cond, detail=""):
        nonlocal checks, failures
        checks += 1
        if not cond:
            failures += 1
        print("  %s  %s%s" % ("PASS" if cond else "FAIL", name,
                              ("  -- " + detail) if detail else ""))

    work = tempfile.mkdtemp(prefix="loop53-mut-")
    try:
        print("M1: the generator's own self-check catches a certificate with the wrong inner key")
        code, out = run(["--dir", work])
        ok("generation into an empty directory succeeds", code == 0,
           out.strip().splitlines()[-1] if out.strip() else "")

        user_cert = os.path.join(work, "usercert-in-cert.pub")
        saved = os.path.join(work, "usercert-in-cert.pub.saved")
        with open(user_cert, "rb") as fh:
            original = fh.read()
        with open(os.path.join(work, "host-good-cert.pub"), "rb") as fh:
            host_cert = fh.read()
        # Swap the USER certificate for the HOST one.
        with open(user_cert, "wb") as fh:
            fh.write(host_cert)

        code, out = run(["--dir", work, "--check"])
        ok("the check rejects the swapped certificate", code != 0, "exit %d" % code)
        ok("it names the offending file", "usercert-in-cert.pub" in out,
           next((l.strip() for l in out.splitlines()
                 if "usercert-in-cert.pub" in l), ""))
        ok("it says which property is wrong",
           ("inner key is not userhost.pub" in out) or ("type=2 want 1" in out),
           next((l.strip() for l in out.splitlines()
                 if "inner key" in l or "want 1" in l), ""))

        # Put it back and require the check to go green again, so the harness
        # is not simply "the check always fails".
        with open(user_cert, "wb") as fh:
            fh.write(original)
        code, out = run(["--dir", work, "--check"])
        ok("the check passes again once the certificate is restored", code == 0,
           out.strip().splitlines()[-1] if out.strip() else "")
    finally:
        import shutil
        shutil.rmtree(work, ignore_errors=True)

    print("")
    print("loop53 fixture mutations: %d/%d checks passed" % (checks - failures, checks))
    if failures:
        return 1
    print("ALL PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
