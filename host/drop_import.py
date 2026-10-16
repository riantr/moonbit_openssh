"""Drop one import from a moon.pkg, verify, and report -- used for the Loop #67
measurement on cmd/wt_ssh's `moonbitlang/async/js_async`.

The package name is taken bare and the line is built here, because PowerShell
strips embedded double quotes when passing arguments to a native process; three
attempts to pass them directly arrived mangled.
"""
import io
import subprocess
import sys

PKG = sys.argv[1]
NAME = sys.argv[2]
RESTORE = "--restore" in sys.argv

path = PKG + "/moon.pkg"
line = '  "%s",' % NAME


def read():
    with io.open(path, encoding="utf-8", newline="") as fh:
        return fh.read()


def write(t):
    with io.open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(t)


t = read()
if RESTORE:
    if line in t:
        write(t.replace(line, "", 1))
        print("restored %s" % line)
    else:
        print("nothing to restore")
    sys.exit(0)

if line not in t:
    sys.exit("%r is not in %s" % (line, path))
write(t.replace(line, "", 1))
print("removed %s from %s" % (line, path))

proc = subprocess.run(["cmd", "/c", "moon", "check", PKG, "--target", "js",
                       "--output-json", "--diagnostic-limit", "1000"],
                      stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
out = proc.stdout.decode("utf-8", "replace")
msgs = []
for l in out.splitlines():
    l = l.strip()
    if l.startswith("{") and '"message"' in l:
        import json
        msgs.append(json.loads(l)["message"])
print("moon check --target js exit=%d messages=%s" % (proc.returncode, msgs[:3]))

build = subprocess.run(["cmd", "/c", "moon", "build", PKG, "--target", "js"],
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
print("moon build --target js exit=%d" % build.returncode)
