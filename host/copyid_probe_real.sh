#!/bin/bash
# Loop #103: run the REAL upstream ssh-copy-id with the REAL ssh.
#
# This is the other half of the oracle: the same upstream script, but with
# nothing standing in for `ssh`, so it talks to the real OpenSSH server this
# repository runs for its own tests.
#
# What it shows there is the thing this loop exists to remove: the script
# runs a POSIX one-liner (`exec sh -c '...'`) on a server whose shell is
# `cmd.exe`, the command cannot run, the key is never written -- and the
# script still reports that it added the key.
#
# The script is run from the directory the caller chooses, so a relative
# `-i` name means the same file on both sides.
#
# Usage: copyid_probe_real.sh <upstream-script> [upstream's own arguments...]

script="$1"
shift

exec "$script" "$@"
