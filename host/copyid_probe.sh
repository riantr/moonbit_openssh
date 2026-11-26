#!/bin/bash
# Loop #103: run the REAL upstream ssh-copy-id with a stand-in for `ssh`.
#
# Why a stand-in: upstream's script cannot install anything on a Windows
# server (measured: it exits, says "Number of key(s) added: 1", and the key
# is never written).  But the SENTENCES it prints and the REMOTE COMMAND it
# builds are still upstream's own bytes, and those are what this tool has to
# reproduce -- so the script is put in front of a stand-in that lets it run
# to the end and keeps every byte it writes.
#
# The stand-in:
#   * records every invocation, one argument per line, in $FAKE_SSH_ARGS
#     (so the exact remote command upstream builds is captured, byte for
#     byte);
#   * answers the **filter** call -- the one whose last argument is "exit"
#     -- with "Permission denied (publickey)." and status 1, which is what
#     makes upstream keep the key instead of giving up with "ERROR: ";
#   * answers every other call with status 0.
#
# $FAKE_SSH_FILTER=allow turns the filter call into a success, and upstream
# then prints its "all keys were skipped" block -- the other golden block.
#
# The script is *sourced* rather than executed, because upstream prints `$0`
# in front of every INFO and ERROR line and a golden vector with the wrong
# program name is not a golden vector.  `exec -a` gives the sourced script
# the `$0` it would have had if it had been run directly.
#
# Usage: copyid_probe.sh <upstream-script> [upstream's own arguments...]

script="$1"
shift

exec -a "$script" bash -c '
ssh() {
  printf "%s\n" "$@" >> "$FAKE_SSH_ARGS"
  last=""
  for a in "$@"; do last="$a"; done
  if [ "$last" = "exit" ]; then
    if [ "$FAKE_SSH_FILTER" = "allow" ]; then
      return 0
    fi
    printf "Permission denied (publickey).\n" >&2
    return 1
  fi
  return 0
}
source "$0" "$@"
' "$script" "$@"
