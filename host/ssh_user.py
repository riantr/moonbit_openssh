#!/usr/bin/env python3
"""The account THIS machine runs as.

The Python half of `host/ssh_user.mjs`, and the same rule: a tool that
connects to a real OpenSSH server has to name an account that EXISTS on the
machine running that server, and the name has to be derived rather than
written down.

Loop #76 measured what a hardcoded name costs. The gate authenticated as `hp`
-- one developer's account -- and on GitHub Actions, where the account is
`runneradmin`, every section that needed a live server failed with
`AuthRejected`. The failure was about the account name, and nothing in the
output said so.

`getpass.getuser()` already consults LOGNAME, USER, LNAME and USERNAME; this
module spells the order out and returns an empty string rather than raising,
so a caller can report the problem in its own words.
"""

import getpass
import os

__all__ = ["ssh_user", "ssh_user_source"]


def ssh_user_source():
    """(name, where the name came from)."""
    for key in ("USERNAME", "USER", "LOGNAME", "LNAME"):
        value = os.environ.get(key)
        if value and value.strip():
            return value.strip(), "env " + key
    try:
        value = getpass.getuser()
    except Exception:
        value = ""
    if value and value.strip():
        return value.strip(), "getpass.getuser()"
    return "", "not found"


def ssh_user():
    """The account this machine runs as, or "" if it cannot be determined."""
    return ssh_user_source()[0]
