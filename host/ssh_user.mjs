// The account THIS machine runs as.
//
// A gate that starts a real OpenSSH server has to authenticate as *some*
// account, and that account has to EXIST on the machine running the server.
// Writing one developer's account name into the gate makes it pass on that
// machine and fail everywhere else -- and it fails in the worst possible way:
// the server says "no" to the public key, the client reports AuthRejected, and
// nothing in the output says that the username was never the machine's.
//
// Loop #76 found this the hard way. GitHub Actions runs as `runneradmin`; the
// gate asked for `hp`; every section that needed a live server failed with an
// authentication rejection that had nothing to do with the forwarding code
// under test. A locally-green gate was measuring one developer's account name.
//
// So the account is DERIVED, never written down. `USERNAME`/`USER`/`LOGNAME`
// are what the OS calls this account; `os.userInfo()` covers the cases where
// the environment does not say.
//
// The same rule, in the same words, is why nothing in this repository's gate
// helpers hardcodes a path either: the machine is not the repository.

import os from "node:os";

/**
 * The account this machine runs as, and where the name came from.
 *
 * @returns {{ name: string, source: string }}
 */
export function sshUserInfo() {
  for (const key of ["USERNAME", "USER", "LOGNAME"]) {
    const v = process.env[key];
    if (v && v.trim()) return { name: v.trim(), source: `env ${key}` };
  }
  try {
    const u = os.userInfo().username;
    if (u && u.trim()) return { name: u.trim(), source: "os.userInfo()" };
  } catch (e) {
    // os.userInfo() can throw where the process has no user entry; the
    // environment is the usual answer and the message below says so.
  }
  throw new Error(
    "the account this machine runs as could not be determined: " +
    "neither USERNAME, USER, LOGNAME nor os.userInfo() answered. " +
    "A gate cannot open a real SSH server without one."
  );
}

/** The account this machine runs as. */
export function sshUser() {
  return sshUserInfo().name;
}
