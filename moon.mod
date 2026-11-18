// Learn more about moon.mod configuration:
// https://docs.moonbitlang.com/en/latest/toolchain/moon/module.html
//
// To add a dependency, run this command in your terminal:
//   moon add moonbitlang/x
//
// Or manually declare it in `import`, for example:
// import {
//   "moonbitlang/x@0.4.6",
// }

name = "riantr/moonbit_openssh"

version = "0.1.4"

readme = "README.mbt.md"

repository = "https://github.com/riantr/moonbit_openssh"

license = "MIT"

keywords = [ "ssh", "openssh", "crypto", "sftp" ]

description = "An OpenSSH-compatible SSH client, server and SFTP stack written from scratch in MoonBit."

import {
  // Loop #98: this was declared 0.22.2 while the resolver installed 0.22.4 --
  // MoonBit's resolver takes the HIGHEST version requested anywhere in the
  // graph, and `proton` asks for 0.22.4.  So the declaration was a claim the
  // build did not honour.  Declaring the version that is actually used makes
  // the module's own record true; the resolution does not change, because the
  // number that wins was 0.22.4 either way.
  "moonbitlang/async@0.22.4",
  "moonbit-community/sqlite3@0.2.2",
  "moonbit-community/proton@0.3.4",
  // `proton_contract` is imported directly by cmd/proton_gui for the
  // Command[Request, Response] descriptors.  It is a transitive dependency of
  // `proton`, but "the module is in the global environment" is not the same as
  // "this module may import it" -- moon requires the direct edge here.  Pinned
  // to the same 0.3.4 the rest of the Proton packages are, because the two
  // share the ContractRoute values and a version skew would silently change
  // the `app:<name>` transport names.
  "moonbit-community/proton_contract@0.3.4",
  // Loop #98: `tonyfettes/xlog` is a TRANSITIVE dependency (proton 0.3.4 asks
  // for 0.4.2), and 0.4.2 no longer compiles: it calls `impl`-defined
  // methods directly (`self.level.to_string()`), which the compiler of
  // 2026-11-17 rejects -- "impl cannot be invoked directly as method unless
  // explicitly promoted via `extend`".  Measured on GitHub run 44065649338:
  // moon 0.1.20261117 on the runner against 0.1.20261102 on this machine, the
  // SAME xlog 0.4.2 source, six errors in three files.
  //
  // 0.5.1 is the version proton itself moved to (proton 0.9.1, published the
  // same day), so it is the upstream-compatible choice, not a guess.  The
  // resolver takes the HIGHEST version requested anywhere in the graph, so
  // this direct edge is what raises xlog; proton 0.3.4 keeps its own pin and
  // its CEF requirement unchanged.
  "tonyfettes/xlog@0.5.1",
}
