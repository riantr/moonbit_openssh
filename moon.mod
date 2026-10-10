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

name = "openssh/openssh_moonbit"

version = "0.1.0"

readme = "README.mbt.md"

repository = ""

license = "Apache-2.0"

keywords = [ ]

description = ""

import {
  "moonbitlang/async@0.22.2",
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
}
