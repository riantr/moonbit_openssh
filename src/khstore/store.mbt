///| Loop #52: the write-back's other half -- actually storing it.
///

///|
///
/// Loops #49/#50 made the *decision* correct and the rendering correct, and then
/// printed the line. Printing is not remembering. The gate caught stdout and fed
/// the line back by hand; a browser user has nobody to do that, so the pin lives
/// exactly as long as the test that produced it. `--kh-tofu` on Tuesday, unpinned
/// again on Wednesday -- the state TOFU exists to remove.
///

///|
///
/// The shape is the one `src/knownhosts/render.mbt` established: "what a line
/// looks like" lives in `src/knownhosts` and is shared by both transports, "where
/// it goes" is the platform's business. What was missing is that the platform side
/// had no implementation at all.
///

///|
///
/// **IndexedDB, not localStorage.** A Web Worker has no `localStorage` at all:
/// `globalThis.localStorage` is `undefined` there, so the property access throws a
/// TypeError that no `try` around the call can rescue. IndexedDB is the only
/// origin-scoped storage a Worker has, and the only one that makes sense for this.
///

///|
///
/// **js target only, and deliberately not gated at the package level** -- same
/// reasoning as `src/wt`: a package-level `targets:` gate would block downstream
/// consumers, so the gating is per file. Both files use `extern "js"`, which the
/// wasm backends reject outright, so a wasm-wanting consumer fails loudly at its
/// own compile instead of silently here.
///

///|
///
/// The extern bodies use the double-quoted IIFE form rather than `#| ... |#`: the
/// compiler evaluates the right-hand side as a module constant, and the inline form
/// leaked its own terminator into the emitted JavaScript and produced a
/// SyntaxError at load time in the browser (`src/wt/ffi.mbt` found that one).
///

///|
///
/// These are Promises because IndexedDB is, and the shim hides the event-to-promise
/// conversion behind one transaction. Wrapping it in more Promises to look tidy
/// would buy nothing.
///

///|
///
/// **No string literals inside an extern body.** MoonBit has no single-quoted
/// string form -- `'` is a lexing error, U+0027 -- so the only way to write `""`
/// inside a double-quoted extern body is `\"`, and the compiler emits that
/// right-hand side as a literal, backslash and all. The generated JavaScript then
/// contains `?? \"\"`, which is a SyntaxError, and the whole module dies at
/// `importScripts` with an empty transcript and the trace pointing at the harness
/// rather than at the code that broke. `src/wt/ffi.mbt` escaped this by accident:
/// none of its bodies needs a string literal.
///

///|
///
/// **No `Option` across the FFI boundary either.** `load`'s null looks like it
/// should arrive as `None`, and it does not: the generated code tests
/// `=== undefined` and treats `null` as `Some(null)`, so the `Some` arm then
/// dereferences null. Rather than depend on which JS null the compiler happened to
/// choose, the extern resolves with a `Bool` for "was there anything" and the
/// value travels in a second call. One extra trip, and it removes a class of bug
/// that otherwise surfaces as a null-pointer in unrelated code.
///

///|
///
/// **Never throw.** Every failure is a value. A storage shim that raised would turn
/// "the browser is in private mode" into a failed connection -- the wrong failure
/// for the wrong reason: the connection is fine, and the user loses the ability to
/// pin for a session rather than losing the session.
///
/// **And never throw when there is no backend at all.** That was the hole in the
/// rule: the bodies below used `globalThis.__moonbit_khs.save(...)` directly, so a
/// Worker (or any embedding) that simply did not install a store raised a
/// TypeError on the *first property access*, synchronously, outside any promise
/// chain -- so the "every failure is a value" promise did not hold for the one
/// case that is actually common. `cmd/wt_ssh` reads the store on every
/// connection, which meant "no store installed" was not an edge case at all: it
/// was every browser run that forgot to load the shim.
///
/// So each body asks whether the backend exists, and if it does not, resolves
/// with the answer that means "there is no pin here" -- which is the same answer
/// a working store gives for an unknown host, and which the policy path already
/// knows how to handle.
///
/// `String()` with no argument is the empty string. The rule above about string
/// literals in extern bodies still holds: `""` would have to be written `\"`,
/// which the compiler emits as a literal backslash-quote pair and the browser
/// reads as a SyntaxError. `String()` needs no literal at all.
extern "js" fn khs_save_raw(
  key : String,
  value : String,
) -> @js_async.Promise[Bool] = "((k, v) => globalThis.__moonbit_khs ? globalThis.__moonbit_khs.save(k, v).then((r) => r === true) : Promise.resolve(false))"

///|
extern "js" fn khs_load_raw(key : String) -> @js_async.Promise[Bool] = "((k) => globalThis.__moonbit_khs ? globalThis.__moonbit_khs.load(k).then((v) => v !== null) : Promise.resolve(false))"

///|
extern "js" fn khs_get_raw(key : String) -> @js_async.Promise[String] = "((k) => globalThis.__moonbit_khs ? globalThis.__moonbit_khs.load(k).then((v) => v === null ? String() : v) : Promise.resolve(String()))"

///|
extern "js" fn khs_forget_raw(key : String) -> @js_async.Promise[Unit] = "((k) => globalThis.__moonbit_khs ? globalThis.__moonbit_khs.forget(k).then((r) => r) : Promise.resolve())"

///|
extern "js" fn khs_probe_raw() -> @js_async.Promise[Bool] = "(() => globalThis.__moonbit_khs ? globalThis.__moonbit_khs.probe().then((r) => r === true) : Promise.resolve(false))"

///| The storage key one host's entry lives under.
///

///|
///
/// The host name is in the key, so a lookup is O(1) and cannot return another
/// host's pin. The prefix keeps the store out of whatever namespace the embedding
/// application uses for its own keys.
fn storage_key(host : String) -> String {
  "moonbit.ssh.known_hosts/" + host
}

///| Everything pinned for `host`, as `known_hosts` text.
///

///|
///
/// Empty string when nothing is stored, or when storage is unavailable -- the two
/// are deliberately indistinguishable to the caller, because both mean "there is
/// no pin here" and both are handled by the same policy path. Storage being
/// *broken* is not a pinning failure, and turning it into one would let a
/// private-mode browser masquerade as a man in the middle.
///

///|
///
/// Two round trips rather than one. `load` is called on every connection and
/// `has` exists only because the null problem above forces the question apart;
/// an IndexedDB read is cheap enough that splitting it costs nothing that
/// matters, and the alternative is depending on an interop detail nobody wrote
/// down.

///|
///
/// **Awaiting is `@js_async.Promise::wait`, not an `await` keyword.** This
/// toolchain has no `await` -- writing `await f(x)` parses the identifier `await`
/// as an unbound value. The whole repo's existing async code (`src/wt/conn.mbt`)
/// uses `Promise::wait(...)`, and the two forms are not interchangeable. Getting
/// this wrong is a parse error rather than a wrong answer, which is the only kind
/// of confusion that costs nothing.
pub async fn load(host : String) -> String {
  let key = storage_key(host)
  // The shim swallows its own failures and resolves, so there is nothing to
  // `catch` here -- and not having a catch clause is deliberate: it would be
  // dead code that suggests a failure path nobody thought through.
  let has = @js_async.Promise::wait(khs_load_raw(key))
  if !has {
    return ""
  }
  @js_async.Promise::wait(khs_get_raw(key))
}

///| Store `line` for `host`, replacing any previous entry.
///

///|
///
/// Resolves with whether the write landed. A caller that ignores this is fine --
/// the connection succeeded either way, and the only cost is that the next one
/// needs `--kh-tofu` again. It is returned so the driver can *say* so instead of
/// leaving a user believing they are pinned.
///

///|
///
/// **The answer used to be hardcoded to `true`.** The shim resolves with whether
/// the write landed, and the MoonBit side threw that away and returned `true`
/// anyway -- which made `cmd/wt_ssh`'s "tofu: NOT stored" line unreachable. A
/// store that refused the write (private mode, quota, policy) was reported to
/// the user as a store that took it, and the whole point of Loop #52's message
/// was to say the difference.
pub async fn save(host : String, line : String) -> Bool {
  @js_async.Promise::wait(khs_save_raw(storage_key(host), line))
}

///| Forget `host`.
///

///|
///
/// `cmd/wt_ssh` exposes this as `kh_forget`, and it is a separate step from
/// connecting on purpose: forgetting must not also accept whatever the peer
/// presents next. One step that does both is how a "remove this pin" button
/// becomes a silent accept -- the same fail-open Loop #51 closed. `verify_loop52`
/// asserts that a forgotten host comes back as `Unknown`, not as a mismatch.
pub async fn forget(host : String) -> Unit {
  let _ = @js_async.Promise::wait(khs_forget_raw(storage_key(host)))
}

///| Whether storage works at all.
///

///|
///
/// Worth one call at startup in a real application: IndexedDB can be present and
/// still refuse to open (private mode, enterprise policy), and the user should
/// hear that from the client rather than discover it on the second connection.
pub async fn available() -> Bool {
  @js_async.Promise::wait(khs_probe_raw())
}
