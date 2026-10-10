///| cmd/proton_gui -- Loop #41, milestone 2: the fault-injection console

///|

///| Milestone 1 proved the shell opens. This milestone gives it something to

///| do: three application commands bound through `.commands(...)` /

///| `CommandRegistrar::bind`, each driving `src/sftp`'s `SftpSession` over a

///| reply no well-behaved `internal-sftp` would send.
///

///| Why a GUI is the right home for this and not a `cmd/sftp_test` case:

///| the Loop #39 KAT and the Loop #40 live round trip both prove the happy

///| path against real OpenSSH bytes. Neither can reach "STATUS before

///| VERSION", "a reply carrying someone else's request id", "a length prefix

///| over `SFTP_MAX_MSG_LENGTH`", or "an extension advertised and then

///| refused" -- OpenSSH does not send those, so no capture contains them. A

///| fault injector is the only way to hold those branches, and holding a

///| branch by hand is a console's job.
///

///| The rule that keeps this safe is unchanged: **this package is the only

///| importer of `@proton`.** `src/` never sees it, so the four-backend KAT

///| gates never depend on a 0.x GUI framework. Everything below reaches the

///| protocol only through `src/sftp`, which is the same package the two

///| transports use -- the console is a third *driver*, not a second

///| implementation.
///

///| Run:  moon run cmd/proton_gui --target native

///| Headless (no window; runs the suite and prints it):

///|   $env:PROTON_HEADLESS = "1"; moon run cmd/proton_gui --target native

///| The three commands. Names become `app:<name>` on the wire and

///|
/// `window.__MoonBit__.app.<name>` in the page.
let cmd_list : @proton_contract.Command[
  @proton_contract.EmptyRequest,
  ListReply,
] = @proton_contract.command("sftp_fault_list")

///|
let cmd_run : @proton_contract.Command[RunRequest, RunReply] = @proton_contract.command(
  "sftp_fault_run",
)

///|
let cmd_all : @proton_contract.Command[@proton_contract.EmptyRequest, AllReply] = @proton_contract.command(
  "sftp_fault_all",
)

///| Every handler is `async` because `CommandRegistrar::bind` says

///| `async (CommandContext, Request) -> Response` -- the runtime hands the op

///| to the MoonBit async executor. `moon check` reports `unused_async` on

///| all three, because none of them awaits anything and MoonBit will promote

///| a plain `fn` to an async one implicitly. The annotation is kept anyway:

///| dropping it would leave a handler whose *declared* type no longer says

///| what the registrar asks for, and the promotion is a coercion rather than a

///| match. When a handler does await -- a real transport, a real socket -- the

///| annotation stops being redundant, and having all three shaped the same way

///| means the day one of them needs it is not also the day the other two look

///| wrong.

///|

///| The context is the first argument and is unused here: these scenarios are

///| pure computation over bytes, with no window and no permission scope, but

///| keeping the parameter is what makes the shape the same as every other

///|
/// Proton command.
async fn fault_list(
  _ctx : @proton.CommandContext,
  _req : @proton_contract.EmptyRequest,
) -> ListReply {
  let names = case_names()
  let intents : Array[String] = []
  for i = 0; i < names.length(); i = i + 1 {
    intents.push(case_intent(names[i]))
  }
  ListReply::{ scenarios: names, intents, }
}

///|
async fn fault_run(_ctx : @proton.CommandContext, req : RunRequest) -> RunReply {
  let (pass, fails, r, c) = run_named(req.name)
  reply_of(c.name, c.intent, pass, r, fails)
}

///|
async fn fault_all(
  _ctx : @proton.CommandContext,
  _req : @proton_contract.EmptyRequest,
) -> AllReply {
  let (passed, fails, notes) = run_all()
  AllReply::{ total: fault_cases.length(), passed, failures: fails, notes, }
}

///| The panel. Inline HTML rather than a bundled asset because there is

///| nothing to bundle: the page is the console, and a separate file would

///| only add a load step that can fail for reasons unrelated to the protocol.

///|

///| `#+"..."#` string interpolation is not used -- this repo's moon lexes it

///| as an unterminated string literal -- so the JS is built by concatenation

///|
/// like the rest of this package.
fn console_html() -> String {
  let head = "<html>\n" +
    "  <head><meta charset=\"utf-8\"><title>openssh_moonbit fault console</title>\n" +
    "  <style>\n" +
    "    body { font-family: Consolas, monospace; background: #14161a; color: #d8dee9; padding: 16px; }\n" +
    "    h2 { color: #88c0d0; margin-top: 0; }\n" +
    "    button { font-family: inherit; background: #2e3440; color: #d8dee9;\n" +
    "             border: 1px solid #4c566a; border-radius: 3px;\n" +
    "             padding: 5px 9px; margin: 0 5px 5px 0; cursor: pointer; }\n" +
    "    button:hover { background: #3b4252; }\n" +
    "    .intent { color: #81a1c1; font-size: 12px; margin: 2px 0 10px 0; }\n" +
    "    .verdict { font-weight: bold; }\n" +
    "    .pass { color: #a3be8c; } .fail { color: #bf616a; }\n" +
    "    pre { background: #2e3440; padding: 10px; border-radius: 3px;\n" +
    "          white-space: pre-wrap; word-break: break-all; }\n" +
    "    .lbl { color: #4c566a; }\n" +
    "  </style></head>\n" +
    "  <body>\n" +
    "    <h2>openssh_moonbit SFTP fault console</h2>\n" +
    "    <p class=\"intent\">Replies OpenSSH never sends, driven through " +
    "<code>src/sftp</code>'s state machine. Expectations come from " +
    "<code>host/sftp_fault_oracle.py</code>, an independent implementation.</p>\n" +
    "    <div id=\"bar\"></div>\n" +
    "    <button id=\"runall\">run all</button>\n" +
    "    <div id=\"detail\"></div>\n" +
    "  </body>\n" +
    "</html>"
  let script = "<script>\n" +
    "  const bar = document.getElementById('bar');\n" +
    "  const detail = document.getElementById('detail');\n" +
    "  const esc = s => String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;');\n" +
    "  const dump = o => esc(JSON.stringify(o, null, 2));\n" +
    "  async function list() {\n" +
    // `{}` and not `null`: the registry decodes the payload straight into the
    // Request type, and `EmptyRequest` is a fieldless struct -- it wants an
    // object. `null` is valid JSON and still fails the decode.
    "    const r = await window.__MoonBit__.app.sftp_fault_list({});\n" +
    "    r.scenarios.forEach((name, i) => {\n" +
    "      const b = document.createElement('button');\n" +
    "      b.textContent = name;\n" +
    "      b.onclick = () => runOne(name);\n" +
    "      bar.appendChild(b);\n" +
    "      const p = document.createElement('div');\n" +
    "      p.className = 'intent';\n" +
    "      p.textContent = r.intents[i];\n" +
    "      bar.appendChild(p);\n" +
    "    });\n" +
    "  }\n" +
    "  async function runOne(name) {\n" +
    "    const r = await window.__MoonBit__.app.sftp_fault_run({ name });\n" +
    "    show(r);\n" +
    "  }\n" +
    "  function show(r) {\n" +
    "    const v = document.createElement('div');\n" +
    "    v.className = 'verdict ' + (r.pass ? 'pass' : 'fail');\n" +
    "    v.textContent = (r.pass ? 'PASS  ' : 'FAIL  ') + r.name + '  --  ' + r.intent;\n" +
    "    detail.replaceChildren(v, pre(dump(r)));\n" +
    "  }\n" +
    "  function pre(text) {\n" +
    "    const p = document.createElement('pre');\n" +
    "    p.textContent = text;\n" +
    "    return p;\n" +
    "  }\n" +
    "  document.getElementById('runall').onclick = async () => {\n" +
    "    const r = await window.__MoonBit__.app.sftp_fault_all({});\n" +
    "    const v = document.createElement('div');\n" +
    "    v.className = 'verdict ' + (r.failures.length ? 'fail' : 'pass');\n" +
    "    v.textContent = r.passed + '/' + r.total + ' scenarios agree with the oracle';\n" +
    "    detail.replaceChildren(v, pre(r.notes.join('\\n') + '\\n\\n' + dump(r.failures)));\n" +
    "  };\n" +
    "  list();\n" +
    "</script>\n"
  head + script
}

///|
async fn main {
  @proton.html(
    "openssh_moonbit fault console",
    console_html(),
    width=980,
    height=720,
  )
  .identifier("dev.openssh-moonbit.console")
  .commands(registrar => {
    registrar.bind(cmd_list, fault_list)
    registrar.bind(cmd_run, fault_run)
    registrar.bind(cmd_all, fault_all)
  })
  .run_or_abort()
}
