///| cmd/proton_gui -- Loop #41, milestone 1: prove the shell opens.
///|
///| Everything here is from the package's own README and
///| `pkg.generated.mbti`, not from a tutorial: `async fn main` (Proton hands
///| its event loop to moonbitlang/async), `@proton.html` for an inline
///| document, `.identifier` for the reverse-DNS identity every app must
///| carry, `.run_or_abort` to run it.
///|
///| The next milestone turns this into a fault-injection console: commands
///| registered through `.commands(...)` / `CommandRegistrar::bind` will drive
///| `src/sftp`'s `SftpSession` directly -- malformed WRITEs, wrong request
///| ids, EXTENDED names no server has -- the branches a KAT against a real
///| well-behaved server never reaches.  The rule that keeps that safe is
///| already in place: this package is the only importer of `@proton`, and
///| `src/` never sees it.
///|
///| Run:  moon run cmd/proton_gui --target native
///| Headless (no window, for a smoke check):
///|   $env:PROTON_HEADLESS = "1"; moon run cmd/proton_gui --target native
async fn main {
  let html = "<html>\n" +
    "  <body style=\"font-family: Consolas, monospace; background: #14161a; color: #d8dee9; padding: 16px;\">\n" +
    "    <h2 style=\"color:#88c0d0; margin-top:0;\">openssh_moonbit debug console</h2>\n" +
    "    <p>Proton shell is up. Command bridge comes with the next milestone.</p>\n" +
    "  </body>\n" +
    "</html>"
  @proton.html("openssh_moonbit debug console", html, width=760, height=480)
  .identifier("dev.openssh-moonbit.console")
  .run_or_abort()
}
