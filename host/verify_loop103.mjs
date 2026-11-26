#!/usr/bin/env node
// host/verify_loop103.mjs -- Loop #103: `ssh-copy-id`.
//
// ## What is being claimed
//
// `ssh-copy-id` installs a public key into a remote account's
// `authorized_keys`.  Upstream's implementation is a POSIX shell script
// that sends ONE remote command and prints a handful of sentences.  This
// repository now has a MoonBit implementation of it, and this gate says
// three things about it:
//
//   1. **the sentences are upstream's own bytes** -- captured from the real
//      script in the same run, with the same arguments, and compared byte
//      for byte;
//   2. **the effect is real** -- the key ends up in the file and the server
//      accepts it afterwards;
//   3. **upstream cannot do this on a Windows server, and it says it did**
//      -- which is the difference this loop exists to remove.
//
// ## The oracle
//
// The real `ssh-copy-id` from Git for Windows
// (`C:\\Program Files\\Git\\usr\\bin\\ssh-copy-id`), run twice:
//
//   * **with a stand-in `ssh`** (`host/copyid_probe.sh`) -- the script then
//     runs to completion and every byte it produces is captured: its
//     stdout, its stderr and the remote command it built.  This is where
//     the golden sentences and the golden POSIX command come from;
//   * **with the real `ssh`** (`host/copyid_probe_real.sh`), against the
//     same Windows `sshd` this gate uses -- and there it fails, while
//     claiming success.
//
// The server is the real OpenSSH `sshd.exe` (`host/sshd_setup.mjs`), and
// the "does the key work now" question is answered by the real `ssh.exe`
// and by the server's own log.
//
// ## How the comparison is made fair
//
// Both sides get **the same arguments**, run **from the same directory**,
// with the same relative `-i` name and the same `-p`, `-t` and `-o` words.
// That matters: upstream's private key path is `dirname(pub) + "/" +
// basename(pub)`, so a relative `-i newkey` gives `./newkey` on both
// sides, and the closing sentence -- which quotes that path -- comes out
// the same.
//
// The program name is the one thing that cannot match: upstream prints
// `$0` and this build prints its own path.  Both are replaced by the
// literal `<prog>` before the comparison, and everything else -- the blank
// lines, the tabs, the line endings -- is compared byte for byte.
//
// ## What is NOT compared
//
//   * The **installation path** of the key.  Upstream's `-t` is relative to
//     the remote home; this gate points it at an absolute path, because the
//     bed's `sshd` reads `authorized_keys` from an absolute path.  That is
//     a property of the bed, not of the tool.
//   * The **POSIX remote command** is compared through the source, not
//     through the wire: a Windows server never receives it, because the
//     tool asks the far side what it is first and sends the PowerShell
//     form to a Windows one.  The gate therefore reads the command out of
//     `src/sshcopyid/install.mbt` and compares it with the bytes upstream
//     built in the same run.  The unit test pins the function's return
//     value to the same literal, so the two together close the loop.
//
// ## What runs where
//
// Every section needs the real script, the real `sshd` and the real
// `ssh.exe`.  Where they are not available the section is SKIPPED LOUDLY
// rather than quietly passed -- a machine that cannot run a check has not
// run it.

import { spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const BED = path.join(ROOT, ".loop103", "bed103");
const HOME = path.join(ROOT, ".loop103", "home103");
const ART = path.join(ROOT, ".loop103", "art103");
const PORT = 22273;

let failures = 0;
let checks = 0;
let skipped = 0;
const section = (t) => console.log(`\n${t}`);
const ok = (name, cond, detail = "") => {
  checks++;
  if (!cond) failures++;
  console.log(`  ${cond ? "PASS" : "FAIL"}  ${name}${detail ? "  -- " + detail : ""}`);
};
const skip = (name, why) => {
  skipped++;
  console.log(`  SKIP  ${name}  -- ${why}`);
};

// ---- the tools we need -------------------------------------------------

const GIT_DIR = "C:\\Program Files\\Git";
const UPSTREAM = path.join(GIT_DIR, "usr", "bin", "ssh-copy-id");
const BASH = path.join(GIT_DIR, "bin", "bash.exe");
const REAL_SSH = "C:\\Windows\\System32\\OpenSSH\\ssh.exe";
const KEYGEN = "C:\\Windows\\System32\\OpenSSH\\ssh-keygen.exe";
const OUR_EXE = path.join(
  ROOT,
  "_build",
  "native",
  "debug",
  "build",
  "cmd",
  "ssh_copy_id",
  "ssh_copy_id.exe",
);

const USER = process.env.USERNAME || process.env.USER || "user";

// ---- helpers -----------------------------------------------------------

/** The program name is the one thing that cannot match; both sides get
 *  the same placeholder before the comparison. */
function normalize(text, prog) {
  let out = text;
  if (prog) out = out.split(prog).join("<prog>");
  return out;
}

/** A Windows path as the POSIX path Git's bash understands. */
function toPosix(p) {
  return p.replace(/\\/g, "/").replace(/^([A-Za-z]):/, "/$1").toLowerCase();
}

function run(cmd, args, opts = {}) {
  const r = spawnSync(cmd, args, {
    encoding: "buffer",
    timeout: opts.timeout || 120000,
    cwd: opts.cwd,
    env: { ...process.env, ...(opts.env || {}) },
    input: opts.input === undefined ? undefined : Buffer.from(opts.input),
  });
  return {
    code: r.status,
    stdout: r.stdout ? r.stdout.toString("utf8") : "",
    stderr: r.stderr ? r.stderr.toString("utf8") : "",
  };
}
/** The arguments both sides are given.  They are the same words for
 *  upstream and for this build, and they are relative where the tool's own
 *  output quotes them. */
function commonArgs(target, khPath) {
  return [
    "-i",
    "newkey",
    "-p",
    String(PORT),
    "-t",
    target,
    "-o",
    `UserKnownHostsFile=${khPath}`,
    "-o",
    "StrictHostKeyChecking=no",
    `${USER}@127.0.0.1`,
  ];
}

/** The literals of a MoonBit function body, in order, with the escapes
 *  undone.  This is how the gate reads a command out of the source: the
 *  source is the only place the command exists as one string. */
function literalsOf(fnName) {
  const src = fs.readFileSync(path.join(ROOT, "src", "sshcopyid", "install.mbt"), "utf8");
  const start = src.indexOf(`pub fn ${fnName}`);
  if (start < 0) return [];
  const body = src.slice(start, src.indexOf("\n}", start));
  return [...body.matchAll(/"((?:[^"\\]|\\.)*)"/g)].map((m) => unescapeMoonBit(m[1]));
}

/** MoonBit's string escapes, undone. */
function unescapeMoonBit(s) {
  let out = "";
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === "\\" && i + 1 < s.length) {
      const d = s[i + 1];
      if (d === "n") { out += "\n"; i++; continue; }
      if (d === "t") { out += "\t"; i++; continue; }
      if (d === "\\") { out += "\\"; i++; continue; }
      if (d === '"') { out += '"'; i++; continue; }
      if (d === "'") { out += "'"; i++; continue; }
    }
    out += c;
  }
  return out;
}

/** The bytes as the shell that runs upstream would hand them over: CRLF
 *  folded to LF.  Git's bash does that to every file it reads, and it is
 *  the only difference between the two sides' dry-run blocks. */
function oursDryBytes(text) {
  return text.replace(/\r\n/g, "\n");
}

/** Whether something is listening on the loopback port. */function portOpen(port) {
  return new Promise((resolve) => {
    const s = net.connect({ host: "127.0.0.1", port }, () => {
      s.destroy();
      resolve(true);
    });
    s.on("error", () => {
      s.destroy();
      resolve(false);
    });
  });
}

async function waitForPort(port, timeoutMs = 30000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await portOpen(port)) return true;
    await new Promise((r) => setTimeout(r, 250));
  }
  return false;
}

// ---- 0. build ----------------------------------------------------------

section("build");

const build = run("moon", ["build", "cmd/ssh_copy_id", "--target", "native"], { cwd: ROOT });
ok("the tool builds", build.code === 0, build.stderr.slice(0, 600));
if (build.code !== 0 || !fs.existsSync(OUR_EXE)) {
  console.log("  the gate cannot continue without the tool");
  process.exit(1);
}
ok("the tool is where it should be", fs.existsSync(OUR_EXE), OUR_EXE);

const unit = run("moon", ["test", "-p", "src/sshcopyid"], { cwd: ROOT });
if (unit.code === 0) {
  ok("the src/sshcopyid unit tests pass", true, unit.stdout.trim().split("\n").pop() || "");
} else {
  // A failing unit test is a FAIL.  Only the one failure this machine
  // produces on its own -- the real-time protection holding the test
  // executable -- is a SKIP, because that is a machine that cannot run the
  // check, not a tree that fails it.
  const av = /access is denied|拒绝访问/i.test(unit.stdout + unit.stderr);
  if (av) {
    skip(
      "the src/sshcopyid unit tests",
      "this machine's real-time protection is holding the test executable (a known trap; the cloud CI runs them)",
    );
  } else {
    ok("the src/sshcopyid unit tests pass", false, unit.stdout.slice(-400));
  }
}

// ---- 1. the bed --------------------------------------------------------

section("the bed");

const haveUpstream = fs.existsSync(UPSTREAM);
const haveBash = fs.existsSync(BASH);
const haveSsh = fs.existsSync(REAL_SSH);
const haveKeygen = fs.existsSync(KEYGEN);

if (!haveSsh || !haveKeygen) {
  skip("the whole gate", "the real ssh.exe or ssh-keygen.exe is not on this machine");
  process.exit(1);
}

fs.mkdirSync(path.join(HOME, ".ssh"), { recursive: true });
fs.mkdirSync(BED, { recursive: true });
fs.mkdirSync(ART, { recursive: true });

const existing = path.join(BED, "existing");
const existingPub = path.join(BED, "existing.pub");
const newKey = path.join(BED, "newkey");
const newPub = path.join(BED, "newkey.pub");
const AK = path.join(BED, "authorized_keys");

for (const [p, seed] of [[existing, "loop103 existing"], [newKey, "loop103 new"]]) {
  // Fresh keys every run, with NO passphrase: `-N ""` and an empty
  // passphrase are two different things, and a key that asks for one is a
  // different thing to measure.  `y` answers ssh-keygen's overwrite
  // question, so an old key file cannot change what is measured.
  const k = run(KEYGEN, ["-t", "ecdsa", "-b", "256", "-f", p, "-N", "", "-C", seed], {
    input: "y\n",
  });
  if (k.code !== 0) {
    skip("the whole gate", "ssh-keygen could not make the test keys");
    process.exit(1);
  }
}

// The default identity: the key the server already accepts.  Upstream's
// install step connects with the default identities, not with the key
// being installed -- the key being installed cannot open the connection,
// because it is not installed yet.
fs.copyFileSync(existing, path.join(HOME, ".ssh", "id_ecdsa"));
fs.copyFileSync(existingPub, path.join(HOME, ".ssh", "id_ecdsa.pub"));

// The bed's authorized_keys starts with the key the server already
// accepts, and with **exactly one** newline at the end.
//
// The one newline matters: upstream's one-liner adds a newline when the
// file does not end with one, and this tool's Windows script does the
// same, so a base file that ends with two newlines would make the two
// sides add different bytes.
const baseContent = Buffer.concat([
  Buffer.from(fs.readFileSync(existingPub, "utf8").replace(/[\r\n]+$/, "")),
  Buffer.from("\n"),
]);
const resetAk = () => {
  fs.writeFileSync(AK, baseContent);
};
resetAk();

// The known_hosts for the bed.  ONE entry: the known_hosts package
// compares the presented key against the LAST entry for the host, so
// several keys for one host would read as a mismatch.  The host key is
// read from the bed's own key files, so this has to wait until the
// server has made them.
const khPath = path.join(HOME, ".ssh", "known_hosts");
const writeKnownHosts = () => {
  const edPub = fs
    .readFileSync(path.join(BED, "hostkey_ed25519.pub"), "utf8")
    .trim()
    .split(/\s+/);
  fs.writeFileSync(khPath, `127.0.0.1 ${edPub[0]} ${edPub[1]}\n`);
};

// The `-t` word: the bed's own authorized_keys, with forward slashes so
// that the same word means the same file to Windows and to Git's bash.
const target = AK.replace(/\\/g, "/");
const khWord = khPath.replace(/\\/g, "/");

// The server helper stays in the foreground on purpose: it holds the sshd
// process, and the sshd goes away with it.  `spawnSync` would block on a
// helper that never returns.
const setup = spawn(
  "node",
  [path.join(ROOT, "host", "sshd_setup.mjs"), "--dir", BED, "--port", String(PORT), "--name", "loop103"],
  { cwd: ROOT, stdio: ["ignore", "pipe", "pipe"] },
);
let setupOut = "";
setup.stdout.on("data", (d) => { setupOut += d.toString(); });
setup.stderr.on("data", (d) => { setupOut += d.toString(); });

const serverUp = await waitForPort(PORT);
ok("the real sshd is listening", serverUp, `port ${PORT}`);
if (!serverUp) {
  console.log(setupOut);
  process.exit(1);
}
writeKnownHosts();

const stopServer = () => {
  spawnSync("node", [path.join(ROOT, "host", "sshd_setup.mjs"), "--dir", BED, "--stop", "--name", "loop103"], { cwd: ROOT });
  setup.kill();
};

// ---- 2. upstream's own bytes -------------------------------------------

section("upstream's own bytes");

let up = { install: null, dry: null, skipped: null };

if (!haveUpstream || !haveBash) {
  skip("upstream's bytes", "the real ssh-copy-id (or Git's bash) is not on this machine");
} else {
  const probeSh = path.join(ROOT, "host", "copyid_probe.sh");
  const upstreamPosix = toPosix(UPSTREAM);
  // The home is the **Windows** path, on purpose.
  //
  // Upstream runs inside Git's bash, and the ssh client it calls is the
  // one on that bash's PATH.  With `HOME` set to a POSIX path the client
  // cannot find the default identity (`~/.ssh/id_ecdsa`), so the install
  // step never even reaches the server -- and the run would be measuring
  // "no identity" instead of "the remote command does not run".  With the
  // Windows path the client finds the key, and the failure that is left
  // is the one this gate is about.
  const homeWord = HOME;

  /** Run the real upstream script with a stand-in for `ssh`. */
  const runUpstream = (name, extra, filter) => {
    const argsFile = path.join(ART, `args_${name}.txt`);
    fs.writeFileSync(argsFile, "");
    const r = run(
      BASH,
      [
        toPosix(probeSh),
        upstreamPosix,
        ...extra,
        ...commonArgs(target, khWord),
      ],
      {
        cwd: BED,
        env: {
          HOME: homeWord,
          FAKE_SSH_ARGS: toPosix(argsFile),
          FAKE_SSH_FILTER: filter,
        },
      },
    );
    const recorded = fs.existsSync(argsFile)
      ? fs.readFileSync(argsFile, "utf8").split("\n").filter((l) => l !== "")
      : [];
    return { code: r.code, stdout: r.stdout, stderr: r.stderr, recorded };
  };

  up.install = runUpstream("install", [], "deny");
  up.dry = runUpstream("dry", ["-n"], "deny");
  up.skipped = runUpstream("skipped", [], "allow");

  ok("upstream's install run ends with status 0", up.install.code === 0, `exit ${up.install.code}`);
  ok("upstream's stdout is the closing block", up.install.stdout.includes("Number of key(s) added: 1"),
    JSON.stringify(up.install.stdout.slice(0, 200)));
  ok("upstream says where the key came from",
    up.install.stderr.includes("INFO: Source of key(s) to be installed:"),
    JSON.stringify(up.install.stderr.slice(0, 200)));
  ok("upstream says how many keys are left",
    up.install.stderr.includes("INFO: 1 key(s) remain to be installed"),
    JSON.stringify(up.install.stderr.slice(0, 300)));
  ok("upstream's dry run says what it would do",
    up.dry.stdout.includes("Would have added the following key(s):"),
    JSON.stringify(up.dry.stdout.slice(0, 200)));
  ok("upstream says the keys were already installed",
    up.skipped.stderr.includes("WARNING: All keys were skipped because they already exist"),
    JSON.stringify(up.skipped.stderr.slice(0, 200)));

  // The remote command upstream built: the last argument of its install
  // call.  This is the golden POSIX command.
  const installCall = up.install.recorded.filter((l) => l.startsWith("exec sh -c ")).pop();
  up.installCommand = installCall || "";
  ok("upstream built a remote command", installCall !== "", JSON.stringify(installCall.slice(0, 160)));
  ok("the remote command names the target we asked for",
    installCall !== "" && installCall.includes(`AUTH_KEY_FILE="${target}"`),
    JSON.stringify((installCall || "").slice(0, 200)));
}

// ---- 3. our tool, dry run ----------------------------------------------

section("our tool, dry run");

const dry = run(OUR_EXE, ["-n", ...commonArgs(target, khWord)], { cwd: BED, env: { HOME } });
ok("our tool exits 0", dry.code === 0, `exit ${dry.code} ${dry.stderr.slice(0, 200)}`);
if (up.dry) {
  const prog = toPosix(UPSTREAM);
  // The one difference, and it is not in a sentence.
  //
  // The dry-run block repeats the key text, and the key text comes from
  // the .pub file, which on Windows ends with CRLF.  Upstream reads it
  // with `cat` inside Git's bash, and that shell translates CRLF to LF
  // on the way (measured: upstream's own bytes carry `new\n`, ours carry
  // `new\r\n`).  So the CR is dropped before the comparison -- and the
  // bytes this build appends to the file are checked separately, against
  // the .pub file's own bytes, in the install section below.
  const oursDry = oursDryBytes(dry.stdout);
  const upstreamDry = up.dry.stdout;
  ok("our stdout is upstream's dry-run block, byte for byte",
    oursDry === upstreamDry,
    JSON.stringify(dry.stdout.slice(0, 300)));
  ok("our stderr is upstream's three INFO lines, byte for byte",
    normalize(dry.stderr, OUR_EXE) === normalize(up.dry.stderr, prog),
    JSON.stringify(dry.stderr.slice(0, 300)));
}
const afterDry = fs.readFileSync(AK);
ok("authorized_keys did not grow", afterDry.length === baseContent.length,
  `${baseContent.length} -> ${afterDry.length}`);

// ---- 4. our tool installs the key --------------------------------------

section("our tool installs the key");

const ours = run(OUR_EXE, commonArgs(target, khWord), { cwd: BED, env: { HOME } });
ok("our tool exits 0", ours.code === 0, `exit ${ours.code} ${ours.stderr.slice(0, 300)}`);
if (up.install) {
  const prog = toPosix(UPSTREAM);
  ok("our stdout is upstream's closing block, byte for byte",
    normalize(ours.stdout, OUR_EXE) === normalize(up.install.stdout, prog),
    JSON.stringify(ours.stdout.slice(0, 400)));
  ok("our stderr is upstream's three INFO lines, byte for byte",
    normalize(ours.stderr, OUR_EXE) === normalize(up.install.stderr, prog),
    JSON.stringify(ours.stderr.slice(0, 400)));
}

// The effect: the file grew by exactly the public key, and the server
// accepts the key afterwards.
const after = fs.readFileSync(AK);
ok("authorized_keys grew by exactly the public key",
  after.length === baseContent.length + fs.statSync(newPub).size,
  `${baseContent.length} -> ${after.length}, the key is ${fs.statSync(newPub).size} bytes`);
ok("the appended bytes are the .pub file's bytes",
  after.subarray(after.length - fs.statSync(newPub).size).equals(fs.readFileSync(newPub)));

const auth = run(REAL_SSH, [
  "-p", String(PORT), "-i", newKey, "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
  "-o", `UserKnownHostsFile=${khPath}`, "-o", "StrictHostKeyChecking=no",
  `${USER}@127.0.0.1`, "echo AUTH-OK",
]);
ok("the new key authenticates after the install",
  auth.code === 0 && auth.stdout.includes("AUTH-OK"),
  `exit ${auth.code} ${auth.stderr.slice(0, 160)}`);

// ---- 5. the key is already there ---------------------------------------

section("the key is already installed");

const again = run(OUR_EXE, commonArgs(target, khWord), { cwd: BED, env: { HOME } });
ok("our tool exits 0", again.code === 0, `exit ${again.code}`);
if (up.skipped) {
  const prog = toPosix(UPSTREAM);
  ok("our stderr is upstream's 'already installed' block, byte for byte",
    normalize(again.stderr, OUR_EXE) === normalize(up.skipped.stderr, prog),
    JSON.stringify(again.stderr.slice(0, 400)));
  ok("our stdout is empty, like upstream's", again.stdout === "",
    JSON.stringify(again.stdout.slice(0, 120)));
}
const afterAgain = fs.readFileSync(AK);
ok("authorized_keys did not grow", afterAgain.length === after.length,
  `${after.length} -> ${afterAgain.length}`);

// ---- 6. upstream cannot do this, and says it did -----------------------

section("upstream on the same server");

if (!haveUpstream || !haveBash) {
  skip("upstream against the bed", "the real ssh-copy-id (or Git's bash) is not on this machine");
} else {
  resetAk();
  const real = run(
    BASH,
    [
      toPosix(path.join(ROOT, "host", "copyid_probe_real.sh")),
      toPosix(UPSTREAM),
      ...commonArgs(target, khWord),
    ],
    { cwd: BED, env: { HOME } },
  );
  ok("upstream exits 0", real.code === 0, `exit ${real.code}`);
  ok("upstream claims the key was added",
    real.stdout.includes("Number of key(s) added: 1"),
    JSON.stringify(real.stdout.slice(0, 240)));
  const akNow = fs.readFileSync(AK);
  ok("but authorized_keys did not change", akNow.length === baseContent.length,
    `${baseContent.length} -> ${akNow.length}`);
  ok("and upstream says why: the remote shell cannot run its command",
    /not recognized|不是内部或外部命令/i.test(real.stderr),
    JSON.stringify(real.stderr.slice(-240)));
  const authUp = run(REAL_SSH, [
    "-p", String(PORT), "-i", newKey, "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
    "-o", `UserKnownHostsFile=${khPath}`, "-o", "StrictHostKeyChecking=no",
    `${USER}@127.0.0.1`, "echo AUTH-OK",
  ]);
  ok("and the key does not authenticate", authUp.code !== 0, `exit ${authUp.code}`);
}

// ---- 7. the command we sent --------------------------------------------

section("the command we sent");

const logPath = path.join(BED, "sshd.log_loop103");
let log = "";
if (fs.existsSync(logPath)) log = fs.readFileSync(logPath, "utf8");
const execLines = log.split("\n").filter((l) => l.includes("exec_command: powershell"));
ok("the server was asked to run a powershell command", execLines.length > 0);
if (execLines.length > 0) {
  const line = execLines[execLines.length - 1];
  const b64 = line.split("EncodedCommand ")[1].trim();
  // The log line is TRUNCATED.
  //
  // OpenSSH's logger keeps one line in a 1024-byte buffer (`MSGBUFSIZ`),
  // and the command this tool sends is longer than that -- it is base64
  // of UTF-16LE, so it is about three times the length of the script.
  // What the log can give is the first few hundred characters of the
  // script, and that is enough for the strongest claim available: the
  // visible part must be the **beginning of the script this repository
  // builds**, and the script this repository builds is checked in full
  // against the source.
  ok("the log line really is cut short, so this section knows its limits",
    line.length < 1100 && b64.length < 1000, `${line.length} chars`);
  ok("the command is the base64 form, with nothing cmd.exe would act on",
    /^[A-Za-z0-9+/=]*$/.test(b64), b64.slice(0, 60));
  const visible = Buffer.from(b64, "base64").toString("utf16le");

  const body = literalsOf("windows_script_body").join("");
  const expected =
    "$t=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" +
    Buffer.from(target, "utf8").toString("base64") +
    "'))" +
    body;
  ok("the visible part of the script is the beginning of the script this build makes",
    expected.startsWith(visible),
    JSON.stringify(visible.slice(-60)));
  ok("and the visible part is long enough for that to mean something",
    visible.length >= 300, `${visible.length} chars`);
  ok("the script the source builds ends by appending stdin to the file",
    expected.trimEnd().endsWith("[IO.File]::AppendAllText($p,[Console]::In.ReadToEnd())"));
  ok("the script the source builds makes the directory first",
    expected.includes("[IO.Directory]::CreateDirectory($d)"));
  ok("the script the source builds adds the missing newline first",
    expected.includes("if($b -ne 10){[IO.File]::AppendAllText($p,[string][char]10)}"));
  const inScript = /FromBase64String\('([A-Za-z0-9+/=]+)'\)/.exec(expected);
  ok("the target path travels as base64 inside the script",
    inScript !== null &&
      Buffer.from(inScript[1], "base64").toString("utf8") === target,
    target);
}

// ---- 8. the POSIX command ----------------------------------------------

section("the posix command");

if (!up.installCommand) {
  skip("the posix command", "upstream's remote command was not captured");
} else {
  // The command our source builds, read out of the source: the pieces of
  // the literal in `install_command_posix`, joined with the place where
  // the target path goes.
  const pieces = literalsOf("install_command_posix");
  const oursCommand = pieces.join("<TARGET>");
  ok("our source builds one command out of literal pieces", pieces.length > 0,
    `${pieces.length} pieces`);
  const upstreamCommand = up.installCommand.split(target).join("<TARGET>");
  ok("the command our source builds is upstream's own bytes, byte for byte",
    oursCommand === upstreamCommand,
    JSON.stringify(oursCommand.slice(0, 200)) + " vs " + JSON.stringify(upstreamCommand.slice(0, 200)));
}

// ---- done --------------------------------------------------------------

stopServer();
section(`summary`);
console.log(`  ${checks} checks, ${failures} failed, ${skipped} skipped`);
process.exit(failures === 0 ? 0 : 1);
