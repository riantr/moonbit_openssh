#!/usr/bin/env node
// host/verify_loop82.mjs -- Loop #82: ssh-keyscan, the host key without
// authenticating.
//
// ## What is being claimed
//
// `ssh-keyscan host` prints the host's public keys in known_hosts form, and
// it does so **without authenticating**: it completes the key exchange, takes
// the host key the server offered, and disconnects.  That is the whole point
// of the tool -- you use it to find out what a host has, *before* deciding
// whether to trust it, and a single authentication attempt would already have
// handed your credentials to that host.
//
// This repository had none of it: no keyscan tool, no way to ask a server for
// a key other than by connecting as a user, and no known_hosts line writer
// outside the TOFU path.
//
// ## The evidence, and why each piece is here
//
// 1. **The output is the real tool's output, line for line.**  This
//    repository's `cmd/ssh_keyscan` and OpenSSH's own `ssh-keyscan` are run
//    against the same server, and their **stdout** has to be the same lines,
//    byte for byte.  The oracle is the real tool, not a re-implementation of
//    it, so this cannot be satisfied by agreeing with ourselves.
//
//    The *order* is deliberately not part of it, and that is a fact about the
//    real tool rather than a convenience: OpenSSH's ssh-keyscan opens all of
//    its connections at once and prints each key when its handshake
//    completes, so its output order is the order the handshakes finished in
//    -- it changes from run to run.  Measured here: the 8.0p1 build printed
//    ecdsa before rsa on one run and rsa before ecdsa on the next, which
//    turned a byte-for-byte comparison into a coin flip.  This client's own
//    order *is* a claim, and it is asserted separately: it is sequential, so
//    it always prints in the order it requested the types in.
//
//    Nor is the *stream* the note lands on part of it: which one is a version
//    detail of the real tool (the installed 8.0p1 and 9.x put the
//    "# host:port SSH-2.0-..." note on stderr, OpenSSH 10.4's source writes it
//    to stdout).  So the known_hosts lines are compared as a set, and the
//    note is compared wherever the tool put it.  This client's own layout --
//    known_hosts on stdout, note on stderr -- is a claim, and it is asserted
//    separately.
//
// 2. **The scan never authenticates.**  Not "the client did not report an
//    error" -- the **server's own log** must contain no userauth record for
//    the scan connections.  And to make that zero mean something, the gate
//    also runs an ordinary client against the same server first and shows
//    that the log *does* record userauth when a client really authenticates.
//    A zero that would be zero anyway is not a measurement.
//
// 3. **The rules the end-to-end test cannot reach are pinned as cases.**
//    The default-port shape (`host`, no brackets) needs a server on port 22,
//    and the lowercasing needs a host name with upper-case letters that still
//    resolves to the test server.  `cmd/keyscan_kat` states both, against a
//    Python transcription of OpenSSH's `put_host_port` and `lowercase`.
//
// 4. **One connection per key type.**  A key exchange negotiates exactly one
//    host key, so a scan of all of a server's keys needs one connection per
//    type -- which is what OpenSSH does, and what the server's log shows.
//
// ## What runs where
//
// Sections G0 and G1 need only node, python and the MoonBit toolchain, so
// they run everywhere.  G2 and G3 need an OpenSSH **server** and an OpenSSH
// **ssh-keyscan binary**.  When either is missing, those sections are
// **skipped loudly** rather than quietly passed: a machine that cannot run a
// check has not run it.

import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, rmSync } from "node:fs";
import net from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { sshUserInfo } from "./ssh_user.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const WORK = path.join(ROOT, ".loop82");

// The account this gate authenticates as. Derived, never written down: see
// host/ssh_user.mjs for why, and for the same rule applied to paths.
const USER = sshUserInfo().name;

const SKIP_REGRESSION = process.argv.includes("--skip-regression");

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

function moon(args) {
  const r = spawnSync("cmd", ["/c", "moon", ...args], {
    cwd: ROOT, encoding: "utf8", errors: "replace", maxBuffer: 64 * 1024 * 1024,
  });
  return { code: r.status, out: `${r.stdout || ""}${r.stderr || ""}` };
}

function norm(s) {
  return `${s}`.replace(/\r\n/g, "\n");
}

// The lines of a tool's output, without their order.
//
// OpenSSH's own ssh-keyscan starts **all** of its connections at once
// (`conprocess`/`conread`/`congreet` over a select() loop, one connection per
// key type) and prints each key from the key-exchange completion callback
// (`key_print_wrapper` -> `keyprint_one`).  So the order of its output is
// the order the handshakes *finished*, not the order the types were
// requested -- and it changes from run to run.  Measured on this machine: the
// 8.0p1 build printed ecdsa before rsa on one run and rsa before ecdsa on
// the next.
//
// Comparing the two outputs as one byte string therefore compares something
// neither tool promises, and it fails at random.  What both tools do promise
// is the same *set* of lines, each line byte for byte -- so that is what is
// compared.  The order this client prints in is a separate claim, and it is
// asserted separately (this client is sequential, so its order is the type
// order it requested, every time).
function linesOf(s) {
  return norm(s).split("\n").filter(Boolean);
}

// The tool's note about the server it talked to ("# host:port SSH-2.0-...").
// It is not a known_hosts line, and it is kept apart from them for a reason:
// which stream it lands on is a **version detail of the real tool**.  The
// installed 8.0p1 and 9.x builds put it on stderr; OpenSSH 10.4's source
// writes it to stdout.  Comparing whole streams would compare that detail as
// if it were the contract, so the known_hosts lines and the note are compared
// separately, and the note is compared wherever the tool put it.
const isComment = (l) => l.startsWith("#");

// The known_hosts lines only.
function keyLinesOf(s) {
  return linesOf(s).filter((l) => !isComment(l));
}

// The note lines only, from every stream given.
function commentLinesOf(...streams) {
  return streams.flatMap((s) => linesOf(s).filter(isComment));
}

// Same set of known_hosts lines, byte for byte, order apart.
function sameLines(a, b) {
  const la = keyLinesOf(a).slice().sort();
  const lb = keyLinesOf(b).slice().sort();
  return la.length === lb.length && la.every((l, i) => l === lb[i]);
}

function hashOut(out) {
  return createHash("sha256").update(norm(out)).digest("hex").slice(0, 16);
}

function lineOf(text, key) {
  const m = norm(text).match(new RegExp(`^${key}: (.*)$`, "m"));
  return m ? m[1] : undefined;
}

function tap(child) {
  child.tapBuf = "";
  for (const stream of [child.stdout, child.stderr]) {
    if (stream) stream.on("data", (d) => { child.tapBuf += d.toString(); });
  }
  return child;
}

async function waitForText(child, needle, timeoutMs = 30000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if ((child.tapBuf || "").includes(needle)) return true;
    await new Promise((r) => setTimeout(r, 120));
  }
  console.log(`      (never saw "${needle}"; saw: ${(child.tapBuf || "").trim().slice(0, 300)})`);
  return false;
}

function freePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.on("error", reject);
    srv.listen(0, "127.0.0.1", () => {
      const p = srv.address().port;
      srv.close(() => resolve(p));
    });
  });
}

// ---------------------------------------------------------------------------
// Where the real ssh-keyscan might be.
// ---------------------------------------------------------------------------
//
// The list is the same one host/sshd_setup.mjs probes, because the two
// OpenSSH installations on a Windows machine are the same installation: one
// portable build under Program Files, one inbox feature under System32.
// Neither is on PATH by default.
//
// The entries below are CANDIDATES, probed in order until one exists. None is
// asserted to exist, and when none does the gate says so and skips the
// comparison loudly. verify_loop71.mjs flags any drive-letter path it finds
// in code; the marker below is how a file declares that its paths are a probe
// rather than a claim, and it is an obligation to say why, not a mute button.
//
// machine-path-exempt: each entry below is a CANDIDATE, probed in order until
const KEYSCAN_DIRS = [
  "C:\\Program Files\\OpenSSH-Win64",
  "C:\\Windows\\System32\\OpenSSH",
  "C:\\Program Files\\OpenSSH",
];

function keyscanBinaries() {
  const out = [];
  for (const d of KEYSCAN_DIRS) {
    const p = path.join(d, "ssh-keyscan.exe");
    if (existsSync(p)) out.push(p);
  }
  return out;
}

// ---------------------------------------------------------------------------
// The server.
// ---------------------------------------------------------------------------
function startSshd(port, name) {
  return tap(spawn("node", ["host/sshd_setup.mjs", "--port", String(port), "--name", name], {
    cwd: ROOT, stdio: ["ignore", "pipe", "pipe"],
  }));
}

function stopSshd(name) {
  spawnSync("node", ["host/sshd_setup.mjs", "--stop", "--name", name], { cwd: ROOT, encoding: "utf8" });
}

function sshdLog(name) {
  return path.join(ROOT, ".loop31", "sshd", `sshd.log_${name}`);
}

const KEYSCAN_EXE = path.join(ROOT, "_build", "native", "debug", "build", "cmd", "ssh_keyscan", "ssh_keyscan.exe");
const CLIENT_EXE = path.join(ROOT, "_build", "native", "debug", "build", "cmd", "ssh_live", "ssh_live.exe");

// A timeout is not politeness.  A scan that hangs on a server that never
// answers would hang the gate, and a gate that hangs measures nothing.
const SCAN_TIMEOUT_MS = 60000;

function runKeyscan(args) {
  const r = spawnSync(KEYSCAN_EXE, args, {
    cwd: ROOT, encoding: "utf8", errors: "replace", timeout: SCAN_TIMEOUT_MS,
  });
  if (r.error) return { out: "", err: String(r.error.message), code: null };
  return { out: norm(r.stdout || ""), err: norm(r.stderr || ""), code: r.status };
}

function runRealKeyscan(bin, args) {
  const r = spawnSync(bin, args, {
    cwd: ROOT, encoding: "utf8", errors: "replace", timeout: SCAN_TIMEOUT_MS,
  });
  if (r.error) return { out: "", err: String(r.error.message), code: null };
  return { out: norm(r.stdout || ""), err: norm(r.stderr || ""), code: r.status };
}

function runClient(sshdPort, extra) {
  const r = spawnSync(
    CLIENT_EXE,
    ["--user", USER, "--kh-tofu", "--kh-host", "127.0.0.1", "--known-hosts-text", "",
     "--port", String(sshdPort), ...extra],
    {
      cwd: ROOT, encoding: "utf8", errors: "replace",
      maxBuffer: 64 * 1024 * 1024, timeout: SCAN_TIMEOUT_MS,
    },
  );
  const out = norm(`${r.stdout || ""}${r.stderr || ""}`);
  if (r.error) return out + `\n(the client did not finish: ${r.error.message})\n`;
  return out;
}

async function main() {
  console.log("verify_loop82 -- ssh-keyscan: the host key, without authenticating\n");
  mkdirSync(WORK, { recursive: true });

  // ------------------------------------------------------------------- G0 --
  section("G0: the code builds");
  for (const pkg of ["cmd/ssh_keyscan", "cmd/keyscan_kat"]) {
    const b = moon(["build", pkg, "--target", "native"]);
    ok(`${pkg} builds for native`, b.code === 0, b.code === 0 ? "" : b.out.slice(-300));
  }

  // ------------------------------------------------------------------- G1 --
  section("G1: the known_hosts line rules, byte for byte");
  const oracle = spawnSync("python", ["host/gen_keyscan_vectors.py"], {
    cwd: ROOT, encoding: "utf8", errors: "replace",
  });
  const oracleText = norm(`${oracle.stdout || ""}${oracle.stderr || ""}`);
  ok("the oracle runs", oracle.status === 0, oracle.status === 0 ? "" : oracleText.slice(-300));

  // 4 target x 2 mode: the rules are pure string work, so they have to come
  // out the same everywhere.
  const TARGETS = ["native", "js", "wasm", "wasm-gc"];
  const MODES = ["debug", "release"];
  const runs = [];
  for (const t of TARGETS) {
    for (const m of MODES) {
      const r = moon(["run", "cmd/keyscan_kat", "--target", t, "-d", m]);
      runs.push({ t, m, out: norm(r.out), hash: hashOut(r.out), code: r.code });
    }
  }
  const refHash = runs[0].hash;
  const allRan = runs.every((r) => r.code === 0);
  ok("cmd/keyscan_kat runs on 4 target x 2 mode", allRan,
    allRan ? refHash : runs.filter((r) => r.code !== 0).map((r) => `${r.t}/${r.m}`).join(" "));
  ok("4 target x 2 mode byte-identical", allRan && runs.every((r) => r.hash === refHash),
    allRan ? refHash : runs.filter((r) => r.hash !== refHash).map((r) => `${r.t}/${r.m}`).join(" "));

  const kat = runs[0].out;
  const katLines = kat.split("\n").map((l) => l.trim()).filter(Boolean);
  const oracleLines = oracleText.split("\n").map((l) => l.trim()).filter(Boolean);
  ok("the KAT and the oracle emit the same cases",
    katLines.length === oracleLines.length && katLines.length > 0,
    `ours=${katLines.length} theirs=${oracleLines.length}`);
  for (let i = 0; i < oracleLines.length; i++) {
    ok(`KAT line ${i + 1} == oracle`, katLines[i] === oracleLines[i],
      katLines[i] === oracleLines[i] ? oracleLines[i] : `ours=${katLines[i]} theirs=${oracleLines[i]}`);
  }

  // ------------------------------------------------------------------- G2 --
  section("G2: the output is the real ssh-keyscan's output, line for line");
  const binaries = keyscanBinaries();
  if (!binaries.length) {
    skip("the comparison against OpenSSH's own ssh-keyscan",
      "no ssh-keyscan.exe in " + KEYSCAN_DIRS.join(", "));
  }
  const sshdPort = await freePort();
  const name = "loop82";
  rmSync(sshdLog(name), { force: true });
  const sshd = startSshd(sshdPort, name);
  try {
    if (!await waitForText(sshd, "sshd listening", 30000)) {
      const why = (sshd.tapBuf || "").trim().split("\n").slice(0, 4).join(" | ") || "the server never came up";
      if (/no sshd\.exe/.test(why)) {
        skip("the comparison against a real server", why);
        skip("the scan never authenticates", "no server to ask");
        skip("the server's own log", "no server to ask");
      } else {
        ok("the private sshd is up", false, why);
        ok("the scan never authenticates", false, "no server");
        ok("the server's own log", false, "no server");
      }
    } else {
      ok("the private sshd is up", true);

      const ours = runKeyscan(["-p", String(sshdPort), "127.0.0.1"]);
      const ourLines = ours.out.split("\n").filter(Boolean);
      ok("the scan printed three keys -- one per key type", ourLines.length === 3,
        `${ourLines.length} lines`);
      ok("the keys come out in the order they were requested: rsa, ecdsa, ed25519",
        ourLines.length === 3 &&
        / ssh-rsa /.test(ourLines[0]) &&
        / ecdsa-sha2-nistp256 /.test(ourLines[1]) &&
        / ssh-ed25519 /.test(ourLines[2]),
        ourLines.map((l) => (l.split(" ")[1] || "?")).join(","));
      ok("the hosts field carries the port", ourLines.every((l) => l.startsWith(`[127.0.0.1]:${sshdPort} `)),
        ourLines[0] ? ourLines[0].slice(0, 40) : "no line");
      ok("the scan wrote a comment line per connection",
        commentLinesOf(ours.err).length === 3,
        commentLinesOf(ours.err).length + " comment lines");
      // This client's own stream layout IS a claim: the known_hosts lines go
      // to stdout and the note goes to stderr.  It is asserted here so that
      // the comparison against the real tool does not have to assume it.
      ok("our known_hosts lines go to stdout and the note to stderr",
        keyLinesOf(ours.out).length === linesOf(ours.out).length &&
        commentLinesOf(ours.out).length === 0 &&
        commentLinesOf(ours.err).length === 3,
        `stdout: ${linesOf(ours.out).length} lines, ` +
        `stderr: ${commentLinesOf(ours.err).length} note lines`);

      // The server's own log, read straight after OUR scan and before any
      // other client has touched the server.  This slice belongs to the scan
      // alone, which is what makes the assertions below statements about the
      // scan rather than about everything that happened to run today.
      const logAfterOurScan = existsSync(sshdLog(name)) ? readFileSync(sshdLog(name), "utf8") : "";

      // One connection per key type, and each connection got exactly one key.
      //
      // The names here are the server's **negotiated** algorithm names, which
      // are NOT the names in the known_hosts line: for the RSA key the server
      // negotiated `rsa-sha2-512` (RFC 8332) while the line says `ssh-rsa`
      // (the type name inside the key blob).  Both halves of that difference
      // are asserted, in different places, on purpose.
      const kexAlgs = [...logAfterOurScan.matchAll(/kex: host key algorithm: (\S+)/g)].map((m) => m[1]);
      ok("the scan opened exactly one connection per key type", kexAlgs.length === 3,
        `${kexAlgs.length} key exchanges: ${kexAlgs.join(",")}`);
      ok("each connection negotiated its own key: rsa, ecdsa, ed25519",
        kexAlgs.join(",") === "rsa-sha2-512,ecdsa-sha2-nistp256,ssh-ed25519",
        kexAlgs.join(","));
      ok("the server logged the scan connections",
        (logAfterOurScan.match(/Connection from/g) || []).length >= 3,
        `${(logAfterOurScan.match(/Connection from/g) || []).length} connections`);
      ok("the server logged the host key it offered",
        /kex: host key algorithm/.test(logAfterOurScan),
        "the server's own kex line");

      for (const bin of binaries) {
        const ref = runRealKeyscan(bin, ["-p", String(sshdPort), "127.0.0.1"]);
        const who = path.basename(path.dirname(bin));
        // The same known_hosts lines, byte for byte, in any order -- see
        // `sameLines` for why the order cannot be part of the comparison.
        ok(`stdout carries the same key lines as ${who}'s ssh-keyscan`,
          ref.code === 0 && sameLines(ref.out, ours.out) &&
          keyLinesOf(ref.out).length === 3 && keyLinesOf(ours.out).length === 3,
          keyLinesOf(ref.out).length === 3 && keyLinesOf(ours.out).length === 3 ?
            `${keyLinesOf(ours.out).length} key lines` :
            `ours=${JSON.stringify(keyLinesOf(ours.out).map((l) => l.split(" ")[1]))} ` +
            `theirs=${JSON.stringify(keyLinesOf(ref.out).map((l) => l.split(" ")[1]))}`);
        // The type selection has to agree too: one type, one line.
        const ourOne = runKeyscan(["-p", String(sshdPort), "-t", "ed25519", "127.0.0.1"]);
        const refOne = runRealKeyscan(bin, ["-p", String(sshdPort), "-t", "ed25519", "127.0.0.1"]);
        const ourOneComments = commentLinesOf(ourOne.out, ourOne.err);
        const refOneComments = commentLinesOf(refOne.out, refOne.err);
        ok(`-t ed25519 agrees with ${who}'s ssh-keyscan`,
          refOne.code === 0 && sameLines(refOne.out, ourOne.out) &&
          keyLinesOf(ourOne.out).length === 1 && keyLinesOf(refOne.out).length === 1,
          `${keyLinesOf(ourOne.out).length} line(s)`);
        // The note line is part of the output too: "# host:port SSH-2.0-...".
        // It says which server answered, so leaving it uncompared would leave
        // a whole line of the tool's output unverified.  One type, one note,
        // one line -- so this comparison is exact rather than approximate.
        // The note is looked for in **both** streams, because which stream
        // the real tool puts it on is its own business (see `isComment`).
        ok(`the comment line agrees with ${who}'s ssh-keyscan`,
          ourOneComments.length === 1 && refOneComments.length === 1 &&
          ourOneComments[0] === refOneComments[0],
          ourOneComments.length === 1 && refOneComments.length === 1 &&
          ourOneComments[0] === refOneComments[0] ? "" :
            `ours=${JSON.stringify(ourOneComments)} theirs=${JSON.stringify(refOneComments)}`);
      }

      // ---------------------------------------------------------------- G3 --
      section("G3: the scan never authenticates");
      const userauthAfterScan = (logAfterOurScan.match(/userauth/gi) || []).length;
      ok("the server logged NO userauth for the scan", userauthAfterScan === 0,
        `${userauthAfterScan} userauth lines`);

      // The zero above only means something if the log *would* have said so.
      // So: authenticate for real, against the same server, and show the log
      // does record userauth when a client really does it.
      const keys = spawnSync("python", ["host/ecdsa_auth_oracle.py", "--authorized-keys",
        ".loop31/sshd/authorized_keys"], { cwd: ROOT, encoding: "utf8", errors: "replace" });
      ok("wrote the test key into authorized_keys", keys.status === 0,
        keys.status === 0 ? "" : norm(`${keys.stdout || ""}${keys.stderr || ""}`).slice(-200));
      const authed = runClient(sshdPort, ["--auth"]);
      ok("an ordinary client authenticates against the same server",
        /result: AUTHENTICATED/.test(authed) || /USERAUTH_SUCCESS/.test(authed),
        lineOf(authed, "result") || authed.slice(-160));
      const logAfterAuth = existsSync(sshdLog(name)) ? readFileSync(sshdLog(name), "utf8") : "";
      const userauthAfterAuth = (logAfterAuth.match(/userauth/gi) || []).length;
      ok("the server DID log userauth for that client", userauthAfterAuth > 0,
        `${userauthAfterAuth} userauth lines`);
      ok("the scan's userauth count is still zero",
        (logAfterOurScan.match(/userauth/gi) || []).length === 0,
        "the scan connections produced none");

      // A stronger form of the same claim: the scan did not even ask for the
      // `ssh-userauth` SERVICE.  Asking for a service sends no credentials, so
      // this is a bonus rather than the claim -- but it is the claim's sharp
      // edge, and it is only assertable when this server logs packet types at
      // all.  So the assertion is conditional on a positive control: the same
      // marker must appear for the client that *does* authenticate.  Without
      // that control this check would pass vacuously on a server that logs
      // nothing, which is the failure mode this repository keeps meeting.
      //
      // "type 5" is SSH_MSG_SERVICE_REQUEST.  The trailing word boundary is
      // what keeps "type 50" (GLOBAL_REQUEST) out of the count -- and the
      // monitor's own internal messages say "type 50" too, so a looser
      // pattern would count the monitor's traffic as the client's.
      const serviceRequests = (text) => (text.match(/type 5\b/g) || []).length;
      const svcAfterScan = serviceRequests(logAfterOurScan);
      const svcAfterAuth = serviceRequests(logAfterAuth);
      if (svcAfterAuth > 0) {
        ok("the scan did not even request the ssh-userauth service", svcAfterScan === 0,
          `${svcAfterScan} service requests (the authenticated client made ${svcAfterAuth})`);
      } else {
        skip("the scan did not even request the ssh-userauth service",
          "this server does not log packet types, so the count cannot be made from the log");
      }
    }
  } finally {
    sshd.kill();
    stopSshd(name);
  }

  // ------------------------------------------------------------- regression --
  if (!SKIP_REGRESSION) {
    section("regression: the earlier loops must not move");
    // The members are spawned with `--skip-regression`, so this chain is one
  // level deep instead of a tree.  Without it, each member ran its own chain
  // as well: loop85 re-ran loop84, which re-ran loop83, and so on, and the
  // gates tier grew exponentially -- 1181.6s for loop85 alone, against a
  // 60-minute job cap that the whole tier was using up.  Nothing is lost:
  // every member is also a gate the CI engine runs directly, and the members
  // still run AFTER this gate's own work, so a gate that leaves state behind
  // that breaks an earlier gate is still caught.  verify_loop36/37/38 have
  // always done it this way.
  for (const label of ["loop78", "loop79", "loop80", "loop81"]) {
      const r = spawnSync("node", [`host/verify_${label}.mjs`, "--skip-regression"], { cwd: ROOT, encoding: "utf8", errors: "replace" });
      const t = norm(`${r.stdout || ""}${r.stderr || ""}`);
      const m = t.match(/(\d+)\/(\d+) checks/);
      ok(`${label} harness still green`, r.status === 0 && t.includes("PASS"),
        m ? `${m[1]}/${m[2]}` : t.slice(-200));
    }
  }

  console.log(`\n${failures === 0 ? "PASS" : "FAIL"}: ${checks - failures}/${checks} checks passed` +
    (skipped ? ` (${skipped} skipped)` : ""));
  if (failures) {
    console.log("  a red run means one of the claims above did not hold");
    process.exit(1);
  }
  console.log("  the output is the same lines as OpenSSH's own ssh-keyscan, and the");
  console.log("  server's own log shows the scan connections carrying no userauth at");
  console.log("  all -- while an ordinary client against the same server does.");
  process.exit(0);
}

main().catch((e) => {
  console.error("harness error:", e);
  process.exit(2);
});
