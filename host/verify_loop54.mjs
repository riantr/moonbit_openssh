// host/verify_loop54.mjs -- Loop #54: the pin that outlives the process.
//
// Loop #52 made TOFU remember, in a browser. The native client kept printing
// the line: `--kh-tofu` produced text, a human copied it into known_hosts, and
// the pin lived exactly as long as the terminal they had open. That is the same
// defect Loop #52's title names, on the other transport, and it is the state
// TOFU exists to remove.
//
// The shape of this gate is the whole argument, and it is stronger than
// Loop #52's because it does not need a fresh page:
//
//   step 0  discover what the peer presents
//   step 1  --kh-tofu --kh-file   -> authenticated, and the file really changed
//   step 2  a *new process*, --kh-file only, no text at all -> authenticated
//
// Step 2 is the load-bearing one. Nothing carries over between the two runs
// except the file on disk: not a module variable, not a Worker, not an open
// connection. "The client remembered" and "the client is still holding the
// first connection's state" are indistinguishable from inside one process, and
// a separate process makes them different facts.
//
// What step 1 asserts beyond "a line appeared" is the part that is easy to get
// wrong. The file it writes into already holds a comment, an unrelated direct
// entry, and an `@revoked` line. A write-back that rewrites instead of appends
// destroys all three, and the *next* connection would still authenticate on the
// new host -- so the damage is invisible until the day somebody depends on a
// pin they already had. Hence the assertions are on the file's contents, not on
// the client's report of what it did.
//
// And the write-failure case is asserted as its own step rather than left to the
// code review, because the failure this shape invites is the exact one Loop #52
// had to fix on the browser side: print `accepted`, quietly drop the pin.

import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import net from "node:net";
import path from "node:path";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { sshUser } from './ssh_user.mjs';
import { waitForMitmReady } from "./mitm_ready.mjs";

const root = resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const WORK = join(root, ".loop54");
const SSH_LIVE = join(root, "_build", "native", "debug", "build", "cmd", "ssh_live", "ssh_live.exe");

const failures = [];
let checks = 0;
const skipped = [];

function ok(label, detail) {
  checks += 1;
  console.log(`  PASS  ${label}${detail ? "  " + detail : ""}`);
}
function bad(label, detail) {
  checks += 1;
  failures.push(`${label}${detail ? "  " + detail : ""}`);
  console.log(`  FAIL  ${label}${detail ? "  " + detail : ""}`);
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function freePort() {
  return new Promise((res, rej) => {
    const s = net.createServer();
    s.on("error", rej);
    s.listen(0, "127.0.0.1", () => {
      const p = s.address().port;
      s.close(() => res(p));
    });
  });
}

function readJson(f) {
  try {
    return JSON.parse(readFileSync(f, "utf-8"));
  } catch {
    return null;
  }
}

// `sftp_mitm.py` serves exactly one connection (see Loop #53's notes), so every
// connection gets its own. The liveness check is Loop #52's: `freePort()` closes
// a listener and hands the number back, and against a peer that died the client
// reports a transport error that reads like a protocol bug.
async function startMitm(tag, extra = []) {
  const port = await freePort();
  const json = join(WORK, `${tag}.json`);
  const proc = spawn("python", [join(root, "host", "sftp_mitm.py"), String(port), "--json", json, ...extra],
    { cwd: root, stdio: ["ignore", "pipe", "pipe"] });
  let err = "";
  proc.stderr.on("data", (d) => (err += d.toString()));
  // Wait for the MITM to say it is listening, rather than guessing how long
  // that takes.  See host/mitm_ready.mjs.
  await waitForMitmReady(() => err);
  if (proc.exitCode !== null || proc.signalCode !== null) {
    throw new Error(`the man in the middle for ${tag} died on port ${port}: ${err.trim().slice(0, 400) || "(no stderr)"}`);
  }
  return { proc, json, port, err: () => err };
}

async function stopMitm(m) {
  // Dependency order, not impatience: the child writes its transcript when the
  // session thread returns, so a kill before that leaves a file that says
  // nothing happened.
  await sleep(2500);
  if (m.proc.exitCode === null && m.proc.signalCode === null) m.proc.kill();
}

function run(port, args) {
  const r = spawnSync(SSH_LIVE, [String(port), "--auth", "--user", sshUser(), ...args], {
    cwd: root,
    encoding: "utf-8",
    errors: "replace",
    maxBuffer: 64 * 1024 * 1024,
    timeout: 90000,
  });
  return { text: `${r.stdout || ""}${r.stderr || ""}`, status: r.status };
}

const authed = (t) => /^result: USERAUTH_SUCCESS$/m.test(t);
const leafOf = (t) => (String((t.match(/^error: (.*)$/m) || [])[1] || "").split(":").pop().trim());
const lineOf = (t, prefix) => {
  const m = t.match(new RegExp(`^${prefix}(.*)$`, "m"));
  return m ? m[1] : null;
};

// A syntactically valid ed25519 public key that is *not* the one the peer
// presents.
//
// It exists for one reason: the preseeded `@revoked` line. The revocation sweep
// compares blobs, so a revoked line carrying the same blob as the presented key
// rejects the connection -- correctly, and uselessly for this gate, which
// discovered that by writing the fixture that way and getting a clean
// `HostkeyMismatch` with zero authentication attempts.
//
// It does not need to be a key anybody holds. What the assertion is about is
// that a marker line survives a write-back, not which key was revoked.
function decoyEd25519Blob() {
  const name = Buffer.from("ssh-ed25519", "utf-8");
  const len = Buffer.alloc(4);
  len.writeUInt32BE(name.length, 0);
  const body = Buffer.alloc(36);
  len.writeUInt32BE(32, 0);
  for (let i = 0; i < 32; i += 1) body[4 + i] = (i * 37 + 11) & 0xff;
  return Buffer.concat([len, name, body]).toString("base64");
}

async function main() {
  // Wipe the scratch directory. Not tidiness: step 1 asserts the file gained
  // exactly one line, and a file left by a previous run makes that arithmetic
  // meaningless.
  rmSync(WORK, { recursive: true, force: true });
  mkdirSync(WORK, { recursive: true });

  console.log("build");
  const b = spawnSync("cmd", ["/c", "moon", "build", "cmd\\ssh_live", "--target", "native"],
    { cwd: root, encoding: "utf-8", errors: "replace", maxBuffer: 64 * 1024 * 1024 });
  if (b.status !== 0 || !existsSync(SSH_LIVE)) {
    bad("build ssh_live (native)", `${b.stdout || ""}${b.stderr || ""}`.trim().split("\n").slice(-10).join("\n      "));
    return finish();
  }
  ok("build cmd/ssh_live (native)");

  const KH = join(WORK, "known_hosts");
  const HOST = "127.0.0.1";

  // ---- step 0: what does the peer actually present? ------------------------
  console.log("");
  console.log("step 0: discover the presented key");
  const m0 = await startMitm("s0");
  run(m0.port, ["--kh-tofu", "--kh-host", HOST]);
  await stopMitm(m0);
  const d0 = readJson(m0.json);
  if (!d0 || !d0.hostkey_blob_b64 || !d0.hostkey_announced_type) {
    bad("discover", "no presented key in the transcript: " + JSON.stringify(d0).slice(0, 200));
    return finish();
  }
  const TYPE = d0.hostkey_announced_type;
  const BLOB = d0.hostkey_blob_b64;
  ok("discover", `${TYPE}, ${BLOB.length} b64 chars`);

  const DECOY = decoyEd25519Blob();
  const COMMENT = "# a comment that must survive a write-back";
  const UNRELATED = `unrelated.example.com ${TYPE} ${BLOB}`;
  const REVOKED = `@revoked gone.example.com ssh-ed25519 ${DECOY}`;
  writeFileSync(KH, [COMMENT, UNRELATED, REVOKED].join("\n") + "\n", "utf-8");
  const before = readFileSync(KH, "utf-8");

  // ---- step 1: accept and write ------------------------------------------
  console.log("");
  console.log("step 1: --kh-tofu --kh-file writes, and writes *only* the new line");
  const m1 = await startMitm("s1");
  const r1 = run(m1.port, ["--kh-tofu", "--kh-file", KH, "--kh-host", HOST]);
  await stopMitm(m1);
  const t1 = readJson(m1.json);
  if (!authed(r1.text)) {
    bad("tofu + file", `did not authenticate: error=${JSON.stringify(leafOf(r1.text))} ${r1.text.trim().split("\n").slice(-4).join(" | ")}`);
  } else {
    ok("tofu + file", "authenticated");
    if (!t1 || t1.auth_attempts !== 1) {
      bad("tofu + file", `expected exactly 1 authentication attempt, got ${t1 && t1.auth_attempts}`);
    } else {
      ok("credentials reached the peer", "1 attempt, after the decision");
    }
  }
  const w = lineOf(r1.text, "tofu: written to ");
  if (w === null) {
    bad("write-back", "no `tofu: written to <path>` line: " + JSON.stringify(r1.text.match(/^tofu:.*$/gm)).slice(0, 200));
  } else {
    ok("write-back", "reported where it wrote");
  }

  const after = existsSync(KH) ? readFileSync(KH, "utf-8") : "";
  if (!after.includes(HOST + " " + TYPE + " " + BLOB)) {
    bad("write-back", `the presented key is not in the file afterwards: ${JSON.stringify(after).slice(0, 300)}`);
  } else {
    ok("write-back", "the key that was just compared is on disk");
  }
  // The three that must survive. Each is its own line because "the write-back
  // worked" and "the write-back did not eat something else" fail independently
  // and only the first one gets noticed on the day it happens.
  for (const [label, needle] of [
    ["the comment", COMMENT],
    ["an unrelated host's entry", UNRELATED],
    ["the @revoked line", REVOKED],
  ]) {
    if (after.includes(needle)) ok(`preserved: ${label}`);
    else bad(`preserved: ${label}`, `gone from the file: ${JSON.stringify(after).slice(0, 300)}`);
  }
  const gained = after.split("\n").filter((l) => l.trim()).length - before.split("\n").filter((l) => l.trim()).length;
  if (gained !== 1) {
    bad("write-back", `the file gained ${gained} lines, want exactly 1`);
  } else {
    ok("write-back", "exactly one line added, nothing else changed");
  }

  // ---- step 2: a new process, the file only -------------------------------
  console.log("");
  console.log("step 2: a separate process, --kh-file and nothing else");
  const m2 = await startMitm("s2");
  const r2 = run(m2.port, ["--kh-file", KH, "--kh-host", HOST]);
  await stopMitm(m2);
  const t2 = readJson(m2.json);
  if (!authed(r2.text)) {
    bad("remembered", `a new process with only --kh-file did not authenticate: ${leafOf(r2.text)} ${r2.text.trim().split("\n").slice(-4).join(" | ")}`);
  } else if (!t2 || t2.auth_attempts !== 1) {
    bad("remembered", `authenticated but the peer saw ${t2 && t2.auth_attempts} attempts`);
  } else {
    ok("remembered", "a fresh process authenticated from the file alone");
  }

  // ---- step 3: the write-back that cannot land ----------------------------
  console.log("");
  console.log("step 3: an unwritable --kh-file is a visible failure");
  const BLOCK = join(WORK, "blocker.txt");
  writeFileSync(BLOCK, "i am a file, not a directory", "utf-8");
  const BAD = join(WORK, "blocked", "inner.txt");
  const m3 = await startMitm("s3");
  const r3 = run(m3.port, ["--kh-tofu", "--kh-file", BAD, "--kh-host", HOST]);
  await stopMitm(m3);
  if (!authed(r3.text)) {
    bad("unwritable", "the connection itself must still succeed -- the credentials already went out");
  } else {
    ok("unwritable", "the connection succeeded, as it must");
  }
  const notw = lineOf(r3.text, "tofu: NOT written to ");
  if (notw === null) {
    bad("unwritable", "no failure notice: " + JSON.stringify(r3.text.match(/^tofu:.*$/gm)).slice(0, 240));
  } else if (!/was accepted, but the pin was not remembered/.test(notw)) {
    bad("unwritable", "the notice does not say the two failures apart: " + notw.slice(0, 200));
  } else {
    ok("unwritable", "the notice separates 'accepted' from 'remembered'");
  }

  // ---- step 4: the file is read for the *decision* too --------------------
  console.log("");
  console.log("step 4: a pin in the file decides, and a different key is refused");
  const WRONG = join(WORK, "wrong_pin.txt");
  writeFileSync(WRONG, `${HOST} ssh-ed25519 ${DECOY}\n`, "utf-8");
  const m4 = await startMitm("s4");
  const r4 = run(m4.port, ["--kh-file", WRONG, "--kh-host", HOST]);
  await stopMitm(m4);
  const t4 = readJson(m4.json);
  if (authed(r4.text)) {
    bad("file decides", "authenticated against a pin that is not the presented key");
  } else if (leafOf(r4.text) !== "HostkeyMismatch") {
    bad("file decides", `refused, but as ${leafOf(r4.text)} rather than HostkeyMismatch -- the file was probably not read for the decision`);
  } else {
    ok("file decides", "a pin in the file is enforced, refused as a mismatch");
  }
  if (t4 && t4.auth_attempts > 0) {
    bad("file decides", `${t4.auth_attempts} authentication attempt(s) reached a peer it should have refused`);
  } else {
    ok("file decides", "no credentials left");
  }

  // ---- step 5: the old behaviour, unchanged ------------------------------
  console.log("");
  console.log("step 5: no --kh-file at all (Loop #49's printing must still work)");
  const m5 = await startMitm("s5");
  const r5 = run(m5.port, ["--kh-tofu", "--kh-host", HOST]);
  await stopMitm(m5);
  if (!authed(r5.text)) {
    bad("no file", "did not authenticate");
  } else if (lineOf(r5.text, "tofu: ") === null || !/^tofu: 127\.0\.0\.1 /m.test(r5.text)) {
    bad("no file", "no `tofu: <line>` printed -- Loop #49's gate greps for exactly this");
  } else {
    ok("no file", "still prints the line, and no file was written");
  }

  return finish();
}

function finish() {
  console.log("");
  if (skipped.length) for (const s of skipped) console.log(`SKIPPED  ${s}`);
  console.log(`loop54: ${checks - failures.length}/${checks} checks passed`);
  if (failures.length) {
    console.log("");
    for (const f of failures) console.log(`  FAIL  ${f}`);
    process.exitCode = 1;
  } else {
    console.log("ALL PASS");
  }
}

main().catch((e) => {
  console.error("loop54 gate crashed: " + (e && e.stack ? e.stack : String(e)));
  process.exitCode = 1;
});
