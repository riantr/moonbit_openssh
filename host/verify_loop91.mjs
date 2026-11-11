// host/verify_loop91.mjs -- scp over SSH, and the key file it signs with.
//
// Loop #90 gated `scp` for everything measurable without credentials: the
// `-D` bed (a spawned `sftp-server.exe`) plus the argument surface, 41/41,
// and it declared two gaps rather than hiding them.  One of them was the
// SSH leg, because a real `scp` signs with a private key FILE and
// `src/keyfile` could read only ed25519.
//
// Loop #91 closed it, in two parts, and this gate is shaped like the parts:
//
//   A. the key file, against `ssh-keygen` -- three curves, a scalar whose
//      top bit is set, and the refusals;
//   B. `scp` over a real sshd, against the real `scp.exe` -- the four
//      transfer shapes, comparing exit status, stdout, stderr BYTES and
//      the resulting trees;
//   C. the refusals that stay refusals.
//
// ## What the far end is
//
// A private `sshd` on a port of this gate's own, started through
// `host/sshd_setup.mjs` -- the same server eleven other gates use, with
// `Subsystem sftp internal-sftp` and an `authorized_keys` this file writes.
// So the far end of section B is the SERVER's own SFTP implementation, not
// a `sftp-server.exe` this repository spawned: that is exactly the
// difference Loop #90's `-D` bed could not cover.
//
// ## The remote paths are absolute, and that is measured
//
// The bed's remote side is a directory on THIS machine (the sshd serves the
// local filesystem), so a relative remote path would resolve against the
// login user's home directory -- `/C:/Users/<user>` -- and the gate would be
// writing outside its own bed.  The absolute form `/E:/.../remote/x` works
// with both tools; measured before this file was written, because the whole
// bed layout depends on it.
//
// ## The two normalisations, unchanged from Loop #90
//
// `argv[0]` becomes `PROG` (the two tools have different names and the
// sentence is otherwise the same), and an mtime within 600s of now becomes
// `NOW` (only `-p` passes an explicit time, and that one is compared
// exactly).
//
// Run: node host/verify_loop91.mjs

import { spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import net from "node:net";
import crypto from "node:crypto";

const ROOT = path.resolve(
  new URL("..", import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1"),
);
// Where the real OpenSSH client might be.
//
// Two installations exist on Windows and they are not the same thing: the
// portable Win32-OpenSSH build under Program Files, and the inbox optional
// feature under System32.  Neither is on PATH by default.
//
// machine-path-exempt: each entry below is a CANDIDATE, probed in order until
// one exists; none is asserted to exist on any machine.  The inbox one comes
// first because that is the client this gate's comparisons were measured
// against, so a machine with both reports the same thing the measurement did.
const SCP_CANDIDATES = [
  "C:\\Windows\\System32\\OpenSSH\\scp.exe",
  "C:\\Program Files\\OpenSSH-Win64\\scp.exe",
  "C:\\Program Files\\OpenSSH\\scp.exe",
];
const REAL_SCP = SCP_CANDIDATES.find((p) => fs.existsSync(p)) || null;
const BED = path.join(ROOT, ".loop91", "gate91");
// The server and the known_hosts file live OUTSIDE the bed, and that is not
// tidiness: `fresh()` wipes the bed before every case, so anything the
// running server needs -- host keys, its config, `authorized_keys` -- would
// be deleted between two cases.  The first version of this file put them
// inside, and every comparison failed with
// `kex_exchange_identification: read: Connection reset`, which reads like a
// protocol problem and was a deleted host key.
const STATE = path.join(ROOT, ".loop91", "state91");
const SSHD_DIR = path.join(STATE, "sshd");
const FIXTURES = path.join(ROOT, ".loop91");
const NAME = "gate91";
const NOW_WINDOW = 600;
const USER = process.env.USERNAME || "";

const OUR_SCP = path.join(
  ROOT, "_build", "native", "debug", "build", "cmd", "scp", "scp.exe",
);
const OUR_KEYGEN = path.join(
  ROOT, "_build", "native", "debug", "build", "cmd", "ssh_keygen",
  "ssh_keygen.exe",
);

let passed = 0;
let failed = 0;
const failures = [];

function ok(name, cond, detail = "") {
  if (cond) {
    passed += 1;
    console.log(`  PASS  ${name}${detail ? "  " + detail : ""}`);
  } else {
    failed += 1;
    failures.push(name);
    console.log(`  FAIL  ${name}`);
    if (detail) {
      for (const line of String(detail).split("\n").slice(0, 40)) {
        console.log(`          ${line}`);
      }
    }
  }
}

// ---------------------------------------------------------------- the bed

// The remote side of the bed, spelled the way an sftp server sees it:
// this machine's `E:` drive at `/E:/`.
function remoteOf(rel) {
  const abs = path.join(BED, "remote", rel);
  return "/" + abs.split(path.sep).join("/");
}

function fresh() {
  fs.rmSync(BED, { recursive: true, force: true });
  fs.mkdirSync(path.join(BED, "local"), { recursive: true });
  fs.mkdirSync(path.join(BED, "remote"), { recursive: true });
}

function mk(rel, data, mtime = null) {
  const p = path.join(BED, rel.split("/").join(path.sep));
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, data);
  const stamp = mtime === null ? 1200000000 + data.length : mtime;
  fs.utimesSync(p, stamp, stamp);
}

function stamp(mtime) {
  return Math.abs(mtime - Date.now() / 1000) < NOW_WINDOW ? "NOW" : mtime;
}

function tree() {
  const out = [];
  for (const side of ["local", "remote"]) {
    const base = path.join(BED, side);
    const walk = (dir) => {
      let entries;
      try {
        entries = fs.readdirSync(dir, { withFileTypes: true });
      } catch {
        return;
      }
      for (const e of entries.sort((a, b) => a.name.localeCompare(b.name))) {
        const p = path.join(dir, e.name);
        if (e.isDirectory()) {
          out.push({
            side,
            path: path.relative(base, p).split(path.sep).join("/") + "/",
            dir: true,
            mtime: stamp(Math.floor(fs.statSync(p).mtimeMs / 1000)),
          });
          walk(p);
        } else {
          const data = fs.readFileSync(p);
          out.push({
            side,
            path: path.relative(base, p).split(path.sep).join("/"),
            size: data.length,
            mtime: stamp(Math.floor(fs.statSync(p).mtimeMs / 1000)),
            sha: crypto.createHash("sha256").update(data).digest("hex").slice(0, 12),
          });
        }
      }
    };
    walk(base);
  }
  return out.sort((a, b) =>
    a.side === b.side ? a.path.localeCompare(b.path) : a.side.localeCompare(b.side));
}

function runOne(prog, args) {
  const r = spawnSync(prog, args, {
    cwd: BED,
    timeout: 180000,
    stdio: ["ignore", "pipe", "pipe"],
  });
  const err = r.stderr === null ? Buffer.alloc(0) : r.stderr;
  const out = r.stdout === null ? Buffer.alloc(0) : r.stdout;
  const progBytes = Buffer.from(prog);
  const latin = (b) =>
    Buffer.from(
      b.toString("latin1").split(progBytes.toString("latin1")).join("PROG"),
      "latin1",
    );
  return { rc: r.status, out: latin(out), err: latin(err), tree: tree() };
}

function brief(buf) {
  return JSON.stringify(buf.toString("latin1"));
}

// --------------------------------------------------------------- the sshd

const knownHosts = path.join(STATE, "known_hosts");

// Both sides get the SAME options, so the comparison is about behaviour and
// not about which tool was told to be quiet.  Our `scp` parses `-o` and does
// not act on it (it skips host key checking outright, a declared gap); the
// real one needs them or it stops at a prompt.
function sshOpts() {
  return [
    "-o", "StrictHostKeyChecking=no",
    "-o", `UserKnownHostsFile=${knownHosts}`,
    "-o", "BatchMode=yes",
    "-o", "LogLevel=ERROR",
  ];
}

let sshdChild = null;

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

function startSshd(port) {
  const child = spawn(
    "node",
    ["host/sshd_setup.mjs", "--port", String(port), "--name", NAME, "--dir", SSHD_DIR],
    { cwd: ROOT, stdio: ["ignore", "pipe", "pipe"] },
  );
  child.tapBuf = "";
  for (const stream of [child.stdout, child.stderr]) {
    if (stream) stream.on("data", (d) => { child.tapBuf += d.toString(); });
  }
  return child;
}

async function waitForText(child, needle, timeoutMs = 40000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if ((child.tapBuf || "").includes(needle)) return true;
    await new Promise((r) => setTimeout(r, 120));
  }
  console.log(`      (never saw "${needle}"; saw: ${(child.tapBuf || "").trim().slice(0, 400)})`);
  return false;
}

function stopSshd() {
  spawnSync(
    "node",
    ["host/sshd_setup.mjs", "--stop", "--name", NAME, "--dir", SSHD_DIR],
    { cwd: ROOT, encoding: "utf8" },
  );
  if (sshdChild && sshdChild.pid) {
    try { sshdChild.kill(); } catch { /* already gone */ }
  }
}

// ------------------------------------------------------------- the driver

function moon(args, timeout = 900000) {
  const r = spawnSync("cmd", ["/c", "moon", ...args], {
    cwd: ROOT, encoding: "utf8", timeout,
  });
  return { code: r.status, out: `${r.stdout || ""}${r.stderr || ""}` };
}

// --------------------------------------------------------- A. the key file

// The four fixtures, and what each one is for.  Three of the four exist
// because a reader can pass the first and fail the others:
//
//   k256         the ordinary case
//   k384         a 49-byte `d` with a leading 00 -- the mpint trap
//   k521         a 66-byte `d` starting 01, and NO padding at all
//   mpint/k0     a P-256 scalar above 2^255: the trap in the curve
//                everybody writes the fixed width for
const KEY_CASES = [
  ["k256", "P-256, ordinary"],
  ["k384", "P-384, 49-byte mpint scalar"],
  ["k521", "P-521, 66-byte scalar and empty padding"],
  ["mpint/k0", "P-256 with the top bit set"],
];

function sectionA() {
  console.log("\nA. the key file, against ssh-keygen");

  // `-y` prints the public line of a private file.  Ours must be the same
  // bytes: exit status, stdout, nothing on stderr.
  for (const [rel, why] of KEY_CASES) {
    const key = path.join(FIXTURES, rel.split("/").join(path.sep));
    if (!fs.existsSync(key)) {
      ok(`fixture ${rel} exists`, false, `missing ${key}`);
      continue;
    }
    const real = spawnSync("ssh-keygen", ["-y", "-f", key], { encoding: "buffer" });
    const mine = spawnSync(OUR_KEYGEN, ["-y", "-f", key], { encoding: "buffer" });
    const sameExit = real.status === mine.status;
    const sameOut = Buffer.compare(real.stdout, mine.stdout) === 0;
    ok(
      `-y ${rel} (${why}) is byte for byte ssh-keygen's`,
      sameExit && sameOut && real.stdout.length > 0,
      sameExit && sameOut
        ? `${real.stdout.length} bytes`
        : `exit ${real.status}/${mine.status} real=${brief(real.stdout)} ours=${brief(mine.stdout)}`,
    );
  }

  // An encrypted key read without a passphrase: our own sentence, and a
  // refusal.  `ssh-keygen -y` would stop at a prompt, so there is nothing
  // to compare here -- and this is section A's only non-comparative check,
  // which is why it asserts the exit status too.
  const enc = path.join(FIXTURES, "enc");
  if (fs.existsSync(enc)) {
    const mine = spawnSync(OUR_KEYGEN, ["-y", "-f", enc], { encoding: "buffer" });
    const err = mine.stderr.toString("latin1").toLowerCase();
    ok(
      "an encrypted key is refused, and says it is encrypted",
      mine.status !== 0 && err.includes("encrypted"),
      `exit=${mine.status} stderr=${brief(mine.stderr).slice(0, 200)}`,
    );
  }

  // A file that is not a key at all.
  const junk = path.join(BED, "junk.txt");
  fs.writeFileSync(junk, "this is not a key file\n");
  const mine = spawnSync(OUR_KEYGEN, ["-y", "-f", junk], { encoding: "buffer" });
  ok(
    "a file that is not a key is refused",
    mine.status !== 0 && mine.stderr.length > 0,
    `exit=${mine.status} stderr=${brief(mine.stderr).slice(0, 200)}`,
  );
}

// --------------------------------------------------- B. scp over the sshd

function scpArgs(port, extra, src, dst, key = null) {
  return [...sshOpts(), "-i", key === null ? path.join(FIXTURES, "k256") : key,
    "-P", String(port), ...extra, src, dst];
}

function compare(label, port, extra, srcFn, dstFn, setup, expectSide, key = null) {
  const argsFor = () => scpArgs(port, extra, srcFn(), dstFn(), key);
  fresh();
  setup();
  const real = runOne(REAL_SCP, argsFor());
  fresh();
  setup();
  const mine = runOne(OUR_SCP, argsFor());
  const diffs = [];
  if (real.rc !== mine.rc) diffs.push(`exit ${real.rc} != ${mine.rc}`);
  if (!real.err.equals(mine.err)) {
    diffs.push(`stderr real ${brief(real.err)}`);
    diffs.push(`stderr ours ${brief(mine.err)}`);
  }
  if (!real.out.equals(mine.out)) {
    diffs.push(`stdout real ${brief(real.out)}`);
    diffs.push(`stdout ours ${brief(mine.out)}`);
  }
  if (JSON.stringify(real.tree) !== JSON.stringify(mine.tree)) {
    diffs.push(`tree real ${JSON.stringify(real.tree)}`);
    diffs.push(`tree ours ${JSON.stringify(mine.tree)}`);
  }
  // Non-vacuity: the case has to have moved the bytes it claims to move.
  const meaningful = real.tree.some((e) => `${e.side}/${e.path}` === expectSide);
  if (!meaningful) diffs.push(`the real run never produced ${expectSide}`);
  ok(label, diffs.length === 0, diffs.join("\n"));
}

async function main() {
  console.log("=== Loop #91: scp over SSH, and the key file behind it ===");
  if (!REAL_SCP) {
    // A loud failure naming every place that was looked at.  Without this the
    // symptom is an ENOENT from deep inside spawnSync, which reads as a bug in
    // this file rather than as "this machine has no OpenSSH client".
    console.log("no scp.exe found in any of:");
    for (const p of SCP_CANDIDATES) console.log(`  ${p}`);
    process.exit(3);
  }
  console.log(`real scp: ${REAL_SCP}`);
  if (!USER) {
    console.log("no USERNAME in the environment: this gate needs a login name");
    process.exit(1);
  }
  console.log(`user: ${USER}`);

  // Build both drivers.  A stale binary would make every case below
  // measure last week's code.
  console.log("\nbuilding cmd/scp and cmd/ssh_keygen (native)");
  for (const pkg of ["cmd/scp", "cmd/ssh_keygen"]) {
    const r = moon(["build", "--target", "native", pkg]);
    if (r.code !== 0) {
      console.log(`  FAIL  ${pkg} does not build\n${r.out.slice(-3000)}`);
      process.exit(1);
    }
  }
  ok("both drivers built", fs.existsSync(OUR_SCP) && fs.existsSync(OUR_KEYGEN));

  fs.mkdirSync(BED, { recursive: true });
  // A stale known_hosts from a previous run would carry a host key that no
  // longer matches this run's server, and the real tool would stop at a
  // "REMOTE HOST IDENTIFICATION HAS CHANGED" warning -- which is a correct
  // thing to print and a useless thing to compare.
  fs.mkdirSync(STATE, { recursive: true });
  fs.rmSync(knownHosts, { force: true });

  sectionA();

  // The bed's host keys and an empty authorized_keys, then OUR key written
  // into it.  `--keys-only` exists for exactly this: generate, do not serve.
  console.log("\npreparing the sshd bed");
  const keysOnly = spawnSync(
    "node",
    ["host/sshd_setup.mjs", "--keys-only", "--dir", SSHD_DIR],
    { cwd: ROOT, encoding: "utf8" },
  );
  ok("sshd_setup --keys-only exits 0", keysOnly.status === 0,
    (keysOnly.stdout || "").trim().split("\n").slice(-1)[0] || "");
  const authKeys = path.join(SSHD_DIR, "authorized_keys");
  // Three keys are authorized, and each one is a different trap: the
  // ordinary P-256 key, the P-256 key whose scalar needs an mpint zero, and
  // the P-384 key.  A key that is NOT authorized is needed too (section C),
  // so one is generated here and left out on purpose.
  const lines = ["k256.pub", "mpint/k0.pub", "k384.pub"]
    .map((f) => fs.readFileSync(path.join(FIXTURES, f.split("/").join(path.sep)), "utf8").trimEnd())
    .join("\n");
  fs.writeFileSync(authKeys, lines + "\n");
  ok("authorized_keys holds the three fixture keys",
    (fs.readFileSync(authKeys, "utf8").match(/ecdsa-sha2-nistp/g) || []).length === 3);

  const port = await freePort();
  console.log(`\nstarting sshd on 127.0.0.1:${port} (dir ${SSHD_DIR})`);
  sshdChild = startSshd(port);
  const up = await waitForText(sshdChild, "sshd listening");
  ok("the sshd bed is listening", up);
  if (!up) {
    stopSshd();
    return summary();
  }

  // Warm the known_hosts file with ONE real run, so that the real tool's
  // "Permanently added ..." warning is not part of every comparison.  Ours
  // never prints it (it does not read known_hosts at all), so without this
  // the first real case would differ for a reason that is not behaviour.
  console.log("\nB. scp over sshd, against the real scp.exe");
  fresh();
  mk("local/warm.txt", "warm\n");
  const warm = spawnSync(REAL_SCP,
    scpArgs(port, [], "local/warm.txt", `${USER}@127.0.0.1:${remoteOf("warm.txt")}`),
    { cwd: BED, timeout: 180000, stdio: ["ignore", "pipe", "pipe"] });
  ok("the warm-up run reached the server", warm.status === 0,
    `exit=${warm.status} err=${(warm.stderr || Buffer.alloc(0)).toString("latin1").slice(0, 200)}`);

  // 1. upload one file
  compare(
    "upload: one file to the host",
    port, [],
    () => "local/up.txt",
    () => `${USER}@127.0.0.1:${remoteOf("up.txt")}`,
    () => { mk("local/up.txt", "loop91 upload\n"); },
    "remote/up.txt",
  );

  // 2. download one file
  compare(
    "download: one file from the host",
    port, [],
    () => `${USER}@127.0.0.1:${remoteOf("down.txt")}`,
    () => "local/down.txt",
    () => { mk("remote/down.txt", "loop91 download\n"); },
    "local/down.txt",
  );

  // 3. recursive upload of a directory
  compare(
    "upload -r: a directory and its children",
    port, ["-r"],
    () => "local/tree",
    () => `${USER}@127.0.0.1:${remoteOf("tree")}`,
    () => {
      mk("local/tree/a.txt", "a\n");
      mk("local/tree/sub/b.txt", "bb\n");
      mk("local/tree/sub/deep/c.txt", "ccc\n");
    },
    "remote/tree/sub/deep/c.txt",
  );

  // 4. recursive download
  compare(
    "download -r: a directory and its children",
    port, ["-r"],
    () => `${USER}@127.0.0.1:${remoteOf("rtree")}`,
    () => "local/rtree",
    () => {
      mk("remote/rtree/a.txt", "a\n");
      mk("remote/rtree/sub/b.txt", "bb\n");
    },
    "local/rtree/sub/b.txt",
  );

  // 5. -p upload: the times must travel, and the gate compares them
  //    exactly because the bed sets them explicitly.
  compare(
    "upload -p: the times travel with the file",
    port, ["-p"],
    () => "local/stamped.txt",
    () => `${USER}@127.0.0.1:${remoteOf("stamped.txt")}`,
    () => { mk("local/stamped.txt", "stamped\n", 1300000000); },
    "remote/stamped.txt",
  );

  // 6. -p download
  compare(
    "download -p: the times travel back",
    port, ["-p"],
    () => `${USER}@127.0.0.1:${remoteOf("stamped2.txt")}`,
    () => "local/stamped2.txt",
    () => { mk("remote/stamped2.txt", "stamped2\n", 1310000000); },
    "local/stamped2.txt",
  );

  // 7. and 8. Two more kinds of key, doing a real copy.
  //
  // **These exist because the `-y` checks above cannot see the scalar.**
  // The public line is built from the POINT, so a reader that takes the
  // wrong 32 bytes out of the `d` field still prints the right line and
  // still passes every check in section A.  The only place a wrong scalar
  // is observable is in a signature -- the server verifies it and says no.
  // So a key whose scalar is the hard case signs a real copy here, and a
  // wrong scalar turns this red.
  //
  // Same argument for the curve: signing a P-384 key as P-256 produces a
  // key of the wrong type and the server refuses it, which is invisible to
  // section A for the same reason.
  compare(
    "upload signed with the top-bit-set (mpint) key",
    port, [], 
    () => "local/mpint.txt",
    () => `${USER}@127.0.0.1:${remoteOf("mpint.txt")}`,
    () => { mk("local/mpint.txt", "signed by a scalar above 2^255\n"); },
    "remote/mpint.txt",
    path.join(FIXTURES, "mpint", "k0"),
  );

  compare(
    "upload signed with the P-384 key",
    port, [],
    () => "local/p384.txt",
    () => `${USER}@127.0.0.1:${remoteOf("p384.txt")}`,
    () => { mk("local/p384.txt", "signed by a P-384 key\n"); },
    "remote/p384.txt",
    path.join(FIXTURES, "k384"),
  );

  // ------------------------------------------------------- C. the refusals
  //
  // These are OUR sentences, not the real tool's: each names something this
  // build cannot do, and the real tool would have succeeded.  So they are
  // asserted for what they are -- a refusal that says why -- rather than
  // compared.
  console.log("\nC. the refusals that stay refusals");

  // A key file that is not there.
  fresh();
  mk("local/x.txt", "x\n");
  let r = runOne(OUR_SCP, [
    ...sshOpts(), "-i", path.join(BED, "no-such-key"),
    "-P", String(port), "local/x.txt", `${USER}@127.0.0.1:${remoteOf("x.txt")}`,
  ]);
  ok(
    "a key file that is not there is named",
    r.rc !== 0 && r.err.length > 0 && r.err.toString("latin1").includes("no-such-key"),
    `exit=${r.rc} stderr=${brief(r.err).slice(0, 240)}`,
  );

  // A key file that is not a key.
  const junkKey = path.join(BED, "junk-key.txt");
  fs.writeFileSync(junkKey, "not a key\n");
  r = runOne(OUR_SCP, [
    ...sshOpts(), "-i", junkKey,
    "-P", String(port), "local/x.txt", `${USER}@127.0.0.1:${remoteOf("x.txt")}`,
  ]);
  ok(
    "a key file that is not a key is refused",
    r.rc !== 0 && r.err.length > 0,
    `exit=${r.rc} stderr=${brief(r.err).slice(0, 240)}`,
  );

  // A key the server does not authorize.  `unauth` is a real P-256 key in a
  // real file -- it is simply not in authorized_keys, which is the whole
  // point of having that mechanism.  It is NOT one of the three authorized
  // fixtures: using one of those here would test nothing.
  const unauth = path.join(FIXTURES, "unauth");
  if (fs.existsSync(unauth)) {
    r = runOne(OUR_SCP, [
      ...sshOpts(), "-i", unauth,
      "-P", String(port), "local/x.txt", `${USER}@127.0.0.1:${remoteOf("x.txt")}`,
    ]);
    ok(
      "a key the server does not authorize says Permission denied",
      r.rc !== 0 && r.err.toString("latin1").includes("Permission denied"),
      `exit=${r.rc} stderr=${brief(r.err).slice(0, 240)}`,
    );
  }

  // No `-i` at all: a declared gap, so it must say so rather than pick one.
  r = runOne(OUR_SCP, [
    ...sshOpts(), "-P", String(port), "local/x.txt", `${USER}@127.0.0.1:${remoteOf("x.txt")}`,
  ]);
  ok(
    "no -i is a refusal that says so",
    r.rc !== 0 && r.err.toString("latin1").includes("-i"),
    `exit=${r.rc} stderr=${brief(r.err).slice(0, 240)}`,
  );

  stopSshd();
  return summary();
}

function summary() {
  console.log(`\n${passed}/${passed + failed} checks passed`);
  if (failed > 0) {
    console.log("failed:");
    for (const f of failures) console.log(`  - ${f}`);
    process.exitCode = 1;
  } else {
    console.log("ALL PASS");
  }
}

main().then(
  () => { try { stopSshd(); } catch { /* already stopped */ } },
  (e) => {
    console.log(`\nthe gate itself threw: ${e && e.stack ? e.stack : e}`);
    try { stopSshd(); } catch { /* already stopped */ }
    process.exitCode = 1;
  },
);
