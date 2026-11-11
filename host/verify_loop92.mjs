// host/verify_loop92.mjs -- our SFTP server against the real one.
//
// Loop #90 gated `scp` for everything measurable without credentials, using
// `scp -D <program>`: the real CLIENT talking to a program over a pipe.
// Loop #92 built the other half -- the server -- and this gate is the same
// idea turned around.
//
// ## The shape
//
// ONE client script, TWO servers: the real `sftp-server.exe` on this
// machine and our `cmd/sftp_server`.  Every request is sent to both, and
// the replies are compared BYTE FOR BYTE.
//
// Comparing two servers against each other is the only way to see the
// differences that matter: a reply can be "correct" in isolation and still
// differ from the one a real client is written against.  So the oracle is
// the real server's own bytes, and the assertion is equality.
//
// ## The bed
//
// One directory, recreated before every run, with the times PINNED.  The
// pin matters: a STAT reply carries the file's access time, and the first
// server to read the file can change it, which would make the second
// server's answer differ for a reason that has nothing to do with
// behaviour.  The times are set before EACH server runs, so both see the
// same file.
//
// ## What is compared
//
// The reply bytes, and -- for the cases that change the disk -- the tree
// that is left behind.  Nothing is normalised away except the reply
// IDENTIFIER, which the client chooses.
//
// ## The cases
//
// They are the ones `.loop92/probe*.py` measured, and each one names the
// probe it comes from.  The refusals are here too: a server that answers
// everything successfully is not a server.
//
// Run: node host/verify_loop92.mjs

import { spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";

const ROOT = path.resolve(
  new URL("..", import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1"),
);

// Where the real server might be.
//
// Three installations exist on Windows and they are not the same thing: the
// portable Win32-OpenSSH build under Program Files, and the inbox optional
// feature under System32.  Neither is on PATH by default.
//
// machine-path-exempt: each entry below is a CANDIDATE, probed in order
// until one exists; none is asserted to exist on any machine.
const SERVER_CANDIDATES = [
  "C:\\Program Files\\OpenSSH-Win64\\sftp-server.exe",
  "C:\\Windows\\System32\\OpenSSH\\sftp-server.exe",
  "C:\\Program Files\\OpenSSH\\sftp-server.exe",
];
const REAL_SERVER =
  SERVER_CANDIDATES.find((p) => fs.existsSync(p)) || null;

const OUR_SERVER = path.join(
  ROOT, "_build", "native", "debug", "build", "cmd", "sftp_server",
  "sftp_server.exe",
);

const BED = path.join(ROOT, ".loop92", "gate92");

// The times every file in the bed carries.
//
// A fixed instant in the past, so the date column is the OLD form -- which
// is twelve characters of "MMM DD  YYYY" and does not move -- and so the
// two runs cannot straddle the half-year switch.
//
// 2025-03-04 05:06:07 UTC.
const STAMP = 1741064767;

// ---------------------------------------------------------------- the wire

const FXP = {
  INIT: 1, OPEN: 3, CLOSE: 4, READ: 5, WRITE: 6, LSTAT: 7, FSTAT: 8,
  SETSTAT: 9, FSETSTAT: 10, OPENDIR: 11, READDIR: 12, REMOVE: 13,
  MKDIR: 14, RMDIR: 15, REALPATH: 16, STAT: 17, RENAME: 18,
  EXTENDED: 200,
};

const FXF_READ = 1;
const FXF_WRITE = 2;
const FXF_CREAT = 8;

function u32(v) {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(v >>> 0, 0);
  return b;
}

function u64(v) {
  const b = Buffer.alloc(8);
  b.writeBigUInt64BE(BigInt(v), 0);
  return b;
}

function str(s) {
  const b = Buffer.from(s, "utf8");
  return Buffer.concat([u32(b.length), b]);
}

function frame(body) {
  return Buffer.concat([u32(body.length), body]);
}

function req(type, ...parts) {
  return frame(Buffer.concat([Buffer.from([type]), ...parts]));
}

// The request builders the cases use.
//
// The request ID is part of the request, so it is part of the comparison:
// both servers are asked the same question with the same number.
function rInit() { return req(FXP.INIT, u32(3)); }
function rStat(id, p) { return req(FXP.STAT, u32(id), str(p)); }
function rLstat(id, p) { return req(FXP.LSTAT, u32(id), str(p)); }
function rRealpath(id, p) { return req(FXP.REALPATH, u32(id), str(p)); }
function rOpen(id, p, flags) {
  return req(FXP.OPEN, u32(id), str(p), u32(flags), u32(0));
}
function rOpendir(id, p) { return req(FXP.OPENDIR, u32(id), str(p)); }
function rFstat(id, h) { return req(FXP.FSTAT, u32(id), str(h)); }
function rReaddir(id, h) { return req(FXP.READDIR, u32(id), str(h)); }
function rRead(id, h, off, len) {
  return req(FXP.READ, u32(id), str(h), u64(off), u32(len));
}
function rWrite(id, h, off, data) {
  return req(FXP.WRITE, u32(id), str(h), u64(off), str(data));
}
function rFsetstat(id, h, attrs) {
  return req(FXP.FSETSTAT, u32(id), str(h), attrs);
}
function rClose(id, h) { return req(FXP.CLOSE, u32(id), str(h)); }
function rRemove(id, p) { return req(FXP.REMOVE, u32(id), str(p)); }
function rMkdir(id, p) { return req(FXP.MKDIR, u32(id), str(p), u32(0)); }
function rRmdir(id, p) { return req(FXP.RMDIR, u32(id), str(p)); }
function rRename(id, a, b) { return req(FXP.RENAME, u32(id), str(a), str(b)); }
function rExtended(id, name, body) {
  return req(FXP.EXTENDED, u32(id), str(name), body);
}
function rUnknown(id) { return frame(Buffer.concat([Buffer.from([99]), u32(id)])); }

// The ATTRS block for "size only".
function attrsSize(size) {
  return Buffer.concat([u32(1), u64(size)]);
}

// The ATTRS block for "size and times".
function attrsSizeTime(size, when) {
  return Buffer.concat([u32(1 | 8), u64(size), u32(when), u32(when)]);
}

// ------------------------------------------------------------ the reporter

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
      for (const line of String(detail).split("\n").slice(0, 30)) {
        console.log(`          ${line}`);
      }
    }
  }
}

// -------------------------------------------------------------- the server

// A server process, with its replies framed out of the byte stream.
//
// The framing is a four-byte big-endian length and then the body, and a
// body can arrive in pieces -- so the reader keeps what it has and takes
// what it needs.  A reader that assumed one read per reply would lose the
// tail of a long one.
class Server {
  constructor(exe, args, cwd) {
    this.exe = exe;
    this.child = spawn(exe, args, { cwd, stdio: ["pipe", "pipe", "pipe"] });
    this.pending = Buffer.alloc(0);
    this.replies = [];
    this.waiters = [];
    this.closed = false;
    this.stderr = "";
    this.child.stdout.on("data", (d) => this._onData(d));
    this.child.stderr.on("data", (d) => { this.stderr += d.toString("latin1"); });
    this.child.stdin.on("error", () => { /* the server closed the pipe */ });
    this.child.on("close", () => {
      this.closed = true;
      this._wake();
    });
  }

  _onData(d) {
    this.pending = Buffer.concat([this.pending, d]);
    for (;;) {
      if (this.pending.length < 4) return;
      const n = this.pending.readUInt32BE(0);
      if (this.pending.length < 4 + n) return;
      const body = this.pending.subarray(4, 4 + n);
      this.pending = this.pending.subarray(4 + n);
      this.replies.push(Buffer.from(body));
      this._wake();
    }
  }

  _wake() {
    for (const w of this.waiters.slice()) {
      if (this.replies.length >= w.need || this.closed) {
        this.waiters.splice(this.waiters.indexOf(w), 1);
        w.resolve();
      }
    }
  }

  send(buf) {
    // The server may have gone away -- a case that expects no reply ends
    // by closing its input -- and a write to a closed pipe is an EPIPE,
    // not a reason to take the whole gate down.
    try {
      this.child.stdin.write(buf);
    } catch { /* the server is gone */ }
  }

  // Wait for `need` replies in total, or for the timeout.
  async wait(need, ms = 15000) {
    const deadline = Date.now() + ms;
    while (this.replies.length < need && !this.closed) {
      const left = deadline - Date.now();
      if (left <= 0) return false;
      await new Promise((resolve) => {
        const w = { need, resolve };
        this.waiters.push(w);
        setTimeout(() => {
          const i = this.waiters.indexOf(w);
          if (i >= 0) {
            this.waiters.splice(i, 1);
            resolve();
          }
        }, Math.min(left, 250));
      });
    }
    return this.replies.length >= need;
  }

  close() {
    try { this.child.stdin.end(); } catch { /* already gone */ }
    try { this.child.kill(); } catch { /* already gone */ }
  }
}

// The times every file AND directory in the bed carries.
//
// A fixed instant in the past, so the date column is the OLD form -- which
// is twelve characters of "MMM DD  YYYY" and does not move -- and so the
// two runs cannot straddle the half-year switch.
//
// 2025-03-04 05:06:07 UTC.

// --------------------------------------------------------------- the bed

function freshBed() {
  // The read-only file cannot be removed while it is read-only, so the
  // attribute is taken off first.  `fs.rmSync` fails with EPERM
  // otherwise, and the bed would keep the previous run's contents.
  if (fs.existsSync(BED)) {
    for (const p of allFiles(BED)) {
      try { fs.chmodSync(p, 0o666); } catch { /* gone */ }
    }
  }
  fs.rmSync(BED, { recursive: true, force: true });
  fs.mkdirSync(BED, { recursive: true });
  fs.mkdirSync(path.join(BED, "dir"), { recursive: true });
  fs.mkdirSync(path.join(BED, "dir", "sub"), { recursive: true });
  writeFile("a.txt", "hello loop92\n");
  writeFile("b.txt", "second file\n");
  writeFile("ro.txt", "read only\n");
  writeFile("dir/inner.txt", "inner\n");
  writeFile("dir/sub/deep.txt", "deep\n");
  // The read-only file: the attribute is what makes the server answer
  // "Permission denied" when it is opened for writing.
  fs.chmodSync(path.join(BED, "ro.txt"), 0o444);
  restamp(BED);
}

// Every file under a directory.
function allFiles(dir) {
  const out = [];
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) out.push(...allFiles(p));
    else out.push(p);
  }
  return out;
}

// The times are pinned on every file AND every directory, so that the
// second server to run sees the same access time as the first.
//
// The directories are stamped LAST, bottom up: writing a file inside a
// directory changes that directory's own time, so a directory stamped
// before its contents would be stamped with a time the next write undid.
function restamp(dir) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) {
      restamp(p);
    } else {
      try { fs.utimesSync(p, STAMP, STAMP); } catch { /* gone */ }
    }
  }
  try { fs.utimesSync(dir, STAMP, STAMP); } catch { /* gone */ }
}

// The file is created with its times pinned already.
function writeFile(rel, data) {
  const p = path.join(BED, rel.split("/").join(path.sep));
  fs.writeFileSync(p, data);
  fs.utimesSync(p, STAMP, STAMP);
}

// What is on the disk, as a comparable string.
//
// The read-only flag is in there, because the server's permission word is
// derived from it and a file that changed its attribute would change the
// answer.
function tree() {
  const out = [];
  const walk = (dir) => {
    for (const e of fs.readdirSync(dir, { withFileTypes: true }).sort(
      (a, b) => a.name.localeCompare(b.name),
    )) {
      const p = path.join(dir, e.name);
      const rel = path.relative(BED, p).split(path.sep).join("/");
      if (e.isDirectory()) {
        out.push(`dir ${rel}`);
        walk(p);
      } else {
        const data = fs.readFileSync(p);
        const st = fs.statSync(p);
        out.push(
          `file ${rel} ${data.length} ` +
          `${crypto.createHash("sha256").update(data).digest("hex").slice(0, 12)} ` +
          `ro=${(st.mode & 0o200) === 0 ? 1 : 0}`,
        );
      }
    }
  };
  walk(BED);
  return out.join("\n");
}

// ------------------------------------------------------------- the cases

// Each case is a list of steps.  A step sends one request and says how
// many replies it expects.
//
// The count matters: the real server answers NOTHING to a request type it
// does not know, so a case that sends one request and expects one reply
// is a case that also says "the server does not go quiet".
const CASES = [
  {
    name: "INIT answers the VERSION",
    steps: [[rInit(), 1]],
  },
  {
    name: "STAT of a file and of a missing path",
    steps: [[rStat(1, "a.txt"), 1], [rStat(2, "nope.txt"), 1]],
  },
  {
    name: "LSTAT answers the same as STAT",
    steps: [[rLstat(3, "a.txt"), 1]],
  },
  {
    name: "REALPATH answers one name with the absolute path",
    steps: [[rRealpath(4, "a.txt"), 1]],
  },
  {
    name: "OPENDIR, READDIR, READDIR again, CLOSE",
    steps: [
      [rOpendir(5, "dir"), 1],
      [rReaddir(6, Buffer.from([0, 0, 0, 0])), 1],
      [rReaddir(7, Buffer.from([0, 0, 0, 0])), 1],
      [rClose(8, Buffer.from([0, 0, 0, 0])), 1],
    ],
  },
  {
    name: "READDIR of a directory that is not there",
    steps: [[rOpendir(9, "nodir"), 1]],
  },
  {
    name: "OPENDIR of a FILE is refused",
    steps: [[rOpendir(10, "a.txt"), 1]],
  },
  {
    name: "OPEN, READ, READ at the end, CLOSE",
    steps: [
      [rOpen(11, "a.txt", FXF_READ), 1],
      [rRead(12, Buffer.from([0, 0, 0, 0]), 0, 64), 1],
      [rRead(13, Buffer.from([0, 0, 0, 0]), 999, 64), 1],
      [rClose(14, Buffer.from([0, 0, 0, 0])), 1],
    ],
  },
  {
    name: "OPEN of a missing path",
    steps: [[rOpen(15, "nope.txt", FXF_READ), 1]],
  },
  {
    name: "OPEN of a read-only file for writing is refused",
    steps: [[rOpen(16, "ro.txt", FXF_WRITE), 1]],
  },
  {
    name: "a READ of a handle that is not open",
    steps: [[rRead(17, Buffer.from([0, 0, 0, 119]), 0, 64), 1]],
  },
  {
    name: "a CLOSE of a handle that is not open",
    steps: [[rClose(18, Buffer.from([0, 0, 0, 119])), 1]],
  },
  {
    name: "an unknown request TYPE is answered with nothing",
    // The STAT after it is the point: the server has to go on.
    steps: [[rUnknown(19), 0], [rStat(20, "a.txt"), 1]],
  },
  {
    name: "an unknown EXTENSION is refused",
    steps: [[rExtended(21, "nosuch@example.com", Buffer.alloc(0)), 1]],
  },
  {
    name: "posix-rename moves a file over another one",
    steps: [
      [rExtended(22, "posix-rename@openssh.com",
        Buffer.concat([str("a.txt"), str("b.txt")])), 1],
    ],
  },
  {
    name: "posix-rename of a source that is not there",
    steps: [
      [rExtended(23, "posix-rename@openssh.com",
        Buffer.concat([str("nope.txt"), str("b.txt")])), 1],
    ],
  },
  {
    name: "RENAME onto a file that is there is refused",
    steps: [[rRename(24, "a.txt", "b.txt"), 1]],
  },
  {
    name: "RENAME of a source that is not there",
    steps: [[rRename(25, "nope.txt", "b.txt"), 1]],
  },
  {
    name: "STAT of a directory",
    // The real server answers 4096 for a directory's size in a STAT --
    // and 0 for the same directory in a LISTING.  Two questions, two
    // answers, and the listing case below pins the other one.
    steps: [[rStat(1, "dir"), 1]],
  },
  {
    name: "FSTAT of an open file",
    // FSTAT's permission word is NOT STAT's: 33206 against 33152 for
    // the same file.
    steps: [
      [rOpen(1, "a.txt", FXF_READ), 1],
      [rFstat(2, Buffer.from([0, 0, 0, 0])), 1],
      [rClose(3, Buffer.from([0, 0, 0, 0])), 1],
    ],
  },
  {
    name: "a handle number is reused after a close",
    // The handle is a SLOT, not a counter: after the first is closed the
    // next open takes it again.  A counter would answer 1 here.
    steps: [
      [rOpen(1, "a.txt", FXF_READ), 1],
      [rClose(2, Buffer.from([0, 0, 0, 0])), 1],
      [rOpen(3, "b.txt", FXF_READ), 1],
      [rClose(4, Buffer.from([0, 0, 0, 0])), 1],
    ],
  },
  {
    name: "OPENDIR the directory with a hundred and fifty files",
    // The listing is cut into batches of a hundred: the first READDIR
    // answers a hundred entries, the next the rest, and the one after
    // that answers EOF.
    steps: [
      [rOpendir(1, "many"), 1],
      [rReaddir(2, Buffer.from([0, 0, 0, 0])), 1],
      [rReaddir(3, Buffer.from([0, 0, 0, 0])), 1],
      [rReaddir(4, Buffer.from([0, 0, 0, 0])), 1],
      [rClose(5, Buffer.from([0, 0, 0, 0])), 1],
    ],
  },
  {
    name: "REMOVE of a directory is refused",
    steps: [[rRemove(26, "dir"), 1]],
  },
  {
    name: "RMDIR of a file is refused",
    steps: [[rRmdir(27, "a.txt"), 1]],
  },
  {
    name: "MKDIR, MKDIR again, RMDIR",
    steps: [
      [rMkdir(28, "made"), 1],
      [rMkdir(29, "made"), 1],
      [rRmdir(30, "made"), 1],
    ],
  },
  {
    name: "WRITE, FSETSTAT, CLOSE",
    steps: [
      [rOpen(31, "new.txt", FXF_WRITE | FXF_CREAT), 1],
      [rWrite(32, Buffer.from([0, 0, 0, 0]), 0, "written bytes\n"), 1],
      [rFsetstat(33, Buffer.from([0, 0, 0, 0]), attrsSizeTime(13, STAMP)), 1],
      [rClose(34, Buffer.from([0, 0, 0, 0])), 1],
    ],
  },
  {
    name: "a READ never returns more than 65536 bytes",
    steps: [
      [rOpen(35, "big.bin", FXF_READ), 1],
      [rRead(36, Buffer.from([0, 0, 0, 0]), 0, 400000), 1],
      [rClose(37, Buffer.from([0, 0, 0, 0])), 1],
    ],
  },
];

// The cases that need something the standard bed does not have.
function specialBed(caseName) {
  if (caseName.includes("hundred and fifty")) {
    // A directory with more files than one batch holds, so that the batch
    // size is observable: the real server answers a hundred entries and
    // then the rest.  Only this case pays for it.
    fs.mkdirSync(path.join(BED, "many"), { recursive: true });
    for (let i = 0; i < 120; i++) {
      writeFile("many/f" + String(i).padStart(3, "0"), "x\n");
    }
  }
  if (caseName.includes("65536")) {
    const p = path.join(BED, "big.bin");
    fs.writeFileSync(p, Buffer.alloc(400000, 0x79));
    fs.utimesSync(p, STAMP, STAMP);
  }
}

// Run one case against one server.
//
// The INIT goes first in EVERY case, and that is not a convenience: the
// protocol has the client open with it, and the real server waits for it
// before it answers anything at all.  A case that started with a STAT
// would see the real server answer NOTHING -- which is correct behaviour
// and would look like a difference in every later reply.
//
// The reply bodies come back as an array of hex strings, so a difference
// is readable: the two hex strings are printed side by side.
async function runCase(exe, args, caseDef) {
  freshBed();
  specialBed(caseDef.name);
  const srv = new Server(exe, args, BED);
  const got = [];
  const steps = [[rInit(), 1], ...caseDef.steps];
  try {
    for (const [buf, expect] of steps) {
      srv.send(buf);
      if (expect > 0) {
        await srv.wait(srv.replies.length + expect);
      } else {
        // A step that expects nothing has to wait long enough to be sure
        // that nothing is coming.
        await srv.wait(srv.replies.length + 1, 1200);
      }
    }
    // Give the server a moment to answer the last request.
    await srv.wait(srv.replies.length + 1, 1500);
    got.push(...srv.replies.map((b) => b.toString("hex")));
  } finally {
    srv.close();
  }
  return { replies: got, tree: tree() };
}

// ----------------------------------------------------------------- driver

async function main() {
  console.log("=== Loop #92: our SFTP server against the real one ===");
  if (!REAL_SERVER) {
    // A named check rather than an exit code: the CI reads the check
    // names, and "no sftp-server.exe in any of: ..." says which machine
    // and which paths.
    ok(
      "a real sftp-server.exe is available",
      false,
      `no sftp-server.exe in any of: ${SERVER_CANDIDATES.join(", ")}`,
    );
    return summary();
  }
  console.log(`real server: ${REAL_SERVER}`);
  console.log(`our server:  ${OUR_SERVER}`);

  const build = spawnSyncMoon(["build", "--target", "native", "cmd/sftp_server"]);
  if (build.code !== 0) {
    console.log(`  FAIL  cmd/sftp_server does not build\n${build.out.slice(-3000)}`);
    process.exit(1);
  }
  ok("our server built", fs.existsSync(OUR_SERVER));

  // The real server is started with `-e`, which is what the probes used:
  // it logs to stderr, and the log is not part of the answer.
  const realArgs = ["-e"];
  const ourArgs = [];

  for (const c of CASES) {
    freshBed();
    specialBed(c.name);
    const real = await runCase(REAL_SERVER, realArgs, c);
    freshBed();
    specialBed(c.name);
    const ours = await runCase(OUR_SERVER, ourArgs, c);

    const diffs = [];
    const expected = 1 + c.steps.reduce((n, s) => n + s[1], 0);
    if (real.replies.length !== expected) {
      diffs.push(
        `the real server answered ${real.replies.length} of ${expected} replies`,
      );
    }
    if (ours.replies.length !== expected) {
      diffs.push(
        `our server answered ${ours.replies.length} of ${expected} replies`,
      );
    }
    for (let i = 0; i < Math.max(real.replies.length, ours.replies.length); i++) {
      const a = real.replies[i];
      const b = ours.replies[i];
      if (a !== b) {
        diffs.push(`reply ${i} differs`);
        diffs.push(`  real ${a}`);
        diffs.push(`  ours ${b}`);
      }
    }
    if (real.tree !== ours.tree) {
      diffs.push("the tree on the disk differs");
      diffs.push(`  real ${JSON.stringify(real.tree)}`);
      diffs.push(`  ours ${JSON.stringify(ours.tree)}`);
    }
    ok(c.name, diffs.length === 0, diffs.join("\n"));
  }

  // The refusals are half the contract, so they are counted separately:
  // a case that expects a refusal is a case where "Success" is a failure.
  const refusals = CASES.filter((c) => c.name.includes("refused")
    || c.name.includes("is not there")
    || c.name.includes("nothing"));
  ok(
    `the refusal cases are covered (${refusals.length} of them)`,
    refusals.length >= 8,
    `${refusals.length} cases`,
  );

  return summary();
}

function spawnSyncMoon(args) {
  const r = spawnSync("cmd", ["/c", "moon", ...args], {
    cwd: ROOT, encoding: "utf8", timeout: 900000,
  });
  return { code: r.status, out: `${r.stdout || ""}${r.stderr || ""}` };
}

function summary() {
  console.log("");
  console.log(`${passed} passed, ${failed} failed`);
  if (failed) {
    console.log("failed:");
    for (const f of failures) console.log(`  - ${f}`);
    return 1;
  }
  return 0;
}

main().then((code) => process.exit(code || 0)).catch((e) => {
  console.log(e);
  process.exit(1);
});
