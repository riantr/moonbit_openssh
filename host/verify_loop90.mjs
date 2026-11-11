#!/usr/bin/env node
// host/verify_loop90.mjs -- Loop #90: scp copies, and says the same thing.
//
// ## What is being claimed
//
// Loop #90 implements `scp` on top of a real SFTP client:
//
//   * `src/scp`        -- the rules (getopt, is_remote, destination naming,
//                         the measured sentences) and the copy engine over an
//                         abstract local filesystem and an interactive SFTP
//                         drive;
//   * `src/sftpdrive`  -- one-request-at-a-time SFTP, which is what `scp`
//                         needs (`src/sftp`'s session is scripted);
//   * `src/subproc`    -- spawns the local `sftp-server.exe` that `-D` speaks
//                         to over its stdio.
//
// The claim is that the whole stack, driven the way the real tool is driven,
// produces the SAME BYTES: exit status, stdout, stderr, and the resulting
// tree -- contents, and (for `-p`) mtimes.
//
// ## The judge
//
// The real `scp.exe` from Windows OpenSSH, talking to the real
// `sftp-server.exe` through `-D`.  That combination needs no network, no
// sshd and no key material, and it exercises a full duplex copy -- which is
// why `.loop90/DESIGN.md` section 3 calls it the cheap oracle.
//
// ## How the two runs are made comparable
//
// Two normalisations, and both are stated rather than hidden:
//
//   1. **argv[0]**.  Every message the tool composes is prefixed with the
//      path it was invoked by, which is necessarily different for the two
//      binaries.  Each program's own path is replaced with `PROG`.
//
//   2. **Clock-derived mtimes**.  A file written during a run carries the
//      time of that run, and the two runs are a second apart.  Such a stamp
//      is folded to `NOW`.  A time that was *given* -- the `-p` cases --
//      is compared exactly, which is the only place a time is a fact about
//      the tool rather than about the clock.
//
// ## The two gaps this gate does not close
//
//   * **The SSH leg.**  A remote spec without `-D` is refused by name: real
//     `scp` needs a private key *file*, and `src/keyfile` reads ed25519 only
//     while the repository's test ECDSA key exists as a scalar in code.
//     `.loop90/DESIGN.md` section 6.  Deferred to its own loop.
//
//   * **local -> local.**  The Windows `scp.exe` hands that to the cmd
//     built-ins, whose messages are the shell's and move with the locale
//     (a GBK message was captured in this very session), so there is no
//     byte-for-byte target.  Those cases assert OUR documented output
//     instead, and the check name says so.
//
// ## Where the facts came from
//
// Not from reading `scp.c`.  From driving the real binary:
// `.loop90/probe_scp_D5.py` (round 5, the twelve base scenarios),
// `probe_scp_D6.py` (round 6, the download side), `probe_scp_D7.py`
// (round 7, recursion and the multi-source pre-flight), `probe_scp_D8.py`
// (round 8, destination shapes), and `probe_optstring9.py` (the option
// surface).  Their outputs are `round5.json` .. `round8.json`.

import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";

const ROOT = path.resolve(new URL("..", import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1"));
// machine-path-exempt: each entry below is a CANDIDATE, probed in order until
// one exists; none is asserted to exist.  The order is the one the forty-one
// measurements were taken with.
const SCP_CANDIDATES = ["C:\\Windows\\System32\\OpenSSH\\scp.exe", "C:\\Program Files\\OpenSSH-Win64\\scp.exe", "C:\\Program Files\\OpenSSH\\scp.exe"];
const SRV_CANDIDATES = ["C:\\Program Files\\OpenSSH-Win64\\sftp-server.exe", "C:\\Windows\\System32\\OpenSSH\\sftp-server.exe", "C:\\Program Files\\OpenSSH\\sftp-server.exe"];
const REAL_SCP = SCP_CANDIDATES.find((p) => fs.existsSync(p)) || null;
const REAL_SRV = SRV_CANDIDATES.find((p) => fs.existsSync(p)) || null;
const HOST = "probehost";
const BED = path.join(ROOT, ".loop90", "gate90");
const NOW_WINDOW = 600;

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

function fresh() {
  fs.rmSync(BED, { recursive: true, force: true });
  fs.mkdirSync(path.join(BED, "local"), { recursive: true });
  fs.mkdirSync(path.join(BED, "srv"), { recursive: true });
}

function mk(rel, data, mtime = null) {
  const p = path.join(BED, rel.split("/").join(path.sep));
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, data);
  // A deterministic default time, so the comparison does not report the
  // bed's clock as a behaviour.  The `-p` cases pass an explicit value,
  // which is exactly where a time is supposed to travel.
  const stamp = mtime === null ? 1200000000 + data.length : mtime;
  fs.utimesSync(p, stamp, stamp);
}

function stamp(mtime) {
  return Math.abs(mtime - Date.now() / 1000) < NOW_WINDOW ? "NOW" : mtime;
}

function tree() {
  const out = [];
  for (const side of ["local", "srv"]) {
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
    timeout: 120000,
    stdio: ["ignore", "pipe", "pipe"],
  });
  const err = r.stderr === null ? Buffer.alloc(0) : r.stderr;
  const out = r.stdout === null ? Buffer.alloc(0) : r.stdout;
  const progBytes = Buffer.from(prog);
  return {
    rc: r.status,
    out: Buffer.from(out.toString("latin1").split(progBytes.toString("latin1")).join("PROG"), "latin1"),
    err: Buffer.from(err.toString("latin1").split(progBytes.toString("latin1")).join("PROG"), "latin1"),
    tree: tree(),
  };
}

function brief(buf) {
  return JSON.stringify(buf.toString("latin1"));
}

function compare(label, args, ours, setup, expect) {
  // The setup runs **after** each wipe: a scenario whose fixture was
  // erased compares two identical failures and passes for the wrong
  // reason.  This gate shipped that bug once -- it printed 35/38 with
  // every transfer case vacuous -- so the fixture is rebuilt here, and
  // `expect` below proves the case did something.
  fresh();
  setup();
  const real = runOne(REAL_SCP, args);
  fresh();
  setup();
  const mine = runOne(ours, args);
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
  // Non-vacuity.  A tree path that must exist means the case moved bytes;
  // otherwise the case must have complained, because a silent run with no
  // output and no tree change would pass while doing nothing at all.
  let meaningful = true;
  if (expect) {
    // `srv/x` or `local/x`: which side the case is supposed to have
    // changed, so a download is proven by its local file and an upload by
    // the remote one.
    meaningful = real.tree.some((e) => `${e.side}/${e.path}` === expect);
    if (!meaningful) diffs.push(`the real run never produced ${expect}`);
  } else {
    meaningful = real.err.length > 0 || real.rc !== 0;
    if (!meaningful) diffs.push("the real run neither failed nor printed anything");
  }
  return { label, diffs };
}

// ------------------------------------------------------------- the driver

function moon(args) {
  const r = spawnSync("cmd", ["/c", "moon", ...args], {
    cwd: ROOT,
    encoding: "utf8",
    timeout: 900000,
  });
  return { code: r.status, out: `${r.stdout || ""}${r.stderr || ""}` };
}

function main() {
  console.log("loop90: the copy engine, against the real scp.exe\n");

  if (!REAL_SCP) {
    ok(
      "a real scp.exe is available",
      false,
      `no scp.exe in any of: ${SCP_CANDIDATES.join(", ")}`,
    );
    summary();
    return;
  }
  if (!REAL_SRV) {
    ok(
      "a real sftp-server.exe is available",
      false,
      `no sftp-server.exe in any of: ${SRV_CANDIDATES.join(", ")}`,
    );
    summary();
    return;
  }

  // The library has to be clean and tested on every backend before the
  // driver's behaviour means anything.
  for (const target of ["native", "js", "wasm", "wasm-gc"]) {
    const t = moon(["test", "-p", "src/scp", "--target", target]);
    ok(`src/scp's tests pass on ${target}`, t.code === 0,
      t.code === 0 ? "" : t.out.slice(-600));
  }

  const build = moon(["build", "--target", "native", "cmd/scp"]);
  ok("cmd/scp builds", build.code === 0, build.code === 0 ? "" : build.out.slice(-800));
  const ours = path.join(ROOT, "_build", "native", "debug", "build", "cmd", "scp", "scp.exe");
  ok("the built scp is there", fs.existsSync(ours), ours);
  if (!fs.existsSync(ours)) {
    summary();
    return;
  }

  // The scenarios, in the order the measured rounds established them.
  // `srv` paths are relative because `sftp-server.exe`'s root is its cwd
  // and an absolute remote path leaves the working tree -- DESIGN.md
  // section 3, trap 2.
  const cases = [
    ["upload", ["local/a.txt", HOST + ":srv/out.txt"], () => mk("local/a.txt", "hello world\n")],
    ["download", [HOST + ":srv/in.txt", "local/got.txt"], () => mk("srv/in.txt", "downloaded\n")],
    ["-r upload", ["-r", "local/t", HOST + ":srv/upload"], () => {
      mk("local/t/x.txt", "x\n");
      mk("local/t/sub/y.txt", "y\n");
    }],
    ["-r upload onto an existing dir", ["-r", "local/t", HOST + ":srv/upload"], () => {
      mk("local/t/x.txt", "x\n");
      mk("local/t/sub/y.txt", "y\n");
      fs.mkdirSync(path.join(BED, "srv", "upload"), { recursive: true });
    }],
    ["-r download", ["-r", HOST + ":srv/dt", "local/dl"], () => {
      mk("srv/dt/x.txt", "x\n");
      mk("srv/dt/sub/y.txt", "y\n");
    }],
    ["-p upload", ["-p", "local/p.txt", HOST + ":srv/kept.txt"],
      () => mk("local/p.txt", "data\n", 1000000000)],
    ["-p download", ["-p", HOST + ":srv/p2.txt", "local/kept2.txt"],
      () => mk("srv/p2.txt", "data2\n", 1000000000)],
    ["-p -r upload keeps directory times", ["-p", "-r", "local/t", HOST + ":srv/up"], () => {
      mk("local/t/x.txt", "x\n", 1000000000);
      mk("local/t/sub/y.txt", "y\n", 1000000001);
      fs.utimesSync(path.join(BED, "local", "t"), 1000000002, 1000000002);
      fs.utimesSync(path.join(BED, "local", "t", "sub"), 1000000003, 1000000003);
    }],
    ["a missing local source is fatal", ["local/nope.txt", HOST + ":srv/x.txt"], () => {}],
    ["a local dir without -r is refused", ["local/t", HOST + ":srv/x"], () => {
      mk("local/t/x.txt", "x\n");
    }],
    ["a missing remote source", [HOST + ":srv/nope.txt", "local/x.txt"], () => {}],
    ["a remote dir without -r is refused", [HOST + ":srv/d", "local/x.txt"], () => {
      mk("srv/d/x.txt", "x\n");
    }],
    ["a missing remote destination directory", ["local/a.txt", HOST + ":srv/nodir/out.txt"],
      () => mk("local/a.txt", "hello\n")],
    ["two sources into a remote dir", ["local/s1.txt", "local/s2.txt", HOST + ":srv/d"], () => {
      mk("local/s1.txt", "1\n");
      mk("local/s2.txt", "2\n");
      fs.mkdirSync(path.join(BED, "srv", "d"), { recursive: true });
    }],
    ["two sources into a MISSING remote dir", ["local/s1.txt", "local/s2.txt", HOST + ":srv/nodir"],
      () => {
        mk("local/s1.txt", "1\n");
        mk("local/s2.txt", "2\n");
      }],
    // The ordering case: two sources, neither of which exists, and a target
    // directory that is not there either.  The real tool never creates it,
    // because it has nothing to put in it -- so the mkdir has to happen
    // per source, after the source is known, and not in a pre-flight.
    ["two MISSING sources leave no target dir", ["local/n1.txt", "local/n2.txt", HOST + ":srv/nodir"],
      () => {}],
    ["two sources onto a remote file is fatal", ["local/s1.txt", "local/s2.txt", HOST + ":srv/afile"],
      () => {
        mk("local/s1.txt", "1\n");
        mk("local/s2.txt", "2\n");
        mk("srv/afile", "x\n");
      }],
    ["one source into an existing remote dir", ["local/one.txt", HOST + ":srv/d"], () => {
      mk("local/one.txt", "one\n");
      fs.mkdirSync(path.join(BED, "srv", "d"), { recursive: true });
    }],
    ["a trailing slash on a missing target", ["local/a.txt", HOST + ":srv/newdir/"],
      () => mk("local/a.txt", "a\n")],
    ["a trailing slash on an existing dir", ["local/one.txt", HOST + ":srv/d/"], () => {
      mk("local/one.txt", "one\n");
      fs.mkdirSync(path.join(BED, "srv", "d"), { recursive: true });
    }],
    ["remote to remote", [HOST + ":srv/r1.txt", HOST + ":srv/r2.txt"],
      () => mk("srv/r1.txt", "r\n")],
  ];

  // What each transfer case must have produced on the REAL side.  A case
  // not listed here is one whose whole point is a refusal, so the
  // non-vacuity rule for it is "the real run complained"; listing the
  // transfers explicitly is what stops a broken fixture from passing.
  const EXPECTS = {
    "upload": "srv/out.txt",
    "download": "local/got.txt",
    "-r upload": "srv/upload/sub/y.txt",
    "-r upload onto an existing dir": "srv/upload/t/sub/y.txt",
    "-r download": "local/dl/sub/y.txt",
    "-p upload": "srv/kept.txt",
    "-p download": "local/kept2.txt",
    "-p -r upload keeps directory times": "srv/up/sub/y.txt",
    "two sources into a remote dir": "srv/d/s2.txt",
    "two sources into a MISSING remote dir": "srv/nodir/s2.txt",
    "one source into an existing remote dir": "srv/d/one.txt",
    "a trailing slash on an existing dir": "srv/d/one.txt",
    "remote to remote": "srv/r2.txt",
  };

  console.log("");
  for (const [label, args, setup] of cases) {
    const r = compare(label, ["-D", REAL_SRV, ...args], ours, setup,
      EXPECTS[label] ?? null);
    ok(label, r.diffs.length === 0, r.diffs.join("\n"));
  }

  // The option surface, measured by `probe_optstring9.py`: no `-D` here, so
  // the run has to end in the parser before any connection is attempted.
  console.log("");
  const argCases = [
    ["no arguments prints the usage block", []],
    ["one positional prints the usage block", ["local/a.txt"]],
    ["an unknown option is refused", ["-Z"]],
    ["an undocumented option letter is refused", ["--nonsense"]],
    ["-P with no value", ["-P"]],
    ["-P 0 is a fatal bad port", ["-P", "0"]],
    ["-P abc is a fatal bad port", ["-P", "abc"]],
    ["-P 70000 is out of range", ["-P", "70000"]],
    ["-1 is the v1 refusal", ["-1"]],
    ["-l 0 prints the usage block", ["-l", "0"]],
    ["-l abc prints the usage block", ["-l", "abc"]],
    ["-- ends the options", ["--"]],
  ];
  for (const [label, args] of argCases) {
    const r = compare(label, args, ours, () => {}, null);
    ok(label, r.diffs.length === 0, r.diffs.join("\n"));
  }

  // ------------------------------------------------ local to local, alone
  //
  // This is the ONE section that does not compare against `scp.exe`, and it
  // says so in the check names.  The Windows `scp.exe` hands a local copy to
  // the cmd built-ins, whose messages are the shell's and move with the
  // locale -- a GBK message was captured in this session -- so there is no
  // byte-for-byte target to match.  What is asserted instead is OUR
  // documented behaviour: the bytes arrive, and a refusal says the same
  // sentence the tool uses for the same failure on a remote path.
  console.log("");
  fresh();
  mk("local/from.txt", "local copy\n");
  const localOk = spawnSync(ours, ["local/from.txt", "local/to.txt"], {
    cwd: BED, timeout: 60000, stdio: ["ignore", "pipe", "pipe"],
  });
  let same = false;
  try {
    same = fs.readFileSync(path.join(BED, "local", "to.txt"), "utf8") === "local copy\n";
  } catch {
    same = false;
  }
  ok("local-to-local (ours, not compared): the bytes arrive",
    localOk.status === 0 && same,
    `exit ${localOk.status}, content ${same ? "ok" : "missing"}`);

  fresh();
  const localBad = spawnSync(ours, ["local/nope.txt", "local/to.txt"], {
    cwd: BED, timeout: 60000, stdio: ["ignore", "pipe", "pipe"],
  });
  const wantErr = Buffer.from(
    `PROG: stat local "local/nope.txt": No such file or directory\r\n`, "latin1");
  const gotErr = Buffer.from(
    (localBad.stderr || Buffer.alloc(0)).toString("latin1")
      .split(ours).join("PROG"), "latin1");
  ok("local-to-local (ours, not compared): a missing source is fatal and says so",
    localBad.status === 255 && gotErr.equals(wantErr),
    `exit ${localBad.status}, stderr ${brief(gotErr)}`);

  summary();
}

function summary() {
  console.log("");
  console.log("---");
  console.log(`loop90: ${passed}/${passed + failed} checks passed`);
  if (failed > 0) {
    console.log("failed:");
    for (const f of failures) console.log(`  - ${f}`);
    process.exit(1);
  }
  console.log("ALL PASS");
}

main();
