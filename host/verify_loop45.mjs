// host/verify_loop45.mjs -- Loop #45: the fault vectors over a real socket.
//
// What this proves, and why it is not a repeat of Loops #41-M2 / #43:
//
//   #41-M2 drove malformed replies straight into SftpSession::feed -- the
//   state machine, no transport.
//   #43    drove them through ChanState, the layer below it -- still no
//          transport, and still in-process.
//   This   drives them through `src/sshclient`'s `live_sftp` over a real TCP
//          socket, against `host/sftp_mitm.py`: paramiko in server mode doing
//          a real key exchange, cipher setup and userauth, then writing the
//          scenario onto the channel instead of speaking SFTP.
//
// The expectation is the *same vector table*, unchanged. That is the claim:
// the SFTP layer cannot tell whether the bytes in front of it came from a
// real internal-sftp, a fake peer inside the process, or a man in the middle
// over a socket. A difference here would be in the transport adapter -- the
// one layer the other two gates structurally cannot reach, because
// `run_sftp_session` is private and starts from a post-authentication session
// state.
//
// Two transcripts are checked per scenario, and they are checked against
// different things on purpose:
//
//   * the client's own report (version / results / done-or-failed) against the
//     vector table's expectations;
//   * the bytes the MITM saw the client send, against the expected request
//     frames. The second one is the one that would catch a transport that
//     mangled what it sent -- a window clamp that over-sends, or a subsystem
//     request that goes out before the confirmation arrives -- and the
//     client's own report cannot see that, because a client has no idea what
//     went out before the channel closed.

import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import net from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const EXE = path.join(
  root, "_build", "native", "debug", "build", "cmd", "sftp_mitm", "sftp_mitm.exe",
);
const ORACLE = path.join(root, ".loop41", "fault_vectors.json");
const WORK = path.join(root, ".loop45");

const failures = [];
let checks = 0;

function ok(label, detail) {
  checks += 1;
  console.log(`  PASS  ${label}${detail ? "  " + detail : ""}`);
}

function bad(label, detail) {
  checks += 1;
  failures.push(`${label}${detail ? "  " + detail : ""}`);
  console.log(`  FAIL  ${label}${detail ? "  " + detail : ""}`);
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

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

// Same rule as everywhere else in this repo: decode explicitly. `moon` prints
// UTF-8 box-drawing diagnostics on a Windows console whose active code page is
// GBK, and `text: true` without an encoding decodes them with cp936 and raises
// inside the batch loop -- which kills the child with its buffer unflushed and
// leaves only the lines that happened to make it out.
function moon(args, timeoutMs = 300000) {
  return spawnSync("cmd", ["/c", "moon", ...args], {
    cwd: root,
    encoding: "utf-8",
    errors: "replace",
    maxBuffer: 64 * 1024 * 1024,
    timeout: timeoutMs,
  });
}

// Windows line endings, normalized before anything line-anchored runs.
//
// This is not cosmetic. In a JavaScript regular expression `.` does not match
// `\r` -- it is a line terminator, alongside `\n` -- so `^op\d+: (.*)$` without
// the `m` flag can never match a line that ends in CRLF. The failure mode is
// not a wrong value, it is **no match at all**, which surfaced as "this
// scenario produced zero results" and pointed at the SFTP layer instead of at
// the harness. `verify_loop39` has normalized this since Loop #38; the rule
// travels with the repo, not with the file that happened to remember it.
const norm = (s) => String(s).replace(/\r\n/g, "\n");

const grab = (t, k) => (norm(t).match(new RegExp(`^${k}: (.*)$`, "m")) || [])[1];
const OP_LINE = /^op\d+: (.*)$/;

// The oracle stores a result as a raw tuple (`["realpath", "/C:/Users/hp"]`)
// because that is the oracle's internal shape; the client prints the *rendered*
// form `cmd/sftp_test` uses. Comparing them directly produced a failure that
// read like a protocol disagreement and was not -- the same mistake
// verify_loop41 made, in the same place, one loop later.
//
// So this is a second port of the same rendering rules, and two ports of one
// rule set is how they drift apart. It is therefore cross-checked against the
// third copy -- the strings `host/gen_fault_vectors.py` wrote into
// `cmd/sftp_mitm/vectors.mbt` -- so the duplication is an assertion rather
// than a fork.
function renderResult(r) {
  switch (r[0]) {
    case "realpath":
      return "realpath=" + Buffer.from(r[1], "latin1").toString("hex");
    case "attrs":
      return "attrs=";
    case "changed":
      return "changed";
    case "wrote":
      return "wrote=" + r[1];
    case "contents":
      return "contents=" + Buffer.from(r[1], "hex").toString("hex");
    case "failed":
      return (
        "failed=code=" + r[1] + ":msg=" + Buffer.from(r[2], "latin1").toString("hex")
      );
    default:
      throw new Error("unknown result kind " + r[0]);
  }
}

function readRenderedFromMbt() {
  const src = readFileSync(
    path.join(root, "cmd", "sftp_mitm", "vectors.mbt"), "utf-8",
  );
  const out = new Map();
  const caseRe = /name:\s*"([^"]+)"[\s\S]*?results:\s*\[([^\]]*)\]/g;
  let m;
  while ((m = caseRe.exec(src)) !== null) {
    out.set(
      m[1],
      [...m[2].matchAll(/"((?:[^"\\]|\\.)*)"/g)].map((x) => JSON.parse(`"${x[1]}"`)),
    );
  }
  return out;
}

// ---------------------------------------------------------------------------
// one scenario: start the MITM, run the client, compare both transcripts
// ---------------------------------------------------------------------------

async function runScenario(vector, chop, renderedFromMbt) {
  const port = await freePort();
  const tag = vector.name + (chop ? `@chop${chop}` : "");

  // Start the MITM first and give it a moment: it has to bind and load
  // paramiko, and the client's connect() failing would be indistinguishable
  // from a protocol difference.
  const mitm = spawn(
    "python",
    [path.join(root, "host", "sftp_mitm.py"), String(port), vector.name, "--chop", String(chop)],
    { cwd: root, stdio: ["ignore", "pipe", "pipe"] },
  );
  let mitmOut = "";
  let mitmErr = "";
  mitm.stdout.on("data", (d) => (mitmOut += d.toString()));
  mitm.stderr.on("data", (d) => (mitmErr += d.toString()));

  await sleep(1500);

  // The prebuilt executable, not `moon run`.
  //
  // `moon run` re-plans and re-checks on every invocation, which costs tens of
  // seconds here -- long enough that the MITM's accept() and the client's
  // connect() stop overlapping reliably, and a scenario that passes when run
  // by hand fails inside the gate. The build already happened above; running
  // the artifact is both faster and the thing actually under test.
  const client = spawnSync(EXE, [String(port), vector.name], {
    cwd: root,
    encoding: "utf-8",
    errors: "replace",
    maxBuffer: 64 * 1024 * 1024,
    timeout: 120000,
  });
  const text = `${client.stdout || ""}${client.stderr || ""}`;

  // The MITM exits once the session is over. Waiting for it rather than
  // killing it means its JSON -- which carries the request transcript -- is
  // complete.
  await new Promise((resolve) => {
    const timer = setTimeout(() => {
      try { mitm.kill(); } catch { /* gone */ }
      resolve();
    }, 15000);
    mitm.on("exit", () => { clearTimeout(timer); resolve(); });
  });

  if (/connected: false/.test(text) || /CONNECT_FAILED/.test(text)) {
    return { tag, ok: false, why: "client could not connect\n      " + mitmErr.slice(0, 400) };
  }
  if (!/^outcome: /m.test(text)) {
    return { tag, ok: false, why: "no verdict from the client\n      " + text.trim().split("\n").slice(-8).join("\n      ") };
  }
  // Carry the outcome into every later failure message. A results mismatch on
  // its own reads like a protocol disagreement; "and the session failed
  // outright" points at the transport instead.
  const outcome = grab(text, "outcome");
  const clientErr = grab(text, "error");

  let mitmJson = null;
  const line = norm(mitmOut).trim().split("\n").filter(Boolean).pop();
  if (line) {
    try {
      mitmJson = JSON.parse(line);
    } catch {
      return { tag, ok: false, why: "MITM output was not JSON: " + line.slice(0, 300) };
    }
  }
  if (!mitmJson) {
    return { tag, ok: false, why: "MITM produced no transcript" };
  }
  if (mitmJson.error) {
    return { tag, ok: false, why: "MITM: " + mitmJson.error };
  }
  if (mitmJson.subsystem !== "sftp") {
    return { tag, ok: false, why: `subsystem was ${JSON.stringify(mitmJson.subsystem)}` };
  }

  // ---- the client's own report -----------------------------------------
  const gotResults = norm(text)
    .split("\n")
    .map((l) => (l.match(OP_LINE) || [])[1])
    .filter((v) => v !== undefined);

  // ---- what the MITM saw the client send -------------------------------
  const gotRequests = mitmJson.requests || [];

  const wantResults = vector.results.map(renderResult);
  const wantRequests = vector.requests;

  // The cross-check that makes the second port safe: this renderer must
  // agree with the generated MoonBit table, which the client itself is
  // compared against.
  const fromMbt = renderedFromMbt.get(vector.name);
  if (!fromMbt) {
    return { tag, ok: false, why: "not present in cmd/sftp_mitm/vectors.mbt" };
  }
  if (JSON.stringify(wantResults) !== JSON.stringify(fromMbt)) {
    return {
      tag,
      ok: false,
      why:
        "renderer drift\n        json->mbt " + JSON.stringify(wantResults) +
        "\n        mbt file " + JSON.stringify(fromMbt),
    };
  }

  const problems = [];
  if (outcome !== (vector.done ? "done" : "failed")) {
    problems.push(`outcome=${outcome} want ${vector.done ? "done" : "failed"}${clientErr ? " (" + clientErr + ")" : ""}`);
  }
  if (JSON.stringify(gotResults) !== JSON.stringify(wantResults)) {
    problems.push(
      `results\n        got  ${JSON.stringify(gotResults)}\n        want ${JSON.stringify(wantResults)}`,
    );
  }
  if (JSON.stringify(gotRequests) !== JSON.stringify(wantRequests)) {
    problems.push(
      `requests on the wire\n        got  ${JSON.stringify(gotRequests)}\n        want ${JSON.stringify(wantRequests)}`,
    );
  }
  if (outcome === "failed") {
    // A failed session reports the session's own reason through
    // `Protocol(<reason>)`. That string is the whole point of several
    // scenarios, so it is compared rather than merely logged.
    const err = grab(text, "error") || "";
    if (vector.failure_reason && !err.includes(vector.failure_reason)) {
      problems.push(
        `failure reason\n        got  ${JSON.stringify(err)}\n        want to contain ${JSON.stringify(vector.failure_reason)}`,
      );
    }
  } else if (vector.version_ok !== false) {
    const ver = grab(text, "version");
    if (ver !== undefined && ver !== "3") {
      problems.push(`version=${ver} want 3`);
    }
  }

  if (problems.length) {
    return { tag, ok: false, why: problems.join("\n      ") };
  }
  return { tag, ok: true, detail: `${outcome} ${gotResults.length} result(s), ${gotRequests.length} request(s) on the wire` };
}

// ---------------------------------------------------------------------------

async function main() {
  mkdirSync(WORK, { recursive: true });

  console.log("build");
  const b = moon(["build", "cmd\\sftp_mitm", "--target", "native"]);
  if (b.status !== 0) {
    const all = `${b.stdout || ""}${b.stderr || ""}`.trim().split("\n");
    const errLines = all.filter((l) => /Error|Record|expected|undefined/.test(l));
    bad("build", (errLines.length ? errLines : all.slice(-10)).slice(0, 10).join("\n      "));
  } else if (!existsSync(EXE)) {
    bad("build", `missing ${EXE}`);
  } else {
    ok("build");
  }
  if (failures.length) return finish();

  const vectors = JSON.parse(readFileSync(ORACLE, "utf-8"));
  const renderedFromMbt = readRenderedFromMbt();

  console.log("");
  console.log("whole payloads");
  const whole = [];
  for (const v of vectors) {
    const r = await runScenario(v, 0, renderedFromMbt);
    whole.push(r);
    if (r.ok) ok(r.tag, r.detail);
    else bad(r.tag, r.why);
  }

  console.log("");
  console.log("re-sliced through a real socket");
  const chopped = [];
  for (const v of vectors) {
    for (const size of v.chop_sizes || []) {
      const r = await runScenario(v, size, renderedFromMbt);
      chopped.push(r);
      if (r.ok) ok(r.tag, r.detail);
      else bad(r.tag, r.why);
    }
  }

  finish();

  function finish() {
    console.log("");
    writeFileSync(
      path.join(WORK, "last_gate45.txt"),
      (failures.length
        ? `${failures.length} FAILURES\n` + failures.map((f) => "FAIL " + f).join("\n")
        : `ALL PASS (${checks} checks)`) + "\n",
    );
    if (failures.length === 0) {
      console.log(`ALL PASS (${checks} checks)`);
      process.exit(0);
    }
    console.log(`${failures.length} FAILURES`);
    for (const f of failures) console.log("FAIL " + f);
    process.exit(1);
  }
}

main().catch((e) => {
  bad("harness", String(e && e.stack ? e.stack : e));
  console.log("");
  console.log(`${failures.length} FAILURES`);
  process.exit(1);
});
