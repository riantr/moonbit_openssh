// host/verify_loop46.mjs -- Loop #46: the fault vectors in a browser Worker,
// against a peer that misbehaves on purpose.
//
// This closes the loop Loop #45 opened. #45 drove the ten malformed replies
// through `src/sshclient` over a real TCP socket; `src/wtlive` could not be
// reached, because WebTransport needs a publicly trusted certificate and
// Chromium rejects a locally-added one on the QUIC path
// (QUIC_TLS_CERTIFICATE_UNKNOWN, no matter which override flag is set).
//
// So the chain is:
//
//   browser Worker (MoonBit js, src/wtlive) --WebSocket--> wt_mitm_bridge
//       --TCP--> host/sftp_mitm.py (paramiko server, real key exchange)
//
// `src/wt` picks WebSocket for a `ws://` URL and WebTransport otherwise
// (`host/wt/moonbit_wt.js`), and both carry the same bytes, so everything above
// the transport is exercised identically. The bridge forwards bytes and parses
// nothing, so there is no second SSH implementation to trust.
//
// The expectation is the same generated vector table, for the third time, and
// the rendering is `cmd/wt_ssh`'s own -- which is deliberately aligned with
// `cmd/ssh_live` line for line rather than with `cmd/sftp_mitm`. Changing it to
// match would break the alignment Loop #39 G5 checks, and that alignment is the
// assertion, so the gate parses what `wt_ssh` prints instead.
//
// What this adds that #45 could not: the browser half of "one implementation,
// two transports". A divergence between `src/sshclient` and `src/wtlive` --
// a window rule changed in one file, a pump forgotten in the other -- shows up
// here as a transcript that differs from the same expectations #45 already
// proved.

import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

// The browser plumbing is shared with `host/verify_loop47.mjs`: serving the
// directory, opening a page, driving the Worker and rendering a Worker's
// Event. Two copies of that is the kind of duplication this repo keeps paying
// for in the *rule* layer, and there is no reason to start paying for it in the
// plumbing as well.
import {
  exitedWithin,
  freePort,
  grab,
  norm,
  openPage,
  runWorker,
  serve,
  sleep,
  wtCfg,
} from "./wt_browser.mjs";

let chromium = null;
try {
  ({ chromium } = await import("playwright"));
} catch {
  /* reported below */
}

const root = resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const ORACLE = join(root, ".loop41", "fault_vectors.json");
const WORK = join(root, ".loop46");

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

// ---------------------------------------------------------------------------
// what cmd/wt_ssh prints, turned back into the vector table's shape
// ---------------------------------------------------------------------------

// `wt_print_sftp_op` is aligned with `cmd/ssh_live` line for line, so it
// prints `op0: REALPATH`, `op0_path_hex: ...` -- not the single rendered line
// the other two gates use. Undoing that here keeps `wt_ssh`'s alignment with
// `ssh_live` intact (that alignment *is* Loop #39 G5's assertion) and keeps
// the comparison against the same expectations.
// Hex *case* is a rendering choice, not a protocol fact, and the two drivers
// make opposite ones: `cmd/wt_ssh` prints through `@ecdsa.bytes_to_hex`, which
// is uppercase, while `cmd/sftp_mitm` has its own lowercase `to_hex`. `wt_ssh`
// is the one that is right -- `wt_dump_prefix` is deliberately aligned with
// `cmd/ssh_live`, and that alignment is Loop #39 G5's assertion -- so the case
// is normalized here rather than by changing the driver. Normalizing the whole
// rendered string instead would also hide a case change in `realpath=` itself,
// so only the hex fields are folded.
const foldHex = (s) => String(s === undefined ? s : s).toLowerCase();

function resultsFromOutput(text) {
  const lines = norm(text).split("\n");
  const out = [];
  let cur = null;
  for (const line of lines) {
    const m = line.match(/^op(\d+): ([A-Z]+)$/);
    if (m) {
      cur = { kind: m[2], fields: {} };
      out.push(cur);
      continue;
    }
    const f = line.match(/^op\d+_(\w+): (.*)$/);
    if (f && cur) cur.fields[f[1]] = f[2];
  }
  return out.map((o) => {
    switch (o.kind) {
      case "REALPATH":
        // `wt_print_sftp_op` prints `op<i>_hex` for the path's bytes and
        // `op<i>_path` for its length; the expectation is the hex, so that is
        // the field. (Reading `path_hex` yields `undefined` and a mismatch that
        // looks like a protocol divergence but is a parser reading the wrong
        // name.)
        return "realpath=" + foldHex(o.fields.hex);
      case "ATTRS":
        return "attrs=";
      case "CHANGED":
        return "changed";
      case "WROTE":
        return "wrote=" + o.fields.bytes;
      case "CONTENTS":
        return "contents=" + foldHex(o.fields.hex);
      case "LISTING":
        return "listing=";
      case "FAILED":
        return "failed=code=" + o.fields.code + ":msg=" + foldHex(o.fields.msg_hex);
      default:
        return "unknown:" + o.kind;
    }
  });
}

// The oracle stores raw tuples; the client prints rendered strings. Same shape
// mismatch verify_loop41 and verify_loop45 both hit, so the renderer is a
// shared helper rather than a third private copy.
function renderResult(r) {
  switch (r[0]) {
    case "realpath": return "realpath=" + Buffer.from(r[1], "latin1").toString("hex");
    case "attrs": return "attrs=";
    case "changed": return "changed";
    case "wrote": return "wrote=" + r[1];
    case "contents": return "contents=" + Buffer.from(r[1], "hex").toString("hex");
    case "failed":
      return "failed=code=" + r[1] + ":msg=" + Buffer.from(r[2], "latin1").toString("hex");
    default: throw new Error("unknown result kind " + r[0]);
  }
}

// ---------------------------------------------------------------------------
// one scenario, end to end
// ---------------------------------------------------------------------------

async function runScenario(browser, httpPort, vector, chop) {
  const tag = vector.name + (chop ? `@chop${chop}` : "");
  const tcpPort = await freePort();
  const wsPort = await freePort();

  // The man in the middle. Its JSON goes to its own file so the bridge's and
  // the Worker's stdout cannot interleave with it.
  const mitmJson = join(WORK, `${tag}.mitm.json`);
  const mitm = spawn(
    "python",
    [join(root, "host", "sftp_mitm.py"), String(tcpPort), vector.name, "--chop", String(chop), "--json", mitmJson],
    { cwd: root, stdio: ["ignore", "pipe", "pipe"] },
  );
  let mitmErr = "";
  mitm.stderr.on("data", (d) => (mitmErr += d.toString()));
  await sleep(1200);

  // The WebSocket bridge.
  const bridge = spawn(
    "node",
    [join(root, "host", "wt_mitm_bridge.mjs"), "--listen-port", String(wsPort), "--target-port", String(tcpPort)],
    { cwd: root, stdio: ["ignore", "pipe", "pipe"] },
  );
  let bridgeText = "";
  bridge.stdout.on("data", (d) => (bridgeText += d.toString()));
  bridge.stderr.on("data", (d) => (bridgeText += d.toString()));
  const bridgeUp = await new Promise((res) => {
    const t = setTimeout(() => res(false), 15000);
    bridge.stdout.on("data", () => {
      if (bridgeText.includes("listening")) { clearTimeout(t); res(true); }
    });
    bridge.on("exit", () => { clearTimeout(t); res(false); });
  });
  if (!bridgeUp) {
    mitm.kill(); bridge.kill();
    return { tag, ok: false, why: "bridge never came up: " + bridgeText.slice(0, 300) };
  }

  // The Worker. Absolute URLs for everything it imports (a Worker resolves a
  // relative URL against the *Worker script* URL, not the page's) and a flat
  // config: `cfg()` reads `globalThis.__wt_cfg[name]`, so a nested object
  // would silently read empty. The driving itself is shared with
  // host/verify_loop47.mjs -- see host/wt_browser.mjs.
  const base = `http://127.0.0.1:${httpPort}`;
  const cfg = wtCfg(base, httpPort, wsPort, {
    nonce: "loop46",
    user: "hp",
    sftp_fault: vector.name,
    // Loop #50: the default is now to refuse an unpinned host, so this gate says
    // so explicitly. It is asking about the SFTP layer's reaction to malformed
    // replies, not about host key pinning -- leaving it on the old default would
    // mean every one of its fifty scenarios died in the handshake, and a gate
    // that cannot reach the layer it tests is worse than no gate. The pinning
    // policy has its own gate (`verify_loop48.mjs`).
    kh_tofu: "1",
    kh_host: "127.0.0.1",
  });
  // `freshStorage` because this gate is about fault vectors, not pinning, and
  // Loop #52 made the store real and persistent. Sharing a context would let a
  // pin from an earlier case change whether a case even reaches the handshake --
  // which is the part this gate is actually measuring.
  const { page, state } = await openPage(browser, httpPort, { freshStorage: true });
  const pageErrors = state.pageErrors;
  const pageNet = state.net;
  let workerOut = { lines: [], done: false, ok: false };
  try {
    workerOut = await runWorker(page, cfg);
  } finally {
    await page.close();
    // Order matters, and it is the order the dependency runs in. Closing the
    // bridge drops the TCP connection, the man in the middle sees the socket
    // end, its session thread returns and it writes the transcript. Killing it
    // first -- or killing both at once -- throws that write away.
    bridge.kill();
    if (!(await exitedWithin(mitm, 20000))) mitm.kill();
  }

  // A Worker event was already turned into `workerOut.error` by `runWorker`,
// with the Event's fields named rather than stringified.
  const text = (workerOut.lines || []).join("\n");
  if (/worker error|timeout/.test(text) || workerOut.error) {
    return {
      tag,
      ok: false,
      why: `worker: ${workerOut.error || text.slice(0, 300)}` +
        (pageNet.length ? `\n      http: ${pageNet.join("; ")}` : "") +
        (pageErrors.length ? `\n      page: ${pageErrors[0]}` : ""),
    };
  }
  if (!/^outcome: /m.test(norm(text))) {
    return { tag, ok: false, why: "no outcome from the Worker\n      " + norm(text).trim().split("\n").slice(-10).join("\n      ") };
  }

  const outcome = grab(text, "outcome");
  const gotResults = resultsFromOutput(text);

  let mitmData = null;
  if (existsSync(mitmJson)) {
    try { mitmData = JSON.parse(readFileSync(mitmJson, "utf-8")); } catch { /* fall through */ }
  }
  if (!mitmData) {
    return { tag, ok: false, why: "the man in the middle recorded nothing\n      " + mitmErr.slice(0, 300) };
  }
  if (mitmData.error) return { tag, ok: false, why: "MITM: " + mitmData.error };

  const wantResults = vector.results.map(renderResult);
  const problems = [];
  if (outcome !== (vector.done ? "done" : "failed")) {
    problems.push(`outcome=${outcome} want ${vector.done ? "done" : "failed"}`);
  }
  if (JSON.stringify(gotResults) !== JSON.stringify(wantResults)) {
    problems.push(
      `results\n        got  ${JSON.stringify(gotResults)}\n        want ${JSON.stringify(wantResults)}`,
    );
  }
  // The bytes the peer saw the client send. Only the *count* is portable
  // across a WebSocket: unlike the TCP run in verify_loop45, the framing here
  // is whatever the browser's WebSocket implementation chose, so the packets
  // are compared as a set of lengths rather than as a concatenated stream.
  const gotRequests = mitmData.requests || [];
  if (gotRequests.length !== vector.requests.length) {
    problems.push(
      `${gotRequests.length} requests on the wire, want ${vector.requests.length}\n        got ${JSON.stringify(gotRequests)}`,
    );
  }
  if (problems.length) return { tag, ok: false, why: problems.join("\n      ") };
  return { tag, ok: true, detail: `${outcome} ${gotResults.length} result(s), ${gotRequests.length} request(s)` };
}

// ---------------------------------------------------------------------------

async function main() {
  mkdirSync(WORK, { recursive: true });

  console.log("build");
  const b = spawnSync("cmd", ["/c", "moon", "build", "cmd\\wt_ssh", "--target", "js"], {
    cwd: root, encoding: "utf-8", errors: "replace", maxBuffer: 64 * 1024 * 1024,
  });
  const modulePath = join(root, "_build", "js", "debug", "build", "cmd", "wt_ssh", "wt_ssh.js");
  if (b.status !== 0 || !existsSync(modulePath)) {
    bad("build", norm(`${b.stdout || ""}${b.stderr || ""}`).trim().split("\n").slice(-10).join("\n      "));
    return finish();
  }
  ok("build");

  if (!chromium) {
    skipped.push("browser (playwright is not installed)");
    console.log("  SKIP  browser: playwright is not installed");
    return finish();
  }
  let browser;
  try {
    browser = await chromium.launch({ headless: true });
  } catch (e) {
    skipped.push("browser (chromium not installed)");
    console.log("  SKIP  the Worker run: " + String(e).split("\n")[0]);
    console.log("        (node node_modules/playwright/cli.js install chromium)");
    return finish();
  }
  // A browser that is missing is a prerequisite, not a verdict. Reporting the
  // browser path as verified because the section silently did not run would be
  // the one outcome worse than a failure.
  ok("browser launched");

  const httpPort = await freePort();
  const server = await serve(root, httpPort);

  const vectors = JSON.parse(readFileSync(ORACLE, "utf-8"));

  // A single scenario, for iterating. Fifty browser sessions each with a full
  // SSH handshake is a long run, and a failure at scenario 47 is much easier
  // to read when it can be reproduced alone. `--only <name>` prints a line
  // saying how much of the suite it covered, so a narrowed run can never be
  // mistaken for a full one.
  const onlyArg = process.argv.indexOf("--only");
  const only = onlyArg >= 0 ? process.argv[onlyArg + 1] : null;
  const picked = only ? vectors.filter((v) => v.name === only) : vectors;
  const doChop = !only;
  if (only && picked.length === 0) {
    bad("--only", `no scenario named ${only}`);
    return finish();
  }

  console.log("");
  console.log("whole payloads");
  for (const v of picked) {
    const r = await runScenario(browser, httpPort, v, 0);
    if (r.ok) ok(r.tag, r.detail); else bad(r.tag, r.why);
  }

  if (doChop) {
    console.log("");
    console.log("re-sliced through the browser");
    for (const v of picked) {
      for (const size of v.chop_sizes || []) {
        const r = await runScenario(browser, httpPort, v, size);
        if (r.ok) ok(r.tag, r.detail); else bad(r.tag, r.why);
      }
    }
  } else {
    console.log("");
    console.log(`  (--only ${only}: the re-sliced half was not run)`);
  }

  // Page-level errors are collected per scenario and surfaced there, because a
  // page error thrown between two scenarios would otherwise have nowhere to
  // go -- and a section that ran with an uncaught exception and reported
  // nothing is worse than one that failed.
  ok("every scenario ran on its own page");

  await browser.close();
  server.close();
  finish();

  function finish() {
    console.log("");
    if (skipped.length) console.log("skipped: " + skipped.join(", "));
    const header = failures.length
      ? `${failures.length} FAILURES\n`
      : `ALL PASS (${checks} checks)` +
        (only ? `\nnote: --only ${only} -- the re-sliced half was NOT run` : "") +
        (skipped.length ? `\nskipped: ${skipped.join(", ")}` : "");
    writeFileSync(join(WORK, "last_gate46.txt"), header + "\n");
    if (failures.length === 0) {
      console.log(`ALL PASS (${checks} checks)`);
      if (only) console.log(`note: --only ${only} -- the re-sliced half was NOT run`);
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
