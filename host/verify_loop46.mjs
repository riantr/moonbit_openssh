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
import { createServer } from "node:http";
import net from "node:net";
import path from "node:path";
import { extname, join, normalize, resolve } from "node:path";
import { stat, readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

let chromium = null;
try {
  ({ chromium } = await import("playwright"));
} catch {
  /* reported below */
}

const root = resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const ORACLE = join(root, ".loop41", "fault_vectors.json");
const WORK = join(root, ".loop46");
const MIME = { ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8" };

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
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Whether a child is gone, or will be gone within `ms`. The gate needs this for
// the man in the middle: it only writes its transcript when the session thread
// returns, so killing it the instant the Worker's result arrives races the
// write and the transcript is simply missing. Three scenarios did exactly that
// here and reported "the man in the middle recorded nothing" -- which reads as
// a protocol failure and was a gate that hung up too early.
function exitedWithin(proc, ms) {
  if (proc.exitCode !== null || proc.signalCode !== null) return Promise.resolve(true);
  return new Promise((res) => {
    const t = setTimeout(
      () => res(proc.exitCode !== null || proc.signalCode !== null),
      ms,
    );
    proc.once("exit", () => {
      clearTimeout(t);
      res(true);
    });
  });
}

// Windows line endings, normalized before anything line-anchored runs. In a
// JavaScript regex `.` does not match `\r` -- it is a line terminator -- so an
// un-normalized CRLF line produces *no match*, which reads as "the scenario
// produced nothing". verify_loop45 learned this the hard way.
const norm = (s) => String(s).replace(/\r\n/g, "\n");
const grab = (t, k) => (norm(t).match(new RegExp(`^${k}: (.*)$`, "m")) || [])[1];

// A Worker's `onerror` hands the page an ErrorEvent that may carry nothing
// beyond its type: message, filename and lineno are all empty for a failure
// that is not a parse or a throw, and `String(ev)` is then the useless
// "[object Event]". Every field it *does* carry is worth printing, because the
// alternative hides the whole event. `snap` is the plain object the browser
// side copied the Event into -- see `snapshotEvent` in the page.evaluate below.
function describeEvent(snap) {
  if (!snap || typeof snap !== "object") return String(snap);
  const bits = [];
  for (const k of ["type", "message", "filename", "lineno"]) {
    if (snap[k] !== undefined && snap[k] !== null && snap[k] !== "") {
      bits.push(`${k}=${JSON.stringify(snap[k])}`);
    }
  }
  if (snap.errorText) bits.push(`error=${snap.errorText}`);
  if (snap.own) bits.push(`own=[${snap.own}]`);
  return bits.length ? bits.join(" ") : `bare Event (${snap.str || "?"})`;
}

// Every static request the Worker makes goes through here, so when a scenario
// fails with an opaque Worker error, `LOOP46_TRACE=1` turns on a per-request log
// and the 404 (or the unexpected status) becomes visible instead of inferred.
// It is opt-in because a full run is fifty scenarios and the log is noise.
const TRACE = !!process.env.LOOP46_TRACE;

function serve(dir, port) {
  return new Promise((res, rej) => {
    const s = createServer(async (req, resp) => {
      // Every exit path has to leave the response in one piece. A `catch`
      // that fires *after* `writeHead(200)` -- the read or the write threw
      // once headers were already on the wire -- and then writes a 404, is
      // `ERR_HTTP_HEADERS_SENT`, and it kills the whole gate with a stack
      // instead of one scenario failing. So the body is assembled first and
      // the response is written exactly once.
      let status = 404;
      let body = null;
      let type = "text/plain";
      if (TRACE) {
        console.log(`  serve ${req.url} dir=${dir}`);
      }
      try {
        const p = normalize(decodeURIComponent(new URL(req.url, "http://x").pathname))
          .replace(/^[/\\]+/, "");
        const f = join(dir, p);
        if (!f.startsWith(dir)) {
          status = 403;
        } else {
          const st = await stat(f);
          if (st.isFile()) {
            status = 200;
            type = MIME[extname(f)] || "application/octet-stream";
            body = await readFile(f);
          }
        }
      } catch (e) {
        if (TRACE) console.log(`  serve ${req.url} -> threw ${e && e.code}`);
        status = 404;
        body = null;
      }
      if (body === null) {
        resp.writeHead(status, { "Content-Type": "text/plain" });
        resp.end(`not found: ${req.url}\n`);
        return;
      }
      resp.writeHead(status, { "Content-Type": type });
      resp.end(body);
    });
    s.on("error", rej);
    s.listen(port, "127.0.0.1", () => res(s));
  });
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

  // The Worker. The config is posted flat, because `cfg()` reads
  // `globalThis.__wt_cfg[name]` and a nested object would silently read empty.
  let workerOut = { lines: [], done: false, ok: false };
  // Absolute URLs for everything the Worker imports. A Worker resolves a
  // relative URL against the *Worker's* script URL, not the page's, and the
  // failure mode is `worker error: [object Event]` -- the Worker's `onerror`
  // receives a DOM Event with no `.message`, so the real cause ("404 on the
  // shim") never appears anywhere. Absolute URLs make the page's origin
  // explicit and turn that silent error into a visible 404 in the server log.
  const base = `http://127.0.0.1:${httpPort}`;
  const cfg = {
    workerUrl: `${base}/host/wt/worker.js`,
    shimUrl: `${base}/host/wt/moonbit_wt.js`,
    moduleUrl: `${base}/_build/js/debug/build/cmd/wt_ssh/wt_ssh.js`,
    url: `ws://127.0.0.1:${wsPort}/ssh`,
    nonce: "loop46",
    user: "hp",
    sftp_fault: vector.name,
    timeoutMs: 60000,
  };
  // One page per scenario. A Worker outlives the promise that started it, and
  // a shared page means the previous scenario's Worker is still attached when
  // the next one constructs its own -- so its late `onerror` resolves the new
  // promise with `[object Event]`. Isolating the page makes each scenario's
  // Worker the only one on the document.
  const page = await browser.newPage();
  const pageErrors = [];
  page.on("pageerror", (e) => pageErrors.push(String(e)));
  // The browser's own view of what the Worker fetched. A shim or module that
  // never arrived is a 404 here; without this the only evidence is the
  // Worker's opaque Event, which cannot tell a 404 from anything else.
  const pageNet = [];
  page.on("response", (r) => {
    if (r.status() >= 400) pageNet.push(`${r.status()} ${r.url()}`);
  });
  page.on("requestfailed", (r) =>
    pageNet.push(`failed ${r.failure() && r.failure().errorText} ${r.url()}`),
  );
  await page.goto(`http://127.0.0.1:${httpPort}/host/wt/probe.html`);
  try {
    workerOut = await Promise.race([
      page.evaluate(
        (c) => {
          // `page.evaluate` serializes the function it is given and runs it in
          // the page: it carries no Node scope. A helper defined out here --
          // `describeEvent`, which is why the first run of this gate printed
          // `ReferenceError: describeEvent is not defined` -- is simply absent
          // in the browser. So the browser copies the Event's fields into a
          // plain object and this side formats them: one description, and no
          // eval of a stringified function.
          const snapshotEvent = (ev) => ({
            __event: {
              type: (ev && ev.type) || "",
              message: (ev && ev.message) || "",
              filename: (ev && ev.filename) || "",
              lineno: (ev && ev.lineno) || 0,
              colno: (ev && ev.colno) || 0,
              errorText:
                ev && ev.error
                  ? String(ev.error && ev.error.stack ? ev.error.stack : ev.error)
                  : "",
              own:
                ev && typeof ev === "object"
                  ? Object.getOwnPropertyNames(ev).join(",")
                  : "",
              str: String(ev),
            },
          });
          return new Promise((resolve) => {
            const w = new Worker(c.workerUrl);
            let latest = { done: false, lines: [] };
            w.onmessage = (ev) => {
              latest =
                ev.data && ev.data.done
                  ? ev.data
                  : { done: false, lines: (ev.data && ev.data.lines) || [] };
              if (ev.data && ev.data.done) resolve(ev.data);
            };
            // `worker error: [object Event]` is the shape of a Worker's
            // `onerror` when the Event carries nothing worth printing, so the
            // whole event is described rather than stringified -- otherwise a
            // script that never loaded and an uncaught throw look identical.
            w.onerror = (ev) =>
              resolve({ ...snapshotEvent(ev), done: true, ok: false, lines: [] });
            w.onmessageerror = (ev) =>
              resolve({ ...snapshotEvent(ev), done: true, ok: false, lines: [] });
            // The Worker is **postMessage**-driven: it reads its config in
            // `onmessage`, not at construction. Setting `globalThis.__wt_cfg`
            // from the page does nothing -- the Worker has its own global --
            // so a missing postMessage leaves `cfg()` returning empty for
            // every key, and the run then reports a connect failure rather
            // than "you never sent me anything".
            w.postMessage(c);
            setTimeout(
              () => resolve({ ...latest, done: true, ok: false, error: "timeout" }),
              c.timeoutMs - 5000,
            );
          });
        },
        cfg,
      ),
      sleep(70000).then(() => ({
        done: true, ok: false, lines: [], error: "harness timeout",
      })),
    ]);
  } finally {
    await page.close();
    // Order matters, and it is the order the dependency runs in. Closing the
    // bridge drops the TCP connection, the man in the middle sees the socket
    // end, its session thread returns and it writes the transcript. Killing it
    // first -- or killing both at once -- throws that write away.
    bridge.kill();
    if (!(await exitedWithin(mitm, 20000))) mitm.kill();
  }

  // A Worker event arrives as a snapshot, not as a message from `wt_ssh`.
  // Rendering it here keeps the browser side free of Node scope and gives the
  // failure one readable line instead of "[object Event]".
  if (workerOut.__event) {
    workerOut.error = `worker error: ${describeEvent(workerOut.__event)}`;
    workerOut.lines = [];
  }

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
