// host/verify_loop41.mjs -- Loop #41-M2: the fault-injection console, end to end.
//
// What this proves, in order:
//
//   1. the oracle is still self-consistent (its own run agrees with the
//      hand-written expectation for every scenario);
//   2. `cmd/proton_gui` builds and the CEF runtime stages beside the exe;
//   3. the three commands are actually *reachable over the bridge* -- this
//      is the part a headless smoke test cannot see. The app opens a real
//      window with a real CDP endpoint, we attach to the renderer, and we
//      evaluate `window.__MoonBit__.app.sftp_fault_all()` in the page. If the
//      grant never reached the renderer, or the route name were wrong, or the
//      payload types did not line up, this is where it shows;
//   4. every scenario's transcript agrees with `host/sftp_fault_oracle.py`,
//      byte for byte.
//
// Point 3 is why this talks CDP instead of calling the MoonBit functions
// directly: calling `fault_all()` in MoonBit would prove the scenarios and
// prove nothing about the bridge.

import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import net from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";
import WebSocket from "ws";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const EXE = path.join(root, "_build", "native", "debug", "build", "cmd", "proton_gui", "proton_gui.exe");
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

function step(name, fn) {
  return async () => {
    console.log("");
    console.log(name);
    try {
      await fn();
    } catch (err) {
      bad(name, String(err && err.stack ? err.stack : err));
    }
  };
}

// ---------------------------------------------------------------------------
// result rendering
// ---------------------------------------------------------------------------

// A port of `host/gen_fault_vectors.py:render_result`. It exists so the
// comparison is shape-to-shape; it is checked against the generated MoonBit
// file so the two ports cannot quietly disagree.
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

// Pulls `results: [...]` back out of the generated MoonBit source, keyed by
// scenario name. Deliberately a regex over the file rather than a re-run of
// the generator: if the generator and this parser were both wrong in the same
// way, re-running it would agree with itself.
function readRenderedResultsFromMbt() {
  const src = readFileSync(
    path.join(root, "cmd", "proton_gui", "fault_vectors.mbt"),
    "utf-8",
  );
  const out = new Map();
  const caseRe = /name:\s*"([^"]+)"[\s\S]*?results:\s*\[([^\]]*)\]/g;
  let m;
  while ((m = caseRe.exec(src)) !== null) {
    const items = [...m[2].matchAll(/"((?:[^"\\]|\\.)*)"/g)].map((x) =>
      JSON.parse(`"${x[1]}"`),
    );
    out.set(m[1], items);
  }
  return out;
}

// ---------------------------------------------------------------------------
// a free port, probed rather than assumed
// ---------------------------------------------------------------------------

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

async function waitFor(fn, { timeoutMs = 30000, everyMs = 200, what = "condition" } = {}) {
  const deadline = Date.now() + timeoutMs;
  let lastErr = null;
  while (Date.now() < deadline) {
    try {
      const v = await fn();
      if (v) return v;
    } catch (e) {
      lastErr = e;
    }
    await new Promise((r) => setTimeout(r, everyMs));
  }
  throw new Error(`timed out waiting for ${what}${lastErr ? ": " + lastErr : ""}`);
}

// ---------------------------------------------------------------------------
// the bare minimum CDP client
// ---------------------------------------------------------------------------

class Cdp {
  constructor(ws) {
    this.ws = ws;
    this.id = 0;
    this.pending = new Map();
    this.events = [];
    ws.on("message", (raw) => {
      const msg = JSON.parse(raw.toString());
      if (msg.id !== undefined && this.pending.has(msg.id)) {
        const { resolve, reject } = this.pending.get(msg.id);
        this.pending.delete(msg.id);
        if (msg.error) reject(new Error(`${msg.error.message} (${msg.error.code})`));
        else resolve(msg.result);
      } else if (msg.method) {
        this.events.push(msg);
      }
    });
  }

  send(method, params = {}, sessionId) {
    const id = ++this.id;
    const payload = { id, method, params };
    if (sessionId) payload.sessionId = sessionId;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.ws.send(JSON.stringify(payload));
      setTimeout(() => {
        if (this.pending.has(id)) {
          this.pending.delete(id);
          reject(new Error(`CDP timeout: ${method}`));
        }
      }, 60000);
    });
  }

  close() {
    try {
      this.ws.close();
    } catch {
      /* already gone */
    }
  }
}

async function cdpTargets(port) {
  const res = await fetch(`http://127.0.0.1:${port}/json/list`);
  if (!res.ok) throw new Error(`CDP /json/list -> ${res.status}`);
  return await res.json();
}

function evaluate(cdp, sessionId, expression) {
  return cdp
    .send(
      "Runtime.evaluate",
      { expression, awaitPromise: true, returnByValue: true },
      sessionId,
    )
    .then((r) => {
      if (r.exceptionDetails) {
        throw new Error(
          "page threw: " +
            (r.exceptionDetails.exception?.description ||
              r.exceptionDetails.text),
        );
      }
      return r.result.value;
    });
}

// ---------------------------------------------------------------------------
// steps
// ---------------------------------------------------------------------------

const runOracle = () =>
  step("oracle self-consistency", () => {
    mkdirSync(path.join(root, ".loop41"), { recursive: true });
    const out = path.join(root, ".loop41", "fault_vectors.json");
    const r = spawnSync("python", [path.join(root, "host", "sftp_fault_oracle.py"), out], {
      cwd: root,
      encoding: "utf-8",
      maxBuffer: 64 * 1024 * 1024,
    });
    if (r.status !== 0) {
      bad("oracle", (r.stderr || r.stdout || "").trim().split("\n").slice(0, 8).join("\n      "));
      return;
    }
    ok("oracle", r.stdout.trim());
    const vectors = JSON.parse(readFileSync(out, "utf-8"));
    ok("scenario count", String(vectors.length));
  });

const runBuild = () =>
  step("build + stage", () => {
    const b = spawnSync("cmd", ["/c", "moon", "build", "cmd\\proton_gui", "--target", "native"], {
      cwd: root,
      encoding: "utf-8",
      maxBuffer: 64 * 1024 * 1024,
    });
    if (b.status !== 0) {
      bad("moon build", (b.stdout + b.stderr).trim().split("\n").slice(-12).join("\n      "));
      return;
    }
    const st = spawnSync("node", [path.join(root, "host", "proton_stage.mjs")], {
      cwd: root,
      encoding: "utf-8",
      maxBuffer: 64 * 1024 * 1024,
    });
    if (st.status !== 0) {
      bad("proton_stage", (st.stdout + st.stderr).trim());
      return;
    }
    if (!existsSync(EXE)) {
      bad("exe", `missing ${EXE}`);
      return;
    }
    ok("build + stage", st.stdout.trim());
  });

// The live one: a real window, a real bridge, a real round trip.
let child = null;
const runBridge = () =>
  step("live bridge over CDP", async () => {
    if (!existsSync(EXE)) {
      bad("bridge", "exe missing; the build step failed");
      return;
    }
    const port = await freePort();
    child = spawn(EXE, [], {
      cwd: path.dirname(EXE),
      env: {
        ...process.env,
        // Both names read off `facade_manifest.mbt`: `proton_dev_mode_enabled`
        // is what makes debug mode on, and `resolve_remote_debugging` returns
        // Disabled unless debug > 0 -- so the port alone is not enough.
        // Guessing either name here would silently produce "no CDP endpoint"
        // rather than an error, which is why they are quoted from the source
        // rather than remembered.
        PROTON_MODE: "dev",
        PROTON_REMOTE_DEBUGGING_PORT: String(port),
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stderr = "";
    child.stderr.on("data", (d) => {
      stderr += d.toString();
      if (stderr.length > 64 * 1024) stderr = stderr.slice(-64 * 1024);
    });
    child.stdout.on("data", (d) => {
      stderr += d.toString();
      if (stderr.length > 64 * 1024) stderr = stderr.slice(-64 * 1024);
    });
    // If the port never opens, the app's own output is the only thing that
    // says why. A bare "timed out waiting for the page target" would send the
    // next person looking at the harness instead of at the app.
    let exited = null;
    child.on("exit", (code, signal) => {
      exited = `exited code=${code} signal=${signal}\n${stderr.slice(-4000)}`;
    });

    // Read *any* page target, and let the readiness probe below decide. Two
    // earlier versions of this filtered on the URL: once for "any page",
    // which attached to CEF's about:blank placeholder (no bridge on it), and
    // once for `url.startsWith("proton")`, which matched nothing because the
    // real URL is `https://proton.localhost/`. Neither guess was right, and
    // both failed as a timeout rather than as a wrong answer. "The page has
    // the bridge and our three ops on it" is the actual precondition, so that
    // is what gets waited for.
    const page = await waitFor(
      async () => {
        if (exited) throw new Error(`proton_gui ${exited}`);
        const list = await cdpTargets(port);
        const candidates = list.filter(
          (t) => t.type === "page" && t.webSocketDebuggerUrl,
        );
        for (const cand of candidates) {
          let ws;
          try {
            ws = new WebSocket(cand.webSocketDebuggerUrl, {
              perMessageDeflate: false,
              // The suite reply carries every scenario's transcript as hex,
              // which is comfortably over the 100 MiB default once four
              // backends and a full KAT are in the picture; without this the
              // connection drops mid-read and the failure looks like a hang.
              maxPayload: 256 * 1024 * 1024,
            });
            await new Promise((resolve, reject) => {
              ws.once("open", resolve);
              ws.once("error", reject);
            });
            const probe = new Cdp(ws);
            const { targetInfos } = await probe.send("Target.getTargets");
            const entry = targetInfos.find((t) => t.url === cand.url);
            if (!entry) {
              ws.close();
              continue;
            }
            const { sessionId } = await probe.send("Target.attachToTarget", {
              targetId: entry.targetId,
              flatten: true,
            });
            await probe.send("Runtime.enable", {}, sessionId);
            const ready = await evaluate(
              probe,
              sessionId,
              `(() => {
                 const m = window.__MoonBit__;
                 if (!m || typeof m.core?.invokeOp !== "function") return null;
                 const n = ["sftp_fault_list", "sftp_fault_run", "sftp_fault_all"]
                   .filter((x) => typeof m.app?.[x] === "function").length;
                 return n === 3 ? { url: location.href } : null;
               })()`,
            );
            if (!ready) {
              ws.close();
              continue;
            }
            return { ws, sessionId, targetId: entry.targetId, url: ready.url };
          } catch {
            try {
              ws?.close();
            } catch {
              /* not open */
            }
          }
        }
        return null;
      },
      // A cold CEF start on Windows unpacks a few hundred resource files; 30s
      // was measured once and immediately proved too tight on a busy machine.
      { timeoutMs: 120000, what: "a page with the bridge and three granted ops" },
    );
    ok("bridge ready on the real document", page.url);

    const cdp = new Cdp(page.ws);
    const { sessionId } = page;

    // The namespace itself, asserted rather than assumed. Readiness above
    // already required core.invokeOp and the three ops to be present; this
    // restates it as a named check so a regression says *which* half broke
    // instead of only "timed out".
    const granted = await evaluate(
      cdp,
      sessionId,
      `(() => {
         const m = window.__MoonBit__;
         return {
           hasCore: typeof m.core?.invokeOp === "function",
           ops: ["sftp_fault_list", "sftp_fault_run", "sftp_fault_all"]
             .filter((n) => typeof m.app[n] === "function"),
         };
       })()`,
    );
    if (!granted.hasCore) bad("core.invokeOp missing");
    else ok("core.invokeOp present");
    const expectedOps = 3;
    if (granted.ops.length !== expectedOps) {
      bad("granted ops", `${granted.ops.length}/${expectedOps}: ${granted.ops.join(", ")}`);
    } else {
      ok("granted ops", granted.ops.join(", "));
    }

    // And the actual call. This is the assertion that the whole bridge works:
    // request decoding, handler dispatch, response encoding, JSON both ways.
    const all = await evaluate(
      cdp,
      sessionId,
      // `{}`, not `null`. The registry decodes the payload with
      // `@json.from_json(payload_json)` straight into the Request type
      // (`core/op_registry.mbt`), and `EmptyRequest` is a fieldless *struct* --
      // it wants an object. `null` decodes as a valid JSON value and then
      // fails the struct decode, which the bridge reports as
      // "invalid payload for op ...". The page sends `{}` for the same reason.
      `window.__MoonBit__.app.sftp_fault_all({})`,
    );
    if (!all || typeof all.total !== "number") {
      bad("sftp_fault_all", "no usable reply: " + JSON.stringify(all).slice(0, 300));
      cdp.close();
      return;
    }
    ok("sftp_fault_all over the bridge", `${all.passed}/${all.total}`);

    // One single-scenario call, so the Request side (FromJson with a field)
    // is exercised too -- EmptyRequest would not prove the payload decoder.
    const one = await evaluate(
      cdp,
      sessionId,
      `window.__MoonBit__.app.sftp_fault_run({ name: "wrong_request_id" })`,
    );
    if (!one || one.name !== "wrong_request_id") {
      bad("sftp_fault_run", JSON.stringify(one).slice(0, 300));
    } else if (!one.pass) {
      bad("sftp_fault_run(wrong_request_id)", JSON.stringify(one.failures));
    } else {
      ok("sftp_fault_run over the bridge", one.name);
    }

    // Cross-check the whole suite against the oracle, from inside the process
    // that produced it -- so the comparison is against a file written by an
    // implementation that never saw `src/sftp`.
    const vectors = JSON.parse(
      readFileSync(path.join(root, ".loop41", "fault_vectors.json"), "utf-8"),
    );
    const byName = new Map(vectors.map((v) => [v.name, v]));

    const allNotes = all.notes.join("\n");
    if (all.failures && all.failures.length) {
      bad("suite failures", all.failures.slice(0, 5).join("\n      "));
    } else if (all.passed !== vectors.length) {
      bad("suite size", `${all.passed}/${all.total}, oracle has ${vectors.length}`);
    } else {
      ok("suite matches the oracle", `${all.passed}/${all.total}`);
    }
    if (!allNotes.includes("PASS  malformed_write_reply")) {
      bad("notes", "malformed_write_reply not reported as PASS");
    } else {
      ok("notes carry per-scenario verdicts");
    }

    // Per-scenario, over the bridge, against the oracle's own bytes.
    //
    // The comparison is rendered-string against rendered-string. The JSON
    // holds a result as a raw tuple (`["realpath", "/C:/Users/hp"]`) because
    // that is the oracle's internal shape; the bridge returns the *rendered*
    // form `cmd/sftp_test` also prints. Comparing the two directly produced
    // seven failures that looked like protocol disagreements and were not --
    // `["changed"]` versus `["changed"]` is the same answer in two shapes.
    //
    // `renderResult` below is therefore a second port of the same rules, and
    // two ports of one rule set is exactly how they drift apart. So it is
    // checked against the third copy -- the strings `host/gen_fault_vectors.py`
    // wrote into `cmd/proton_gui/fault_vectors.mbt`, which the MoonBit side
    // is compared against. The duplication becomes an assertion.
    const renderedFromMbt = readRenderedResultsFromMbt();
    let compared = 0;
    for (const v of vectors) {
      const r = await evaluate(
        cdp,
        sessionId,
        `window.__MoonBit__.app.sftp_fault_run({ name: ${JSON.stringify(v.name)} })`,
      );
      if (!r || r.name !== v.name) {
        bad(v.name, "bridge returned " + JSON.stringify(r).slice(0, 200));
        continue;
      }
      const wantResults = v.results.map(renderResult);
      const wantFromMbt = renderedFromMbt.get(v.name);
      if (!wantFromMbt) {
        bad(v.name, "not present in cmd/proton_gui/fault_vectors.mbt");
        continue;
      }
      if (JSON.stringify(wantResults) !== JSON.stringify(wantFromMbt)) {
        bad(
          `${v.name}: renderer drift`,
          `json->mbt   ${JSON.stringify(wantResults)}\n      mbt file ${JSON.stringify(wantFromMbt)}`,
        );
        continue;
      }
      const sameRequests =
        JSON.stringify(r.requests) === JSON.stringify(v.requests);
      const sameResults = JSON.stringify(r.results) === JSON.stringify(wantResults);
      const sameEnd =
        r.done === v.done && r.failed === v.failed &&
        (v.failure_reason === "" || r.reason === v.failure_reason);
      if (!sameRequests) {
        bad(v.name, `requests\n      got  ${JSON.stringify(r.requests)}\n      want ${JSON.stringify(v.requests)}`);
      } else if (!sameResults) {
        bad(v.name, `results\n      got  ${JSON.stringify(r.results)}\n      want ${JSON.stringify(wantResults)}`);
      } else if (!sameEnd) {
        bad(v.name, `done/failed/reason ${JSON.stringify([r.done, r.failed, r.reason])} want ${JSON.stringify([v.done, v.failed, v.failure_reason])}`);
      } else {
        compared += 1;
        ok(v.name, r.intent.slice(0, 70));
      }
    }
    if (compared === vectors.length) {
      ok("every scenario byte-identical to the oracle", `${compared}/${vectors.length}`);
    }

    // The extension list is the load-bearing part of two of these: the count
    // is a server property and the *names* are what decide EXTENDED vs
    // RENAME. Assert the names came through, not just the number.
    const extCase = await evaluate(
      cdp,
      sessionId,
      `window.__MoonBit__.app.sftp_fault_run({ name: "ext_absent_falls_back_to_v3" })`,
    );
    if (!extCase || extCase.extensions !== 6 || extCase.ext_names.length !== 6) {
      bad("extension names", JSON.stringify([extCase?.extensions, extCase?.ext_names]));
    } else {
      ok("six extension names kept, not just the count", extCase.ext_names[0]);
    }

    cdp.close();
  });

function cleanup() {
  if (child && !child.killed) {
    try {
      child.kill();
    } catch {
      /* already gone */
    }
    child = null;
  }
}

// ---------------------------------------------------------------------------

const steps = [runOracle(), runBuild(), runBridge()];
try {
  for (const s of steps) {
    await s();
  }
} finally {
  cleanup();
}

const logDir = path.join(root, ".loop41");
mkdirSync(logDir, { recursive: true });
writeFileSync(
  path.join(logDir, "last_gate41.txt"),
  (failures.length
    ? `${failures.length} FAILURES\n` + failures.map((f) => "FAIL " + f).join("\n")
    : `ALL PASS (${checks} checks)`) + "\n",
);

console.log("");
if (failures.length === 0) {
  console.log(`ALL PASS (${checks} checks)`);
  process.exit(0);
} else {
  console.log(`${failures.length} FAILURES`);
  for (const f of failures) {
    console.log("FAIL " + f);
  }
  process.exit(1);
}
