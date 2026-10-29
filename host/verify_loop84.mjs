#!/usr/bin/env node
// host/verify_loop84.mjs -- Loop #84: the client has a random source.
//
// ## What is being claimed
//
// Before this loop the client had no entropy at all:
//
//   * the KEXINIT cookie was the fixed 16-byte array A0 A1 .. AF
//     (`sshclient.fixed_cookie`);
//   * the Diffie-Hellman private exponent was a fixed 32-byte constant that
//     three drivers each carried a copy of (`cmd/ssh_live.fixed_x` and
//     friends).
//
// So every session this client opened began with the same sixteen bytes and
// derived its shared secret from an exponent that is in the source code.  A
// DH exchange with a known private exponent has no forward secrecy at all:
// the shared secret is `f^x` for an `x` anybody with the repository can
// compute.
//
// OpenSSH draws both from the platform CSPRNG and never reuses either:
//
//   kex.c:598        arc4random_buf(cookie, KEX_COOKIE_LEN)
//   kexc25519.c:54   arc4random_buf(key, CURVE25519_SIZE)
//   dh.c:303         DH_generate_key(dh) -- OpenSSL, whose randomness comes
//                    from the platform
//
// This gate checks the claims, and it checks them where they can be checked
// at all:
//
//   G1  `src/rng` keeps its contract on the two backends that HAVE an
//       entropy source (native: BCryptGenRandom; js: Web Crypto), and on
//       the one that has none (wasm) it fails HONESTLY -- the call aborts
//       with a message that says the platform source failed, rather than
//       handing back zeros that would be used as a key.
//
//   G2  Against a real sshd, the cookie and the DH public value on the wire
//       are FRESH: two connections produce two different cookies and two
//       different `e`, and neither is the old constant.
//
//   G3  The reproducible escape hatch still reproduces the old value
//       EXACTLY.  This is the load-bearing check: it says the difference
//       between the random run and the fixed run is exactly the difference
//       between a fresh exponent and the old constant, and nothing else.
//       The `e` is computed independently in Python from the group14 prime.
//
//   G4  The browser draws entropy too, from the Web Crypto API, in a real
//       Web Worker.
//
// ## A note on how randomness is checked
//
// A gate cannot check randomness by looking at it -- that is what randomness
// is.  What it can check is the contract a CSPRNG *wrapper* can be wrong
// about, and the observable difference between two runs:
//
//   * the length asked for is the length delivered;
//   * two calls are not the same bytes (that would mean a constant);
//   * the output is not all zeros (zero is not a key);
//   * the WHOLE buffer was written -- 4096 bytes, two halves, and a
//     half-filled implementation would leave them equal.  That one is
//     structural, not statistical.
//
// And on the wire, where the truth is: two connections, two cookies, two
// public values, and neither of them the constant that used to be there.
//
// ## What runs where
//
// G0..G3 need only node, the MoonBit toolchain, Python and an OpenSSH
// **server**.  When the server is missing those sections are **skipped
// loudly** rather than quietly passed.  G4 needs a browser; when there is
// none it is skipped loudly too, for the same reason.
//
// The browser section is here, in the default CI tier, rather than only in
// Loop #32's gate, because Loop #32's gate is a peer gate and does not run
// in CI at all -- so a browser check that lived only there would never run
// where the code is supposed to work.

import { spawn, spawnSync } from "node:child_process";
import { createServer } from "node:http";
import { existsSync } from "node:fs";
import { readFile, stat } from "node:fs/promises";
import net from "node:net";
import path from "node:path";
import { extname, join, normalize, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const SKIP_REGRESSION = process.argv.includes("--skip-regression");
const HEADED = process.argv.includes("--headed");

const HTTP_PORT = 18784;
const RNG_PROBE_JS = "/_build/js/debug/build/cmd/wt_rng_probe/wt_rng_probe.js";

// The constant cookie this client used before Loop #84.
const OLD_COOKIE = "A0A1A2A3A4A5A6A7A8A9AAABACADAEAF";

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

function norm(s) {
  return `${s}`.replace(/\r\n/g, "\n");
}

function moon(args) {
  const r = spawnSync("cmd", ["/c", "moon", ...args], {
    cwd: ROOT, encoding: "utf8", errors: "replace", maxBuffer: 64 * 1024 * 1024,
  });
  return { code: r.status, out: norm(`${r.stdout || ""}${r.stderr || ""}`) };
}

// `moon check` on one package and one target.  The exit status is the
// reliable signal; the "N warnings, M errors" summary only appears when
// work actually ran, because a cached package prints "no work to do".
function moonCheck(pkg, target) {
  const r = moon(["check", "--target", target, "-p", pkg]);
  const failed = /^\s*Error:/m.test(r.out) || (r.code !== 0 && r.code !== null);
  const m = r.out.match(/(\d+)\s+warnings?,\s*(\d+)\s+errors?/);
  return { errors: failed ? (m ? Number(m[2]) : 1) : 0, warnings: m ? Number(m[1]) : -1, out: r.out };
}

async function freePort() {
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
// The private sshd.
// ---------------------------------------------------------------------------

function startSshd(port, name) {
  // The host key algorithm is pinned to ECDSA P-256, and the reason is NOT
  // that this loop is about ECDSA.  It is that `host/transcript_check.py` --
  // the oracle that recomputes the exchange hash in Python and verifies the
  // server's signature over it -- can only do that for an ECDSA host key: it
  // looks the curve up in a table of three, and an ed25519 key is not in it.
  //
  // Loop #38 removed the pin that used to be baked into sshd_setup.mjs,
  // rightly, and every harness written before it inherited the pin
  // silently.  This one asks for it explicitly, for the same reason Loop
  // #31's harness does.
  //
  // Nothing in G2 depends on the host key algorithm: the cookie and the DH
  // public value are the client's own, and they do not depend on what the
  // server signs with.
  const child = spawn("node", [
    "host/sshd_setup.mjs", "--port", String(port), "--name", name,
    "--hostkey-algs", "ecdsa-sha2-nistp256",
  ], {
    cwd: ROOT, stdio: ["ignore", "pipe", "pipe"],
  });
  child.tapBuf = "";
  for (const stream of [child.stdout, child.stderr]) {
    if (stream) stream.on("data", (d) => { child.tapBuf += d.toString(); });
  }
  return child;
}

function stopSshd(name) {
  spawnSync("node", ["host/sshd_setup.mjs", "--stop", "--name", name], { cwd: ROOT, encoding: "utf8" });
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

// ---------------------------------------------------------------------------
// The oracle: the client's cookie and DH public value, read off the wire.
// ---------------------------------------------------------------------------

// `host/loop84_peek.py` tees the client's bytes to a real sshd and prints the
// KEXINIT cookie and the KEX_ECDH_INIT public value, together with the value
// the OLD constant exponent would have produced (computed in Python, from
// the group14 prime, not read out of the repository).
function peek(args) {
  const r = spawnSync("python", ["host/loop84_peek.py", ...args], {
    cwd: ROOT, encoding: "utf8", errors: "replace", timeout: 180000,
  });
  const out = norm(`${r.stdout || ""}${r.stderr || ""}`);
  const field = (name) => {
    const m = out.match(new RegExp(`^${name}: (.*)$`, "m"));
    return m ? m[1].trim() : "";
  };
  return {
    out,
    code: r.status,
    established: out.includes("result: ESTABLISHED"),
    cookie: field("cookie"),
    e: field("e"),
    eFixed: field("e_fixed"),
    cookieIsOld: field("cookie_is_old_constant") === "True",
    eIsOld: field("e_is_old_constant") === "True",
  };
}

// The one line of the transcript that says what happened -- without the
// 512-hex-character public value that is also in there, which would drown the
// line it is supposed to explain.
function verdict(out) {
  const m = norm(out).match(/^result: .*$/m);
  if (m) return m[0];
  const lines = norm(out).trim().split("\n").filter(Boolean);
  return lines[lines.length - 1] || "(no output)";
}

// The client needs the same three switches the Loop #31 gate uses: the
// proxy port (the first positional argument) and the two that let it talk to
// a server whose host key it has never seen.
function clientArgs(proxyPort, extra = []) {
  return [
    "--proxy-port", String(proxyPort),
    "--client-arg=--kh-tofu",
    "--client-arg=--kh-host",
    "--client-arg=127.0.0.1",
    ...extra.map((a) => `--client-arg=${a}`),
  ];
}

// ---------------------------------------------------------------------------
// The browser harness.
// ---------------------------------------------------------------------------
//
// The same shape as Loop #32's: a static server over the repository, a page
// that creates the Worker, and the Worker that imports the MoonBit IIFE.

const MIME = { ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8" };

function serve(root, port) {
  return new Promise((resolve, reject) => {
    const s = createServer(async (req, res) => {
      try {
        const p = normalize(decodeURIComponent(new URL(req.url, "http://x").pathname))
          .replace(/^[/\\]+/, "");
        const f = join(root, p);
        const st = await stat(f);
        res.writeHead(200, {
          "content-type": MIME[extname(f)] || "application/octet-stream",
          "cache-control": "no-store",
        });
        res.end(await readFile(st.isDirectory() ? join(f, "index.html") : f));
      } catch {
        res.writeHead(404).end("not found");
      }
    });
    s.once("error", reject);
    s.listen(port, "127.0.0.1", () => resolve(s));
  });
}

async function runInWorker(browser, cfg, timeoutMs) {
  const page = await browser.newPage();
  const pageErrors = [];
  page.on("pageerror", (e) => pageErrors.push(String(e)));
  await page.goto(`http://127.0.0.1:${HTTP_PORT}/host/wt/probe.html`);
  let payload;
  try {
    payload = await page.evaluate(
      (c) =>
        new Promise((resolve, reject) => {
          const t = setTimeout(() => reject(new Error("worker timeout")), c.timeoutMs);
          let latest = { done: false, lines: [] };
          const w = new Worker(c.workerUrl);
          w.onmessage = (ev) => {
            latest = ev.data && ev.data.done ? ev.data : { done: false, lines: ev.data.lines };
            if (ev.data && ev.data.done) {
              clearTimeout(t);
              resolve(ev.data);
            }
          };
          w.onerror = (ev) => {
            clearTimeout(t);
            reject(new Error("worker error: " + ev.message));
          };
          setTimeout(() => {
            clearTimeout(t);
            resolve(latest);
          }, c.timeoutMs - 5000);
          w.postMessage(c);
        }),
      { ...cfg, timeoutMs }
    );
  } catch (e) {
    payload = { done: false, lines: [], result: { ok: false, error: String(e) } };
  }
  await page.close();
  return { payload, pageErrors };
}

async function launchBrowser() {
  // The Playwright-bundled Chromium first: CI installs exactly that one, so
  // it is the browser the gate can count on.  Real Chrome is the fallback,
  // because that is what Loop #32's gate uses.
  const { chromium } = await import("playwright");
  try {
    return await chromium.launch({ headless: !HEADED });
  } catch (e) {
    try {
      return await chromium.launch({ headless: !HEADED, channel: "chrome" });
    } catch (e2) {
      throw new Error(`${e.message} / ${e2.message}`);
    }
  }
}

// ---------------------------------------------------------------------------

function hexLines(text) {
  const out = {};
  for (const line of norm(text).split("\n")) {
    const m = line.match(/^([a-z0-9_]+): (.+)$/);
    if (m) out[m[1]] = m[2].trim();
  }
  return out;
}

async function main() {
  console.log("verify_loop84 -- src/rng: the client has a random source\n");

  // ------------------------------------------------------------------- G0 --
  section("G0: the code builds");
  for (const [pkg, target] of [
    ["cmd/ssh_live", "native"],
    ["cmd/rng_probe", "native"],
    ["cmd/wt_rng_probe", "js"],
    ["cmd/wasm_rng_probe", "wasm"],
  ]) {
    const b = moon(["build", pkg, "--target", target]);
    ok(`${pkg} builds for ${target}`, b.code === 0, b.code === 0 ? "" : b.out.slice(-400));
  }
  const c = moon(["check"]);
  ok("the whole tree type-checks", c.code === 0, c.code === 0 ? "" : c.out.slice(-400));
  for (const target of ["native", "js", "wasm", "wasm-gc"]) {
    const r = moonCheck("src/rng", target);
    ok(`src/rng type-checks on ${target}`, r.errors === 0, r.errors === 0 ? `${r.warnings} warnings` : r.out.slice(-200));
  }

  // ------------------------------------------------------------------- G1 --
  //
  // The contract, on the backends that can keep it, and the honest failure on
  // the one that cannot.
  section("G1: src/rng keeps its contract -- and says so when it cannot");

  for (const target of ["native", "js"]) {
    const t = moon(["test", "src/rng", "--target", target]);
    const m = t.out.match(/Total tests: (\d+), passed: (\d+), failed: (\d+)/);
    ok(`${target}: every contract test passes`,
      t.code === 0 && m && m[1] === "5" && m[2] === "5" && m[3] === "0",
      m ? `${m[2]}/${m[1]} passed` : t.out.slice(-300));
  }

  // The wasm backends have no entropy source: there is no operating system
  // underneath a bare wasm module and no Web Crypto API.  The claim under
  // test is that the package REPORTS that rather than inventing bytes --
  // a zero key is not a key, and a client that quietly used one would be a
  // client whose traffic could be read.
  //
  // The test files are gated per target, so the wasm run holds exactly ONE
  // test: the wasm backends' own, which asserts that the backend returns
  // failure.  The contract file -- four tests about a source of entropy --
  // is not compiled there at all, and the count is what says so.
  for (const target of ["wasm", "wasm-gc"]) {
    const t = moon(["test", "src/rng", "--target", target]);
    const m = t.out.match(/Total tests: (\d+), passed: (\d+), failed: (\d+)/);
    ok(`${target}: the one test that can hold there passes`,
      t.code === 0 && m && m[1] === "1" && m[2] === "1" && m[3] === "0",
      m ? `${m[2]}/${m[1]} passed` : t.out.slice(-300));
    ok(`${target}: the contract tests are NOT compiled there`,
      !!m && m[1] === "1",
      m ? `${m[1]} test(s) ran -- the four contract tests should not be among them` : "no summary");
  }

  // And from the OUTSIDE: a wasm build of the probe has to PANIC, not print
  // bytes.  This is the half no unit test can see -- a test cannot watch an
  // abort from the inside -- and it is the half that matters, because it is
  // the difference between "reports the failure" and "hands back zeros".
  {
    const wasmExe = path.join(ROOT, "_build", "wasm", "debug", "build", "cmd", "wasm_rng_probe", "wasm_rng_probe.wasm");
    if (!existsSync(wasmExe)) {
      ok("the wasm probe was built", false, wasmExe);
    } else {
      const r = spawnSync("node", ["host/node_host.mjs", wasmExe], {
        cwd: ROOT, encoding: "utf8", errors: "replace", timeout: 60000,
      });
      const out = norm(`${r.stdout || ""}${r.stderr || ""}`);
      ok("the wasm probe starts", out.includes("wasm_rng_probe: start"),
        out.trim().split("\n").slice(-3).join(" | "));
      ok("the wasm draw PANICS instead of returning bytes",
        r.status === 3 && out.includes("Runtime error"),
        `exit=${r.status}`);
      ok("the wasm probe printed no bytes",
        !out.includes("wasm_rng_probe: got"),
        "the draw returned something on a target that has no entropy source");
    }
  }

  // The same contract, from the command line, so the gate can look at the
  // bytes themselves instead of trusting a test's verdict.
  const probeExe = path.join(ROOT, "_build", "native", "debug", "build", "cmd", "rng_probe", "rng_probe.exe");
  if (!existsSync(probeExe)) {
    ok("cmd/rng_probe produced an executable", false, probeExe);
  } else {
    const r = spawnSync(probeExe, [], { cwd: ROOT, encoding: "utf8", errors: "replace", timeout: 60000 });
    const f = hexLines(`${r.stdout || ""}${r.stderr || ""}`);
    ok("cmd/rng_probe ran", r.status === 0, `exit=${r.status}`);
    ok("a 32-byte draw is 32 bytes", /^[0-9A-F]{64}$/.test(f.rng_first || ""),
      (f.rng_first || "").length + " hex chars");
    ok("a 1-byte draw is 1 byte", /^[0-9A-F]{2}$/.test(f.rng_len1 || ""), f.rng_len1 || "(none)");
    ok("a 0-byte draw is 0 bytes", f.rng_zero_len === "0", f.rng_zero_len || "(none)");
    ok("two draws are not the same bytes", !!f.rng_first && f.rng_first !== f.rng_second);
    ok("a draw is not all zeros", !!f.rng_first && /[^0]/.test(f.rng_first));
    const big = f.rng_4096 || "";
    ok("a 4096-byte draw is 4096 bytes", big.length === 8192, `${big.length} hex chars`);
    // The SECOND HALF is what says the whole buffer was written: an
    // implementation that filled only the first half leaves the second half
    // exactly as it found it -- all zeros.
    //
    // The check that compares the two halves does NOT say this, and the
    // difference matters: a half-filled buffer has a random first half and a
    // zero second half, and those two are DIFFERENT.  Comparing them says
    // "not a constant"; it does not say "all of it was written".
    ok("the WHOLE 4096-byte buffer was written",
      big.length === 8192 && /[^0]/.test(big.slice(4096)),
      "the second half of the buffer is all zeros -- only the first half was filled");
    ok("the two halves of the buffer are different",
      big.length === 8192 && big.slice(0, 4096) !== big.slice(4096),
      "the two halves are equal -- the buffer was filled with one value");
  }

  // --------------------------------------------------------------- G1b --
  //
  // The exponent's SIZE and its SHAPE -- the two properties that decide
  // whether the exchange is worth anything.  Neither can be seen on the
  // wire: `e = g^x mod p` is what goes out, `x` never does, and a 256-bit x
  // in a 2048-bit group produces an `e` that is indistinguishable from the
  // one a 2047-bit x produces.  So they are asserted where they can be: on
  // the exponent itself.
  section("G1b: the DH private exponent has the group's size and shape");
  for (const target of ["native", "js", "wasm", "wasm-gc"]) {
    const t = moon(["test", "src/kexdh", "--target", target]);
    const m = t.out.match(/Total tests: (\d+), passed: (\d+), failed: (\d+)/);
    ok("the exponent keeps the group's size and shape",
      t.code === 0 && m && m[1] === "5" && m[2] === "5" && m[3] === "0",
      `${target}: ${m ? `${m[2]}/${m[1]} passed` : t.out.slice(-200)}`);
  }

  // ------------------------------------------------------------------- G2 --
  section("G2: on the wire, the cookie and the DH public value are fresh");

  const sshdPort = await freePort();
  const name = "loop84";
  const sshd = startSshd(sshdPort, name);
  try {
    if (!await waitForText(sshd, "sshd listening", 30000)) {
      const why = (sshd.tapBuf || "").trim().split("\n").slice(0, 4).join(" | ") || "the server never came up";
      ok("the private sshd is up", false, why);
      for (const what of [
        "the first connection reached ESTABLISHED",
        "the second connection reached ESTABLISHED",
        "the first cookie was read off the wire",
        "the second cookie was read off the wire",
        "the two cookies are different",
        "the cookie is not the old constant",
        "the first DH public value was read off the wire",
        "the second DH public value was read off the wire",
        "the two DH public values are different",
        "the DH public value is not the old constant's",
        "the oracle agrees the cookie is not the old constant",
        "the oracle agrees the DH public value is not the old constant's",
        "the fixed-KEX connection reached ESTABLISHED",
        "the fixed-KEX DH public value was read off the wire",
        "the fixed-KEX DH public value is the old constant's, byte for byte",
        "the cookie is STILL random under --fixed-kex",
        "the transcript oracle still recomputes the exchange hash",
        "the server's signature still verifies over it",
      ]) {
        skip(what, "no OpenSSH server to talk to");
      }
    } else {
      ok("the private sshd is up", true);

      const p1 = await freePort();
      const first = peek(["--port", String(sshdPort), "--proxy-port", String(p1), ...clientArgs(p1)]);
      const p2 = await freePort();
      const second = peek(["--port", String(sshdPort), "--proxy-port", String(p2), ...clientArgs(p2)]);

      ok("the first connection reached ESTABLISHED", first.established, verdict(first.out));
      ok("the second connection reached ESTABLISHED", second.established, verdict(second.out));

      ok("the first cookie was read off the wire", /^[0-9A-F]{32}$/.test(first.cookie), first.cookie);
      ok("the second cookie was read off the wire", /^[0-9A-F]{32}$/.test(second.cookie), second.cookie);
      ok("the two cookies are different", !!first.cookie && first.cookie !== second.cookie,
        `${first.cookie} / ${second.cookie}`);
      ok("the cookie is not the old constant",
        first.cookie !== OLD_COOKIE && second.cookie !== OLD_COOKIE, OLD_COOKIE);

      ok("the first DH public value was read off the wire", /^[0-9A-F]{512}$/.test(first.e),
        `${(first.e || "").length} hex chars`);
      ok("the second DH public value was read off the wire", /^[0-9A-F]{512}$/.test(second.e),
        `${(second.e || "").length} hex chars`);
      ok("the two DH public values are different", !!first.e && first.e !== second.e);
      ok("the DH public value is not the old constant's",
        !first.eIsOld && !second.eIsOld,
        "the client is still using the fixed exponent that was in the source");

      // The oracle says so in its own words too, so a failure in the parsing
      // above cannot hide behind a comparison that never ran.
      ok("the oracle agrees the cookie is not the old constant",
        /cookie_is_old_constant: False/.test(first.out));
      ok("the oracle agrees the DH public value is not the old constant's",
        /e_is_old_constant: False/.test(first.out));

      // --------------------------------------------------------------- G3 --
      //
      // The escape hatch.  It has to reproduce the old value EXACTLY, because
      // that is what makes the G2 comparison mean something: the two runs
      // differ in one input and in nothing else.
      section("G3: the reproducible escape hatch still reproduces the old value");
      {
        const p = await freePort();
        const fixed = peek(["--port", String(sshdPort), "--proxy-port", String(p), ...clientArgs(p, ["--fixed-kex"])]);
        ok("the fixed-KEX connection reached ESTABLISHED", fixed.established, verdict(fixed.out));
        ok("the fixed-KEX DH public value was read off the wire", /^[0-9A-F]{512}$/.test(fixed.e),
          `${(fixed.e || "").length} hex chars`);
        ok("the fixed-KEX DH public value is the old constant's, byte for byte",
          !!fixed.e && fixed.e === fixed.eFixed && fixed.eIsOld,
          "the escape hatch no longer reproduces the value the oracle computes");
        ok("the cookie is STILL random under --fixed-kex",
          !!fixed.cookie && fixed.cookie !== OLD_COOKIE,
          "the flag is about the exponent only; the cookie was never the problem");

        // And the Loop #31 oracle -- the one that recomputes the exchange hash
        // in Python and verifies the server's signature over it -- still
        // works.  It can only do that with a KNOWN exponent, which is what
        // the flag is for.
        const tp = await freePort();
        const tc = spawnSync("python", [
          "host/transcript_check.py",
          "--port", String(sshdPort),
          "--proxy-port", String(tp),
          "--client-arg=--kh-tofu",
          "--client-arg=--kh-host",
          "--client-arg=127.0.0.1",
          "--client-arg=--fixed-kex",
        ], { cwd: ROOT, encoding: "utf8", errors: "replace", timeout: 180000 });
        const t = norm(`${tc.stdout || ""}${tc.stderr || ""}`);
        ok("the transcript oracle still recomputes the exchange hash",
          /H_match:\s+True/.test(t), (t.match(/H_match:.*/) || ["no H_match line"])[0]);
        ok("the server's signature still verifies over it",
          /sig_verified: PASS/.test(t), (t.match(/sig_verified:.*/) || ["no sig_verified line"])[0]);
      }
    }
  } finally {
    sshd.kill();
    stopSshd(name);
  }

  // ------------------------------------------------------------------- G4 --
  section("G4: the browser draws entropy too");
  {
    let browser = null;
    let httpSrv = null;
    let launchError = "";
    try {
      browser = await launchBrowser();
      httpSrv = await serve(ROOT, HTTP_PORT);
    } catch (e) {
      launchError = String(e.message || e);
    }
    if (!browser) {
      skip("the browser draws entropy (Web Crypto, in a real Web Worker)",
        "no browser could be launched: " + launchError);
    } else {
      const { payload, pageErrors } = await runInWorker(
        browser,
        { workerUrl: "/host/wt/worker.js", moduleUrl: RNG_PROBE_JS, tag: "verify84" },
        30000
      );
      const lines = (payload.lines || []).join("\n");
      console.log("    --- Worker transcript ---");
      for (const l of payload.lines || []) console.log(`      ${l}`);
      ok("the MoonBit js output ran in a real Web Worker", lines.includes("rng: done"),
        lines.trim().split("\n").slice(-3).join(" | "));
      ok("a 16-byte draw is 16 bytes", lines.includes("rng: len=16"));
      ok("two draws in the browser are not the same bytes", lines.includes("rng: differs=1"));
      ok("a draw in the browser is not all zeros", lines.includes("rng: nonzero=1"));
      ok("the whole 4096-byte buffer was written in the browser", lines.includes("rng: tail=1"));
      ok("the two halves of the browser's buffer are different", lines.includes("rng: halves=1"));
      const head = (lines.match(/rng: head=([0-9A-F]{32})/) || [])[1];
      ok("the browser's bytes are not the old constant", !!head && head !== OLD_COOKIE, head || "(no head line)");
      ok("no uncaught page errors", pageErrors.length === 0, pageErrors.join(" | "));
      await browser.close();
      if (httpSrv) httpSrv.close();
    }
  }

  // ------------------------------------------------------------- regression --
  if (!SKIP_REGRESSION) {
    section("regression: the earlier loops must not move");
    for (const label of ["loop79", "loop80", "loop81", "loop82", "loop83"]) {
      const r = spawnSync("node", [`host/verify_${label}.mjs`], { cwd: ROOT, encoding: "utf8", errors: "replace" });
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
  console.log("  the client draws its cookie and its DH exponent from the platform");
  console.log("  CSPRNG, the two are fresh on every connection, and the one target");
  console.log("  that has no entropy source says so instead of inventing bytes.");
  process.exit(0);
}

main().catch((e) => {
  console.error("harness error:", e);
  process.exit(2);
});
