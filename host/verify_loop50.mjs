// host/verify_loop50.mjs -- Loop #50: the default is the refusal.
//
// Loop #48 made host key pinning real on the live clients. Loop #49 made it
// write back. Neither changed the *default*, which stayed where Loop #48 left
// it: pin nothing, connect anyway. That is the shape OpenSSH has spent twenty
// years defaulting away from, and every forgotten configuration file landed on
// it silently. This loop puts the default on the safe side.
//
// The interesting part is not that refusing works -- that is four lines in
// `src/knownhosts`. It is that **the refusal is the default path**, which is a
// different claim with a much worse failure mode. Loop #50's own first three
// attempts at this looked correct: the code changed, `moon check` passed, and a
// client with nothing configured kept authenticating. The reason was one line
// in `KnownHostsPolicy::verify` that returned early when `entries` was empty,
// a state `decide` read as "nothing to object to". Nothing was ever going to
// catch that end to end, because the peer does not care what our default is.
//
// So this gate is built around *differences*, not absolute outcomes:
//
//   a        no pinning flags at all               -> refuse, 0 auth attempts
//   b        a + exactly one switch                -> authenticate
//   c        b's written-back line, no switch      -> authenticate
//   d        --kh-strict (deleted in Loop #50)     -> still refuse
//
// `b` is the whole thesis of the loop: in the safe default, the unsafe thing
// costs one flag; in the old one, the safe thing cost a file *and* a flag.
// `c` is the payoff -- once the key is written back, the unsafe switch is not
// needed again. `d` exists because a deleted flag is not automatically an
// inert one, and "we removed it" is a claim, not a measurement.
//
// The refusal in `a` is asserted three ways on purpose, and only the third is
// new. The error name could be anything; the transcript's `auth_attempts`
// could be zero for an unrelated reason (the peer hung, the port was wrong,
// the bridge died). What makes it *the pinning* is that the man in the middle
// still recorded a host key blob: the exchange got all the way through
// signature verification, and we refused a peer whose key we had proven to
// hold. That is the one assertion that cannot be satisfied by an incidental
// failure, and it is checked per connection, because "zero auth attempts" only
// means something about the connection that actually had zero.

import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

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
const WORK = join(root, ".loop50");
const SSH_LIVE = join(root, "_build", "native", "debug", "build", "cmd", "ssh_live", "ssh_live.exe");
const WT_MODULE = join(root, "_build", "js", "debug", "build", "cmd", "wt_ssh", "wt_ssh.js");

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

const leafOf = (s) => String(s || "").split(":").pop().trim();

function classify(text) {
  const n = norm(text);
  const err = grab(n, "error") || "";
  return {
    text: n,
    authed: /^result: USERAUTH_SUCCESS$/m.test(n),
    error: err,
    leaf: leafOf(err),
    // The write-back is two lines: a status, then the known_hosts text. Only the
    // second is an entry, and picking the first match on the status would feed
    // "accepted-unpinned" to --known-hosts-text -- which parses to zero entries
    // and fails with a message that points at the parser instead of at the bug.
    tofuLine: (n.match(/^tofu: (.+)$/gm) || [])
      .map((l) => l.slice("tofu: ".length))
      .find((l) => l !== "accepted-unpinned") || null,
    tofuAccepted: /^tofu: accepted-unpinned$/m.test(n),
  };
}

async function startMitm(tag, extra) {
  const port = await freePort();
  const json = join(WORK, `${tag}.json`);
  const proc = spawn(
    "python",
    [join(root, "host", "sftp_mitm.py"), String(port), ...extra, "--json", json],
    { cwd: root, stdio: ["ignore", "pipe", "pipe"] },
  );
  let err = "";
  proc.stderr.on("data", (d) => (err += d.toString()));
  await sleep(1200);
  return { proc, json, port, err: () => err };
}

async function stopMitm(m) {
  if (!(await exitedWithin(m.proc, 20000))) m.proc.kill();
}

function readJson(file) {
  if (!existsSync(file)) return null;
  try {
    return JSON.parse(readFileSync(file, "utf-8"));
  } catch {
    return null;
  }
}

async function runNative(port, args) {
  const r = spawnSync(SSH_LIVE, [String(port), "--auth", "--user", "hp", ...args], {
    cwd: root,
    encoding: "utf-8",
    errors: "replace",
    maxBuffer: 64 * 1024 * 1024,
    timeout: 90000,
  });
  return classify(`${r.stdout || ""}${r.stderr || ""}`);
}

async function startBridge(tcpPort) {
  const wsPort = await freePort();
  const bridge = spawn(
    "node",
    [join(root, "host", "wt_mitm_bridge.mjs"), "--listen-port", String(wsPort), "--target-port", String(tcpPort)],
    { cwd: root, stdio: ["ignore", "pipe", "pipe"] },
  );
  let text = "";
  bridge.stdout.on("data", (d) => (text += d.toString()));
  bridge.stderr.on("data", (d) => (text += d.toString()));
  const up = await new Promise((res) => {
    const t = setTimeout(() => res(false), 15000);
    bridge.stdout.on("data", () => {
      if (text.includes("listening")) {
        clearTimeout(t);
        res(true);
      }
    });
    bridge.on("exit", () => {
      clearTimeout(t);
      res(false);
    });
  });
  return { bridge, wsPort, up, text: () => text };
}

async function runWorkerAuth(browser, httpPort, wsPort, tag, extraCfg) {
  const base = `http://127.0.0.1:${httpPort}`;
  const cfg = wtCfg(base, httpPort, wsPort, { nonce: tag, user: "hp", auth: "1", ...extraCfg });
  const { page, state } = await openPage(browser, httpPort);
  let out;
  try {
    out = await runWorker(page, cfg);
  } finally {
    await page.close();
  }
  if (out.error) {
    return { text: "", authed: false, error: out.error, leaf: "", tofuLine: null, tofuAccepted: false, net: state.net };
  }
  return { ...classify((out.lines || []).join("\n")), net: state.net };
}

// ---------------------------------------------------------------------------

// One connection's answer, judged against what that connection was supposed to
// do. `data` is *this* connection's transcript -- never a previous one's.
function judge(label, got, wantAuth, wantLeaf, data) {
  const problems = [];
  if (wantAuth) {
    if (!got.authed) problems.push(`did not authenticate: error=${JSON.stringify(got.error)}`);
  } else {
    if (got.authed) problems.push("reached USERAUTH_SUCCESS");
    if (wantLeaf && got.leaf !== wantLeaf) {
      problems.push(`error=${JSON.stringify(got.error)} want leaf ${wantLeaf}`);
    }
  }
  // A client can print whatever it likes, but it cannot un-send userauth.
  if (!wantAuth && data && data.auth_attempts > 0) {
    problems.push(`${data.auth_attempts} authentication attempt(s) reached a peer it should have refused`);
  }
  // The refusal has to be *this* layer's doing. A man in the middle that never
  // got as far as presenting a key would also show zero auth attempts -- but it
  // would be refusing for a reason that has nothing to do with pinning, and an
  // incidental failure dressed as a security pass is worse than no check.
  if (!wantAuth && data && !data.hostkey_blob_b64) {
    problems.push("the peer never presented a host key, so the refusal cannot be about pinning");
  }
  if (problems.length) {
    bad(label, problems.join("\n      "));
    return false;
  }
  return true;
}

// ---------------------------------------------------------------------------

async function main() {
  mkdirSync(WORK, { recursive: true });

  console.log("build");
  // Both halves rebuilt every run. A gate that reports PASS for a tree it did
  // not compile turns a caught regression into a silent one -- and that is
  // exactly how Loop #50's first three attempts looked: the code was right and
  // the binary was stale, with `moon build` reporting "no work to do".
  const b1 = spawnSync("cmd", ["/c", "moon", "build", "cmd\\ssh_live", "--target", "native"], {
    cwd: root, encoding: "utf-8", errors: "replace", maxBuffer: 64 * 1024 * 1024,
  });
  if (b1.status !== 0 || !existsSync(SSH_LIVE)) {
    bad("build ssh_live (native)", norm(`${b1.stdout || ""}${b1.stderr || ""}`).trim().split("\n").slice(-10).join("\n      "));
    return finish();
  }
  ok("build cmd/ssh_live (native)");
  const b2 = spawnSync("cmd", ["/c", "moon", "build", "cmd\\wt_ssh", "--target", "js"], {
    cwd: root, encoding: "utf-8", errors: "replace", maxBuffer: 64 * 1024 * 1024,
  });
  if (b2.status !== 0 || !existsSync(WT_MODULE)) {
    bad("build wt_ssh (js)", norm(`${b2.stdout || ""}${b2.stderr || ""}`).trim().split("\n").slice(-10).join("\n      "));
    return finish();
  }
  ok("build cmd/wt_ssh (js)");

  let browser = null;
  if (chromium) {
    try {
      browser = await chromium.launch({ headless: true });
      ok("browser launched");
    } catch (e) {
      skipped.push("the browser half (chromium not installed)");
      console.log("  SKIP  the browser half: " + String(e).split("\n")[0]);
    }
  } else {
    skipped.push("the browser half (playwright is not installed)");
    console.log("  SKIP  the browser half: playwright is not installed");
  }

  const httpPort = await freePort();
  const server = browser ? await serve(root, httpPort) : null;

  // ---- a: nothing configured ------------------------------------------
  // The headline case, and the only one that needs no fixture at all. Every
  // other case in this file is a comparison against this one.
  console.log("");
  console.log("a: nothing configured");
  let m = await startMitm("a-native", []);
  const aNative = await runNative(m.port, []);
  await stopMitm(m);
  const aNativeData = readJson(m.json);
  if (judge("native default", aNative, false, "HostkeyUnknown", aNativeData)) {
    ok("native default", "refused with HostkeyUnknown, 0 auth attempts, KEX completed");
  }

  if (!browser) {
    skipped.push("the browser cases");
  } else {
    const mitm = await startMitm("a-browser", []);
    const br = await startBridge(mitm.port);
    let got = { authed: false, error: "the bridge never came up: " + br.text().slice(0, 200), leaf: "" };
    if (br.up) {
      got = await runWorkerAuth(browser, httpPort, br.wsPort, "a-default", {});
      br.bridge.kill();
    }
    await stopMitm(mitm);
    const data = readJson(mitm.json);
    if (judge("browser default", got, false, "HostkeyUnknown", data)) {
      ok("browser default", "refused with HostkeyUnknown, 0 auth attempts, KEX completed");
    }
  }

  // ---- b: one more switch ----------------------------------------------
  // Same peer shape, same nothing configured -- exactly one flag different.
  console.log("");
  console.log("b: exactly one more switch");
  let writtenNative = null;
  m = await startMitm("b-native", []);
  const bNative = await runNative(m.port, ["--kh-tofu"]);
  await stopMitm(m);
  const bNativeData = readJson(m.json);
  if (judge("native + --kh-tofu", bNative, true, null, bNativeData)) {
    if (!bNative.tofuAccepted || !bNative.tofuLine) {
      bad("native + --kh-tofu", `authenticated but reported no write-back: tofu=${JSON.stringify(bNative.tofuLine)}`);
    } else {
      writtenNative = bNative.tofuLine;
      ok("native + --kh-tofu", "authenticated and reported a known_hosts line to write back");
    }
  }

  let writtenBrowser = null;
  if (browser) {
    const mitm = await startMitm("b-browser", []);
    const br = await startBridge(mitm.port);
    let got = { authed: false, error: "the bridge never came up: " + br.text().slice(0, 200), leaf: "" };
    if (br.up) {
      got = await runWorkerAuth(browser, httpPort, br.wsPort, "b-tofu", { kh_tofu: "1" });
      br.bridge.kill();
    }
    await stopMitm(mitm);
    const data = readJson(mitm.json);
    if (judge("browser + kh_tofu", got, true, null, data)) {
      if (!got.tofuAccepted || !got.tofuLine) {
        bad("browser + kh_tofu", `authenticated but reported no write-back: tofu=${JSON.stringify(got.tofuLine)}`);
      } else {
        writtenBrowser = got.tofuLine;
        ok("browser + kh_tofu", "authenticated and reported a known_hosts line to write back");
      }
    }
  }

  // The two transports must not end up with two different known_hosts files for
  // the same server. Each case used its own man in the middle, but they sign
  // with the same key, so the lines have to be identical -- and if the drivers
  // ever grew a transport-specific rendering, this is where it would show.
  if (writtenNative && writtenBrowser) {
    if (writtenNative === writtenBrowser) {
      ok("both transports write back the same bytes", writtenNative.split(" ").slice(0, 2).join(" "));
    } else {
      bad("both transports write back the same bytes",
        `native ${JSON.stringify(writtenNative)} vs browser ${JSON.stringify(writtenBrowser)}`);
    }
  }

  // ---- c: the pin from case b is enough on its own ----------------------
  // The payoff. After the write-back, the *safe default* gets in: no unsafe
  // switch, because there is nothing left to accept. If this case needed
  // --kh-tofu as well, then accept-new would be a permanent downgrade rather
  // than a one-time decision, and "remember it" would be a lie.
  console.log("");
  console.log("c: written back, so the safe default is enough");
  if (!writtenNative) {
    bad("native with the written-back pin", "case b produced no line to feed back");
  } else {
    const mitm = await startMitm("c-native", []);
    const got = await runNative(mitm.port, ["--known-hosts-text", writtenNative]);
    await stopMitm(mitm);
    const data = readJson(mitm.json);
    if (judge("native with the written-back pin", got, true, null, data)) {
      ok("native with the written-back pin", "authenticated with no unsafe switch");
    }
  }

  if (browser && writtenBrowser) {
    const mitm = await startMitm("c-browser", []);
    const br = await startBridge(mitm.port);
    let got = { authed: false, error: "the bridge never came up: " + br.text().slice(0, 200), leaf: "" };
    if (br.up) {
      got = await runWorkerAuth(browser, httpPort, br.wsPort, "c-pinned", { known_hosts: writtenBrowser });
      br.bridge.kill();
    }
    await stopMitm(mitm);
    const data = readJson(mitm.json);
    if (judge("browser with the written-back pin", got, true, null, data)) {
      ok("browser with the written-back pin", "authenticated with no unsafe switch");
    }
  }

  // ---- d: the removed switch -------------------------------------------
  // `--kh-strict` was Loop #48's explicit strict flag. Loop #50 made refusing
  // the default, which left it meaning the same thing as no flag at all -- and
  // a flag that silently means "nothing" is a thing people type believing it
  // did something. So it was deleted. This case is the measurement that
  // "deleted" really did mean "not load-bearing", in the safe direction.
  console.log("");
  console.log("d: the switch that was deleted");
  let mD = await startMitm("d-native", []);
  const dNative = await runNative(mD.port, ["--kh-strict"]);
  await stopMitm(mD);
  const dData = readJson(mD.json);
  if (judge("native --kh-strict", dNative, false, "HostkeyUnknown", dData)) {
    ok("native --kh-strict", "ignored -- the default already refuses");
  }

  if (browser) {
    const mitm = await startMitm("d-browser", []);
    const br = await startBridge(mitm.port);
    let got = { authed: false, error: "the bridge never came up: " + br.text().slice(0, 200), leaf: "" };
    if (br.up) {
      got = await runWorkerAuth(browser, httpPort, br.wsPort, "d-strict", { kh_strict: "1" });
      br.bridge.kill();
    }
    await stopMitm(mitm);
    const data = readJson(mitm.json);
    if (judge("browser kh_strict", got, false, "HostkeyUnknown", data)) {
      ok("browser kh_strict", "ignored -- the default already refuses");
    }
  }

  // ---- the unit-level default ------------------------------------------
  // Fast, and it covers the thing that actually went wrong. `decide` on an empty
  // known_hosts under strict must refuse; that single assertion is the regression
  // test for the early return in `verify` that made three edits to the default
  // look like they had worked.
  console.log("");
  console.log("unit");
  const t = spawnSync("cmd", ["/c", "moon", "test", "src\\knownhosts"], {
    cwd: root, encoding: "utf-8", errors: "replace", maxBuffer: 64 * 1024 * 1024, timeout: 900000,
  });
  const tout = norm(t.stdout || "") + norm(t.stderr || "");
  const mTotal = tout.match(/Total tests: (\d+), passed: (\d+), failed: (\d+)/);
  if (mTotal && mTotal[3] === "0") {
    ok("src/knownhosts", `${mTotal[2]}/${mTotal[1]} unit tests`);
  } else {
    bad("src/knownhosts", tout.trim().split("\n").slice(-6).join("\n      "));
  }

  if (browser) await browser.close();
  if (server) server.close();
  finish();

  function finish() {
    console.log("");
    if (skipped.length) console.log("skipped: " + skipped.join(", "));
    if (failures.length === 0) {
      console.log(`ALL PASS (${checks} checks)`);
      writeFileSync(join(WORK, "last_gate50.txt"), `ALL PASS (${checks} checks)\n`);
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
