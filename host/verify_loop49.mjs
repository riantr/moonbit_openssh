// host/verify_loop49.mjs -- Loop #49: TOFU has to actually remember.
//
// Loop #48 added the comparison. This closes the half that makes TOFU a T-O-F-U:
// **trust on first *use***. Accepting an unpinned host is only half a policy. If
// nothing is written back, then "use" never happened, and the next connection is
// again a fresh credential-free acceptance -- and so is the one after that. The
// client never becomes harder to fool; it just gets slower.
//
// The sequence is the whole point:
//
//   1. connect to a peer that presents a self-consistent key, with no
//      known_hosts at all          -> authenticate, and the client reports the
//                                       key it just accepted
//   2. feed that reported text back in as known_hosts, reconnect to the *same*
//      peer                        -> authenticate, and now it is a MATCH, not
//                                       an unknown host
//   3. feed it back in and reconnect to a peer with a *different* key
//                                    -> refuse
//
// Step 3 is what makes step 2 mean something. A write-back that produced text
// that never matches anything would pass step 2 on its own -- TOFU would be
// indistinguishable from never having pinned at all, which is precisely the bug
// the sequence is here to catch.
//
// **The write-back is printed, not written to disk.** This moon's core has no
// file-reading API, nothing in the repo touches the filesystem, and `src/wt` is
// js-only where a browser has no filesystem at all. So `src/knownhosts` decides
// what a line looks like (one implementation, both transports) and the driver
// decides where it goes; the gate captures it. In a browser application the
// destination is localStorage, not a file, and this is the same code either way.

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
// One place knows what a `tofu:` status line is. This file had its own copy of
// the filter, `verify_loop50` had another, and Loop #52 broke both at once by
// adding two status lines. See `host/tofu_transcript.mjs`.
import { hasAcceptedUnpinned, tofuEntry } from "./tofu_transcript.mjs";

let chromium = null;
try {
  ({ chromium } = await import("playwright"));
} catch {
  /* reported below */
}

const root = resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const WORK = join(root, ".loop49");
const SSH_LIVE = join(root, "_build", "native", "debug", "build", "cmd", "ssh_live", "ssh_live.exe");
const WT_MODULE = join(root, "_build", "js", "debug", "build", "cmd", "wt_ssh", "wt_ssh.js");
const OTHER_KEY = join(root, ".loop44", "mitm_signer_key.pem");

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
    // The written-back known_hosts line: the FIRST `tofu: ` line whose content
    // is not the status marker.
    //
    // Three traps, all hit here. (1) The driver prints `tofu: accepted-unpinned`
    // and then the line, so a first-match read hands back the status marker as
    // if it were content. (2) `println` can wrap the base64 across lines, so a
    // single-line regex truncates the key -- and that then fails as "the
    // written line does not carry the key the peer presented", pointing at the
    // driver when the driver was right. (3) Taking the *last* match instead
    // swallows the whole rest of the driver's output, which is every field
    // after the TOFU line, and then "both transports write the same line"
    // compares two transcripts.
    written: tofuEntry(n),
    tofu: hasAcceptedUnpinned(n),
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
  const { page, state } = await openPage(browser, httpPort, { freshStorage: true });
  let out;
  try {
    out = await runWorker(page, cfg);
  } finally {
    await page.close();
  }
  if (out.error) {
    return { text: "", authed: false, error: out.error, leaf: "", written: null, tofu: false, net: state.net };
  }
  return { ...classify((out.lines || []).join("\n")), net: state.net };
}

// ---------------------------------------------------------------------------
// the sequence, for one client
// ---------------------------------------------------------------------------

// Three steps, three separate man in the middle runs: the peer's key has to be
// the same one in step 1 and step 2, and a different one in step 3. Reusing a
// single run would make the peer immortal and prove nothing about the client.
async function runSequence(kind, first, second, third) {
  // --- step 1: nothing pinned ------------------------------------------
  let mitm = await startMitm(`${kind}-1-unpinned`, first);
  const one = await second(mitm);
  await stopMitm(mitm);
  // Read after the connection, always. The man in the middle writes its
  // transcript when its session thread returns; a read placed before the client
  // has connected gets an empty file and reports the peer as silent.
  const transcript1 = readJson(mitm.json);

  if (!one.authed) {
    bad(`${kind} 1 unpinned`, "did not authenticate: " + JSON.stringify(one.error));
    return null;
  }
  if (!one.tofu) {
    bad(`${kind} 1 unpinned`, "accepted an unpinned host but reported no TOFU");
    return null;
  }
  if (!one.written) {
    bad(`${kind} 1 unpinned`, "reported a TOFU but wrote no line back");
    return null;
  }
  // The written line must be about the host we asked about, and must carry the
  // key this peer actually presented. Both are checkable against the peer's own
  // transcript, which is what makes this an assertion about the run rather than
  // about the driver.
  if (!transcript1 || !transcript1.hostkey_blob_b64) {
    bad(`${kind} 1 unpinned`, "the peer reported no key, so the write-back cannot be checked");
    return null;
  }
  if (!one.written.includes(transcript1.hostkey_blob_b64)) {
    bad(`${kind} 1 unpinned`, "the written line does not carry the key the peer presented");
    return null;
  }
  if (!one.written.startsWith(transcript1.hostkey_announced_type)) {
    // The line is `host type base64`, so the type sits in the middle. Checked
    // against the peer's own transcript rather than a constant.
    if (!one.written.includes(" " + transcript1.hostkey_announced_type + " ")) {
      bad(`${kind} 1 unpinned`, `the written line is not for ${transcript1.hostkey_announced_type}`);
      return null;
    }
  }
  ok(`${kind} 1 unpinned`, `accepted and wrote back ${one.written.slice(0, 40)}...`);

  // --- step 2: the written line, same peer ------------------------------
  mitm = await startMitm(`${kind}-2-match`, first);
  const two = await second(mitm, one.written);
  await stopMitm(mitm);
  if (!two.authed) {
    bad(`${kind} 2 match`, "the key we wrote back did not match on reconnect: " + JSON.stringify(two.error));
    return null;
  }
  ok(`${kind} 2 match`, "the written-back key is recognised on reconnect");
  // A second TOFU here is *correct*, not a failure: writing back again on every
  // accepted connection is what keeps the file current when a host legitimately
  // rotates its key. What would be wrong is a second TOFU for a host that was
  // NOT written back -- and step 3 is where that shows, because the mismatching
  // peer must be refused rather than re-pinned.
  //
  // The first draft of this gate treated a repeated TOFU as "the first
  // write-back was not remembered" and failed on correct behaviour. The
  // distinction that actually matters is in step 3.

  // --- step 3: the written line, a different peer ------------------------
  mitm = await startMitm(`${kind}-3-mismatch`, third);
  const three = await second(mitm, one.written);
  await stopMitm(mitm);
  // Read *after* the connection: the man in the middle writes its transcript
  // when its session thread returns, so reading it here-but-not-really-earlier
  // gets an empty file and reports "the second peer reported no key".
  const transcript3 = readJson(mitm.json);
  if (!transcript3 || !transcript3.hostkey_blob_b64) {
    bad(`${kind} 3 mismatch`, "the second peer reported no key");
    return null;
  }
  if (transcript3.hostkey_blob_b64 === transcript1.hostkey_blob_b64) {
    bad(`${kind} 3 mismatch`, "the two peers presented the same key; the test proves nothing");
    return null;
  }
  if (three.authed) {
    bad(`${kind} 3 mismatch`, "reached USERAUTH_SUCCESS against a peer with a different key");
    return null;
  }
  if (three.leaf !== "HostkeyMismatch") {
    bad(`${kind} 3 mismatch`, `error=${JSON.stringify(three.error)} want leaf HostkeyMismatch`);
    return null;
  }
  ok(`${kind} 3 mismatch`, `refused with ${three.leaf}`);
  return one.written;
}

// ---------------------------------------------------------------------------

async function main() {
  mkdirSync(WORK, { recursive: true });

  console.log("build");
  // Both halves rebuilt every run: a gate that reports PASS for a tree it did
  // not compile turns a caught regression into a silent one (Loop #47).
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

  // The unit-level round trip: read a known_hosts back out byte for byte. The
  // end-to-end sequence below cannot see a lost `@revoked` marker -- nothing in
  // it writes one -- and a write-back that quietly turns a revocation into a
  // trust is worse than no write-back at all.
  const t = spawnSync("cmd", ["/c", "moon", "test", "src\\knownhosts"], {
    cwd: root, encoding: "utf-8", errors: "replace", maxBuffer: 32 * 1024 * 1024, timeout: 900,
  });
  const tOut = norm(`${t.stdout || ""}${t.stderr || ""}`);
  if (t.status !== 0 || !/passed: \d+, failed: 0/.test(tOut)) {
    bad("known_hosts round trip", tOut.trim().split("\n").slice(-8).join("\n      "));
  } else {
    const m = tOut.match(/Total tests: (\d+), passed: (\d+), failed: 0/);
    ok("known_hosts round trip", `${m ? m[2] : "?"} unit tests, read-back byte identical`);
  }

  if (!existsSync(OTHER_KEY)) {
    bad("other key", "missing " + OTHER_KEY + " (Loop #47 generates it)");
    return finish();
  }

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

  // Step 1 and 2 face the man in the middle's default key; step 3 faces a
  // *different* real one. `--host-key` needs no lying wrapper -- that peer is
  // entirely self-consistent, which is exactly what step 3 has to be: a
  // consistent peer with the wrong key is the case pinning exists for, and a
  // forged one would fail earlier for an unrelated reason.
  const honest = [];
  const other = ["--host-key", OTHER_KEY];

  console.log("");
  console.log("src/sshclient over TCP");
  const nativeLine = await runSequence(
    "native",
    honest,
    async (mitm, knownHosts) => {
      const args = ["--kh-host", "127.0.0.1", "--kh-tofu"];
      if (knownHosts) args.push("--known-hosts-text", knownHosts);
      return runNative(mitm.port, args);
    },
    other,
  );

  if (!browser) {
    skipped.push("the browser sequence");
  } else {
    console.log("");
    console.log("src/wtlive in a browser Worker");
    const browserLine = await runSequence(
      "browser",
      honest,
      async (mitm, knownHosts) => {
        const extra = { kh_host: "127.0.0.1", kh_tofu: "1" };
        if (knownHosts) extra.known_hosts = knownHosts;
        const br = await startBridge(mitm.port);
        if (!br.up) {
          return { authed: false, error: "bridge never came up: " + br.text().slice(0, 200), written: null, tofu: false };
        }
        const got = await runWorkerAuth(browser, httpPort, br.wsPort, "tofu", extra);
        br.bridge.kill();
        return got;
      },
      other,
    );

    // The one line both halves must produce. If they differ, a browser user and
    // a native user end up with different known_hosts files for the same server,
    // and neither can read the other's.
    if (nativeLine && browserLine) {
      if (nativeLine === browserLine) {
        ok("both transports write the same line", nativeLine.slice(0, 50) + "...");
      } else {
        bad("both transports write the same line", "\n        native   " + JSON.stringify(nativeLine) + "\n        browser " + JSON.stringify(browserLine));
      }
    }
  }

  if (browser) await browser.close();
  if (server) server.close();
  finish();

  function finish() {
    console.log("");
    if (skipped.length) console.log("skipped: " + skipped.join(", "));
    if (failures.length === 0) {
      console.log(`ALL PASS (${checks} checks)`);
      if (skipped.length) console.log(`skipped: ${skipped.join(", ")}`);
      writeFileSync(join(WORK, "last_gate49.txt"), `ALL PASS (${checks} checks)\n`);
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