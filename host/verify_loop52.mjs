// host/verify_loop52.mjs -- Loop #52: a pin that survives the page going away.
//
// Loops #49 and #50 made the *decision* right and the *rendering* right, and then
// printed the line. Printing is not remembering. The gate caught stdout and fed
// the line back by hand; a browser user has nobody to do that, so their pin lives
// exactly as long as the test that produced it. `--kh-tofu` on Tuesday, unpinned
// again on Wednesday -- which is the state TOFU exists to remove.
//
// The shape of this gate is the only thing that makes it worth writing. The
// obvious version passes for the wrong reason:
//
//   step 1  kh_tofu        -> authenticated, "tofu: stored"
//   step 2  no flags       -> authenticated
//
// Step 2 succeeding could mean the store worked, or it could mean nothing
// changed and the browser is still holding the first connection's state. Both
// look identical from inside one page. So every step after the first runs in a
// **fresh page** (`openPage` calls `newPage`, and localStorage is scoped to the
// origin): everything that lives in a module variable, a Worker, or a closure is
// gone, and only what was actually written to storage can answer step 2.
//
// The negative case is what makes it more than a round trip:
//
//   no-pinning-flags, no stored pin -> refuse
//   stored pin, no flags            -> authenticate  <- the whole point
//   stored pin, a different key     -> refuse, HostkeyMismatch
//
// And the two directions of "forgetting", because a store you cannot clear is a
// store you cannot recover from when a key really does change:
//
//   forget()  -> refused, and refused as *unknown*, not as a mismatch
//
// That last one is worth its own case. After forgetting, the honest answer is
// "this host is not pinned any more", and answering `Mismatch` would accuse
// whoever holds the next key -- the exact false accusation Loop #51 was about.
// A store that made forgetting indistinguishable from a compromise would be worse
// than no store.

import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { waitForMitmReady } from "./mitm_ready.mjs";
import path from "node:path";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  exitedWithin,
  freePort,
  grab,
  newPageInSharedContext,
  norm,
  openPage,
  runWorker,
  serve,
  sleep,
  wtCfg,
} from "./wt_browser.mjs";
import {
  hasAcceptedUnpinned,
  hasNotStored,
  hasStored,
  tofuEntry,
} from "./tofu_transcript.mjs";
import { sshUser } from "./ssh_user.mjs";

let chromium = null;
try {
  ({ chromium } = await import("playwright"));
} catch {
  /* reported below */
}

const root = resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const WORK = join(root, ".loop52");
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
    stored: hasStored(n),
    notStored: hasNotStored(n),
    fromStorage: /^known_hosts: \d+ bytes from storage$/m.test(n),
    // `host/tofu_transcript.mjs` knows which `tofu:` line is the entry. It exists
    // because this filter, and the same filter in `verify_loop49` and
    // `verify_loop50`, were three copies of one list -- and Loop #52's two new
    // status lines broke two of them before the list was lifted out.
    tofuLine: tofuEntry(n),
    tofuAccepted: hasAcceptedUnpinned(n),
  };
}

async function startMitm(tag) {
  const port = await freePort();
  const json = join(WORK, `${tag}.json`);
  const proc = spawn("python", [join(root, "host", "sftp_mitm.py"), String(port), "--json", json],
    { cwd: root, stdio: ["ignore", "pipe", "pipe"] });
  let err = "";
  proc.stderr.on("data", (d) => (err += d.toString()));
  // Wait for the MITM to say it is listening, rather than guessing how long
  // that takes.  See host/mitm_ready.mjs.
  await waitForMitmReady(() => err);
  // Check that it is actually alive. `freePort()` closes a listener and hands the
  // number back, and the OS is free to give that same number to something else --
  // or to refuse it, in which case paramiko exits immediately with an address
  // already in use. Without this check the gate proceeds against a dead server,
  // and the connection that follows reaches whatever else holds the port: the
  // symptom is a transcript with an authentication in it under a tag whose client
  // never connected, which is exactly what `kh_forget` looked like.
  if (proc.exitCode !== null || proc.signalCode !== null) {
    throw new Error(
      `the man in the middle for ${tag} died on port ${port}: ${err.trim().slice(0, 200)}`,
    );
  }
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

async function startBridge(tcpPort) {
  const wsPort = await freePort();
  const bridge = spawn("node",
    [join(root, "host", "wt_mitm_bridge.mjs"), "--listen-port", String(wsPort), "--target-port", String(tcpPort)],
    { cwd: root, stdio: ["ignore", "pipe", "pipe"] });
  let text = "";
  bridge.stdout.on("data", (d) => (text += d.toString()));
  bridge.stderr.on("data", (d) => (text += d.toString()));
  const up = await new Promise((res) => {
    const t = setTimeout(() => res(false), 15000);
    bridge.stdout.on("data", () => { if (text.includes("listening")) { clearTimeout(t); res(true); } });
    bridge.on("exit", () => { clearTimeout(t); res(false); });
  });
  return { bridge, wsPort, up, text: () => text };
}

// One connection, in its own page, against its own man in the middle.
//
// `page` is deliberately *not* passed in: a fresh page is the isolation this gate
// depends on. `extraCfg` merges over the defaults, and `known_hosts` is left out
// by default so the client has to find its own pin.
async function connect(browser, httpPort, tag, mitm, extraCfg = {}) {
  const br = await startBridge(mitm.port);
  if (!br.up) {
    return {
      text: "",
      authed: false,
      leaf: "",
      error: "bridge never came up: " + br.text().slice(0, 200),
      stored: false,
      notStored: false,
      fromStorage: false,
      tofuLine: null,
    };
  }
  const base = `http://127.0.0.1:${httpPort}`;
  // The account to authenticate as: derived, never written down (Loop #76).
  // The man in the middle accepts any name, so this is not about the gate
  // passing -- it is about a gate that says one developer's account name
  // being a fact about the protocol.
  const cfg = wtCfg(base, httpPort, br.wsPort, { nonce: tag, user: sshUser(), auth: "1", ...extraCfg });
  const { page, state } = await openPage(browser, httpPort);
  let got;
  try {
    const out = await runWorker(page, cfg);
    got = out.error
      ? {
          text: "",
          authed: false,
          leaf: "",
          error: out.error,
          stored: false,
          notStored: false,
          fromStorage: false,
          tofuLine: null,
        }
      : classify((out.lines || []).join("\n"));
  } finally {
    await page.close();
  }
  br.bridge.kill();
  if (state.pageErrors.length) got.pageErrors = state.pageErrors;
  return got;
}

// Ask the browser directly, rather than believing the client's own report.
//
// The first version of step 1 asserted the `tofu: stored` line, and mutation A
// (`let stored = true`) sailed straight through it -- because `stored` was
// exactly what A made it. A self-report checked against itself is not evidence.
// Reading the same IndexedDB the client wrote, from this side, is: a client that
// claims to have stored something and did not now fails at step 1 instead of
// quietly at step 2.
async function readStore(browser, httpPort, host) {
  const page = await newPageInSharedContext(browser);
  try {
    await page.goto(`http://127.0.0.1:${httpPort}/host/wt/probe.html`);
    return await page.evaluate(
      // The key is namespaced by `src/khstore`'s `storage_key`, and the
      // prefix is part of what is being checked -- a pin filed under the bare
      // host name would look identical from here and be found by nothing.
      (k) =>
        new Promise((resolve) => {
          const open = indexedDB.open("moonbit.ssh.known_hosts");
          open.onerror = () => resolve({ error: "open failed" });
          open.onsuccess = () => {
            const db = open.result;
            if (!db.objectStoreNames.contains("pins")) {
              resolve({ error: "no object store" });
              return;
            }
            const req = db.transaction("pins", "readonly").objectStore("pins").get(k);
            req.onsuccess = () =>
              resolve({ value: req.result === undefined ? null : req.result });
            req.onerror = () => resolve({ error: "get failed" });
          };
        }),
      // Duplicated from `src/khstore/storage_key` on purpose. If the shim ever
      // changes it, this lookup returns null and step 1 fails loudly rather than
      // quietly agreeing with a store that moved.
      "moonbit.ssh.known_hosts/" + host,
    );
  } finally {
    await page.close();
  }
}

function judge(label, got, wantAuth, wantLeaf, data) {
  const problems = [];
  // A connection that never got as far as a host key is not a pinning result, it
  // is a harness or timing problem. Reporting it as "wanted HostkeyUnknown, got
  // NoServerIdent" sends the next reader looking for a pinning bug that is not
  // there -- and under mutation A that is exactly what happened, once.
  const LEAFES_WITHOUT_A_HOST_KEY = ["NoServerIdent", "ConnectFailed", "KexinitSendFailed", "NoPeerKexinit", "ConnectFailed"];
  if (!wantAuth && LEAFES_WITHOUT_A_HOST_KEY.includes(got.leaf)) {
    bad(label, `never reached a host key (leaf=${got.leaf}): ${JSON.stringify(got.error).slice(0, 120)}`);
    return false;
  }
  if (wantAuth) {
    if (!got.authed) problems.push(`did not authenticate: error=${JSON.stringify(got.error)}`);
  } else {
    if (got.authed) problems.push("reached USERAUTH_SUCCESS");
    if (got.leaf !== wantLeaf) problems.push(`error=${JSON.stringify(got.error)} want leaf ${wantLeaf}`);
  }
  if (!wantAuth && data && data.auth_attempts > 0) {
    problems.push(`${data.auth_attempts} authentication attempt(s) reached a peer it should have refused`);
  }
  if (got.pageErrors && got.pageErrors.length) {
    problems.push("page errors: " + got.pageErrors.slice(0, 2).join(" | "));
  }
  if (problems.length) { bad(label, problems.join("\n      ")); return false; }
  return true;
}

async function main() {
  // Wipe the scratch directory first. Not tidiness: step 4a asserts that the man in
// the middle wrote **no** transcript, and a file left by a previous run is
// indistinguishable from one written by this one. The first version of this gate
// read exactly that stale file and reported an authentication attempt that never
// happened -- a failure with no cause behind it, which is the worst kind to chase.
for (const f of existsSync(WORK) ? readdirSync(WORK) : []) {
  rmSync(join(WORK, f), { force: true });
}
mkdirSync(WORK, { recursive: true });

  console.log("build");
  const b = spawnSync("cmd", ["/c", "moon", "build", "cmd\\wt_ssh", "--target", "js"],
    { cwd: root, encoding: "utf-8", errors: "replace", maxBuffer: 64 * 1024 * 1024 });
  if (b.status !== 0 || !existsSync(WT_MODULE)) {
    bad("build wt_ssh (js)", norm(`${b.stdout || ""}${b.stderr || ""}`).trim().split("\n").slice(-10).join("\n      "));
    return finish();
  }
  ok("build cmd/wt_ssh (js)");

  if (!chromium) {
    skipped.push("every case (playwright is not installed)");
    console.log("  SKIP  every case: playwright is not installed");
    return finish();
  }
  let browser = null;
  try {
    browser = await chromium.launch({ headless: true });
    ok("browser launched");
  } catch (e) {
    skipped.push("every case (chromium not installed)");
    console.log("  SKIP  every case: " + String(e).split("\n")[0]);
    return finish();
  }

  const httpPort = await freePort();
  const server = await serve(root, httpPort);
  const HOST = "127.0.0.1";

  // ---- step 0: nothing stored, nothing pinned --------------------------
  // The control for step 1. If this ever authenticates, every later "it
  // remembered" result is void.
  console.log("");
  console.log("step 0: an empty store refuses");
  let m0 = await startMitm("s0");
  const g0 = await connect(browser, httpPort, "s0", m0);
  await stopMitm(m0);
  if (judge("empty store", g0, false, "HostkeyUnknown", readJson(m0.json))) {
    ok("empty store", "refused with HostkeyUnknown -- nothing was remembered yet");
  }

  // ---- step 1: accept, and write ---------------------------------------
  console.log("");
  console.log("step 1: accept a new key and store it");
  let m1 = await startMitm("s1");
  const g1 = await connect(browser, httpPort, "s1", m1, { kh_tofu: "1", kh_host: HOST });
  await stopMitm(m1);
  if (judge("tofu", g1, true, null, readJson(m1.json))) {
    const store = await readStore(browser, httpPort, HOST);
    if (!store.value) {
      bad("tofu", "authenticated and said it stored, but the browser has nothing: " +
        JSON.stringify(store).slice(0, 160));
    } else if (!g1.tofuLine) {
      bad("tofu", "stored correctly, but the printed line is missing -- store and transcript must agree");
    } else {
      ok("tofu", `accepted, and the browser really holds the pin (${store.value.length} bytes)`);
    }
  }

  const d1 = readJson(m1.json);
  if (!d1 || !d1.hostkey_blob_b64) {
    bad("the peer", "no transcript: " + JSON.stringify(d1).slice(0, 160));
    return finish();
  }
  const type = d1.hostkey_announced_type;
  const blob = d1.hostkey_blob_b64;

  // The stored text must carry *the key we were shown*, not merely something.
  // Checked after the transcript is read, and as its own line, because a pin
  // filed under the right host with the wrong key would authenticate on the next
  // connection only by luck -- and "only by luck" is exactly what TOFU is.
  const storedNow = await readStore(browser, httpPort, HOST);
  if (storedNow.value && !(storedNow.value.includes(type) && storedNow.value.includes(blob))) {
    bad("the stored pin", `does not carry the key presented: ${JSON.stringify(storedNow.value).slice(0, 160)}`);
  } else if (storedNow.value) {
    ok("the stored pin", "carries the key the peer actually presented");
  }

  // ---- step 2: a brand new page, no flags ------------------------------
  // The whole loop. Nothing is passed in: not the line, not `kh_tofu`, not a
  // config key. The client has to find the pin by itself.
  console.log("");
  console.log("step 2: a new page, no flags at all");
  let m2 = await startMitm("s2");
  const g2 = await connect(browser, httpPort, "s2", m2, { kh_host: HOST });
  await stopMitm(m2);
  if (judge("remembered", g2, true, null, readJson(m2.json))) {
    if (!g2.fromStorage) {
      bad("remembered", "authenticated, but nothing said it read a pin -- so it was not the store that let it in");
    } else {
      ok("remembered", "authenticated from the stored pin, no unsafe switch, new page");
    }
  }

  // ---- step 3: the host changes keys ----------------------------------
  // A store that remembers everything and checks nothing is not a pin, it is a
  // cache. This is the case that keeps step 2 honest.
  console.log("");
  console.log("step 3: a different real key is refused");
  let m3 = await startMitm("s3");
  const g3 = await connect(browser, httpPort, "s3", m3, {
    kh_host: HOST,
    // Same host, same storage key, a key that is definitely not the stored one.
    known_hosts: `${HOST} ${type} AAAA`,
  });
  await stopMitm(m3);
  if (judge("key changed", g3, false, "HostkeyMismatch", readJson(m3.json))) {
    ok("key changed", "refused with HostkeyMismatch -- the store does not override a pin");
  }

  // ---- step 4: forgetting ---------------------------------------------
  // Clearing the pin must be possible, and it must read as "not pinned any
  // more", not as "someone changed the key". A store that cannot express the
  // difference is worse than no store: it will cry wolf about a legitimate key
  // rotation and its users will learn to click through.
  //
  // Two steps on purpose, and that is the design under test rather than a detail
  // of the harness. `kh_forget` forgets and *stops* -- it does not go on to
  // accept whatever the peer presents. Folding the two together is exactly how a
  // "remove this pin" button becomes a silent accept, which is the fail-open
  // Loop #51 closed. So step 4a forgets without connecting, and step 4b connects
  // and must be refused.
  //
  // 4a passes `kh_tofu` as well, and that combination is the point. Forgetting
  // and accepting together is how one becomes the other, and a `kh_forget` that
  // honours both is a "remove this pin" button that silently trusts whoever shows
  // up next.
  //
  // Trying `kh_forget` alone would have been satisfied by any implementation that
  // simply forgot and carried on: the pin is gone, so the connection that follows
  // reads an empty store and is refused anyway. That is *safe*, and the mutation
  // driver spent four attempts discovering that removing the `return` alone was
  // never a vulnerability. Testing the combination is what reaches one.
  console.log("");
  console.log("step 4: forgetting reads as 'unknown', not as a mismatch");
  let m4a = await startMitm("s4a");
  const g4a = await connect(browser, httpPort, "s4a", m4a, {
    kh_forget: "1",
    kh_tofu: "1",
    kh_host: HOST,
  });
  await stopMitm(m4a);
  // Deliberately **not** read here. The assertion below is `existsSync`, because
  // "the man in the middle wrote nothing" is the evidence that no connection
  // happened, and reading a file that a previous run may have left behind turns
  // that into a statement about history.
  //
  // `.loop52/` is not cleaned between runs, which is what made the first version
  // of this report an authentication that never happened.
  if (g4a.authed) {
    bad("forget", "kh_forget authenticated -- forgetting must not also accept what comes next");
  } else if (/timeout/i.test(g4a.error || "")) {
    // Worth its own message. A mode that prints its output and then never signals
    // completion is a real bug, but the harness reports it as a plain timeout --
    // which reads like a slow machine, not like a missing `wt_finish`. `kh_forget`
    // shipped exactly that way once.
    bad("forget", "the mode printed nothing to the harness and timed out; check that it calls wt_finish");
  } else if (!/^forget: /m.test(norm(g4a.text))) {
    bad("forget", "no `forget:` line: " + JSON.stringify(g4a.text).slice(0, 160));
  } else if (existsSync(m4a.json)) {
    // The right assertion for "it did not connect": the man in the middle writes
    // its transcript when a connection happens, so **no file at all** is the
    // evidence. The first version read the transcript and asserted
    // `auth_attempts == 0`, which reads a stale file left by a previous run --
    // `.loop52/` is not cleaned between runs -- and reported an authentication
    // that never happened. An assertion whose input may predate the test is not
    // an assertion.
    bad("forget", "the man in the middle wrote a transcript, so something connected");
  } else {
    ok("forget", "pin cleared, nothing connected, and nothing was accepted despite kh_tofu");
  }

  let m4 = await startMitm("s4");
  const g4 = await connect(browser, httpPort, "s4", m4, { kh_host: HOST });
  await stopMitm(m4);
  if (judge("after forgetting", g4, false, "HostkeyUnknown", readJson(m4.json))) {
    ok("after forgetting", "refused with HostkeyUnknown -- 'not pinned', not 'the key changed'");
  }

  // ---- step 5: no store installed at all ---------------------------------
  // The case that used to crash the client.
  //
  // `src/khstore` says "never throw; every failure is a value", and it meant it
  // for a store that *fails*. It did not mean it for a store that is not
  // *there*: the extern bodies went straight to `globalThis.__moonbit_khs`, so a
  // Worker with no store installed raised a TypeError on the very first
  // property access -- synchronously, outside any promise chain. And
  // `cmd/wt_ssh` reads the store on *every* connection, so "no store" was not an
  // edge case; it was every browser run that forgot to load the shim.
  //
  // So this step removes the store (`khsShimUrl: ''` -- an explicit "there is
  // none", which is a different thing from "I did not think about it") and
  // connects. Two things must hold:
  //
  //   * the connection still succeeds. A missing pin store is not a broken
  //     connection, and treating it as one would let a private-mode browser
  //     masquerade as a man in the middle;
  //   * the client *says* the pin was not stored, because the next connection
  //     will need `kh_tofu` again. A client that said "stored" here would be
  //     lying, and the user would find out on the next connection.
  console.log("");
  console.log("step 5: with no store installed at all");
  let m5 = await startMitm("s5");
  const g5 = await connect(browser, httpPort, "s5", m5, {
    khsShimUrl: "",
    kh_tofu: "1",
    kh_host: HOST,
  });
  await stopMitm(m5);
  const s5 = [];
  if (!g5.authed) {
    s5.push("the connection failed: " + JSON.stringify(g5.error).slice(0, 160));
  }
  if (!g5.tofuAccepted) s5.push("no `tofu: accepted-unpinned` line");
  if (!g5.notStored) s5.push("no `tofu: NOT stored` line");
  if (g5.stored) s5.push("the client said `tofu: stored` with no store installed");
  if (g5.pageErrors && g5.pageErrors.length) {
    s5.push("page errors: " + g5.pageErrors.slice(0, 2).join(" | "));
  }
  if (s5.length) {
    bad("no store installed", s5.join("\n      "));
  } else {
    ok("no store installed", "connected anyway, and said the pin was not stored");
  }

  if (browser) await browser.close();
  if (server) server.close();
  finish();

  function finish() {
    console.log("");
    if (skipped.length) console.log("skipped: " + skipped.join(", "));
    if (failures.length === 0) {
      console.log(`ALL PASS (${checks} checks)`);
      writeFileSync(join(WORK, "last_gate52.txt"), `ALL PASS (${checks} checks)\n`);
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