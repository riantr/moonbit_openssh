// host/verify_loop48.mjs -- Loop #48: host key pinning, end to end.
//
// Loop #47 closed the two branches a client can reach when a peer's key
// exchange does not hold up. Both are *inconsistent* forgeries: the blob does
// not prove the signature. What they cannot reach is the attack that actually
// matters in practice -- a man in the middle with its own key and its own
// perfectly valid signature. That exchange is entirely self-consistent, so
// every signature check passes. The only thing that stops it is comparing the
// presented key against the one the client was told to expect, and before this
// loop **neither transport adapter did that at all**: `src/kexflow` carries the
// rule, and both live adapters implement their own handshake without going
// through kexflow, so the live client never pinned anything.
//
// Five cases per client, and the set matters more than any single one:
//
//   match          pin the key the peer actually sent   -> authenticate
//   mismatch       pin a different key                  -> refuse, send nothing
//   unknown-strict pin another host, strict             -> refuse, send nothing
//   unknown-tofu   pin another host, non-strict         -> authenticate (TOFU)
//   no-policy      no known_hosts at all                -> authenticate
//
// `unknown-tofu` and `no-policy` are the ones that look like failures and are
// not. They are here to pin down the policy that is actually in force: pinning
// is opt-in, and an unpinned host is accepted. OpenSSH's default is the
// opposite. Writing that down as a *passing* case is what keeps the gap visible
// instead of quietly closed by someone assuming it was handled.
//
// The matching case's known_hosts line is built from the blob the man in the
// middle reports in its transcript, not from a file checked into the repo. A
// pinned file would go stale the moment the key was regenerated, and the stale
// file would read as a mismatch -- which looks like a protocol bug and is a
// test-fixture problem.

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
const WORK = join(root, ".loop48");
const SSH_LIVE = join(root, "_build", "native", "debug", "build", "cmd", "ssh_live", "ssh_live.exe");
const WT_MODULE = join(root, "_build", "js", "debug", "build", "cmd", "wt_ssh", "wt_ssh.js");
// A real key the man in the middle never presents, so pinning it is a mismatch
// by construction rather than by assumption.
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
  };
}

// ---------------------------------------------------------------------------

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

// The known_hosts line the client is told to trust, for a key we know the peer
// is *not* using. paramiko's own keys.m line, because the format has to be the
// one OpenSSH writes -- a line we invented would only prove we can read our own
// invention.
async function knownHostsLineForOtherKey(hostField) {
  const r = spawnSync(
    "python",
    [join(root, "host", "known_hosts_line.py"), OTHER_KEY, hostField],
    { cwd: root, encoding: "utf-8", errors: "replace", timeout: 30000 },
  );
  if (r.status !== 0) throw new Error("known_hosts_line.py failed: " + (r.stderr || r.stdout));
  return String(r.stdout).trim();
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
    return { text: "", authed: false, error: out.error, leaf: "", net: state.net };
  }
  return { ...classify((out.lines || []).join("\n")), net: state.net };
}

// ---------------------------------------------------------------------------
// one case, one client
// ---------------------------------------------------------------------------

// `wantAuth` says whether the client is supposed to get past authentication.
// `wantLeaf` is the error it must report when it is not, or null.
function judge(label, got, wantAuth, wantLeaf, mitmData) {
  const problems = [];
  if (wantAuth) {
    if (!got.authed) problems.push(`did not authenticate: error=${JSON.stringify(got.error)}`);
  } else {
    if (got.authed) problems.push("reached USERAUTH_SUCCESS");
    if (wantLeaf && got.leaf !== wantLeaf) {
      problems.push(`error=${JSON.stringify(got.error)} want leaf ${wantLeaf}`);
    }
  }
  // The property that makes this a security test: a client can print whatever
  // it likes, but it cannot un-send userauth.
  if (!wantAuth && mitmData && mitmData.auth_attempts > 0) {
    problems.push(`${mitmData.auth_attempts} authentication attempt(s) reached a peer whose key was not pinned`);
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

  // ---- discovery ------------------------------------------------------
  // One connection whose only job is to make the man in the middle write its
  // transcript, so the known_hosts lines below can be built from the key the
  // peer actually presents. It doubles as the `no-policy` case, which is the
  // one that documents the policy actually in force: no pinning configured, and
  // the client authenticates anyway.
  let m = await startMitm("pin", []);
  const discovery = await runNative(m.port, []);
  await stopMitm(m);
  if (!discovery.authed) {
    bad("discovery", "an unpinned client failed to authenticate: " + JSON.stringify(discovery.error));
    return finish();
  }
  ok("native no-policy", "authenticated -- pinning is opt-in, not the default");

  const mitmData = readJson(join(WORK, "pin.json"));
  if (!mitmData || !mitmData.hostkey_blob_b64) {
    bad("man in the middle", "no transcript or no presented blob: " + JSON.stringify(mitmData).slice(0, 200));
    return finish();
  }
  const presented = mitmData.hostkey_blob_b64;
  const presentedType = mitmData.hostkey_announced_type;
  ok("the peer presents one self-consistent key", presentedType);

  // The host field is plain `127.0.0.1`, with no `:port`. Each case gets its
  // own man in the middle on its own port, and a `[host]:port` field would then
  // have to be rebuilt for every one of them -- coupling the fixture to the
  // ephemeral port is exactly the kind of coupling that makes a fixture go stale
  // silently. A plain host field is a legitimate known_hosts entry and matches
  // the same rule on both sides.
  const hostField = "127.0.0.1";
  const matchLine = `${hostField} ${presentedType} ${presented}`;
  const mismatchLine = await knownHostsLineForOtherKey(hostField);
  const otherHostLine = await knownHostsLineForOtherKey("other.example");

  // The peer never changes across these: it presents one consistent key, and
  // the client is told different things about what to expect. Every difference
  // between the answers is therefore the policy, not the peer.
  const cases = [
    { name: "match", line: matchLine, host: hostField, strict: false, auth: true, leaf: null },
    { name: "mismatch", line: mismatchLine, host: hostField, strict: false, auth: false, leaf: "HostkeyMismatch" },
    { name: "unknown-strict", line: otherHostLine, host: hostField, strict: true, auth: false, leaf: "HostkeyUnknown" },
    { name: "unknown-tofu", line: otherHostLine, host: hostField, strict: false, auth: true, leaf: null },
  ];

  function nativeArgs(c) {
    if (!c.line) return [];
    const args = ["--known-hosts-text", c.line, "--kh-host", c.host];
    if (c.strict) args.push("--kh-strict");
    return args;
  }
  function workerCfg(c) {
    if (!c.line) return {};
    const extra = { known_hosts: c.line, kh_host: c.host };
    if (c.strict) extra.kh_strict = "1";
    return extra;
  }

  // ---- the native client ------------------------------------------------
  console.log("");
  console.log("src/sshclient over TCP");
  for (const c of cases) {
    // One man in the middle serves one connection, so each case gets its own.
    const mitm = await startMitm(`pin-native-${c.name}`, []);
    const got = await runNative(mitm.port, nativeArgs(c));
    await stopMitm(mitm);
    // This connection's transcript, not the discovery run's: "zero
    // authentication attempts" only means something about the connection that
    // actually had zero.
    const here = readJson(mitm.json);
    const label = `native ${c.name}`;
    if (judge(label, got, c.auth, c.leaf, here)) {
      ok(label, c.auth ? "authenticated" : `refused with ${got.leaf}, 0 auth attempts`);
    }
  }

  // ---- the browser client ----------------------------------------------
  if (!browser) {
    skipped.push("the browser cases");
  } else {
    console.log("");
    console.log("src/wtlive in a browser Worker");
    for (const c of cases) {
      const mitm = await startMitm(`pin-browser-${c.name}`, []);
      const br = await startBridge(mitm.port);
      let got = { authed: false, error: "the bridge never came up: " + br.text().slice(0, 200), leaf: "" };
      if (br.up) {
        got = await runWorkerAuth(browser, httpPort, br.wsPort, `pin-${c.name}`, workerCfg(c));
        br.bridge.kill();
      }
      await stopMitm(mitm);
      const here = readJson(mitm.json);
      const label = `browser ${c.name}`;
      if (judge(label, got, c.auth, c.leaf, here)) {
        ok(label, c.auth ? "authenticated" : `refused with ${got.leaf}, 0 auth attempts`);
      }
    }

    // The browser half's own `no-policy` case: a browser client that skipped
    // the check must still get in, for the same reason the native one must.
    const mitm = await startMitm("pin-browser-nopolicy", []);
    const br = await startBridge(mitm.port);
    let got = { authed: false, error: "the bridge never came up: " + br.text().slice(0, 200), leaf: "" };
    if (br.up) {
      got = await runWorkerAuth(browser, httpPort, br.wsPort, "pin-nopolicy", {});
      br.bridge.kill();
    }
    await stopMitm(mitm);
    if (got.authed) ok("browser no-policy", "authenticated -- pinning is opt-in, not the default");
    else bad("browser no-policy", "an unpinned client failed to authenticate: " + JSON.stringify(got.error));
  }

  // ---- the reference implementation ------------------------------------
  console.log("");
  console.log("paramiko, as the reference");
  const wmitm = await startMitm("pin-witness", []);
  const khPath = join(WORK, "witness.known_hosts");
  // The bracketed `[host]:port` form, because that is how paramiko looks a host
  // up. With a plain host field it reported "not found in known_hosts" -- a
  // refusal, but for a different reason than the one under test, and a witness
  // that refuses for the wrong reason is not a witness.
  writeFileSync(
    khPath,
    (await knownHostsLineForOtherKey(`[127.0.0.1]:${wmitm.port}`)) + "\n",
    "utf8",
  );
  const w = spawnSync(
    "python",
    [join(root, "host", "hostkey_witness.py"), String(wmitm.port), "--known-hosts", khPath],
    { cwd: root, encoding: "utf-8", errors: "replace", timeout: 60000 },
  );
  await stopMitm(wmitm);
  let witness = null;
  try {
    witness = JSON.parse(String(w.stdout || "").trim().split("\n").pop() || "{}");
  } catch {
    witness = null;
  }
  if (witness && witness.refused && witness.because_of_host_key) {
    ok("paramiko rejects a pinned mismatch", String(witness.error).slice(0, 90));
  } else if (witness && witness.refused) {
    // It refused, but not because of the pin -- an unrelated failure would
    // otherwise stand in as evidence that pinning works.
    bad("paramiko rejects a pinned mismatch", "refused for the wrong reason: " + String(witness.error).slice(0, 160));
  } else {
    bad("paramiko rejects a pinned mismatch", JSON.stringify(witness || `${w.stdout}${w.stderr}`).slice(0, 200));
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
      writeFileSync(join(WORK, "last_gate48.txt"), `ALL PASS (${checks} checks)\n`);
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