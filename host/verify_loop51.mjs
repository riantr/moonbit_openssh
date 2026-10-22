// host/verify_loop51.mjs -- Loop #51: `@cert-authority` is not a host key pin.
//
// Loop #50 made refusing the default. This loop closes a hole that hole made
// reachable: a `@cert-authority` line was treated as an ordinary trust entry, so
// a peer that presented the CA's own public key as its host key was accepted and
// credentials went out. Measured, not theorised -- `host/probe_certauthority.mjs`
// printed AUTHENTICATED next to the direct-pin control before this fix.
//
// The entry says "trust this host only when it presents a certificate signed by
// this CA". This client does not validate host certificates. So the entry is a
// question we cannot answer -- and the two obvious ways to answer it are both
// wrong, in opposite directions:
//
//   treat it as a direct pin   -> fail open when the blobs coincide (the hole)
//   treat it as a mismatch    -> fail closed, but accuse a man in the middle
//                                who does not exist, and the documented remedy
//                                for HOST_CHANGED is "add --kh-tofu"
//
// That second one is why this is more than a missing check. A client that cries
// wolf about a perfectly ordinary CA deployment trains its user to disable the
// protection, and Loop #50's whole argument was that turning protection off
// should cost a deliberate keystroke. The bug was finding ways around the
// keystroke.
//
// The six cases, on both transports:
//
//   ca-same-blob    @cert-authority, CA blob == presented  -> refuse, cert-authority
//   ca-other-blob   @cert-authority, a real different CA   -> refuse, cert-authority
//   tofu-ca         the same, plus --kh-tofu               -> refuse
//   direct-pin      the control                            -> authenticate
//   revoked         the other control                      -> refuse, mismatch
//   unpinned        nothing configured (Loop #50's default)-> refuse, unknown
//
// `ca-other-blob` is the one that looks like a pass and is not: refusing is
// correct, but refusing *for the wrong reason* is the damage. A user whose
// known_hosts legitimately pins a CA must be told "this client does not do
// certificates", not "the host key changed". Asserting only the refusal would
// let the accusation through, which is why the leaf name is compared here and
// not just the yes/no.
//
// Every refusal also asserts its `hint:` line, and that the hint mentions what
// that case is about. A distinct error *name* changes nothing on its own: an
// unfamiliar label in a log is still an unfamiliar label, and the user walks the
// path they walked last time. `revoked` must say "man in the middle" and `ca-*`
// must say "certificate", so the three cannot quietly converge back into one
// paragraph while every leaf name stays correct.
//
// `tofu-ca` exists because "accept what you haven't seen" reads like permission
// to accept this. It is not: TOFU is about a host with *no* pin, and letting it
// through would restore exactly the downgrade this loop removes, through a
// switch that looks entirely reasonable.

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
import { sshUser } from "./ssh_user.mjs";
import { waitForMitmReady } from "./mitm_ready.mjs";

let chromium = null;
try {
  ({ chromium } = await import("playwright"));
} catch {
  /* reported below */
}

const root = resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const WORK = join(root, ".loop51");
const SSH_LIVE = join(root, "_build", "native", "debug", "build", "cmd", "ssh_live", "ssh_live.exe");
const WT_MODULE = join(root, "_build", "js", "debug", "build", "cmd", "wt_ssh", "wt_ssh.js");
// A real key the man in the middle never presents, standing in for a real CA.
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
    hint: grab(n, "hint") || "",
  };
}

async function startMitm(tag) {
  const port = await freePort();
  const json = join(WORK, `${tag}.json`);
  const proc = spawn(
    "python",
    [join(root, "host", "sftp_mitm.py"), String(port), "--json", json],
    { cwd: root, stdio: ["ignore", "pipe", "pipe"] },
  );
  let err = "";
  proc.stderr.on("data", (d) => (err += d.toString()));
  // Wait for the MITM to say it is listening, rather than guessing how long
  // that takes.  See host/mitm_ready.mjs.
  await waitForMitmReady(() => err);
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
  const r = spawnSync(SSH_LIVE, [String(port), "--auth", "--user", sshUser(), ...args], {
    cwd: root, encoding: "utf-8", errors: "replace", maxBuffer: 64 * 1024 * 1024, timeout: 90000,
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
      if (text.includes("listening")) { clearTimeout(t); res(true); }
    });
    bridge.on("exit", () => { clearTimeout(t); res(false); });
  });
  return { bridge, wsPort, up, text: () => text };
}

async function runWorkerAuth(browser, httpPort, wsPort, tag, extraCfg) {
  const base = `http://127.0.0.1:${httpPort}`;
  const cfg = wtCfg(base, httpPort, wsPort, { nonce: tag, user: sshUser(), auth: "1", ...extraCfg });
  const { page, state } = await openPage(browser, httpPort, { freshStorage: true });
  let out;
  try {
    out = await runWorker(page, cfg);
  } finally {
    await page.close();
  }
  if (out.error) {
    return { authed: false, error: out.error, leaf: "", net: state.net };
  }
  return { ...classify((out.lines || []).join("\n")), net: state.net };
}

async function otherKeyLine(hostField) {
  const r = spawnSync("python", [join(root, "host", "known_hosts_line.py"), OTHER_KEY, hostField],
    { cwd: root, encoding: "utf-8", errors: "replace", timeout: 30000 });
  if (r.status !== 0) throw new Error("known_hosts_line.py failed: " + (r.stderr || r.stdout));
  return String(r.stdout).trim();
}

// ---------------------------------------------------------------------------

// `wantLeaf` is the whole point of most cases here. A refusal that arrives with
// the wrong reason is a different failure, and for `ca-other-blob` it is the
// failure this loop exists to prevent.
function judge(label, got, wantAuth, wantLeaf, data, wantHint) {
  const problems = [];
  if (wantAuth) {
    if (!got.authed) problems.push(`did not authenticate: error=${JSON.stringify(got.error)}`);
  } else {
    if (got.authed) problems.push("reached USERAUTH_SUCCESS");
    if (got.leaf !== wantLeaf) {
      problems.push(`error=${JSON.stringify(got.error)} want leaf ${wantLeaf}`);
    }
    // A distinct error *name* changes nothing on its own: an unfamiliar label
    // in a log is just an unfamiliar label, and the user still walks the path
    // they walked last time. Asserting the prose keeps the argument honest --
    // deleting `print_pin_hint` would otherwise turn every gate green again
    // while silently putting back the autopilot this loop was written against.
    if (wantHint) {
      if (!got.hint) problems.push("no `hint:` line -- the error name alone does not tell the user what to do");
      else if (!got.hint.toLowerCase().includes(wantHint)) {
        problems.push(`hint does not mention ${JSON.stringify(wantHint)}: ${got.hint.slice(0, 120)}`);
      }
    }
  }
  if (!wantAuth && data && data.auth_attempts > 0) {
    problems.push(`${data.auth_attempts} authentication attempt(s) reached a peer it should have refused`);
  }
  // Same reasoning as Loop #50: a peer that never presented a key also shows
  // zero auth attempts, and would pass for a refusal it did not earn.
  if (!wantAuth && data && !data.hostkey_blob_b64) {
    problems.push("the peer never presented a host key, so the refusal cannot be about pinning");
  }
  if (problems.length) { bad(label, problems.join("\n      ")); return false; }
  return true;
}

// ---------------------------------------------------------------------------

async function main() {
  mkdirSync(WORK, { recursive: true });

  console.log("build");
  const b1 = spawnSync("cmd", ["/c", "moon", "build", "cmd\\ssh_live", "--target", "native"],
    { cwd: root, encoding: "utf-8", errors: "replace", maxBuffer: 64 * 1024 * 1024 });
  if (b1.status !== 0 || !existsSync(SSH_LIVE)) {
    bad("build ssh_live (native)", norm(`${b1.stdout || ""}${b1.stderr || ""}`).trim().split("\n").slice(-10).join("\n      "));
    return finish();
  }
  ok("build cmd/ssh_live (native)");
  const b2 = spawnSync("cmd", ["/c", "moon", "build", "cmd\\wt_ssh", "--target", "js"],
    { cwd: root, encoding: "utf-8", errors: "replace", maxBuffer: 64 * 1024 * 1024 });
  if (b2.status !== 0 || !existsSync(WT_MODULE)) {
    bad("build wt_ssh (js)", norm(`${b2.stdout || ""}${b2.stderr || ""}`).trim().split("\n").slice(-10).join("\n      "));
    return finish();
  }
  ok("build cmd/wt_ssh (js)");

  if (!existsSync(OTHER_KEY)) {
    bad("a real CA key", "missing " + OTHER_KEY + " (Loop #47 generates it)");
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

  // Learn the key the peer actually presents. --kh-tofu here is only to get
  // past the handshake; nothing downstream uses this connection's acceptance.
  let m = await startMitm("discover");
  await runNative(m.port, ["--kh-tofu"]);
  await stopMitm(m);
  const d = readJson(m.json);
  if (!d || !d.hostkey_blob_b64) {
    bad("the peer", "no transcript or no presented blob: " + JSON.stringify(d).slice(0, 200));
    return finish();
  }
  const type = d.hostkey_announced_type;
  const blob = d.hostkey_blob_b64;
  ok("the peer presents one key", type);

  const host = "127.0.0.1";
  const realCa = await otherKeyLine(host);
  const realCaBlob = realCa.split(" ")[2];

  const cases = [
    {
      name: "ca-same-blob",
      line: `@cert-authority ${host} ${type} ${blob}`,
      auth: false, leaf: "HostkeyCertAuthority", hint: "certificate",
      note: "the fail-open, closed",
    },
    {
      name: "ca-other-blob",
      line: `@cert-authority ${host} ${realCa.split(" ")[1]} ${realCaBlob}`,
      auth: false, leaf: "HostkeyCertAuthority", hint: "certificate",
      note: "a legitimate CA setup must not be reported as a man in the middle",
    },
    {
      name: "tofu-ca",
      line: `@cert-authority ${host} ${type} ${blob}`,
      tofu: true,
      auth: false, leaf: "HostkeyCertAuthority", hint: "certificate",
      note: "accept-new must not restore the downgrade",
    },
    {
      name: "direct-pin",
      line: `${host} ${type} ${blob}`,
      auth: true, leaf: null, hint: null,
      note: "the control: pinning still works",
    },
    {
      name: "revoked",
      line: `@revoked ${host} ${type} ${blob}`,
      auth: false, leaf: "HostkeyMismatch", hint: "man in the middle",
      note: "the other control: revocation still bites first",
    },
    {
      name: "unpinned",
      line: null,
      auth: false, leaf: "HostkeyUnknown", hint: "no key pinned",
      note: "the control: Loop #50's default, told apart in prose too",
    },
  ];

  function nativeArgs(c) {
    // `unpinned` passes nothing at all -- it is Loop #50's default case, and the
    // point is that no flag has to be typed to reach it.
    if (!c.line) return [];
    const args = ["--known-hosts-text", c.line, "--kh-host", host];
    if (c.tofu) args.push("--kh-tofu");
    return args;
  }
  function workerCfg(c) {
    if (!c.line) return {};
    const extra = { known_hosts: c.line, kh_host: host };
    if (c.tofu) extra.kh_tofu = "1";
    return extra;
  }

  console.log("");
  console.log("src/sshclient over TCP");
  for (const c of cases) {
    const mitm = await startMitm(`native-${c.name}`);
    const got = await runNative(mitm.port, nativeArgs(c));
    await stopMitm(mitm);
    const data = readJson(mitm.json);
    const label = `native ${c.name}`;
    if (judge(label, got, c.auth, c.leaf, data, c.hint)) ok(label, c.note);
  }

  if (!browser) {
    skipped.push("the browser cases");
  } else {
    console.log("");
    console.log("src/wtlive in a browser Worker");
    for (const c of cases) {
      const mitm = await startMitm(`browser-${c.name}`);
      const br = await startBridge(mitm.port);
      let got = { authed: false, error: "the bridge never came up: " + br.text().slice(0, 200), leaf: "" };
      if (br.up) {
        got = await runWorkerAuth(browser, httpPort, br.wsPort, `ca-${c.name}`, workerCfg(c));
        br.bridge.kill();
      }
      await stopMitm(mitm);
      const data = readJson(mitm.json);
      const label = `browser ${c.name}`;
      if (judge(label, got, c.auth, c.leaf, data, c.hint)) ok(label, c.note);
    }
  }

  console.log("");
  console.log("unit");
  const t = spawnSync("cmd", ["/c", "moon", "test", "src\\knownhosts"],
    { cwd: root, encoding: "utf-8", errors: "replace", maxBuffer: 64 * 1024 * 1024, timeout: 900000 });
  const tout = norm(t.stdout || "") + norm(t.stderr || "");
  const mTotal = tout.match(/Total tests: (\d+), passed: (\d+), failed: (\d+)/);
  if (mTotal && mTotal[3] === "0") ok("src/knownhosts", `${mTotal[2]}/${mTotal[1]} unit tests`);
  else bad("src/knownhosts", tout.trim().split("\n").slice(-6).join("\n      "));

  if (browser) await browser.close();
  if (server) server.close();
  finish();

  function finish() {
    console.log("");
    if (skipped.length) console.log("skipped: " + skipped.join(", "));
    if (failures.length === 0) {
      console.log(`ALL PASS (${checks} checks)`);
      writeFileSync(join(WORK, "last_gate51.txt"), `ALL PASS (${checks} checks)\n`);
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
