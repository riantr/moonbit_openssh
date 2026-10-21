// host/verify_loop47.mjs -- Loop #47: a peer that lies about its host key.
//
// Every handshake test in this repo so far has talked to a peer that told the
// truth. Loop #38 pinned the host key algorithms against a real sshd; Loops #34,
// #35, #36, #39, #40 and #43-#46 all completed handshakes against a man in the
// middle whose host key was correct. So `HostkeyInvalid` and `SignatureInvalid`
// are defined in both transport adapters and **nothing has ever driven them** --
// they are reachable only by a peer whose key exchange does not hold up.
//
// That is the most security-relevant gap left. The property is not "the client
// reports an error"; it is **the client sends no credentials at all**. An
// implementation that logs an error and then authenticates anyway has leaked the
// very thing the error was about. So the man in the middle counts the
// authentication attempts it is asked to approve -- it approves everything, so
// it cannot notice a client that should not have arrived, and has to be told.
//
// Three clients answer the same question, and the third one is not ours:
//
//   paramiko     an implementation somebody else wrote. If it refuses, the
//                expectation is not "whatever MoonBit does".
//   sshclient    `cmd/ssh_live --auth` over a real TCP socket.
//   wtlive       `cmd/wt_ssh` (`auth: 1`) in a browser Worker over WebSocket.
//
// `--auth` is the mode to drive on purpose: its success condition *is* reaching
// authentication, so a verification hole shows up as the run succeeding where it
// must fail.
//
// **A control run is not optional.** Three clients that refused everything would
// satisfy every check below. So each client also runs against an honest man in
// the middle and must authenticate, which is what makes the refusals mean
// something. The refusals and the control are the same measurement from two
// ends.
//
// **The error name is compared by its leaf.** `cmd/ssh_live` renders
// `transport:handshake:SignatureInvalid` and `cmd/wt_ssh` renders
// `handshake:SignatureInvalid`; the leaf is the part the rule produces and the
// prefixes are two renderings of where it surfaced. Both MoonBit transports must
// agree on the leaf, which is the part that must not differ.

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

let chromium = null;
try {
  ({ chromium } = await import("playwright"));
} catch {
  /* reported below */
}

const root = resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const WORK = join(root, ".loop47");
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

// The two forgeries, and the client error each one must produce. They are
// different rules on different branches: one signs with a key that is not the
// blob it presented, the other presents a real blob under a name that is not
// its type. Driving only one leaves the other untested end to end, and they are
// not interchangeable -- the client checks the type before it checks the
// signature, so `--lie-hostkey-type` never even reaches the signature check.
const LIES = [
  {
    name: "lie-signer",
    argv: ["--lie-hostkey"],
    mode: "lie-hostkey",
    want: "SignatureInvalid",
  },
  {
    name: "lie-type",
    argv: ["--lie-hostkey-type", "ssh-ed25519"],
    mode: "lie-hostkey-type",
    want: "HostkeyInvalid",
  },
];

// ---------------------------------------------------------------------------
// the man in the middle
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

// ---------------------------------------------------------------------------
// the clients
// ---------------------------------------------------------------------------

// The leaf of an error string: the part the rule produced, without the path the
// two drivers render differently on the way to it.
const leafOf = (s) => String(s || "").split(":").pop().trim();

function classifyClientText(text) {
  const n = norm(text);
  const err = grab(n, "error") || "";
  return {
    text: n,
    authed: /^result: USERAUTH_SUCCESS$/m.test(n),
    error: err,
    leaf: leafOf(err),
  };
}

async function runParamiko(port, tag) {
  const json = join(WORK, `${tag}.witness.json`);
  const r = spawnSync("python", [join(root, "host", "hostkey_witness.py"), String(port), "--json", json], {
    cwd: root,
    encoding: "utf-8",
    errors: "replace",
    maxBuffer: 16 * 1024 * 1024,
    timeout: 60000,
  });
  const data = readJson(json);
  if (!data) {
    return { refused: null, why: "no witness transcript: " + `${r.stdout || ""}${r.stderr || ""}`.slice(0, 300) };
  }
  return { refused: !!data.refused, error: data.error || "" };
}

async function runNative(port) {
  // Loop #50: pinning defaults to refusing, so an honest peer would be turned
  // away and every case here would read as "the client noticed something". That
  // is the wrong reason to pass. `--kh-tofu` says the client will accept *any*
  // self-consistent key -- which makes the forgery harder to stop, not easier:
  // with pinning effectively disabled, the only thing left between a forged
  // signature and a credential is signature verification itself.
  const r = spawnSync(SSH_LIVE, [String(port), "--auth", "--user", sshUser(), "--kh-tofu", "--kh-host", "127.0.0.1"], {
    cwd: root,
    encoding: "utf-8",
    errors: "replace",
    maxBuffer: 64 * 1024 * 1024,
    timeout: 90000,
  });
  return classifyClientText(`${r.stdout || ""}${r.stderr || ""}`);
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

async function runWorker_(browser, httpPort, wsPort, tag) {
  const base = `http://127.0.0.1:${httpPort}`;
  const cfg = wtCfg(base, httpPort, wsPort, { nonce: tag, user: sshUser(), auth: "1", kh_tofu: "1", kh_host: "127.0.0.1" });
  const { page, state } = await openPage(browser, httpPort, { freshStorage: true });
  let out;
  try {
    out = await runWorker(page, cfg);
  } finally {
    await page.close();
  }
  if (out.error) {
    return { text: "", authed: false, error: out.error, leaf: "", net: state.net, pageErrors: state.pageErrors };
  }
  const c = classifyClientText((out.lines || []).join("\n"));
  return { ...c, net: state.net, pageErrors: state.pageErrors };
}

// ---------------------------------------------------------------------------
// one forgery, three clients
// ---------------------------------------------------------------------------

// What the man in the middle must have seen, whatever the client did. These are
// the assertions that make this a security test rather than an error-message
// test: a client can print anything it likes, but it cannot un-send userauth.
function checkTranscript(tag, data, mitm, lie) {
  if (!data) {
    bad(`${tag} transcript`, "the man in the middle wrote nothing: " + mitm.err().slice(0, 300));
    return false;
  }
  if (data.error) {
    bad(`${tag} transcript`, "the MITM itself failed: " + data.error);
    return false;
  }
  let good = true;
  if (data.mode !== lie.mode) {
    bad(`${tag} transcript`, `mode=${data.mode} want ${lie.mode}`);
    good = false;
  }
  // The lie has to be a real one. Two fingerprints that happen to be equal --
  // the same file generated twice, say -- would make every other check pass
  // while nothing was actually forged.
  if (
    !data.hostkey_presented_sha256 ||
    !data.hostkey_signer_sha256 ||
    data.hostkey_presented_sha256 === data.hostkey_signer_sha256
  ) {
    bad(`${tag} transcript`, "presented and signing key are not two different keys");
    good = false;
  }
  if (data.auth_attempts !== 0) {
    bad(`${tag} credentials`, `${data.auth_attempts} authentication attempt(s) reached a peer whose key does not prove it`);
    good = false;
  }
  if (data.channel_requests !== 0) {
    bad(`${tag} channels`, `${data.channel_requests} channel request(s) after a failed key exchange`);
    good = false;
  }
  if (data.reached_sftp !== false) {
    bad(`${tag} channels`, "the session reached SFTP after a failed key exchange");
    good = false;
  }
  return good;
}

async function runLie(lie, browser, httpPort) {
  const tag = lie.name;

  // --- paramiko, the witness -------------------------------------------
  const m1 = await startMitm(`${tag}-witness`, lie.argv);
  const witness = await runParamiko(m1.port, `${tag}-witness`);
  await stopMitm(m1);
  if (witness.refused === null) {
    bad(`${tag} paramiko`, witness.why);
  } else if (!witness.refused) {
    bad(`${tag} paramiko`, "paramiko completed the forged key exchange");
  } else {
    ok(`${tag} paramiko refused`, witness.error.slice(0, 90));
  }

  // --- src/sshclient over TCP ------------------------------------------
  const m2 = await startMitm(`${tag}-native`, lie.argv);
  const native = await runNative(m2.port);
  await stopMitm(m2);
  const t2 = checkTranscript(`${tag} native`, readJson(m2.json), m2, lie);
  if (native.authed) {
    bad(`${tag} native`, "reached USERAUTH_SUCCESS with a forged host key");
  } else if (native.leaf !== lie.want) {
    bad(`${tag} native`, `error=${JSON.stringify(native.error)} want leaf ${lie.want}`);
  } else {
    ok(`${tag} native refused`, native.error);
  }
  if (t2) ok(`${tag} native sent nothing`, "0 auth attempts, 0 channels");

  // --- src/wtlive in a browser Worker ----------------------------------
  if (!browser) {
    // No browser: the native client and the paramiko witness need none, so the
    // run continues rather than skipping the whole forgery. Reporting the
    // browser half as verified because it did not execute would be the one
    // outcome worse than a failure, so it is named as skipped at the end.
    skipped.push(`${tag} browser half (no browser)`);
    return;
  }
  const m3 = await startMitm(`${tag}-browser`, lie.argv);
  const br = await startBridge(m3.port);
  let wt = { text: "", authed: false, error: "the bridge never came up: " + br.text().slice(0, 200), leaf: "" };
  if (br.up) {
    wt = await runWorker_(browser, httpPort, br.wsPort, tag);
    br.bridge.kill();
  }
  await stopMitm(m3);
  const t3 = checkTranscript(`${tag} browser`, readJson(m3.json), m3, lie);
  if (wt.authed) {
    bad(`${tag} browser`, "reached USERAUTH_SUCCESS with a forged host key");
  } else if (wt.leaf !== lie.want) {
    bad(`${tag} browser`, `error=${JSON.stringify(wt.error)} want leaf ${lie.want}` + (wt.net && wt.net.length ? ` http=${wt.net.join(";")}` : ""));
  } else {
    ok(`${tag} browser refused`, wt.error);
  }
  if (t3) ok(`${tag} browser sent nothing`, "0 auth attempts, 0 channels");

  // One rule, two transports: the leaf is what they must agree on. The
  // prefixes (`transport:` and nothing) are how each driver says where it
  // surfaced, and Loop #44 already pins the fifteen session-loop rules the two
  // adapters share.
  if (native.leaf === lie.want && wt.leaf === lie.want) {
    ok(`${tag} both transports agree`, lie.want);
  }
}

// The control. Without it, three clients that refuse everything pass every
// check above, so the refusals would prove nothing at all.
async function runControl(browser, httpPort) {
  const m1 = await startMitm("control-native", []);
  const native = await runNative(m1.port);
  await stopMitm(m1);
  const d1 = readJson(m1.json);
  if (native.authed) ok("control native", "authenticated against an honest peer");
  else bad("control native", "did not authenticate against an honest peer: " + JSON.stringify(native.error));
  if (d1 && d1.auth_attempts > 0) ok("control native reached auth", `${d1.auth_attempts} attempt(s)`);
  else bad("control native reached auth", JSON.stringify(d1));

  const m2 = await startMitm("control-browser", []);
  const br = await startBridge(m2.port);
  if (!br.up) {
    bad("control browser", "the bridge never came up: " + br.text().slice(0, 200));
  } else {
    const wt = await runWorker_(browser, httpPort, br.wsPort, "control");
    br.bridge.kill();
    if (wt.authed) ok("control browser", "authenticated against an honest peer");
    else bad("control browser", "did not authenticate against an honest peer: " + JSON.stringify(wt.error) + JSON.stringify(wt.net || []));
  }
  await stopMitm(m2);
  const d2 = readJson(m2.json);
  if (d2 && d2.auth_attempts > 0) ok("control browser reached auth", `${d2.auth_attempts} attempt(s)`);
  else bad("control browser reached auth", JSON.stringify(d2));
}

// ---------------------------------------------------------------------------

async function main() {
  mkdirSync(WORK, { recursive: true });

  console.log("build");
  // Both halves are rebuilt, and both are rebuilt *every run*. Building only
  // the native one was a real defect found by mutating `src/hostkey`: the
  // browser half kept passing, because it was running a `wt_ssh.js` left over
  // from whenever it was last built. A gate that can report PASS for a source
  // tree it did not compile is worse than no gate -- it converts a caught
  // regression into a silent one, and the browser half is the half this loop
  // exists to cover.
  const b = spawnSync("cmd", ["/c", "moon", "build", "cmd\\ssh_live", "--target", "native"], {
    cwd: root, encoding: "utf-8", errors: "replace", maxBuffer: 64 * 1024 * 1024,
  });
  if (b.status !== 0 || !existsSync(SSH_LIVE)) {
    bad("build ssh_live (native)", norm(`${b.stdout || ""}${b.stderr || ""}`).trim().split("\n").slice(-10).join("\n      "));
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

  for (const lie of LIES) {
    console.log("");
    console.log(lie.name);
    await runLie(lie, browser, httpPort);
  }

  if (browser) {
    console.log("");
    console.log("control: an honest peer");
    await runControl(browser, httpPort);
  } else {
    console.log("");
    console.log("control: an honest peer (native only)");
    const m = await startMitm("control-native", []);
    const native = await runNative(m.port);
    await stopMitm(m);
    if (native.authed) ok("control native", "authenticated against an honest peer");
    else bad("control native", "did not authenticate: " + JSON.stringify(native.error));
    const d = readJson(m.json);
    if (d && d.auth_attempts > 0) ok("control native reached auth", `${d.auth_attempts} attempt(s)`);
    else bad("control native reached auth", JSON.stringify(d));
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
      writeFileSync(join(WORK, "last_gate47.txt"), `ALL PASS (${checks} checks)\n`);
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