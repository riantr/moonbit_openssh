// host/verify_loop53.mjs -- Loop #53: `@cert-authority` is a trust anchor that works.
//
// Loop #51 established that a `@cert-authority` line is not a host key pin, and
// stopped there: the honest answer became "this client does not do host
// certificates". That left the standard CA deployment (Puppet/Chef/Ansible all
// write those lines) unusable. This loop makes the answer real: a certificate is
// accepted when -- and only when -- it is signed by the CA that line names, is
// inside its validity window, and lists this host among its principals.
//
// What the gate is actually for is the set of ways that can be wrong, which all
// look the same from the outside:
//
//   ca-signed-ok     authenticate
//   no-anchor        refuse, and the peer never even got to offer a certificate
//   tofu             refuse (accept-new must not learn a certificate)
//   other-ca         refuse, untrusted, not "signature invalid"
//   expired          refuse, and say *validity*
//   principal        refuse, and say *principal*
//   user-cert        refuse a USER certificate as a host identity
//   direct-pin-wins  a direct pin still outranks the CA entry (Loop #51's rule)
//   revoked-ca       an `@revoked` CA stops cutting certificates
//   plain-key        the Loop #51 control: CA entry + bare key still refuses
//   direct-pin       the other control: plain pinning still authenticates
//
// Three of these exist because a *refusal* is not the hard part:
//
//   * `no-anchor` is where the conditional advertisement shows up. The client
//     only offers `ssh-ed25519-cert-v01@openssh.com` when the host has a CA
//     entry, so a peer configured with a certificate cannot even negotiate a
//     host key. The transcript's `hostkey_negotiated_type` is what makes this
//     distinguishable from "the certificate was presented and then refused".
//   * `other-ca` must be `HostkeyCertUntrusted`, not `HostkeyCertAuthority`.
//     The rogue certificate's signature is perfectly valid; what is missing is a
//     local trust anchor. Reporting it as "the certificate did not validate"
//     sends the user to re-issue a certificate that was fine.
//   * Every refusal asserts its `hint:` prose. A correct leaf name with a stale
//     paragraph changes nothing: an unfamiliar explanation is still an
//     unfamiliar explanation, and the user walks the path they walked last time.
//
// And every refusal asserts `auth_attempts == 0` *and* that the peer was
// configured with a host key, for Loop #50's reason: a peer that never presented
// one also shows zero authentication attempts, and would pass for a refusal it
// did not earn.
//
// Browser gates must not run concurrently with each other -- each pulls its own
// Chromium, static server and WS bridge.

import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync } from "node:fs";
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
const WORK = join(root, ".loop53");
const KEYS = join(root, ".loop53");
const SSH_LIVE = join(root, "_build", "native", "debug", "build", "cmd", "ssh_live", "ssh_live.exe");
const WT_MODULE = join(root, "_build", "js", "debug", "build", "cmd", "wt_ssh", "wt_ssh.js");

const CERT_TYPE = "ssh-ed25519-cert-v01@openssh.com";
const HOST = "127.0.0.1";

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

function pubB64(file) {
  return readFileSync(file, "utf-8").trim().split(/\s+/)[1];
}

async function startMitm(tag, certSpec) {
  const port = await freePort();
  const json = join(WORK, `${tag}.json`);
  const argv = [join(root, "host", "sftp_mitm.py"), String(port), "--json", json];
  if (certSpec) argv.push("--host-cert", certSpec);
  const proc = spawn("python", argv, { cwd: root, stdio: ["ignore", "pipe", "pipe"] });
  let err = "";
  proc.stderr.on("data", (d) => (err += d.toString()));
  // Wait for the MITM to say it is listening, rather than guessing how long
  // that takes.  See host/mitm_ready.mjs.
  await waitForMitmReady(() => err);
  // Loop #52's check, and the reason it is here rather than being new: `freePort()`
  // closes a listener and hands the number back, and the OS may have given it to
  // something else in the meantime, or paramiko died on it. Either way the client
  // below connects to nothing and reports `NoServerIdent` -- which reads exactly
  // like a protocol failure in the certificate path. Three loops' worth of
  // certificate work sat behind that symptom before the check was copied over.
  if (proc.exitCode !== null || proc.signalCode !== null) {
    throw new Error(
      `the man in the middle for ${tag} died on port ${port}: ` +
      `${err.trim().slice(0, 400) || "(no stderr)"}`,
    );
  }
  return { proc, json, port, err: () => err };
}

async function stopMitm(m) {
  if (!(await exitedWithin(m.proc, 25000))) m.proc.kill();
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
  return { bridge, wsPort, up };
}

async function runWorkerAuth(browser, httpPort, wsPort, tag, extraCfg) {
  const base = `http://127.0.0.1:${httpPort}`;
  const cfg = wtCfg(base, httpPort, wsPort, { nonce: tag, user: sshUser(), auth: "1", ...extraCfg });
  const { page, state } = await openPage(browser, httpPort, { freshStorage: true });
  let out;
  try {
    out = await runWorker(page, cfg);
  } finally {
    // The *context*, not just the page. `openPage(..., { freshStorage: true })`
    // opens a brand new browser context per case, and a context outlives its page
    // -- eleven cases leave eleven of them, each with a live IndexedDB, alive
    // until the whole browser goes down.
    await page.context().close();
  }
  if (out.error) return { authed: false, error: out.error, leaf: "", hint: "" };
  return classify((out.lines || []).join("\n"));
}

function judge(label, got, c, data) {
  const problems = [];
  if (c.auth) {
    if (!got.authed) problems.push(`did not authenticate: error=${JSON.stringify(got.error)}`);
  } else {
    if (got.authed) problems.push("reached USERAUTH_SUCCESS");
    if (!c.noLeaf && got.leaf !== c.leaf) {
      problems.push(`error=${JSON.stringify(got.error)} want leaf ${c.leaf}`);
    }
    if (data && data.auth_attempts > 0) {
      problems.push(`${data.auth_attempts} authentication attempt(s) reached a peer it should have refused`);
    }
    if (data && !data.hostkey_blob_b64 && !data.hostkey_cert_b64) {
      problems.push("the peer had no host key configured at all, so the refusal cannot be about certificates");
    }
    if (c.hint) {
      if (!got.hint) problems.push("no `hint:` line -- the error name alone does not tell the user what to do");
      else if (!got.hint.toLowerCase().includes(c.hint)) {
        problems.push(`hint does not mention ${JSON.stringify(c.hint)}: ${got.hint.slice(0, 140)}`);
      }
    }
  }
  // `cert-never-offered` is the one case whose whole point is what did NOT
  // happen, so it needs the opposite assertion: the peer must have tried and
  // failed to present one.
  if (c.neverNegotiated && data && data.hostkey_negotiated_type) {
    problems.push(`the peer negotiated ${data.hostkey_negotiated_type} even though no CA is configured`);
  }
  if (c.negotiatedCert && data && data.hostkey_negotiated_type !== CERT_TYPE) {
    problems.push(`peer negotiated ${JSON.stringify(data.hostkey_negotiated_type)}, want ${CERT_TYPE}`);
  }
  if (problems.length) { bad(label, problems.join("\n      ")); return false; }
  // Reported, not just returned. A gate that only counts its *failures* reads
  // `4/5 checks passed` for a run in which twenty cases passed -- which is the
  // same silent-success shape Loop #47 found in a gate that never rebuilt the
  // browser half.
  ok(label);
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

  for (const f of ["ca", "ca.pub", "rogue.pub", "host", "host.pub", "userhost",
    "host-good-cert.pub", "host-other-cert.pub", "host-exp-cert.pub",
    "host-rogue-cert.pub", "usercert-in-cert.pub"]) {
    if (!existsSync(join(KEYS, f))) {
      bad("fixtures", `missing .loop53/${f}`);
      return finish();
    }
  }
  ok("certificate fixtures present");

  const CA_B64 = pubB64(join(KEYS, "ca.pub"));
  const ROGUE_B64 = pubB64(join(KEYS, "rogue.pub"));
  const INNER_B64 = pubB64(join(KEYS, "host.pub"));

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

  // `certSpec(certFile, innerFile, caFile)` -- three files, because the
  // certificate cannot contain the inner private key (it must not) and nothing
  // in it names the CA in a form the MITM can read without re-implementing a
  // certificate parser on the MITM side. Semicolons, not colons: every one of
  // these paths starts with a Windows drive letter.
  const certSpec = (cert, inner, ca) =>
    `${join(KEYS, cert)};${join(KEYS, inner)};${join(KEYS, ca)}`;
  const caLine = (blob, hostField = HOST) => `@cert-authority ${hostField} ssh-ed25519 ${blob}`;

  const cases = [
    {
      name: "ca-signed-ok",
      spec: certSpec("host-good-cert.pub", "host", "ca.pub"),
      kh: caLine(CA_B64),
      auth: true, negotiatedCert: true,
      note: "the whole point of the loop",
    },
    {
      name: "no-anchor",
      spec: certSpec("host-good-cert.pub", "host", "ca.pub"),
      kh: null,
      // No leaf name and no hint: with no CA entry the client never offers the
      // certificate algorithm, so the peer has no host key to negotiate and the
      // handshake dies at **agreement**, before the pinning decision is ever
      // reached. That is the stronger outcome, not a weaker one -- there is no
      // moment at which this client could have sent credentials. Asserting
      // `HostkeyUnknown` here would demand the weaker behaviour and read a
      // correct run as a failure.
      auth: false, noLeaf: true,
      neverNegotiated: true,
      note: "no CA entry -> the certificate algorithm is never even offered",
    },
    {
      name: "tofu",
      spec: certSpec("host-good-cert.pub", "host", "ca.pub"),
      kh: null, tofu: true,
      auth: false, noLeaf: true,
      neverNegotiated: true,
      note: "accept-new must not learn a certificate either",
    },
    {
      name: "other-ca",
      spec: certSpec("host-good-cert.pub", "host", "ca.pub"),
      kh: caLine(ROGUE_B64),
      auth: false, leaf: "HostkeyCertUntrusted", hint: "cert-authority",
      note: "the rogue signature is valid; what is missing is a local anchor",
    },
    {
      name: "expired",
      spec: certSpec("host-exp-cert.pub", "host", "ca.pub"),
      kh: caLine(CA_B64),
      auth: false, leaf: "HostkeyCertAuthority", hint: "validity",
      note: "the remedy is re-issuing, not hunting a man in the middle",
    },
    {
      name: "principal",
      spec: certSpec("host-other-cert.pub", "host", "ca.pub"),
      kh: caLine(CA_B64),
      auth: false, leaf: "HostkeyCertAuthority", hint: "principal",
      note: "signed by the right CA, for a different name",
    },
    {
      name: "user-cert",
      spec: certSpec("usercert-in-cert.pub", "userhost", "ca.pub"),
      kh: caLine(CA_B64),
      auth: false, leaf: "HostkeyCertAuthority", hint: "user certificate",
      note: "a USER certificate proves a user, not a host",
    },
    {
      name: "direct-pin-wins",
      spec: certSpec("host-good-cert.pub", "host", "ca.pub"),
      kh: `${HOST} ssh-ed25519 ${INNER_B64}\n${caLine(CA_B64)}`,
      auth: false, leaf: "HostkeyMismatch", hint: "man in the middle",
      note: "Loop #51's priority rule must hold for certificates too",
    },
    {
      name: "revoked-ca",
      spec: certSpec("host-good-cert.pub", "host", "ca.pub"),
      kh: `${caLine(CA_B64)}\n@revoked * ssh-ed25519 ${CA_B64}`,
      auth: false, leaf: "HostkeyCertAuthority", hint: "revoked",
      note: "revoking the CA stops every certificate it cut",
    },
    {
      name: "plain-key-with-ca-entry",
      spec: null,
      kh: caLine(CA_B64),
      auth: false, leaf: "HostkeyCertAuthority", hint: "plain key",
      note: "Loop #51's control: a CA entry does not become a bare-key pin",
    },
  ];

  // One MITM per transport, and that is not tidiness. `sftp_mitm.py` listens
  // with a backlog of one and serves a single `accept`; running the browser
  // client against the peer the native client just consumed leaves nobody
  // listening, and the browser run fails as `NoServerIdent` -- which reads like
  // a transport bug in the client and is really a harness that reused a
  // single-use server.
  async function runNativeCase(c, tag) {
    const m = await startMitm(tag, c.spec);
    const nativeArgs = [];
    // `--known-hosts-text` is the real flag; `--kh-host` has to be given
    // explicitly because the default is 127.0.0.1 only by coincidence of this
    // gate living on the loopback interface. Passing an unknown flag here fails
    // *open*: the policy is built empty, the client offers no certificate
    // algorithm, and the peer reports "no acceptable host key" -- which reads
    // like the client refusing certificates rather than never offering them.
    if (c.kh) nativeArgs.push("--known-hosts-text", c.kh, "--kh-host", HOST);
    if (c.tofu) nativeArgs.push("--kh-tofu");
    const got = await runNative(m.port, nativeArgs);
    await stopMitm(m);
    return { got, data: readJson(m.json) };
  }

  async function runBrowserCase(c, tag) {
    const m = await startMitm(tag, c.spec);
    const br = await startBridge(m.port);
    if (!br.up) {
      await stopMitm(m);
      try { br.bridge.kill(); } catch { /* already gone */ }
      return { got: { authed: false, error: "the bridge never came up", leaf: "" } };
    }
    const extra = { known_hosts: c.kh || "", kh_host: HOST };
    if (c.tofu) extra.kh_tofu = "1";
    const got = await runWorkerAuth(browser, httpPort, br.wsPort, tag, extra);
    try { br.bridge.kill(); } catch { /* already gone */ }
    await stopMitm(m);
    return { got, data: readJson(m.json) };
  }

  for (const c of cases) {
    console.log(`\n${c.name}  (${c.note})`);
    const rn = await runNativeCase(c, c.name);
    if (!rn.data) {
      bad(`${c.name} [native]`, "no transcript at all: " + JSON.stringify(rn.data));
    } else {
      judge(`${c.name} [native]`, rn.got, c, rn.data);
    }
    if (browser && server) {
      const rb = await runBrowserCase(c, `browser-${c.name}`);
      judge(`${c.name} [browser]`, rb.got, c, rb.data);
    }
  }

  // The control that says plain pinning still works at all. Without it, "the
  // client refused" would also be true of a client that refuses everything.
  console.log("\ndirect-pin  (the other control: plain pinning still authenticates)");
  {
    const discover = await startMitm("discover", null);
    await runNative(discover.port, ["--kh-tofu"]);
    await stopMitm(discover);
    const d = readJson(discover.json);
    if (!d || !d.hostkey_blob_b64) {
      bad("direct-pin [native]", "no presented blob: " + JSON.stringify(d).slice(0, 160));
    } else {
      const line = `${HOST} ${d.hostkey_announced_type} ${d.hostkey_blob_b64}`;
      // A man in the middle each, again. The first version of this control gave
      // the native client its peer and then pointed the browser at the *same*
      // port; `sftp_mitm.py` serves exactly one connection, so the browser got a
      // closed socket and reported `NoServerIdent` -- the same symptom as the
      // certificate bug this loop spent most of its time on, for a reason that
      // had nothing to do with certificates.
      const mn = await startMitm("direct-pin", null);
      const got = await runNative(mn.port, ["--known-hosts-text", line, "--kh-host", HOST]);
      await stopMitm(mn);

      const mb = await startMitm("direct-pin-browser", null);
      const br = await startBridge(mb.port);
      let bgot;
      if (browser && server && br.up) {
        bgot = await runWorkerAuth(browser, httpPort, br.wsPort, "direct-pin", {
          known_hosts: line, kh_host: HOST,
        });
      } else {
        bgot = { authed: false, error: "the browser half did not run", leaf: "" };
      }
      try { br.bridge.kill(); } catch { /* already gone */ }
      await stopMitm(mb);
      judge("direct-pin [native]", got, { auth: true }, readJson(mn.json));
      judge("direct-pin [browser]", bgot, { auth: true }, readJson(mb.json));
    }
  }

  return teardown(server, browser).then(finish);
}

// Loop #53. The gate used to print its verdict and then sit there forever: `serve()`
// leaves an HTTP server listening and `chromium.launch()` leaves a browser open, and
// neither was ever closed. The shell that ran it never returned, which is not merely
// untidy -- an orphaned gate from a previous run stays on the machine, holds ports,
// and races the next one. That is exactly what produced two `verify_loop53.mjs`
// writing the same `.loop53/*.json` at the same time, and a mutation verdict read
// from a transcript the other gate had overwritten. A gate that does not exit is a
// gate whose results cannot be attributed.
async function teardown(server, browser) {
  if (server) {
    try {
      if (typeof server.closeAllConnections === "function") server.closeAllConnections();
    } catch { /* older node */ }
    await new Promise((r) => server.close(() => r()));
  }
  if (browser) {
    try {
      await browser.close();
    } catch { /* already gone */ }
  }
}

function finish() {
  console.log("");
  if (skipped.length) for (const s of skipped) console.log(`SKIPPED  ${s}`);
  console.log(`loop53: ${checks - failures.length}/${checks} checks passed`);
  if (failures.length) {
    console.log("");
    for (const f of failures) console.log(`  FAIL  ${f}`);
    process.exitCode = 1;
  } else {
    console.log("ALL PASS");
  }
}

main().catch((e) => {
  console.error("loop53 gate crashed: " + (e && e.stack ? e.stack : String(e)));
  process.exitCode = 1;
});