// host/verify_loop59.mjs -- Loop #59: the client dials what the config says, and
// the pin is stored under the name the user typed.
//
// Loop #58 made `cmd/ssh_live` *print* its resolved connection parameters and
// checked those against `ssh -G`. Printing the right thing and connecting to the
// right thing are different claims, and only the first one was proven. A
// `HostName` that resolves correctly in the dump while the socket still goes to
// 127.0.0.1 would have passed every check in Loop #58.
//
// So this gate runs the client against a real SSH peer -- `host/sftp_mitm.py`,
// the same one Loop #54 uses -- with **no port argument at all**. If the
// connection succeeds, the host and the port came out of the config file. There
// is nowhere else for them to have come from.
//
// ## What is asserted, and why each one is not decoration
//
// 1. A config naming an alias resolves to 127.0.0.1:<the peer's port> and the
//    client authenticates, having been given nothing but `--config`, `--target`
//    and `--auth`.
//
// 2. The user it authenticated as is the config's `User`. The peer accepts any
//    username, so this asserts what the client *reported*, not what the server
//    did with it -- which is the only part that is ours to get wrong.
//
// 3. The known_hosts pin is written under **the alias**, not under the resolved
//    `HostName`. This is not a style choice. OpenSSH's
//    `add_host_to_hostfile(filename, host, key, store_hash)` takes exactly one
//    host and `write_host_entry(f, host, NULL, ...)` passes `ip = NULL`
//    (hostfile.c:542 / :476) -- `HostName` never enters the key. Pinning under
//    the resolved name means the next connection *by alias* looks up a name that
//    is not in the file, so every connection looks like a first connection and
//    TOFU fires forever. That failure is invisible from the outside: it never
//    errors, it just never remembers.
//
// 4. With no `--config`, the client still dials 127.0.0.1:<port from argv> and
//    authenticates -- Loop #59 changed six `TcpConn::connect` call sites and two
//    `find_user` re-parses, and this is the step that notices if it broke a gate
//    that was passing before.
//
// Process discipline is Loop #53's: the peers are killed and the work directory
// is removed on the way out, including on the failure path, because a peer left
// running answers the *next* gate and turns a real failure into a phantom one.

import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import net from "node:net";
import path from "node:path";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { sshUser } from './ssh_user.mjs';

const root = resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const WORK = join(root, ".loop59");
const SSH_LIVE = join(root, "_build", "native", "debug", "build", "cmd", "ssh_live", "ssh_live.exe");
const MITM = join(root, "host", "sftp_mitm.py");

const failures = [];
let checks = 0;
const live = [];

function ok(label, detail) {
  checks += 1;
  console.log(`  PASS  ${label}${detail ? "  " + detail : ""}`);
}
function bad(label, detail) {
  checks += 1;
  failures.push(`${label}${detail ? "  " + detail : ""}`);
  console.log(`  FAIL  ${label}${detail ? "  " + detail : ""}`);
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function cleanup() {
  for (const p of live.splice(0)) {
    if (p.exitCode === null && p.signalCode === null) {
      try { p.kill(); } catch { /* already gone */ }
    }
  }
  try { rmSync(WORK, { recursive: true, force: true }); } catch { /* nothing to remove */ }
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

// One connection per instance: `sftp_mitm.py` serves exactly one, so a gate that
// reuses an instance sees it die mid-run and reads the failure as a protocol bug.
async function startPeer(tag) {
  const port = await freePort();
  const proc = spawn("python", [MITM, String(port), "--json", join(WORK, `${tag}.json`)],
    { cwd: root, stdio: ["ignore", "pipe", "pipe"] });
  live.push(proc);
  let err = "";
  proc.stderr.on("data", (d) => (err += d.toString()));
  await sleep(1200);
  if (proc.exitCode !== null || proc.signalCode !== null) {
    throw new Error(`peer ${tag} died on port ${port}: ${err.trim().slice(0, 300) || "(no stderr)"}`);
  }
  return { proc, port };
}

async function stopPeer(p) {
  // The peer writes its transcript on the way out; give it that window.
  await sleep(2500);
  if (p.proc.exitCode === null && p.proc.signalCode === null) p.proc.kill();
}

function run(args) {
  const r = spawnSync(SSH_LIVE, args, {
    cwd: root,
    encoding: "utf-8",
    errors: "replace",
    maxBuffer: 64 * 1024 * 1024,
    timeout: 180000,
  });
  return `${r.stdout || ""}${r.stderr || ""}`;
}

const authed = (t) => /USERAUTH_SUCCESS/.test(t);
const lineOf = (t, k) => {
  const m = new RegExp(`^${k}: (.*)$`, "m").exec(t);
  return m ? m[1].trim() : null;
};

// Does known_hosts have an entry for this host, whatever the key type?
//
// The key type is `\S+`, not `ssh-`. The first version of this helper spelled
// `ssh-` out, and it cost two checks at once: the alias check failed against a
// file that was correct, and the "not keyed by the resolved HostName" check
// passed *vacuously* -- a regex that never matches anything looks exactly like a
// regex proving an absence. A check that cannot fail is worse than no check,
// because it reads as evidence.
function keyLineFor(body, host) {
  const re = new RegExp(`^\\s*\\[?${host.replace(/[.*+?^${}()|[\\]\\\\]/g, "\\\\$&")}\\]?(?::\\d+)?\\s+\\S`, "m");
  const m = re.exec(body);
  return m ? m[0].trim() : null;
}

async function main() {
  try {
    // Recreate the work directory every run. `cleanup()` removes it on the way
    // out, so a second run without this would fail on a missing directory --
    // and it would do so after the build, which is where the time goes.
    mkdirSync(WORK, { recursive: true });

    console.log("build");
    const b = spawnSync("cmd", ["/c", "moon", "build", "cmd\\ssh_live", "--target", "native"],
      { cwd: root, encoding: "utf-8", errors: "replace", maxBuffer: 64 * 1024 * 1024 });
    if (b.status !== 0 || !existsSync(SSH_LIVE)) {
      bad("build ssh_live (native)", `${b.stdout || ""}${b.stderr || ""}`.trim().split("\n").slice(-10).join("\n      "));
      return finish();
    }
    ok("build ssh_live (native)");

    // ---- step 1: the config supplies the host and the port ----------------
    console.log("");
    console.log("step 1: host and port come from the config; no port argument is passed");
    const p1 = await startPeer("s1");
    const cfg1 = join(WORK, "alias.conf");
    const KH1 = join(WORK, "kh1");
    writeFileSync(cfg1,
      `# Loop #59. The alias below resolves to a real peer.\n` +
      `Host loop59-alias\n` +
      `  HostName 127.0.0.1\n` +
      `  Port ${p1.port}\n` +
      `  User cfguser\n`, "utf-8");
    // `--kh-tofu` is required, not decorative: the client's default policy is
    // strict (Loop #50), so an unpinned peer is refused before userauth. The
    // hint line names whichever host the policy asked about, which is how the
    // `--kh-host` default change shows up in the output at all.
    const r1 = run(["--config", cfg1, "--target", "loop59-alias", "--auth",
      "--kh-tofu", "--kh-file", KH1]);
    await stopPeer(p1);

    if (authed(r1)) {
      ok("config supplies the dial target", `authenticated against 127.0.0.1:${p1.port}`);
    } else {
      bad("config supplies the dial target",
        `no USERAUTH_SUCCESS: ${r1.trim().split("\n").slice(-4).join(" | ")}`);
    }
    if (lineOf(r1, "user") === "cfguser") {
      ok("authenticated as the config's User", "cfguser");
    } else {
      bad("authenticated as the config's User", `reported ${JSON.stringify(lineOf(r1, "user"))}`);
    }

    // ---- step 2: the pin is keyed by the alias, not the HostName ---------
    console.log("");
    console.log("step 2: the known_hosts pin is written under the alias");
    const p2 = await startPeer("s2");
    const cfg2 = join(WORK, "alias2.conf");
    const KH = join(WORK, "known_hosts");
    writeFileSync(cfg2,
      `Host loop59-pin\n  HostName 127.0.0.1\n  Port ${p2.port}\n  User cfguser\n`, "utf-8");
    const r2 = run(["--config", cfg2, "--target", "loop59-pin", "--auth", "--kh-tofu", "--kh-file", KH]);
    await stopPeer(p2);

    if (!authed(r2)) {
      bad("pin: connect", r2.trim().split("\n").slice(-6).join(" | "));
    } else if (!existsSync(KH)) {
      bad("pin: written under the alias", `no ${KH} at all`);
    } else {
      const body = readFileSync(KH, "utf-8");
      // Loop #40: the failure and its evidence land together. A bare "no line
      // keyed by loop59-pin" costs a re-run with a debug print to diagnose;
      // three guesses about whether the file is empty, keyed differently, or
      // written elsewhere is three re-runs.
      const dump = body.trim() ? body.trim().split("\n").slice(0, 4).join(" | ") : "(file is empty)";
      const wrote = lineOf(r2, "tofu: written to");
      const underAlias = keyLineFor(body, "loop59-pin");
      const underResolved = keyLineFor(body, "127.0.0.1");
      if (underAlias) ok("pin is keyed by the alias the user typed", "loop59-pin");
      else bad("pin is keyed by the alias the user typed", `known_hosts: ${dump}`);
      if (underResolved) {
        bad("pin is NOT keyed by the resolved HostName",
          `the file also has a 127.0.0.1 line (${underResolved.slice(0, 60)}); ` +
          "OpenSSH's write_host_entry passes ip=NULL, so HostName never enters the key");
      } else {
        ok("pin is NOT keyed by the resolved HostName");
      }
    }

    // ---- step 3: without a config, nothing moved -------------------------
    console.log("");
    console.log("step 3: no --config, the old behaviour is unchanged");
    const p3 = await startPeer("s3");
    const KH3 = join(WORK, "kh3");
    const r3 = run([String(p3.port), "--auth", "--user", sshUser(), "--kh-tofu", "--kh-file", KH3]);
    await stopPeer(p3);
    if (authed(r3)) ok("no config -> dials 127.0.0.1:<argv port>", `authenticated as ${lineOf(r3, "user")}`);
    else bad("no config -> dials 127.0.0.1:<argv port>", r3.trim().split("\n").slice(-4).join(" | "));

    // ---- step 4: --proposal is still the same bytes ----------------------
    console.log("");
    console.log("step 4: --proposal unchanged");
    const prop = run(["--proposal"]);
    if (prop.includes("kex_algs: diffie-hellman-group14-sha256") && prop.includes("enc_ctos: aes128-ctr")) {
      ok("--proposal unchanged");
    } else {
      bad("--proposal unchanged", prop.trim().split("\n").slice(0, 5).join(" | "));
    }

    return finish();
  } finally {
    // Loop #53: the gate must leave nothing running, on the failure path too.
    cleanup();
  }
}

function finish() {
  console.log("");
  console.log(`loop59: ${checks - failures.length}/${checks} checks passed`);
  if (failures.length) {
    console.log("");
    for (const f of failures) console.log(`  FAIL  ${f}`);
    process.exitCode = 1;
  } else {
    console.log("ALL PASS");
  }
}

await main();