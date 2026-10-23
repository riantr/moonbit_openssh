#!/usr/bin/env node
// host/verify_loop81.mjs -- Loop #81: cancel-tcpip-forward, the third global
// request of `ssh -R`.
//
// ## What is being claimed
//
// `ssh -R 9000:db:5432 host` is three things at the protocol level:
//
//   1. the client asks the **server** to listen on a port (the "tcpip-forward"
//      global request, RFC 4254 section 7.1),
//   2. when somebody connects to that port, the server opens a
//      "forwarded-tcpip" channel back to the client (Loop #78), and
//   3. when the client no longer wants the forward, it **cancels** it (the
//      "cancel-tcpip-forward" global request, same section).
//
// Loop #78 built (2). Nothing built (3): `src/channel/globalreq.mbt` had the
// request name as a constant and no code sent it.
//
// ## Why the cancel is harder than the request
//
// The request's payload is self-describing: name, want_reply, address, port.
// The cancel's payload must **match the request it cancels**, and the server
// decides what "match" means (OpenSSH 10.4, `channels.c`):
//
//   * the address is compared with `strcmp(c->path, host)`, byte for byte,
//     and `c->path` is the address string exactly as the request carried it;
//   * the port is compared with the port the **server allocated**, not 0.
//
// So the cancel's inputs are the *result* of the request -- only a client that
// made that request knows them.
//
// ## The evidence, and why each piece is here
//
// 1. **The bytes are paramiko's bytes.** `cmd/cancel_fwd_kat` prints this
//    client's payloads; `host/gen_cancel_fwd_vectors.py` prints the same
//    payloads built with paramiko's own `Message` encoder. Comparing our
//    encoder with our encoder would prove nothing.
//
// 2. **The cancel echoes the request.** The tail of the cancel (address +
//    port) must be the *same bytes* as the tail of the request it cancels.
//    That relation is the whole point of the request, and it is invisible if
//    each payload is only compared against a third party.
//
// 3. **A real OpenSSH server confirms it.** The server's own debug log says
//    which address and port it received, and `channel_cancel_rport_listener_
//    tcpip: close channel` says it actually closed a listener. The client
//    cannot forge that line.
//
// 4. **The behaviour changes.** The port the server was listening on accepts
//    connections before the cancel and refuses them after it -- measured while
//    the SSH connection is still alive, because a closed connection tears the
//    listener down anyway and would make the measurement meaningless.
//
// 5. **want_reply=0 is proven, not assumed.** OpenSSH's own client sends
//    "cancel-tcpip-forward" with want_reply=0, and the server then sends
//    *nothing at all*. A client that waits for that reply hangs for ever.
//    This gate sends a second cancel that *does* want a reply: the server
//    answers REQUEST_FAILURE, and that answer can only happen if the first
//    (silent) cancel really took effect.
//
// ## What runs where
//
// Section G1 needs only node, python and the MoonBit toolchain, so it runs
// everywhere. Section G2 needs an OpenSSH **server**. When there is none,
// that section is **skipped loudly** rather than quietly passed: a machine
// that cannot run a check has not run it.

import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, rmSync } from "node:fs";
import net from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { sshUserInfo } from "./ssh_user.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const WORK = path.join(ROOT, ".loop81");

// The account this gate authenticates as. Derived, never written down: see
// host/ssh_user.mjs for why, and for the same rule applied to paths.
const USER_INFO = sshUserInfo();
const USER = USER_INFO.name;

const SKIP_REGRESSION = process.argv.includes("--skip-regression");

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

function moon(args) {
  const r = spawnSync("cmd", ["/c", "moon", ...args], {
    cwd: ROOT, encoding: "utf8", errors: "replace", maxBuffer: 64 * 1024 * 1024,
  });
  return { code: r.status, out: `${r.stdout || ""}${r.stderr || ""}` };
}

function norm(s) {
  return `${s}`.replace(/\r\n/g, "\n");
}

function hashOut(out) {
  return createHash("sha256").update(norm(out)).digest("hex").slice(0, 16);
}

function lineOf(text, key) {
  const m = norm(text).match(new RegExp(`^${key}: (.*)$`, "m"));
  return m ? m[1] : undefined;
}

function tap(child) {
  child.tapBuf = "";
  for (const stream of [child.stdout, child.stderr]) {
    if (stream) stream.on("data", (d) => { child.tapBuf += d.toString(); });
  }
  return child;
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

// ---------------------------------------------------------------------------
// The payload layout, read from the wire format rather than from our code.
// ---------------------------------------------------------------------------

/**
 * The bytes after the request name and the want_reply byte: the address
 * string and the port.  That is the part a cancel has to reproduce.
 */
function payloadTail(hex) {
  const b = Buffer.from(hex, "hex");
  if (b.length < 5) return Buffer.alloc(0);
  const nameLen = b.readUInt32BE(0);
  return b.subarray(4 + nameLen + 1);
}

/** The want_reply byte, which sits right after the request name. */
function wantReplyByte(hex) {
  const b = Buffer.from(hex, "hex");
  if (b.length < 5) return -1;
  const nameLen = b.readUInt32BE(0);
  return b[4 + nameLen];
}

/**
 * Parse a "KEY value" line map out of the KAT's output.
 *
 * The HOST lines are the reason this does not use a naive `split(/\s+/)`:
 * the normalised bind address can legitimately be the **empty string**, so
 * the line is "HOST H2 " with a trailing space and nothing after it. Splitting
 * on whitespace and dropping the empties would turn that case into a missing
 * one -- and the missing case is exactly the one that matters ("" and "*" both
 * mean "any local address").
 */
function katLines(out) {
  const map = new Map();
  for (const raw of norm(out).split("\n")) {
    const line = raw.replace(/\r$/, "");
    let m = /^(REQ|CANC)\s+(\S+)\s+([0-9a-fA-F]+)$/.exec(line);
    if (m) {
      map.set(`${m[1]} ${m[2]}`, m[3].toLowerCase());
      continue;
    }
    m = /^HOST\s+(\S+)\s?(.*)$/.exec(line);
    if (m) map.set(`HOST ${m[1]}`, m[2]);
  }
  return map;
}

function oracleLines(out) {
  return katLines(out);
}

// ---------------------------------------------------------------------------
// The server.
// ---------------------------------------------------------------------------
function startSshd(port, name) {
  return tap(spawn("node", ["host/sshd_setup.mjs", "--port", String(port), "--name", name], {
    cwd: ROOT, stdio: ["ignore", "pipe", "pipe"],
  }));
}

function stopSshd(name) {
  spawnSync("node", ["host/sshd_setup.mjs", "--stop", "--name", name], { cwd: ROOT, encoding: "utf8" });
}

function sshdLog(name) {
  return path.join(ROOT, ".loop31", "sshd", `sshd.log_${name}`);
}

const CLIENT_EXE = path.join(ROOT, "_build", "native", "debug", "build", "cmd", "ssh_live", "ssh_live.exe");

// The client is run through an argv **array**, never a command string: on
// Windows an empty argument cannot survive a shell, and `--known-hosts-text ''`
// is exactly such an argument.
//
// The timeout is not politeness. A defect in this protocol can make the
// client and the server wait for each other for ever -- and the worst case is
// *by design*: with want_reply=0 the server answers nothing, so a client that
// waits for an answer that will never come hangs for ever. A gate that hangs
// measures nothing, so the client gets a deadline, and a client that misses it
// has no "result:" line, which fails the check that wanted one.
const CLIENT_TIMEOUT_MS = 60000;

function runClient(sshdPort, extra) {
  const r = spawnSync(
    CLIENT_EXE,
    ["--user", USER, "--kh-tofu", "--kh-host", "127.0.0.1", "--known-hosts-text", "",
     "--port", String(sshdPort), ...extra],
    {
      cwd: ROOT, encoding: "utf8", errors: "replace",
      maxBuffer: 64 * 1024 * 1024, timeout: CLIENT_TIMEOUT_MS,
    },
  );
  const out = norm(`${r.stdout || ""}${r.stderr || ""}`);
  if (r.error) {
    return out + `\n(the client did not finish: ${r.error.message})\n`;
  }
  return out;
}

async function main() {
  console.log("verify_loop81 -- cancel-tcpip-forward: the request that undoes a forward\n");
  mkdirSync(WORK, { recursive: true });

  // ------------------------------------------------------------------- G0 --
  section("G0: the client builds");
  // The gate runs a *prebuilt* client binary, so a change to the protocol
  // layer would not reach it unless the binary is rebuilt here.  Without this
  // build the mutation harness would happily "prove" that a broken payload
  // still passes, because the broken payload was never in the binary.
  const build = moon(["build", "cmd/ssh_live", "--target", "native"]);
  ok("cmd/ssh_live builds for native", build.code === 0,
    build.code === 0 ? "" : build.out.slice(-300));

  // ------------------------------------------------------------------- G1 --
  section("G1: the bytes are paramiko's bytes");
  const oracle = spawnSync("python", ["host/gen_cancel_fwd_vectors.py"], {
    cwd: ROOT, encoding: "utf8", errors: "replace",
  });
  const oracleText = norm(`${oracle.stdout || ""}${oracle.stderr || ""}`);
  ok("the oracle runs", oracle.status === 0, oracle.status === 0 ? "" : oracleText.slice(-300));

  // 4 target x 2 mode, byte identical: the payloads are pure byte assembly,
  // so they have to come out the same everywhere.
  const TARGETS = ["native", "js", "wasm", "wasm-gc"];
  const MODES = ["debug", "release"];
  const runs = [];
  for (const t of TARGETS) {
    for (const m of MODES) {
      const r = moon(["run", "cmd/cancel_fwd_kat", "--target", t, "-d", m]);
      runs.push({ t, m, out: norm(r.out), hash: hashOut(r.out), code: r.code });
    }
  }
  const refHash = runs[0].hash;
  const allRan = runs.every((r) => r.code === 0);
  ok("cmd/cancel_fwd_kat runs on 4 target x 2 mode", allRan,
    allRan ? refHash : runs.filter((r) => r.code !== 0).map((r) => `${r.t}/${r.m}`).join(" "));
  ok("4 target x 2 mode byte-identical", allRan && runs.every((r) => r.hash === refHash),
    allRan ? refHash : runs.filter((r) => r.hash !== refHash).map((r) => `${r.t}/${r.m}`).join(" "));

  const mine = katLines(runs[0].out);
  const theirs = oracleLines(oracleText);
  const keys = [...theirs.keys()];
  ok("the oracle and the KAT emit the same cases", keys.length > 0 && mine.size === theirs.size,
    `ours=${mine.size} theirs=${theirs.size}`);
  for (const k of keys) {
    const got = mine.get(k);
    const want = theirs.get(k);
    ok(`KAT ${k} == oracle`, got !== undefined && got === want,
      got === want ? `${(want || "").length / 2} bytes` : `ours=${got} theirs=${want}`);
  }

  // The relation the request exists for: the cancel carries the *same*
  // address and port as the request it cancels. C4 cancels R3.
  const reqTail = payloadTail(mine.get("REQ R3") || "");
  const cancTail = payloadTail(mine.get("CANC C4") || "");
  ok("the cancel's address and port are the request's",
    reqTail.length > 0 && reqTail.equals(cancTail),
    `req=${reqTail.toString("hex")} canc=${cancTail.toString("hex")}`);
  ok("C1 asks for no reply -- the shape OpenSSH's own client sends",
    wantReplyByte(mine.get("CANC C1") || "") === 0,
    `want_reply=${wantReplyByte(mine.get("CANC C1") || "")}`);
  ok("C4 asks for a reply", wantReplyByte(mine.get("CANC C4") || "") === 1,
    `want_reply=${wantReplyByte(mine.get("CANC C4") || "")}`);
  ok("the bind address '*' is normalised to the empty string",
    mine.get("HOST H2") === "" && mine.get("HOST H3") === "127.0.0.1",
    `H2="${mine.get("HOST H2")}" H3="${mine.get("HOST H3")}"`);

  // ------------------------------------------------------------------- G2 --
  section("G2: a real OpenSSH server cancels the forward");
  const sshdPort = await freePort();
  const name = "loop81";
  rmSync(sshdLog(name), { force: true });
  const sshd = startSshd(sshdPort, name);
  let grantedA = 0;
  let grantedB = 0;
  try {
    if (!await waitForText(sshd, "sshd listening", 30000)) {
      const why = (sshd.tapBuf || "").trim().split("\n").slice(0, 4).join(" | ") || "the server never came up";
      if (/no sshd\.exe/.test(why)) {
        skip("the cancel against a real server", why);
        skip("the server's own log", "no server to ask");
      } else {
        ok("the private sshd is up", false, why);
        ok("the server's own log", false, "no server");
      }
    } else {
      ok("the private sshd is up", true);
      ok("the sshd is listening", await waitForPort(sshdPort, 5000));

      // --- the cancel that wants a reply -------------------------------
      const a = runClient(sshdPort, ["--forward-cancel", "127.0.0.1:0"]);
      for (const l of a.split("\n")) {
        if (/^(result|error|probe_|attempt|granted_port)/.test(l)) console.log(`      ${l.trim()}`);
      }
      grantedA = Number(lineOf(a, "granted_port") || 0);
      ok("result: FORWARD_CANCEL_DONE", a.includes("result: FORWARD_CANCEL_DONE"), lineOf(a, "result"));
      ok("the server allocated a port", grantedA > 0, `granted_port=${grantedA}`);
      ok("the port was listening before the cancel", lineOf(a, "probe_before") === "open",
        lineOf(a, "probe_before"));
      ok("the first cancel was answered with SUCCESS",
        /attempt0: want_reply=true replied=true success=true/.test(a), lineOf(a, "attempt0"));
      ok("the second cancel was answered with FAILURE -- the listener was gone",
        /attempt1: want_reply=true replied=true success=false/.test(a), lineOf(a, "attempt1"));
      ok("the port refuses connections after the cancel", lineOf(a, "probe_after") === "closed",
        lineOf(a, "probe_after"));

      // --- the cancel that does NOT want a reply -----------------------
      // OpenSSH's own client sends want_reply=0.  The server then answers
      // nothing, so the *second* cancel is what proves the first one worked.
      const b = runClient(sshdPort, ["--forward-cancel-no-reply", "127.0.0.1:0"]);
      for (const l of b.split("\n")) {
        if (/^(result|error|probe_|attempt|granted_port)/.test(l)) console.log(`      ${l.trim()}`);
      }
      grantedB = Number(lineOf(b, "granted_port") || 0);
      ok("result: FORWARD_CANCEL_DONE (no-reply variant)", b.includes("result: FORWARD_CANCEL_DONE"),
        lineOf(b, "result"));
      ok("the server allocated a port (no-reply variant)", grantedB > 0, `granted_port=${grantedB}`);
      ok("the port was listening before the cancel (no-reply variant)",
        lineOf(b, "probe_before") === "open", lineOf(b, "probe_before"));
      ok("the silent cancel was not answered -- the server sends nothing",
        /attempt0: want_reply=false replied=false success=false/.test(b), lineOf(b, "attempt0"));
      ok("the second cancel was answered with FAILURE -- so the silent one worked",
        /attempt1: want_reply=true replied=true success=false/.test(b), lineOf(b, "attempt1"));
      ok("the port refuses connections after the silent cancel",
        lineOf(b, "probe_after") === "closed", lineOf(b, "probe_after"));

      // --- the server's own account of what it received ----------------
      const log = existsSync(sshdLog(name)) ? readFileSync(sshdLog(name), "utf8") : "";
      ok("the server received the cancel with the port it allocated",
        grantedA > 0 && log.includes(`cancel-tcpip-forward addr 127.0.0.1 port ${grantedA}`),
        grantedA > 0 ? `port ${grantedA}` : "no granted port");
      ok("the server received the second cancel with its own port",
        grantedB > 0 && log.includes(`cancel-tcpip-forward addr 127.0.0.1 port ${grantedB}`),
        grantedB > 0 ? `port ${grantedB}` : "no granted port");
      ok("the server saw want_reply=1 for the first client",
        log.includes("rtype cancel-tcpip-forward want_reply 1"));
      ok("the server saw want_reply=0 for the second client",
        log.includes("rtype cancel-tcpip-forward want_reply 0"));
      ok("the server closed a listener because of the cancel",
        /close channel \d+/.test(log),
        (log.match(/^.*close channel \d+.*$/m) || ["the server never logged a closed channel"])[0].trim());
      ok("the server never saw a cancel for port 0",
        !/cancel-tcpip-forward addr 127\.0\.0\.1 port 0\b/.test(log),
        "the granted port, not the requested one");
    }
  } finally {
    sshd.kill();
    stopSshd(name);
  }

  // ------------------------------------------------------------- regression --
  if (!SKIP_REGRESSION) {
    section("regression: the earlier loops must not move");
    for (const label of ["loop78", "loop79", "loop80"]) {
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
  console.log("  the cancel was pinned byte for byte against an independent implementation,");
  console.log("  a real OpenSSH server closed the listener because of it, and the silent");
  console.log("  want_reply=0 form -- the one OpenSSH's own client uses -- was proven by");
  console.log("  the next cancel failing, not by the absence of an error.");
  process.exit(0);
}

function waitForPort(port, timeoutMs) {
  return new Promise((resolve) => {
    const deadline = Date.now() + timeoutMs;
    const attempt = () => {
      const s = net.connect({ host: "127.0.0.1", port }, () => { s.destroy(); resolve(true); });
      s.on("error", () => {
        s.destroy();
        if (Date.now() > deadline) resolve(false);
        else setTimeout(attempt, 150);
      });
    };
    attempt();
  });
}

main().catch((e) => {
  console.error("harness error:", e);
  process.exit(2);
});
