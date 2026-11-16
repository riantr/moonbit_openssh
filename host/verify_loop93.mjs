// host/verify_loop93.mjs -- our SSH server, judged by the REAL OpenSSH client.
//
// Loop #92 put our SFTP server next to the real one and compared the bytes.
// Loop #93 has only one oracle worth having: the real `ssh.exe`.  A server is
// not right because it agrees with us -- it is right when a real client
// believes it.
//
// ## The verdict is the client's own words
//
// The client prints `Authenticated to <host> using "publickey".` when it has
// verified our host key's signature, switched to the encrypted transport,
// negotiated `ssh-userauth` and checked the signature over the session
// identifier.  Every one of those is a thing our server has to get right,
// and the client says so in one line.  This gate reads that line -- it does
// not read our own opinion of ourselves.
//
// The failure modes this catches are the ones a self-check cannot: a reply
// that is well formed but framed wrongly is refused by the peer, and the
// peer says so in its own words.  Two of the three bugs this loop found
// were exactly that.
//
// ## The bytes are checked too
//
// The client's verdict is about the handshake as a whole.  Two of the bugs
// were in the FRAMING of one message, and a whole-handshake verdict cannot
// say WHICH message was wrong.  So `host/ssh_recorder.py` records the
// plaintext part of the session and the gate checks the shape of the
// `SSH_MSG_KEX_ECDH_REPLY` against the shape the REAL sshd was measured to
// send (the signature field is 87 bytes on the wire: a length and a blob).
//
// ## The bed
//
// One directory with a host key, a user key, a second key that is NOT
// authorized, and the `authorized_keys` file.  The keys are made with the
// REAL `ssh-keygen`, not with ours: a bed built by the code under test is a
// bed that agrees with a bug.
//
// Run: node host/verify_loop93.mjs

import { spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const ROOT = path.resolve(
  new URL("..", import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1"),
);

const OUR_SSHD = path.join(
  ROOT, "_build", "native", "debug", "build", "cmd", "sshd", "sshd.exe",
);
const OUR_SSH_KEYGEN = path.join(
  ROOT, "_build", "native", "debug", "build", "cmd", "ssh_keygen",
  "ssh_keygen.exe",
);

// Where the real tools might be.
//
// machine-path-exempt: each entry below is a CANDIDATE, probed in order until
// one exists; none is asserted to exist on any machine.
const OPENSSH_DIRS = [
  "C:\\Windows\\System32\\OpenSSH",
  "C:\\Program Files\\OpenSSH",
  "C:\\Program Files\\OpenSSH-Win64",
];
const REAL_CLIENT =
  OPENSSH_DIRS.map((d) => path.join(d, "ssh.exe")).find((p) => fs.existsSync(p)) ||
  null;
const REAL_KEYGEN =
  OPENSSH_DIRS.map((d) => path.join(d, "ssh-keygen.exe")).find((p) => fs.existsSync(p)) ||
  null;

const BED = path.join(ROOT, ".loop93", "gate93");
const CAPTURE = path.join(ROOT, ".loop93", "gate93_capture");

let passed = 0;
let failed = 0;
const failures = [];

function ok(name, cond, detail) {
  if (cond) {
    passed += 1;
    console.log(`  ok    ${name}`);
  } else {
    failed += 1;
    failures.push(name);
    console.log(`  FAIL  ${name}`);
    if (detail) {
      const lines = String(detail).split("\n");
      for (const l of lines.slice(0, 12)) console.log(`        ${l}`);
      if (lines.length > 12) console.log(`        ... (${lines.length - 12} more)`);
    }
  }
}

function summary() {
  console.log("");
  console.log(`${passed} passed, ${failed} failed`);
  if (failed) {
    console.log("failed:");
    for (const f of failures) console.log(`  - ${f}`);
    return 1;
  }
  return 0;
}

// ------------------------------------------------------------------ the bed

function freshBed() {
  fs.rmSync(BED, { recursive: true, force: true });
  fs.mkdirSync(BED, { recursive: true });
  // The real ssh-keygen makes the keys.  `-N ""` is an EMPTY argument, which
  // a shell would eat -- so the bed is made with spawn and an argument array,
  // where an empty string survives.
  for (const [name, file] of [["host", "hostkey"], ["user", "userkey"], ["other", "otherkey"]]) {
    const r = spawnSync(
      REAL_KEYGEN,
      ["-t", "ed25519", "-f", path.join(BED, file), "-N", "", "-C", `loop93 ${name} key`],
      { encoding: "utf8", timeout: 60000 },
    );
    if (r.status !== 0) {
      throw new Error(`ssh-keygen failed for ${file}: ${r.stderr}`);
    }
  }
  const pub = fs.readFileSync(path.join(BED, "userkey.pub"), "utf8").trim();
  fs.writeFileSync(
    path.join(BED, "authorized_keys"),
    pub + " loop93 user key\n",
  );
}

// The fingerprint of the bed's host key, as the real ssh-keygen prints it.
function hostFingerprint() {
  const r = spawnSync(
    REAL_KEYGEN,
    ["-lf", path.join(BED, "hostkey.pub")],
    { encoding: "utf8", timeout: 60000 },
  );
  const m = /SHA256:[A-Za-z0-9+/=]+/.exec(r.stdout || "");
  return m ? m[0] : null;
}

// --------------------------------------------------------------- the server

// Start our sshd and wait for it to say which port it took.
function startServer(authorizedKeys) {
  const ak = authorizedKeys || path.join(BED, "authorized_keys");
  return new Promise((resolve, reject) => {
    const p = spawn(
      OUR_SSHD,
      [
        "--host-key", path.join(BED, "hostkey"),
        "--authorized-keys", ak,
        "--port", "0",
        "--accept-timeout-ms", "30000",
      ],
      { stdio: ["ignore", "pipe", "pipe"] },
    );
    let out = "";
    let err = "";
    let done = false;
    const timer = setTimeout(() => {
      if (!done) {
        done = true;
        p.kill();
        reject(new Error(`the server did not report a port\n${err}`));
      }
    }, 20000);
    p.stdout.on("data", (d) => { out += d.toString(); });
    p.stderr.on("data", (d) => {
      err += d.toString();
      const m = /listen_port: (\d+)/.exec(err);
      if (m && !done) {
        done = true;
        clearTimeout(timer);
        resolve({
          proc: p,
          port: Number(m[1]),
          stderr: () => err,
          stdout: () => out,
          wait: (ms) =>
            new Promise((r) => setTimeout(r, ms)),
        });
      }
    });
    p.on("error", (e) => {
      if (!done) {
        done = true;
        clearTimeout(timer);
        reject(e);
      }
    });
  });
}

// Wait for a process to exit, with a bound.
//
// A gate that HANGS is worse than a gate that is wrong: it takes the CI's
// whole budget with it and says nothing.  So the wait is bounded, and a
// process that does not exit in time is reported as `null` -- which the
// checks read as "it did not exit", and so as a failure.
function waitExit(p, ms = 30000) {
  return new Promise((resolve) => {
    if (p.exitCode !== null) {
      resolve(p.exitCode);
      return;
    }
    let done = false;
    const timer = setTimeout(() => {
      if (!done) {
        done = true;
        resolve(null);
      }
    }, ms);
    p.on("exit", (code) => {
      if (!done) {
        done = true;
        clearTimeout(timer);
        resolve(code);
      }
    });
  });
}

// --------------------------------------------------------------- the client

// Run the real client against a port.
function runClient(port, keyFile, command) {
  const args = [
    "-F", "none",
    "-p", String(port),
    "-i", path.join(BED, keyFile),
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=NUL",
    "-o", "IdentitiesOnly=yes",
    "-o", "BatchMode=yes",
    "-v",
    "hp@127.0.0.1",
    command,
  ];
  const r = spawnSync(REAL_CLIENT, args, { encoding: "utf8", timeout: 60000 });
  return {
    code: r.status,
    stdout: r.stdout || "",
    stderr: r.stderr || "",
  };
}

// ------------------------------------------------------------- the capture

// Split a capture into its plaintext packets.
//
// Everything up to NEWKEYS is plaintext, and that is the part a server has to
// get right before anything is encrypted.
function plainPackets(buf) {
  const nl = buf.indexOf("\r\n");
  if (nl < 0) return { ident: null, packets: [] };
  const ident = buf.slice(0, nl).toString("latin1");
  const packets = [];
  let off = nl + 2;
  while (off + 4 <= buf.length) {
    const plen = buf.readUInt32BE(off);
    if (off + 4 + plen > buf.length) break;
    const pkt = buf.slice(off + 4, off + 4 + plen);
    const pad = pkt[0];
    const body = pkt.slice(1, pkt.length - pad);
    packets.push({ type: body[0], payload: body.slice(1) });
    off += 4 + plen;
    if (body[0] === 21) break; // NEWKEYS: the rest is encrypted
  }
  return { ident, packets };
}

// The three string fields of an ECDH_REPLY, as they are ON THE WIRE.
//
// The point of this function is the third one: the signature field is a
// string whose CONTENT is the signature blob, so on the wire it is a length
// and then 83 bytes.  The bug this loop found wrote the blob without that
// outer length -- the same 83 bytes of content with a different framing --
// and the peer read an 11-byte "signature" and refused to go on.
function ecdhReplyFields(payload) {
  const fields = [];
  let off = 0;
  for (let i = 0; i < 3; i++) {
    const len = payload.readUInt32BE(off);
    fields.push({ len, off });
    off += 4 + len;
  }
  return { fields, end: off };
}

// ----------------------------------------------------------------- driver

async function main() {
  console.log("=== Loop #93: our SSH server, judged by the real OpenSSH client ===");
  if (!REAL_CLIENT) {
    ok(
      "a real ssh.exe is available",
      false,
      `no ssh.exe in any of: ${OPENSSH_DIRS.join(", ")}`,
    );
    return summary();
  }
  if (!REAL_KEYGEN) {
    ok("a real ssh-keygen.exe is available", false, "no ssh-keygen.exe found");
    return summary();
  }
  console.log(`real client: ${REAL_CLIENT}`);
  console.log(`our server:  ${OUR_SSHD}`);

  const build = spawnSyncMoon(["build", "--target", "native", "cmd/sshd"]);
  if (build.code !== 0) {
    console.log(`  FAIL  cmd/sshd does not build\n${build.out.slice(-3000)}`);
    process.exit(1);
  }
  ok("our server built", fs.existsSync(OUR_SSHD));

  const unit = spawnSyncMoon(["test", "--target", "native", "src/sshd"]);
  ok(
    "the src/sshd unit tests pass",
    unit.code === 0,
    unit.code === 0 ? "" : unit.out.slice(-3000),
  );

  freshBed();
  ok(
    "the key bed is in place",
    fs.existsSync(path.join(BED, "hostkey")) &&
      fs.existsSync(path.join(BED, "userkey")) &&
      fs.existsSync(path.join(BED, "authorized_keys")),
  );
  const fp = hostFingerprint();
  ok("the bed's host key has a fingerprint", fp !== null, String(fp));

  // ---- the successful authentication ----
  const server = await startServer();
  const client = runClient(server.port, "userkey", "echo hello");
  const exit = await waitExit(server.proc);
  const serverOut = server.stdout();
  const serverErr = server.stderr();

  ok(
    "the client authenticates with publickey",
    client.stderr.includes('Authenticated to 127.0.0.1') &&
      client.stderr.includes('using "publickey"'),
    client.stderr.slice(-2000),
  );
  ok(
    "the client verified our host key",
    // The fingerprint line is printed BEFORE the signature is checked, so
    // on its own it cannot tell a good signature from a bad one.  What tells
    // them apart is the client's own sentence when the signature does not
    // verify: `incorrect signature` (measured, with the signature zeroed).
    fp !== null &&
      client.stderr.includes("Server host key: ssh-ed25519 " + fp) &&
      !client.stderr.includes("incorrect signature"),
    client.stderr.slice(-2000),
  );
  ok(
    "the client negotiated the measured algorithms",
    client.stderr.includes("kex: algorithm: diffie-hellman-group14-sha256") &&
      client.stderr.includes("kex: host key algorithm: ssh-ed25519") &&
      client.stderr.includes("server->client cipher: aes128-ctr MAC: hmac-sha2-256"),
    client.stderr.slice(-2000),
  );
  ok(
    "our server names the authenticated user",
    serverOut.includes("user: hp") && serverOut.includes("authenticated: 1"),
    serverOut,
  );
  ok(
    "our server reports the negotiated algorithms",
    serverOut.includes("kex_alg: diffie-hellman-group14-sha256") &&
      serverOut.includes("hostkey_alg: ssh-ed25519") &&
      serverOut.includes("cipher_ctos: aes128-ctr") &&
      serverOut.includes("cipher_stoc: aes128-ctr"),
    serverOut,
  );
  ok("our server exits 0 after a successful authentication", exit === 0, `exit ${exit}`);
  ok(
    "the identification string is ours",
    client.stderr.includes("remote software version MoonBit_sshd_0.1"),
    client.stderr.slice(-2000),
  );

  // ---- the channel refusal ----
  //
  // The channel layer is the NEXT loop.  What this loop owes the peer is a
  // refusal it can read: addressed to the channel the peer opened, with the
  // language tag the format asks for.  The bug this loop found named channel
  // 2097152 (the window size) and the client answered `open failure packet
  // referred to nonexistent channel 2097152`.
  ok(
    "the channel refusal is addressed to the channel the peer opened",
    !client.stderr.includes("nonexistent channel"),
    client.stderr.slice(-2000),
  );
  ok(
    "the channel refusal says why",
    client.stderr.includes("open failed: administratively prohibited"),
    client.stderr.slice(-2000),
  );
  ok(
    "the exec did not run",
    !client.stdout.includes("hello"),
    client.stdout,
  );

  // ---- the unauthorized key ----
  const server2 = await startServer();
  const client2 = runClient(server2.port, "otherkey", "echo hello");
  const exit2 = await waitExit(server2.proc);
  const serverOut2 = server2.stdout();

  ok(
    "an unauthorized key is refused",
    client2.stderr.includes("Permission denied") &&
      !client2.stderr.includes('Authenticated to 127.0.0.1'),
    client2.stderr.slice(-2000),
  );
  ok(
    "the client is told which methods may continue",
    client2.stderr.includes("Authentications that can continue: publickey"),
    client2.stderr.slice(-2000),
  );
  ok(
    "our server reports the refusal",
    serverOut2.includes("authenticated: 0"),
    serverOut2,
  );
  ok("our server exits 1 after a refused authentication", exit2 === 1, `exit ${exit2}`);

  // ---- a key that carries options ----
  //
  // `authorized_keys` may carry options before the key type
  // (`command="...",no-pty ssh-ed25519 AAAA...`).  This server does not
  // implement `command=` or `no-pty`, so accepting the key without honouring
  // them would silently drop the restrictions the file asked for.  So a key
  // with options is REFUSED -- and refused loudly enough that the client says
  // so.
  const pubLine = fs.readFileSync(path.join(BED, "userkey.pub"), "utf8").trim();
  const optionsPath = path.join(BED, "authorized_keys_options");
  fs.writeFileSync(
    optionsPath,
    pubLine.replace("ssh-ed25519", 'command="echo hi",no-pty ssh-ed25519') + "\n",
  );
  const server2b = await startServer(optionsPath);
  const client2b = runClient(server2b.port, "userkey", "echo hello");
  const exit2b = await waitExit(server2b.proc);
  ok(
    "a key with options in authorized_keys is refused",
    client2b.stderr.includes("Permission denied") &&
      !client2b.stderr.includes('Authenticated to 127.0.0.1'),
    client2b.stderr.slice(-2000),
  );
  ok(
    "our server reports the refusal of a key with options",
    server2b.stdout().includes("authenticated: 0") && exit2b === 1,
    server2b.stdout(),
  );

  // ---- the bytes on the wire ----
  //
  // The recorder is put between the client and our server, and the
  // plaintext part of the session is read.  This is the check that says
  // WHICH message is wrong when something is wrong.
  fs.rmSync(CAPTURE, { recursive: true, force: true });
  fs.mkdirSync(CAPTURE, { recursive: true });
  const server3 = await startServer();
  const recorder = spawn(
    "python",
    [
      path.join(ROOT, "host", "ssh_recorder.py"),
      String(server3.port + 1),
      String(server3.port),
      "--out", CAPTURE,
    ],
    { stdio: ["ignore", "pipe", "pipe"] },
  );
  let recErr = "";
  recorder.stderr.on("data", (d) => { recErr += d.toString(); });
  recorder.stdout.on("data", () => {});
  // give the recorder a moment to bind
  await new Promise((r) => setTimeout(r, 1500));
  const client3 = runClient(server3.port + 1, "userkey", "echo hello");
  await waitExit(recorder);
  await waitExit(server3.proc);

  const s2cPath = path.join(CAPTURE, "s2c.bin");
  const c2sPath = path.join(CAPTURE, "c2s.bin");
  const haveCapture = fs.existsSync(s2cPath) && fs.existsSync(c2sPath);
  ok("the handshake was recorded", haveCapture, recErr.slice(-1500));

  if (haveCapture) {
    const s2c = plainPackets(fs.readFileSync(s2cPath));
    const c2s = plainPackets(fs.readFileSync(c2sPath));
    const reply = s2c.packets.find((p) => p.type === 31);
    ok(
      "our reply is the ECDH_REPLY",
      reply !== undefined,
      s2c.packets.map((p) => p.type).join(","),
    );
    if (reply) {
      const { fields, end } = ecdhReplyFields(reply.payload);
      ok(
        "the reply is three strings and nothing else",
        end === reply.payload.length,
        `end ${end} of ${reply.payload.length}`,
      );
      ok(
        "the host key field is 51 bytes, as the real sshd sends it",
        fields[0].len === 51,
        `len ${fields[0].len}`,
      );
      ok(
        "the signature field is 87 bytes on the wire",
        fields[2].len === 83 && 4 + fields[2].len === 87,
        `content ${fields[2].len} bytes at offset ${fields[2].off}`,
      );
      // The signature blob's own content: string "ssh-ed25519" + string 64
      const blob = reply.payload.slice(fields[2].off + 4, fields[2].off + 4 + fields[2].len);
      const algLen = blob.readUInt32BE(0);
      const alg = blob.slice(4, 4 + algLen).toString("latin1");
      const sigLen = blob.readUInt32BE(4 + algLen);
      ok(
        "the signature blob is string(alg) + string(64 bytes)",
        alg === "ssh-ed25519" && sigLen === 64 &&
          blob.length === 4 + algLen + 4 + sigLen,
        `alg ${alg} sig ${sigLen} blob ${blob.length}`,
      );
    }
    ok(
      "our side sends KEXINIT, ECDH_REPLY and NEWKEYS",
      JSON.stringify(s2c.packets.map((p) => p.type)) === "[20,31,21]",
      s2c.packets.map((p) => p.type).join(","),
    );
    ok(
      "the client sends KEXINIT, ECDH_INIT and NEWKEYS",
      JSON.stringify(c2s.packets.map((p) => p.type)) === "[20,30,21]",
      c2s.packets.map((p) => p.type).join(","),
    );
  }

  return summary();
}

function spawnSyncMoon(args) {
  const r = spawnSync("cmd", ["/c", "moon", ...args], {
    cwd: ROOT, encoding: "utf8", timeout: 900000,
  });
  return { code: r.status, out: `${r.stdout || ""}${r.stderr || ""}` };
}

main().then((code) => process.exit(code || 0)).catch((e) => {
  console.log(e);
  process.exit(1);
});
