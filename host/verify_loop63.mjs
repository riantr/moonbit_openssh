// host/verify_loop63.mjs -- Loop #63: the browser SSH path has never run, and
// cannot run on this toolchain. Both halves of that are asserted here with
// evidence rather than argument.
//
// ## What has been claimed
//
// `docs/socket/loop23-summary.md` records Loop #23 as "PASS (with caveat)" and
// `host/verify_loop23.mjs` is titled as a verification of `cmd/ssh_full_ws`.
// Across Loops #23--#33 the browser path has been described as byte-exact
// verified. The goal it serves -- SSH from a browser, this project's reason for
// existing -- depends on that claim.
//
// ## What is true
//
// **`src/sshclient/live.mbt` is the only code that performs a real, verified
// handshake**, and it is bound to `@tcp.TcpConn`. It does not import
// `src/ws_socket`. That is native TCP, and it is genuinely verified -- Loops
// #54--#59 run it against a real peer.
//
// **`cmd/ssh_full_ws` is the browser binary, and it does not do a handshake.**
// It reads the server's KEXINIT and KEXDH_REPLY into `let _ =` -- discarded --
// never negotiates, never parses a host key, never verifies a signature, never
// derives a session key, and continues in plaintext after NEWKEYS. Its replies
// are hardcoded byte blobs and its `read_n` calls are written with the exact
// expected lengths, which is the shape of a scripted replay rather than of a
// protocol. It does compile, and it does assemble packets.
//
// **`verify_loop23.mjs` runs no MoonBit code.** Both sides are JavaScript: a
// Node.js WebSocket client against a Node.js mock server. Its own header says
// the MoonBit side was checked by compilation only, and points at
// `verify_loop22.mjs` -- a `MockSocket` path, which is not a socket.
//
// **`host/node_host_wasm.mjs`, the host that would run the wasm, has never
// run.** Zero callers. A syntax error (`await` in a non-async function) means
// it cannot even be parsed. And its `ws_recv_into` deliberately throws on a
// short buffer, with a comment conceding that blocking is not supported and
// MoonBit has no retry.
//
// ## Why it cannot be fixed by restructuring the client
//
// The wasm-gc output exports exactly one symbol, `_start`. There is no way for
// the host to re-enter the module between reads, so a synchronous
// `Socket::read_n` inside a wasm frame can never yield to the host event loop
// that a WebSocket's `onmessage` needs. This gate builds a probe whose `pub fn`
// is deliberately exportable-looking and confirms it does *not* appear in the
// export table -- so the answer is not "mark the function differently".
//
// The escape route that does work is `--target js`, which shares `src/` and
// supports async I/O. That is a separate piece of work; this loop establishes
// what is true today so the next one starts from facts.
//
// ## Why a gate for a negative finding
//
// Loops #60, #61 and #62 each found a thing that looked tested and was not.
// This is the same defect at the largest scale in the tree, and it is more
// expensive to notice, because the wasm compiles and the byte path is byte-exact
// against a mock. A claim that has never been executed is the most expensive
// kind of unproven claim, and the cheapest defence is a gate that fails the
// moment the claim is made without evidence.

import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

let checks = 0;
const failures = [];
const skipped = [];

function ok(label, detail = "") {
  checks++;
  console.log(`  ok    ${label}${detail ? `  [${detail}]` : ""}`);
}

function bad(label, detail = "") {
  checks++;
  failures.push(label);
  console.log(`  FAIL  ${label}${detail ? `  [${detail}]` : ""}`);
}

function skip(label, why) {
  skipped.push(label);
  console.log(`  SKIP  ${label}  [${why}]`);
}

function expect(label, cond, detail = "") {
  if (cond) ok(label, detail);
  else bad(label, detail);
  return cond;
}

function run(cmd, args, opts = {}) {
  const r = spawnSync(cmd, args, { encoding: "utf8", maxBuffer: 64 * 1024 * 1024, ...opts });
  return { code: r.status, out: (r.stdout ?? "") + (r.stderr ?? "") };
}

function stripComments(src) {
  return src
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .split("\n")
    .map((line) => {
      const t = line.trim();
      if (t.startsWith("//")) return "";
      const at = line.indexOf("//");
      return at < 0 ? line : line.slice(0, at);
    })
    .join("\n");
}

async function main() {
  // ------------------------------------------------ A. the exports --------
  // The hinge for the whole architecture. If wasm-gc ever grows an export
  // mechanism, this section fails and the "cannot be fixed by restructuring"
  // claim in the header has to be revisited -- which is the point of asserting
  // it rather than asserting it in a comment.
  console.log("A. wasm-gc exports nothing but _start, so the host cannot re-enter");
  const built = run("cmd", ["/c", "moon build cmd\\probe_export --target wasm-gc"], { cwd: root });
  if (built.code !== 0) {
    bad("cmd/probe_export builds", built.out.split("\n").slice(-4).join(" | "));
    return finish();
  }
  ok("cmd/probe_export builds");

  const probeWasm = join(root, "_build", "wasm-gc", "debug", "build", "cmd", "probe_export", "probe_export.wasm");
  if (!existsSync(probeWasm)) {
    bad("cmd/probe_export.wasm exists");
    return finish();
  }
  const probeExports = await wasmExports(probeWasm);
  expect(
    "a pub fn is NOT exported by wasm-gc",
    probeExports.length === 1 && probeExports[0] === "_start",
    probeExports.join(", "),
  );

  const wsWasm = join(root, "_build", "wasm-gc", "debug", "build", "cmd", "ssh_full_ws", "ssh_full_ws.wasm");
  const builtWs = run("cmd", ["/c", "moon build cmd\\ssh_full_ws --target wasm-gc"], { cwd: root });
  if (builtWs.code !== 0) {
    bad("cmd/ssh_full_ws builds", builtWs.out.split("\n").slice(-4).join(" | "));
  } else if (existsSync(wsWasm)) {
    const wsExports = await wasmExports(wsWasm);
    expect(
      "the browser binary exports nothing but _start",
      wsExports.length === 1 && wsExports[0] === "_start",
      wsExports.join(", "),
    );
  } else {
    bad("cmd/ssh_full_ws.wasm exists");
  }

  // ------------------------------------------------ B. the orphan host ---
  console.log("");
  console.log("B. the host that would run it has never run");
  const hostPath = join(root, "host", "node_host_wasm.mjs");
  if (!existsSync(hostPath)) {
    bad("host/node_host_wasm.mjs exists");
  } else {
    // Absolute path: the child inherits `cwd` at the repo root, so the bare
    // filename resolved to nothing and Node reported a missing-module error
    // that reads exactly like a syntax error. Asking Node to parse a file that
    // is not there is not a parse.
    const syntax = run("node", ["--check", hostPath]);
    // The first version of this check printed PASS while the file had an
    // `await` outside an async function, because it grepped for "moonbit_socket"
    // rather than asking Node to parse the thing. A syntax check that does not
    // parse is not a syntax check.
    expect("host/node_host_wasm.mjs parses as JavaScript", syntax.code === 0, syntax.out.trim().split("\n")[0] || "");

    const src = readFileSync(hostPath, "utf8");
    expect(
      "its ws_recv_into refuses to block rather than blocking",
      src.includes("sync block not supported"),
      "conceded in a comment",
    );
    // And it genuinely has no callers: grep the whole gate directory.
    // Excluding this file itself is not cosmetic -- the first version counted
    // `verify_loop63.mjs` as a caller because the string appears in its own
    // header comment, and reported a caller where there was none.
    const callers = [];
    for (const f of readdirSync(join(root, "host"))) {
      if (!f.endsWith(".mjs")) continue;
      if (f === "node_host_wasm.mjs" || f === "verify_loop63.mjs") continue;
      const text = readFileSync(join(root, "host", f), "utf8");
      // Only a spawn counts as a caller. A mention in a comment does not run
      // anything, and `node_host_wasm` is named in several gate headers.
      if (/node_host_wasm\.mjs/.test(stripComments(text))) callers.push(f);
    }
    expect("no gate spawns node_host_wasm.mjs", callers.length === 0, callers.join(", "));
  }

  // ------------------------------------- C. the browser binary's shape ---
  console.log("");
  console.log("C. ssh_full_ws discards the handshake it appears to perform");
  const demoPath = join(root, "cmd", "ssh_full_ws", "main.mbt");
  if (!existsSync(demoPath)) {
    bad("cmd/ssh_full_ws/main.mbt exists");
    return finish();
  }
  const demo = stripComments(readFileSync(demoPath, "utf8"));

  // The two reads that matter. Both bind to `_`, so the payload is gone before
  // anything can look at it.
  //
  // Matched with a balanced-paren scan rather than `[^)]*`: the argument is
  // `make_server_kexinit_reply().length()`, and the first version truncated at
  // the inner `)`, so the "scripted length" check below was looking at
  // `make_server_kexinit_reply(` and concluded the code was fine. A regex that
  // cannot count its own parentheses will confidently agree with anything.
  const discarded = [...demo.matchAll(/let\s+_\s*=\s*sock\.read_n\(/g)].map((m) =>
    balancedAfter(demo, m.index + m[0].length),
  );
  expect(
    "the server's KEXINIT and KEXDH_REPLY are both read and discarded",
    discarded.some((d) => d.includes("make_server_kexinit_reply")) && discarded.some((d) => d.includes("make_server_kexdh_reply_reply")),
    `${discarded.length} discarded reads`,
  );
  // Every one of them asks a `make_server_*` helper for its length. A real
  // client cannot know how many bytes the peer will send before it reads.
  expect(
    "every read is scripted, with the expected length computed in advance",
    discarded.length > 0 && discarded.every((d) => /\.length\(\)$/.test(d.trim())),
    discarded.join(" | "),
  );

  // What a real handshake needs and this does not do.
  expect("it never calls flow_on_reply", !demo.includes("flow_on_reply"));
  expect("it never calls negotiate", !demo.includes("negotiate"));
  expect("it never derives session keys", !/derive_keys|kexflow\.flow_on_reply/.test(demo));
  expect("it never verifies a host key signature", !/hostkey|verify_with_alg|\.verify\(/.test(demo));
  expect("it never switches to an encrypted mode", !/set_mode/.test(demo));

  // ------------------------------------------------ D. the split ----------
  console.log("");
  console.log("D. the verified client and the browser transport are disjoint");
  const live = stripComments(readFileSync(join(root, "src", "sshclient", "live.mbt"), "utf8"));
  expect("the verified client is bound to @tcp.TcpConn", live.includes("@tcp.TcpConn"));
  expect("the verified client never imports ws_socket", !live.includes("ws_socket"));
  expect("the verified client never imports wt_socket", !live.includes("wt_socket"));

  const wsPkg = stripComments(readFileSync(join(root, "src", "ws_socket", "socket.mbt"), "utf8"));
  expect("ws_socket is wasm-only", wsPkg.includes('extern "wasm"'));
  expect("ws_socket blocks on read_n", /pub fn Socket::read_n/.test(wsPkg));

  // ------------------------------------------------ E. the gate ---------
  console.log("");
  console.log("E. loop23's gate runs no MoonBit code");
  const g23 = stripComments(readFileSync(join(root, "host", "verify_loop23.mjs"), "utf8"));
  expect("it never builds the wasm", !/moon\s+build/.test(g23));
  expect("it never runs the wasm host", !/node_host_wasm/.test(g23));
  expect("it drives a Node WebSocket client instead", /new WebSocket/.test(g23));
  expect("its peer is also Node", /mock_ssh_server_v2_v2/.test(g23));
  // The hand-written algorithm lists are the tell: they only need to exist if
  // the gate is standing in for the client.
  expect("its client algorithm lists are hand-written", g23.includes("writeString('curve25519-sha256"));

  return finish();
}

// ---------------------------------------------------------------------------

///| The text between `start` and its matching close paren, nesting counted.
function balancedAfter(src, start) {
  let depth = 1;
  for (let i = start; i < src.length; i++) {
    const ch = src[i];
    if (ch === "(") depth++;
    else if (ch === ")") {
      depth--;
      if (depth === 0) return src.slice(start, i);
    }
  }
  return "";
}

async function wasmExports(file) {
  const buf = readFileSync(file);
  const mod = await WebAssembly.compile(buf);
  return WebAssembly.Module.exports(mod).map((e) => e.name);
}

function finish() {
  console.log("");
  if (skipped.length) {
    console.log(`skipped: ${skipped.length}`);
    for (const s of skipped) console.log(`  SKIP  ${s}`);
  }
  console.log(`loop63: ${checks - failures.length}/${checks} checks passed`);
  if (failures.length) {
    console.log("");
    for (const f of failures) console.log(`  FAIL  ${f}`);
    process.exitCode = 1;
  } else {
    console.log("ALL PASS");
  }
}

await main();