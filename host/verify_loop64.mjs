// host/verify_loop64.mjs -- Loop #64: the SSH layer is transport-generic, and
// a browser transport still cannot be bolted onto it synchronously.
//
// ## The seam
//
// Until Loop #64 every function in `src/sshclient` and `src/sftp` named
// `@tcp.TcpConn` in its signature. That made the protocol layer and one Winsock
// binding the same thing at the type level: "run the same handshake over a
// WebSocket" was not expressible without rewriting 25 signatures, and the two
// could not be shown equivalent because only one existed.
//
// `src/transport` now supplies the contract. This gate checks the seam is real
// (section A/B) and that the migration was total (section C).
//
// ## The wall
//
// The obvious next step -- implement `Transport` over a browser WebSocket --
// runs into a fact this gate measures at runtime rather than argues about.
// `src/sshclient` is synchronous: `conn.wire_read_exact(4)` returns
// `FixedArray[Byte]?` directly. A browser WebSocket can only be read by
// awaiting, and in MoonBit only an `async fn` can await. So the question is
// whether a synchronous `fn` can hand control back to the JS event loop and
// pick up a byte that a deferred callback has not delivered yet.
//
// `cmd/probe_async_wall` answers it by measurement, with the callback standing
// in for `WebSocket.onmessage`. It does not matter that the byte arrives after
// 0ms, a tick, or a network hop: the byte does not exist yet, and only the
// event loop can create it.
//
// The loop53--#63 gates passing is the other half of the story: those assert
// byte-exact wire transcripts, so a clean run is evidence that lifting 25
// signatures changed no protocol behaviour at all.

import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));

let passed = 0;
const failures = [];

function expect(name, cond, detail = "") {
  if (cond) {
    passed++;
    console.log(`  ok    ${name}`);
  } else {
    failures.push(name);
    console.log(`  FAIL  ${name}${detail ? `  [${detail}]` : ""}`);
  }
}

/// Source text gates must strip comments first: a comment explaining a bug
/// necessarily contains the bug's text.
function stripComments(src) {
  return src.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/[^\n]*/g, "");
}

function section(title) {
  console.log("");
  console.log(title);
}

const transportDir = join(root, "src", "transport");
const transportSrc = readdirSync(transportDir)
  .filter((f) => f.endsWith(".mbt"))
  .map((f) => stripComments(readFileSync(join(transportDir, f), "utf8")))
  .join("\n");

const live = stripComments(readFileSync(join(root, "src", "sshclient", "live.mbt"), "utf8"));
const sftp = stripComments(readFileSync(join(root, "src", "sshclient", "sftp.mbt"), "utf8"));
const tcpPkg = readFileSync(join(root, "src", "tcp", "moon.pkg"), "utf8");
const sshPkg = readFileSync(join(root, "src", "sshclient", "moon.pkg"), "utf8");

// ------------------------------------------------ A. the seam --------------
section("A. src/transport declares exactly the contract sshclient uses");
expect("the trait exists", /pub\(open\)\s+trait\s+Transport/.test(transportSrc));
expect("it has a send method", /fn\s+wire_send\(/.test(transportSrc));
expect("it has an exact-read method", /fn\s+wire_read_exact\(/.test(transportSrc));
expect("it has a close method", /fn\s+wire_close\(/.test(transportSrc));
// The contract is three methods because that is all sshclient calls. A fourth
// would be a claim about a caller that does not exist.
{
  const methods = [...transportSrc.matchAll(/^\s*fn\s+(wire_\w+)\(/gm)].map((m) => m[1]);
  const unique = [...new Set(methods)].sort();
  expect(
    "the contract is exactly those three",
    JSON.stringify(unique) === JSON.stringify(["wire_close", "wire_read_exact", "wire_send"]),
    unique.join(", "),
  );
}
{
  // Existence is not uniqueness. A second impl is exactly what would let a
  // browser transport in, and nothing in section C would notice.
  const impls = [
    ...new Set(
      [...transportSrc.matchAll(/impl\s+Transport\s+for\s+([@A-Za-z_][\w.]*)/g)].map((m) => m[1]),
    ),
  ].sort();
  expect(
    "TcpConn is the only implementation",
    JSON.stringify(impls) === JSON.stringify(["@tcp.TcpConn"]),
    impls.join(", ") || "(none)",
  );
}

// ------------------------------------------------ B. the arrow -------------
section("B. the dependency arrow points one way");
expect("src/transport imports src/tcp", /openssh\/openssh_moonbit\/src\/tcp/.test(readFileSync(join(transportDir, "moon.pkg"), "utf8")));
expect("src/tcp does not import src/transport", !/src\/transport/.test(tcpPkg));
expect("src/sshclient does import src/transport", /src\/transport/.test(sshPkg));
// Loop #64 mutation M6 found this hole: an unused `ws_socket` import added to
// src/transport changed no behaviour and no assertion here noticed. Checking
// only that src/tcp stays clean is not enough -- the browser transport can be
// brought in from either end of the arrow.
{
  const transportPkg = readFileSync(join(transportDir, "moon.pkg"), "utf8");
  const smuggled = [...transportPkg.matchAll(/"([^"]+)"/g)]
    .map((m) => m[1])
    .filter((p) => /ws_socket|wt_socket|wt_net/.test(p));
  expect(
    "src/transport imports no browser socket package",
    smuggled.length === 0,
    smuggled.join(", "),
  );
  expect(
    "src/transport imports only src/tcp from this module",
    ![...transportPkg.matchAll(/"openssh\/openssh_moonbit\/src\/[^"]+"/g)]
      .map((m) => m[0])
      .some((p) => !p.includes("src/tcp")),
    transportPkg.replace(/\s+/g, " "),
  );
}
// The TCP binding must stay a plain Winsock binding; if it learned about the
// trait, the seam would be a cycle wearing a trait's clothes.
{
  const tcpSrc = readdirSync(join(root, "src", "tcp"))
    .filter((f) => f.endsWith(".mbt"))
    .map((f) => stripComments(readFileSync(join(root, "src", "tcp", f), "utf8")))
    .join("\n");
  expect("src/tcp never mentions Transport", !/\bTransport\b/.test(tcpSrc));
  expect("src/tcp is still a plain socket binding", /struct\s+TcpConn/.test(tcpSrc));
}

// ------------------------------------------------ C. the migration ----------
section("C. the migration was total");
expect("live.mbt is generic over the trait", live.includes("@transport.Transport"));
expect("live.mbt no longer names TcpConn", !live.includes("@tcp.TcpConn"));
expect("sftp.mbt is generic over the trait", sftp.includes("@transport.Transport"));
expect("sftp.mbt no longer names TcpConn", !sftp.includes("@tcp.TcpConn"));
// The type parameter must precede the name; the compiler's own hint is
// `fn[T] f`, and the migration got this wrong three times before it was right.
{
  const wrong = (src) => [...src.matchAll(/^\s*(?:pub(?:\([a-z]+\))?\s+)?fn\s+\w+\[/gm)].length;
  expect("live.mbt has no mispositioned type parameters", wrong(live) === 0, String(wrong(live)));
  expect("sftp.mbt has no mispositioned type parameters", wrong(sftp) === 0, String(wrong(sftp)));
  const dup = [...(live + sftp).matchAll(/fn\[T : @transport\.Transport\][^\n]*?\bfn\s+fn\b/g)].length;
  expect("no duplicated fn keywords remain", dup === 0, String(dup));
}
// Every call site must have been renamed, or the trait methods are dead code.
{
  const stale = [...(live + sftp).matchAll(/conn\.(?:send|read_exact|close)\(/g)].length;
  expect("no stale conn.send / read_exact / close calls", stale === 0, String(stale));
  const wired = [...(live + sftp).matchAll(/conn\.wire_(?:send|read_exact|close)\(/g)].length;
  expect("the trait methods are actually called", wired > 0, String(wired));
}

// ------------------------------------------------ D. the wall ---------------
section("D. a synchronous fn cannot receive a byte the event loop has not made yet");
const probe = join(root, "cmd", "probe_async_wall");
expect("cmd/probe_async_wall exists", existsSync(probe));
{
  const r = spawnSync("cmd", ["/c", "moon", "run", "cmd\\probe_async_wall", "--target", "js"], {
    cwd: root,
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
  });
  const out = `${r.stdout || ""}${r.stderr || ""}`;
  expect("the probe builds and runs", r.status === 0, out.split("\n").slice(-4).join(" | "));
  expect(
    "synchronous code starves",
    /sync\s*: STARVED after \d+ spins/.test(out),
    out.split("\n").filter((l) => l.startsWith("sync")).join(" | "),
  );
  expect(
    "asynchronous code receives the same byte",
    /async\s*: GOT 0x5a/.test(out),
    out.split("\n").filter((l) => l.startsWith("async")).join(" | "),
  );
  // The whole claim is that the *same* deferred delivery is reachable from
  // async and unreachable from sync. If the two arms used different
  // scheduling, the comparison would prove nothing.
  const probeSrc = stripComments(readFileSync(join(probe, "main.mbt"), "utf8"));
  expect(
    "both arms are driven by the same setTimeout scheduling",
    (probeSrc.match(/setTimeout\(/g) || []).length === 2,
    String((probeSrc.match(/setTimeout\(/g) || []).length),
  );
  expect("the sync arm is bounded so it terminates", /spin_budget/.test(probeSrc));
}

// ------------------------------------------------ E. the gate --------------
section("E. loop63's gate still holds after the seam landed");
{
  const r = spawnSync("cmd", ["/c", "node", "host\\verify_loop63.mjs"], {
    cwd: root,
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
  });
  expect("loop63 still passes", r.status === 0, (r.stdout || "").trim().split("\n").pop());
  // Loop #63 asserted the client was bound to @tcp.TcpConn. That literal is
  // gone by design; what must replace it is the stronger statement that
  // TcpConn is still the only implementation.
  const g63 = readFileSync(join(root, "host", "verify_loop63.mjs"), "utf8");
  expect(
    "loop63 now asserts the intent, not the old type name",
    g63.includes("TcpConn is still the only Transport implementation"),
  );
  expect("loop63 no longer asserts the superseded literal", !g63.includes('"the verified client is bound to @tcp.TcpConn"'));
}

// ------------------------------------------------ summary -------------------
console.log("");
console.log(`loop64: ${passed}/${passed + failures.length} checks passed`);
if (failures.length > 0) {
  console.log("");
  for (const f of failures) console.log(`  FAIL  ${f}`);
  process.exit(1);
}
console.log("ALL PASS");
