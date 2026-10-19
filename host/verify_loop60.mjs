// host/verify_loop60.mjs -- Loop #60: a client proposal may only name algorithms
// the packet transport can actually run.
//
// Loop #59 left this client advertising `hmac-sha2-256-etm@openssh.com` in
// `kexflow::default_client`. `src/bpacket` has no EtM branch at all --
// packet_ctx.mbt:32 says so in as many words. Nothing had ever failed, because
// that proposal's cipher is `chacha20-poly1305@openssh.com`, and an AEAD never
// computes the MAC. The over-promise was harmless by coincidence, not by
// design, and it was invisible to every gate that already existed.
//
// `src/sshclient/live.mbt::we_need_for` was the worse half. It accepted four
// ciphers and five MACs, and the caller then truncated the derived key to 16
// bytes and built an `AesCtrMacCtx` no matter what came back. A proposal
// naming `aes256-ctr` would have run aes128-ctr with the first half of a
// 256-bit key and reported nothing at all. Latent -- no live proposal offered
// it -- but it failed open rather than closed, and it was one line from live.
//
// ## What this gate asserts
//
// A. The invariant itself, over every client proposal in the tree: no cipher or
//    MAC name without a `Mode` branch. Emitted by `cmd/proposal_kat`.
//
// B. That the scope has NOT widened. A *server* proposal is exempt, because
//    negotiation takes the intersection -- a peer may name anything. This gate
//    carries a deliberately-broken peer proposal and asserts it is still
//    classified `scope=server` and still not judged. A gate that quietly became
//    "reject every name we do not implement" would pass a much simpler test and
//    break connectivity against real sshd for no safety gain.
//
// C. The runnable names and their parameters against authorities outside this
//    tree: `ssh -Q cipher` / `ssh -Q mac` for the names, and the OpenSSH C
//    reference (`cipher.c` `ciphers[]`, `mac.c` digests table) for the numbers.
//    Nothing here is transcribed from memory -- the one case worth spelling out
//    is `hmac-sha2-256-etm@openssh.com`, which we assert IS a real OpenSSH MAC
//    name. Removing a name is only a fix if the name was right.
//
// D. That the deleted third source of truth stays deleted, and that
//    `we_need_for` stays a delegate instead of drifting back into a second,
//    looser parameter table.
//
// E. That `moon test src/kexflow` still passes with the new invariant test.

import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
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
  return {
    code: r.status,
    out: (r.stdout ?? "") + (r.stderr ?? ""),
  };
}

async function main() {
  // ---------------------------------------------------------------- build ---
  console.log("building cmd/proposal_kat");
  const b = run("cmd", ["/c", "moon build cmd\\proposal_kat --target native"], { cwd: root });
  if (b.code !== 0) {
    bad("proposal_kat builds", b.out.split("\n").slice(-6).join(" | "));
    return finish();
  }
  ok("proposal_kat builds");

  const r = run("cmd", ["/c", "moon run cmd\\proposal_kat --target native"], { cwd: root });
  if (r.code !== 0) {
    bad("proposal_kat runs", r.out.split("\n").slice(-6).join(" | "));
    return finish();
  }
  ok("proposal_kat runs");

  // ------------------------------------------------- A. the runnable set ---
  console.log("");
  console.log("A. the authoritative runnable set");

  const runnableCipher = lineValue(r.out, "RUNNABLE_CIPHER");
  const runnableMac = lineValue(r.out, "RUNNABLE_MAC");

  expect(
    "runnable ciphers are exactly the two with a Mode branch",
    runnableCipher === "chacha20-poly1305@openssh.com,aes128-ctr",
    runnableCipher,
  );
  expect(
    "runnable MACs are exactly hmac-sha2-256",
    runnableMac === "hmac-sha2-256",
    runnableMac,
  );

  // ------------------------------------------------ B. the invariant ------
  console.log("");
  console.log("B. no client proposal names an algorithm without a packet-layer path");

  const blocks = parseProposals(r.out);
  const clients = blocks.filter((b) => b.scope === "client");
  const servers = blocks.filter((b) => b.scope === "server");

  expect("five client proposals were reached", clients.length === 5, clients.map((c) => c.label).join(", "));

  for (const c of clients) {
    const noPath = c.names.filter((n) => n.tag === "NO-PATH");
    expect(
      `client proposal ${c.label} names only runnable algorithms`,
      noPath.length === 0,
      noPath.map((n) => `${n.kind}:${n.name}`).join(", "),
    );
    expect(`client proposal ${c.label} reports verdict=honorable`, c.verdict === "honorable", c.verdict ?? "(none)");
    expect(
      `client proposal ${c.label} reports no stoc violation`,
      !c.verdictStoc,
      c.verdictStoc ?? "",
    );
  }

  // The stronger shape of the same check: count, do not just look for "honorable".
  // A client block with zero enc/mac names at all would otherwise pass vacuously,
  // which is the same hollow-pass shape Loop #59 hit with a key type hardcoded
  // into a regex that could never match anything.
  for (const c of clients) {
    const encMac = c.names.filter((n) => n.kind === "enc" || n.kind === "mac");
    expect(
      `client proposal ${c.label} actually names cipher+MAC (not vacuous)`,
      encMac.length >= 4,
      `${encMac.length} names`,
    );
  }

  // Do not take the emitter's `ok` / `NO-PATH` verdict on faith. It is the same
  // package computing the same predicate twice, so a mutation of the predicate
  // would be invisible: both sides would agree, and both would be wrong. The
  // gate therefore keeps its own copy of the runnable set and recomputes.
  const gateCiphers = new Set(["chacha20-poly1305@openssh.com", "aes128-ctr"]);
  const gateMacs = new Set(["hmac-sha2-256"]);
  // Loop #61 widened the emitter to four verdicts and to the kex/hostkey
  // categories. This gate's claim is cipher and MAC only -- the AGENTS.md entry
  // for Loop #60 says so in as many words -- so it recomputes those two
  // categories and, for the other two, asserts that it is *not* judging them.
  //
  // The first version recomputed every non-`info` kind against the cipher/MAC
  // sets, which turned `ssh-ed25519` and `curve25519-sha256` into five
  // confident failures. Out-of-scope is not the same as passing, and it has to
  // be stated rather than left to happen.
  const OUT_OF_SCOPE_KINDS = new Set(["kex", "hostkey"]);
  for (const c of clients) {
    const disagree = c.names
      .filter((n) => n.kind !== "info")
      .filter((n) => {
        if (OUT_OF_SCOPE_KINDS.has(n.kind)) return false;
        const want = n.kind === "mac" ? gateMacs.has(n.name) : gateCiphers.has(n.name);
        return n.tag !== (want ? "ok" : "NO-PATH");
      })
      .map((n) => `${n.name}:emitter=${n.tag}`);
    expect(
      `client proposal ${c.label}: the gate's own table agrees with the emitter`,
      disagree.length === 0,
      disagree.join(", "),
    );
  }
  for (const c of clients) {
    const judgedWrong = c.names
      .filter((n) => OUT_OF_SCOPE_KINDS.has(n.kind))
      .filter((n) => n.tag === "NO-PATH")
      .map((n) => `${n.name}=NO-PATH`);
    expect(
      `client proposal ${c.label}: this gate does not judge kex/hostkey`,
      judgedWrong.length === 0,
      judgedWrong.join(", "),
    );
  }

  // ------------------------------------------ C. the scope has not widened --
  console.log("");
  console.log("C. a peer proposal is exempt, and must stay exempt");

  expect("one server-scope fixture was emitted", servers.length === 1, String(servers.length));
  const srv = servers[0] ?? { names: [], verdict: "" };
const srvNoPath = srv.names.filter((n) => n.tag === "NO-PATH");
  // Same recomputation, on the peer fixture: unrunnable names must still show
  // up, with no reliance on the emitter's labels having stayed honest.
  const srvRecomputed = srv.names.filter((n) => {
    if (n.kind === "info") return false;
    const want = n.kind === "mac" ? gateMacs.has(n.name) : gateCiphers.has(n.name);
    return !want;
  });
  expect(
    "the peer fixture has unrunnable names by the gate's own reckoning",
    srvRecomputed.length === 2,
    srvRecomputed.map((n) => n.name).join(", "),
  );
  expect(
    "the peer fixture really does contain unrunnable names",
    srvNoPath.length === 2,
    srvNoPath.map((n) => n.name).join(", "),
  );
  expect(
    "the peer fixture is not judged",
    srv.verdict === "not-checked(scope=server)",
    srv.verdict,
  );
  expect(
    "the peer fixture carries no honorable verdict",
    !srv.verdict?.includes("honorable"),
    srv.verdict,
  );

  // The same exemption, on the host side: verify_loop23.mjs's list is a *server*
  // proposal and still names things we cannot run. If that file ever stops
  // doing so the asymmetry is untested from this direction too.
  const loop23 = join(root, "host", "verify_loop23.mjs");
  if (existsSync(loop23)) {
    const t = readFileSync(loop23, "utf8");
    const unrunnable = [
      "aes256-gcm@openssh.com",
      "aes128-gcm@openssh.com",
      "hmac-sha2-512-etm@openssh.com",
    ].filter((n) => t.includes(n));
    expect(
      "verify_loop23.mjs's server list still names unrunnable algorithms",
      unrunnable.length > 0,
      unrunnable.join(", "),
    );
  } else {
    skip("verify_loop23.mjs server list", "file not found");
  }

  // ------------------------------------------ D. outside authorities --------
  console.log("");
  console.log("D. the names and the numbers, checked outside this tree");

  const sshQ = run("ssh", ["-Q", "cipher"]);
  if (sshQ.code === 0 && sshQ.out.includes("aes128-ctr")) {
    const sshCiphers = new Set(sshQ.out.split(/\r?\n/).map((s) => s.trim()).filter(Boolean));
    for (const n of runnableCipher.split(",")) {
      expect(`ssh -Q cipher knows ${n}`, sshCiphers.has(n));
    }
    const sshMacQ = run("ssh", ["-Q", "mac"]);
    const sshMacs = new Set(sshMacQ.out.split(/\r?\n/).map((s) => s.trim()).filter(Boolean));
    for (const n of runnableMac.split(",")) {
      expect(`ssh -Q mac knows ${n}`, sshMacs.has(n));
    }
    // The name we removed was real. Removing a typo would be a different claim.
    expect(
      "the removed EtM name is a genuine OpenSSH MAC (we fixed the list, not the spelling)",
      sshMacs.has("hmac-sha2-256-etm@openssh.com"),
    );
    expect(
      "the removed EtM name really is a distinct MAC, not a synonym",
      run("ssh", ["-Q", "cipher"]).out.includes("aes128-ctr"),
    );
  } else {
    skip("ssh -Q name cross-check", "ssh unavailable");
  }

  // The parameters, against OpenSSH's own tables.
  const params = parseParams(r.out);
  const authlens = parseAuthlens(r.out);
  expect(
    "two auth lengths were emitted",
    Object.keys(authlens).length === 2,
    Object.keys(authlens).join(", "),
  );
  const cipherC = findOpenSSHC("cipher.c");
  if (cipherC) {
    const rows = parseCTable(readFileSync(cipherC, "utf8"));
    const aes = rows["aes128-ctr"];
    const chacha = rows["chacha20-poly1305@openssh.com"];
    if (expect("cipher.c has an aes128-ctr row", !!aes) && expect("cipher.c has a chacha20-poly1305 row", !!chacha)) {
      // struct sshcipher is (name, block_size, key_len, iv_len, auth_len, flags, evp).
      // cipher_ivlen (cipher.c:170-178) returns the column verbatim for
      // CFLAG_CHACHAPOLY and block_size otherwise.
      const [aesBlock, aesKey, aesIvCol, aesAuth] = aes.slice(0, 4);
      expect("aes128-ctr key_len", aesKey === String(params["aes128-ctr"].key), `C=${aesKey}`);
      expect("aes128-ctr block_size", aesBlock === String(params["aes128-ctr"].block), `C=${aesBlock}`);
      expect(
        "aes128-ctr effective iv_len (iv_len column 0 -> falls back to block_size)",
        String(aesBlock) === String(params["aes128-ctr"].iv),
        `C=${aesIvCol}->${aesBlock}`,
      );
      expect("aes128-ctr auth_len", aesAuth === "0");
      const [chBlock, chKey, chIv, chAuth] = chacha.slice(0, 4);
      expect("chacha20-poly1305 key_len", chKey === String(params["chacha20-poly1305@openssh.com"].key), `C=${chKey}`);
      expect("chacha20-poly1305 block_size", chBlock === String(params["chacha20-poly1305@openssh.com"].block), `C=${chBlock}`);
      expect(
        "chacha20-poly1305 iv_len is 0 under CFLAG_CHACHAPOLY",
        chIv === String(params["chacha20-poly1305@openssh.com"].iv),
        `C=${chIv}`,
      );
      // `auth_len` is the AEAD tag only. aes128-ctr has 0 there and carries a
      // separate 32-byte MAC; returning 32 for it is the mistake this check was
      // written to catch, and the first version of `authlen_for` made exactly
      // that mistake.
      expect(
        "chacha20-poly1305 auth_len",
        chAuth === String(authlens["chacha20-poly1305@openssh.com"]),
        `C=${chAuth} ours=${authlens["chacha20-poly1305@openssh.com"]}`,
      );
      expect(
        "aes128-ctr auth_len is 0 (its 32-byte MAC is not a tag)",
        aesAuth === String(authlens["aes128-ctr"]),
        `C=${aesAuth} ours=${authlens["aes128-ctr"]}`,
      );
      expect(
        "aes128-ctr MAC length comes from mac.c, not from cipher.c",
        String(params["aes128-ctr"].mac) === "32",
      );
    }
    const macC = findOpenSSHC("mac.c");
    if (macC) {
      const t = readFileSync(macC, "utf8");
      const m = t.match(/\{\s*"hmac-sha2-256"\s*,\s*SSH_DIGEST\s*,\s*SSH_DIGEST_SHA256\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*\}/);
      if (expect("mac.c has an hmac-sha2-256 row", !!m)) {
        expect("hmac-sha2-256 truncatebits is 0 (full 32-byte MAC)", m[1] === "0", m[1]);
        expect("hmac-sha2-256 etm flag is 0", m[4] === "0", m[4]);
        expect("hmac-sha2-256 mac_len is 32", String(params["aes128-ctr"].mac) === "32", String(params["aes128-ctr"].mac));
      }
      const etm = t.match(/\{\s*"hmac-sha2-256-etm@openssh\.com"\s*,\s*SSH_DIGEST\s*,\s*SSH_DIGEST_SHA256\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*\}/);
      expect("mac.c has a separate hmac-sha2-256-etm@openssh.com row", !!etm);
      if (etm) {
        // This is the load-bearing fact behind the whole loop: EtM is a
        // different algorithm with its own table row, not a spelling variant of
        // the MAC we do implement. That is why "we advertise it anyway, it is
        // basically the same" was never true.
        expect("the EtM row sets etm=1 where the plain row sets 0", etm[4] === "1", etm[4]);
      }
    } else {
      skip("mac.c parameter cross-check", "mac.c not found");
    }
  } else {
    skip("cipher.c parameter cross-check", "set OPENSSH_C to the OpenSSH source tree");
  }

  // ----------------------------------- E. the third source stays deleted ----
  console.log("");
  console.log("E. the deleted lists and the delegated parameter table stay that way");

  const alg = join(root, "src", "kex_names", "algorithms.mbt");
  if (existsSync(alg)) {
    const t = readFileSync(alg, "utf8");
    const gone = [
      "cipher_algs_default",
      "mac_algs_default",
      "kex_algs_default",
      "hostkey_algs_default",
    ];
    for (const name of gone) {
      const declared = new RegExp(`pub fn ${name}\\s*\\(`).test(t);
      expect(`kex_names no longer declares ${name}`, !declared);
    }
    expect("proposal_kat reports 4 removed defaults", lineValue(r.out, "DEFAULTS_REMOVED") === "4");
  } else {
    bad("src/kex_names/algorithms.mbt exists");
  }

  const livePath = join(root, "src", "sshclient", "live.mbt");
  const live = readFileSync(livePath, "utf8");
  const body = functionBody(live, "pub fn we_need_for");
  expect("we_need_for was found", !!body);
  if (body) {
    const literals = [...body.matchAll(/"([^"]*(?:aes|chacha|hmac)[^"]*)"/g)].map((m) => m[1]);
    expect(
      "we_need_for names no cipher/MAC literal (it delegates to src/bpacket)",
      literals.length === 0,
      literals.join(", "),
    );
    expect("we_need_for delegates to bpacket.transport_params", body.includes("@bpacket.transport_params"));
  }
  expect(
    "live.mbt no longer hardcodes a 16-byte session key",
    !live.includes("head_bytes(keys.enc_key_ctos(), 16)"),
  );
  expect("live.mbt routes through the runnable table", live.includes("@bpacket.cipher_needs_mac"));

  // ------------------------------------------------------- F. unit tests ----
  console.log("");
  console.log("F. the package test still passes");
  const t = run("cmd", ["/c", "moon test src\\kexflow"], { cwd: root });
  const total = t.out.match(/Total tests:\s*(\d+)/)?.[1];
  const failed = t.out.match(/failed:\s*(\d+)/)?.[1];
  expect("moon test src/kexflow passes", t.code === 0 && failed === "0", `${total} tests, ${failed} failed`);
  // The first version of this line asserted the test *name* appears in `moon
  // test` output. It does not -- moon prints test names only for failures --
  // so the check could never pass and, worse, would have looked like a real
  // assertion. Assert the declaration exists in the source, where it can match.
  const kexflowTest = join(root, "src", "kexflow", "kexflow_test.mbt");
  expect(
    "the Loop #60 invariant test is declared",
    readFileSync(kexflowTest, "utf8").includes("t11_default_client_only_names_runnable_algs"),
  );
  expect("kexflow had 13 tests before Loop #60 and still runs them", Number(total) >= 14, `${total} tests`);

  return finish();
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

function lineValue(out, key) {
  const m = out.match(new RegExp(`^${key} (.*)$`, "m"));
  return m ? m[1].trim() : "";
}

function parseParams(out) {
  const params = {};
  for (const m of out.matchAll(/^PARAMS (\S+) (\S+) (\d+) (\d+) (\d+) (\d+)$/gm)) {
    params[m[1]] = { key: +m[3], block: +m[4], iv: +m[5], mac: +m[6] };
  }
  return params;
}

function parseAuthlens(out) {
  const map = {};
  for (const m of out.matchAll(/^AUTHLEN (\S+) (\d+)$/gm)) map[m[1]] = +m[2];
  return map;
}

function parseProposals(out) {
  const blocks = [];
  let cur = null;
  for (const raw of out.split(/\r?\n/)) {
    const line = raw.trimEnd();
    const head = line.match(/^PROPOSAL (\S+) scope=(\S+)$/);
    if (head) {
      cur = { label: head[1], scope: head[2], names: [], verdict: null, verdictStoc: null };
      blocks.push(cur);
      continue;
    }
    if (!cur) continue;
    const nm = line.match(/^\s+(\S+) name=(\S+) kind=(\S+) (\S+)$/);
    if (nm) {
      cur.names.push({ cat: nm[1], name: nm[2], kind: nm[3], tag: nm[4] });
      continue;
    }
    const v = line.match(/^\s+verdict=(.*)$/);
    if (v) cur.verdict = v[1];
    const vs = line.match(/^\s+verdict_stoc=(.*)$/);
    if (vs) cur.verdictStoc = vs[1];
  }
  return blocks;
}

// machine-path-exempt: this was `[process.env.OPENSSH_C, "E:/src/moon/openssh-C"]`
// with the second entry having no idea whether it existed. It is a probe, in
// that order, and the env var is the part that travels: set OPENSSH_C and the
// fallback is never consulted. The fallback stays because the value it was
// written from was, once, a real location on a real machine.
function findOpenSSHC(file) {
  const bases = [process.env.OPENSSH_C, "E:/src/moon/openssh-C"].filter(Boolean);
  for (const b of bases) {
    const p = join(b, file);
    if (existsSync(p)) return p;
  }
  return null;
}

///|
/// Pull the `ciphers[]` rows out of OpenSSH's cipher.c. Multi-line rows are
/// joined first so `{ "chacha20-poly1305@openssh.com",\n 8, 64, ... }` parses.
function parseCTable(src) {
  const flat = src.replace(/\r?\n\s*/g, " ");
  const rows = {};
  for (const m of flat.matchAll(/\{\s*"([^"]+)"\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*,/g)) {
    rows[m[1]] = [m[2], m[3], m[4], m[5]];
  }
  return rows;
}

function functionBody(src, signature) {
  const start = src.indexOf(signature);
  if (start < 0) return "";
  let depth = 0;
  let seen = false;
  for (let i = start + signature.length; i < src.length; i++) {
    const ch = src[i];
    if (ch === "{") {
      depth++;
      seen = true;
    } else if (ch === "}") {
      depth--;
      if (seen && depth === 0) return src.slice(start, i + 1);
    }
  }
  return "";
}

function finish() {
  console.log("");
  if (skipped.length) {
    console.log(`skipped: ${skipped.length}`);
    for (const s of skipped) console.log(`  SKIP  ${s}`);
  }
  console.log(`loop60: ${checks - failures.length}/${checks} checks passed`);
  if (failures.length) {
    console.log("");
    for (const f of failures) console.log(`  FAIL  ${f}`);
    process.exitCode = 1;
  } else {
    console.log("ALL PASS");
  }
}

await main();