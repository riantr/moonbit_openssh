#!/usr/bin/env node
// Loop #66 gate.
//
// What this asserts is *intent*, not literal text. Loop #24's gate was written
// against a hardcoded "23/23" and stayed red for three loops after the count
// moved; loop63's gate was written against `live.includes("@tcp.TcpConn")` and
// passed for the wrong reason once the name appeared in a comment. So every
// check here either proves a property of the tree or names the exact reason it
// is allowed to differ.
//
// The three accepted warnings are asserted as an *equality*: the collector's
// report must equal the table in host/collect_warnings.py. A new warning fails.
// A warning that has been fixed also fails, because the table would be lying
// about why it is still there.

import { readFileSync, readdirSync, existsSync } from "node:fs";
import { execFileSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const read = (p) => readFileSync(path.join(ROOT, p), "utf8");
const results = [];
const check = (name, fn) => {
  try {
    const detail = fn();
    results.push({ name, ok: true, detail: detail || "" });
  } catch (e) {
    results.push({ name, ok: false, detail: e.message });
  }
};
const assert = (cond, msg) => {
  if (!cond) throw new Error(msg);
};

// Strip comments before any source-text assertion. A gate that greps raw text
// will happily pass on a match inside a comment, which is how loop63's gate
// became a gate on prose.
const stripComments = (src) =>
  src
    .split("\n")
    .map((l) => {
      let out = "";
      let inStr = null;
      for (let i = 0; i < l.length; i++) {
        const c = l[i], n = l[i + 1];
        if (inStr) {
          out += c;
          if (c === inStr && l[i - 1] !== "\\") inStr = null;
          continue;
        }
        if (c === '"') { inStr = '"'; out += c; continue; }
        if (c === "/" && n === "/") break;
        if (c === "/" && n === "*") {
          const end = l.indexOf("*/", i + 2);
          if (end === -1) break;
          i = end + 1;
          continue;
        }
        out += c;
      }
      return out;
    })
    .join("\n");

// ---------------------------------------------------------------- collector

check("collector exposes an evidence-backed accept table", () => {
  const cw = read("host/collect_warnings.py");
  assert(cw.includes("KNOWN_ACCEPTED"), "KNOWN_ACCEPTED table is gone");
  assert(cw.includes("accepted_sites()"), "accepted_sites() accessor is gone");
  // Every entry must carry a reason. An entry with a one-word justification is
  // an entry nobody will re-check in six months.
  const entries = cw.match(/\("(?:[^"\\]|\\.)*", "\d+"\): \(\n\s+"[^"]+"/g) || [];
  assert(entries.length >= 3, `only ${entries.length} entries carry a reason string`);
  return `${entries.length} entries, each with a reason`;
});

check("a failed build is never reported as clean", () => {
  const cw = read("host/collect_warnings.py");
  assert(
    cw.includes("failed to build") && cw.includes("sys.exit(2)"),
    "the per-package build-failure path is gone"
  );
  return "broken packages exit 2 and are named on stderr";
});

// ------------------------------------------------------- truly-dead imports

check("src/tcp no longer imports moonbitlang/core/bytes", () => {
  // Loop #66 finding: `Bytes` comes from the implicit prelude, so the import was
  // dead on all four targets while four files still used the type. Proved by
  // deletion, not by inspection.
  const pkg = read("src/tcp/moon.pkg");
  assert(
    !pkg.includes("moonbitlang/core/bytes"),
    "the dead core/bytes import is back"
  );
  return "import removed; Bytes resolves from the prelude";
});

check("src/sshclient does not depend on src/tcp", () => {
  // Loop #64 moved the Transport impl to the transport side. This is the payoff:
  // the dependency arrow the loop argued about is now a deleted line.
  const pkg = read("src/sshclient/moon.pkg");
  assert(!/src\/tcp"/.test(pkg), "src/sshclient imports src/tcp again");
  const live = read("src/sshclient/live.mbt");
  const sftp = read("src/sshclient/sftp.mbt");
  for (const [name, src] of [["live.mbt", live], ["sftp.mbt", sftp]]) {
    assert(!stripComments(src).includes("@tcp."), `${name} references @tcp again`);
  }
  assert(pkg.includes("src/transport"), "src/sshclient lost its transport import");
  return "transport one-way; no @tcp reference in live.mbt or sftp.mbt";
});

check("cmd/main and cmd/ssh_full dropped their unused imports", () => {
  for (const p of ["cmd/main/moon.pkg", "cmd/ssh_full/moon.pkg"]) {
    const src = read(p);
    assert(!src.includes("src/socket"), `${p} imports src/socket again`);
  }
  assert(!read("cmd/ssh_full/moon.pkg").includes("src/sshwire"),
         "cmd/ssh_full imports src/sshwire again");
  return "three dead imports removed";
});

// --------------------------------------------------- must-stay (negative)

// A negative assertion. Removing this import is a real break -- measured, not
// assumed -- so the gate's job is to make sure the next person cannot "clean it
// up" and find out from CI.
check("src/khfile still imports moonbitlang/async", () => {
  const pkg = read("src/khfile/moon.pkg");
  assert(
    pkg.includes('"moonbitlang/async"'),
    "moonbitlang/async was removed from src/khfile; this breaks every async test"
  );
  assert(
    pkg.includes("Do not") && pkg.includes("clean it up"),
    "the comment explaining why the import looks dead was removed with it"
  );
  return "import and its justification both present";
});

// ------------------------------------------------------------- dead code

check("dead private helpers are gone", () => {
  const gone = [
    ["src/sshconfig/fnmatch.mbt", "fn eq_at("],
    ["src/sshconfig/parser.mbt", "fn bytes_to_ascii_string("],
    ["src/sshconfig/parser.mbt", "fn ascii_bytes("],
    ["cmd/aes_test/main.mbt", "fn byte_to_hex("],
    ["src/kexflow/proposal.mbt", "struct PfCursor"],
  ];
  for (const [file, needle] of gone) {
    assert(!read(file).includes(needle), `${needle} is back in ${file}`);
  }
  return `${gone.length} dead definitions removed`;
});

check("dead locals are gone", () => {
  const gone = [
    ["cmd/aes_test/main.mbt", "key_kat256_dbg"],
    ["src/knownhosts/match.mbt", "HASH_LEN"],
    ["src/knownhosts/match.mbt", "HASH_MAGIC"],
  ];
  for (const [file, needle] of gone) {
    assert(!stripComments(read(file)).includes(needle), `${needle} is back in ${file}`);
  }
  // `in_section` is scoped, not deleted. It is dead in `parse_ssh_config` --
  // written at the old line 254 and read nowhere -- but a second function in the
  // same file still reads it at two sites, so a whole-file assertion would fail
  // on correct code. Slice to the *end of that function*, not to end of file.
  const parser = stripComments(read("src/sshconfig/parser.mbt"));
  const start = parser.indexOf("pub fn parse_ssh_config");
  assert(start !== -1, "parse_ssh_config is missing from parser.mbt");
  const rest = parser.slice(start);
  const m = rest.match(/\n(pub )?fn /);
  const parseFn = m ? rest.slice(0, m.index) : rest;
  assert(!/let mut in_section/.test(parseFn),
         "the write-only in_section in parse_ssh_config is back");
  assert(!/in_section = true/.test(parseFn), "the in_section assignment is back");
  const uses = parser.match(/in_section &&/g) || [];
  assert(uses.length >= 2,
         `expected the second function to keep reading in_section, found ${uses.length}`);
  return `${gone.length} dead bindings removed; the live in_section left alone`;
});

// -------------------------------------------------------- deprecations

check("no deprecated substring(start=.., end=..) remains", () => {
  const files = [
    "src/hostkey/cert.mbt",
    "src/knownhosts/match.mbt",
    "src/knownhosts/parse.mbt",
  ];
  for (const f of files) {
    const src = stripComments(read(f));
    assert(
      !/\.substring\(/.test(src),
      `${f} still calls .substring(...); Loop #66 rewrote 19 of these to [a:b].to_owned()`
    );
  }
  return "19 call sites converted to slice + to_owned";
});

check("HostCert string slicing returns an owned String", () => {
  // The rewrite has two failure modes and both compile-fail rather than
  // misbehave: `s[:n]` alone is a StringView, and `.to_string()` on a
  // StringView is *itself* deprecated. `to_owned()` is the only form that is
  // both owned and non-deprecated.
  const src = stripComments(read("src/hostkey/cert.mbt"));
  const m = src.match(/name\[[^\]]*\]\.to_owned\(\)/);
  assert(m, "plain_type_of_cert no longer slices with to_owned()");
  assert(!/name\[[^\]]*\]\.to_string\(\)/.test(src),
         "a StringView .to_string() is back");
  return "plain_type_of_cert uses [:n].to_owned()";
});

check("the deprecated Eq method promotion is written out", () => {
  const src = read("src/knownhosts/entry.mbt");
  for (const t of ["Marker", "HostStatus"]) {
    assert(
      src.includes(`pub extend ${t} with Eq::{equal, not_equal}`),
      `${t} relies on the deprecated implicit method promotion again`
    );
  }
  return "both extends declared explicitly";
});

// ------------------------------------------------------------- renamed field

check("AuthReport.method was renamed but its printed label was not", () => {
  // Renaming the field is required (the word is reserved). Renaming the printed
  // label would break verify_loop34, which greps stdout for `method: publickey`
  // -- and "method" is RFC 4252's term, so the label is right and the field name
  // was the thing that had to move.
  const live = read("src/sshclient/live.mbt");
  assert(!/^\s*method\s*:\s*String/m.test(live), "AuthReport.method is back");
  assert(/auth_method\s*:\s*String/.test(live), "auth_method field missing");

  const sites = ["cmd/ssh_live/main.mbt", "cmd/wt_ssh/main.mbt"];
  for (const s of sites) {
    const src = stripComments(read(s));
    assert(src.includes('"method: " + r.auth_method'),
           `${s} does not print the method label from auth_method`);
    assert(!/\br\.method\b/.test(src), `${s} still reads r.method`);
  }
  const gate = read("host/verify_loop34.mjs");
  assert(gate.includes("method: publickey"),
         "verify_loop34's expected label changed; the wire term should not");
  return "field renamed, RFC 4252 label preserved, loop34 contract intact";
});

// ------------------------------------------------------------ hard boundary

check("no src/ package imports @proton", () => {
  const offenders = [];
  const walk = (dir) => {
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      const p = path.join(dir, e.name);
      if (e.isDirectory()) {
        if (["_build", ".mooncakes", "node_modules", ".git"].includes(e.name)) continue;
        walk(p);
      } else if (/\.(mbt|moon)$/.test(e.name) || e.name === "moon.pkg") {
        if (stripComments(readFileSync(p, "utf8")).includes("@proton")) {
          offenders.push(path.relative(ROOT, p));
        }
      }
    }
  };
  walk(path.join(ROOT, "src"));
  assert(offenders.length === 0, `proton leaked into src/: ${offenders.join(", ")}`);
  return "src/ stays free of the GUI layer";
});

// --------------------------------------------------------- end-to-end report

check("the live collector run matches the accept table exactly", () => {
  if (process.argv.includes("--skip-live")) {
    throw new Error("SKIPPED");
  }
  const out = execFileSync("cmd", ["/c", "python", "host/collect_warnings.py"],
                           { cwd: ROOT, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
  const reported = JSON.parse(out);
  const got = new Set();
  for (const [file, lines] of Object.entries(reported)) {
    for (const line of Object.keys(lines)) got.add(`${file.replace(/\\/g, "/")}:${line}`);
  }
  const cw = read("host/collect_warnings.py");
  const accepted = new Set(
    [...cw.matchAll(/\("([^"]+)", "(\d+)"\): \(/g)].map((m) => `${m[1]}:${m[2]}`)
  );
  const extra = [...got].filter((s) => !accepted.has(s));
  const stale = [...accepted].filter((s) => !got.has(s));
  assert(extra.length === 0, `new warnings not in the accept table: ${extra.join(", ")}`);
  assert(stale.length === 0, `accept table entries that no longer occur: ${stale.join(", ")}`);
  return `${got.size} reported sites, equal to the ${accepted.size}-entry accept table`;
});

// --------------------------------------------------------------------- report

let failed = 0;
let skipped = 0;
for (const r of results) {
  if (r.detail === "SKIPPED") {
    skipped++;
    console.log(`SKIP  ${r.name}`);
    continue;
  }
  if (!r.ok) failed++;
  console.log(`${r.ok ? "PASS" : "FAIL"}  ${r.name}`);
  if (r.detail) console.log(`      ${r.detail}`);
}
console.log(`---`);
console.log(`loop66: ${results.length - failed - skipped}/${results.length - skipped}` +
            (skipped ? ` (${skipped} skipped)` : ""));
process.exit(failed === 0 ? 0 : 1);
