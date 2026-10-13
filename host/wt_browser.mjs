// host/wt_browser.mjs -- the browser half of a gate, in one place.
//
// Loop #46 and Loop #47 both need the same thing: serve a directory over HTTP,
// open a page, build a MoonBit Worker from a flat config, and read back what it
// printed. Written twice, that harness would drift in exactly the way this repo
// keeps paying for -- verify_loop45 and verify_loop41 each ported the same
// rendering rules and had to be cross-checked back into agreement. So it lives
// here once and both gates import it.
//
// Everything here is plumbing. No gate rule, no expectation, no comparison:
// those belong to the gate, where a failure can name the thing that failed.
//
// Two things it does that are easy to get wrong, both of which cost Loop #46 a
// long debugging detour, so they are carried with comments rather than left to
// the next reader to rediscover:
//
//   * a Worker whose *script* fails to load hands `onerror` an Event with no
//     message, no filename and no line -- `String(ev)` is the literal
//     "[object Event]", and the reason (a 404, here) appears nowhere. So the
//     Event's fields are copied into a plain object and rendered by name here,
//     and `openPage` also reports every response >= 400 and every failed
//     request, so a missing asset is visible instead of inferred.
//   * `page.evaluate` serializes the function it is given and runs it in the
//     page: it carries no Node scope. A helper defined beside the gate is
//     simply absent in the browser. So the browser side copies fields out and
//     this module formats them -- never `eval` of a stringified function.

import { createServer } from "node:http";
import net from "node:net";
import path from "node:path";
import { extname, join, normalize } from "node:path";
import { stat, readFile } from "node:fs/promises";

const MIME = { ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8" };

// Opt-in per-request log. A full gate run is dozens of scenarios and the log is
// noise; it is worth having exactly when a scenario failed with an opaque
// Worker error and the 404 has to be found.
export const TRACE = !!process.env.LOOP46_TRACE;

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Windows line endings, normalized before anything line-anchored runs. In a
// JavaScript regular expression `.` does not match `\r` -- it is a line
// terminator -- so an un-normalized CRLF line produces *no match*, which reads
// as "the scenario produced nothing". verify_loop45 learned this the hard way.
export const norm = (s) => String(s).replace(/\r\n/g, "\n");
export const grab = (t, k) => (norm(t).match(new RegExp(`^${k}: (.*)$`, "m")) || [])[1];

export function freePort() {
  return new Promise((res, rej) => {
    const s = net.createServer();
    s.on("error", rej);
    s.listen(0, "127.0.0.1", () => {
      const p = s.address().port;
      s.close(() => res(p));
    });
  });
}

// Whether a child is gone, or will be gone within `ms`. The gates need this for
// the man in the middle: it only writes its transcript when its session thread
// returns, so killing it the instant the Worker's result arrives races the write
// and the transcript is simply missing. Three scenarios did exactly that in
// Loop #46 and reported "the man in the middle recorded nothing" -- which reads
// as a protocol failure and was a gate that hung up too early.
export function exitedWithin(proc, ms) {
  if (proc.exitCode !== null || proc.signalCode !== null) return Promise.resolve(true);
  return new Promise((res) => {
    const t = setTimeout(
      () => res(proc.exitCode !== null || proc.signalCode !== null),
      ms,
    );
    proc.once("exit", () => {
      clearTimeout(t);
      res(true);
    });
  });
}

// A directory over HTTP. Every exit path writes the response exactly once: a
// `catch` that fires *after* `writeHead(200)` and then writes a 404 is
// ERR_HTTP_HEADERS_SENT, and it kills the whole gate with a stack instead of
// one scenario failing.
export async function serve(dir, port) {
  return new Promise((res, rej) => {
    const s = createServer(async (req, resp) => {
      let status = 404;
      let body = null;
      let type = "text/plain";
      if (TRACE) console.log(`  serve ${req.url} dir=${dir}`);
      try {
        const p = normalize(decodeURIComponent(new URL(req.url, "http://x").pathname))
          .replace(/^[/\\]+/, "");
        const f = join(dir, p);
        if (!f.startsWith(dir)) {
          status = 403;
        } else {
          const st = await stat(f);
          if (st.isFile()) {
            status = 200;
            type = MIME[extname(f)] || "application/octet-stream";
            body = await readFile(f);
          }
        }
      } catch (e) {
        // A missing import is a `ReferenceError` here, not an `ENOENT`, and
        // `e.code` is what tells the two apart -- which is how a missing
        // import hides as a 404 until somebody looks at this line.
        if (TRACE) console.log(`  serve ${req.url} -> threw ${e && e.code}`);
        status = 404;
        body = null;
      }
      if (body === null) {
        resp.writeHead(status, { "Content-Type": "text/plain" });
        resp.end(`not found: ${req.url}\n`);
        return;
      }
      resp.writeHead(status, { "Content-Type": type });
      resp.end(body);
    });
    s.on("error", rej);
    s.listen(port, "127.0.0.1", () => res(s));
  });
}

function describeEvent(snap) {
  if (!snap || typeof snap !== "object") return String(snap);
  const bits = [];
  for (const k of ["type", "message", "filename", "lineno"]) {
    if (snap[k] !== undefined && snap[k] !== null && snap[k] !== "") {
      bits.push(`${k}=${JSON.stringify(snap[k])}`);
    }
  }
  if (snap.errorText) bits.push(`error=${snap.errorText}`);
  if (snap.own) bits.push(`own=[${snap.own}]`);
  return bits.length ? bits.join(" ") : `bare Event (${snap.str || "?"})`;
}

// A page, opened on a page that exists, with the network failures recorded.
// One page per scenario: a Worker outlives the promise that started it, and on
// a shared page the previous scenario's Worker is still attached when the next
// one constructs its own -- so its late `onerror` resolves the new promise.
export async function openPage(browser, httpPort, opts = {}) {
  const page = opts.freshStorage
    ? await newPageInFreshContext(browser)
    : await newPageInSharedContext(browser);
  const state = { pageErrors: [], net: [] };
  page.on("pageerror", (e) => state.pageErrors.push(String(e)));
  page.on("response", (r) => {
    if (r.status() >= 400) state.net.push(`${r.status()} ${r.url()}`);
  });
  page.on("requestfailed", (r) =>
    state.net.push(`failed ${r.failure() && r.failure().errorText} ${r.url()}`),
  );
  await page.goto(`http://127.0.0.1:${httpPort}/host/wt/probe.html`);
  return { page, state };
}

// A page that shares its browser's **context**, so origin-scoped storage
// survives it.
//
// `browser.newPage()` opens a fresh context every call, and a fresh context has
// its own IndexedDB -- so a pin written on one page is invisible to the next.
// That is right for the pinning gates (Loop #48/49/51 wanted total isolation) and
// wrong for Loop #52, whose entire claim is "this survives the page going away".
// Getting that wrong produces a gate that reports a working store as a broken
// one, so the distinction is deliberate rather than incidental.
//
// **`freshStorage: true` exists because sharing has a cost.** Once the store is
// real and persistent, every gate that used to rely on "a new context means a
// clean slate" silently inherits whatever the previous gate wrote. Loop #48's
// `unpinned` case started passing for the wrong reason -- authenticated, because
// Loop #52 had left a pin behind -- which is a worse failure than the one the
// shared context was introduced to fix. A gate that wants isolation asks for it.
const sharedContexts = new WeakMap();
export async function newPageInSharedContext(browser) {
  let ctx = sharedContexts.get(browser);
  if (!ctx) {
    ctx = await browser.newContext();
    sharedContexts.set(browser, ctx);
  }
  return ctx.newPage();
}

const freshContexts = new WeakMap();
export async function newPageInFreshContext(browser) {
  let n = freshContexts.get(browser) || 0;
  n += 1;
  freshContexts.set(browser, n);
  // A brand new context has no storage at all, which is exactly what
  // "isolated" has to mean once there is something to isolate from.
  return (await browser.newContext()).newPage();
}

// Drive one Worker. `cfg` is posted flat because `cfg()` in the MoonBit side
// reads `globalThis.__wt_cfg[name]` and a nested object would silently read
// empty. The Worker is **postMessage**-driven: it reads its config in
// `onmessage`, not at construction, so a missing postMessage leaves every key
// empty and the run reports a connect failure rather than "you never sent me
// anything".
export async function runWorker(page, cfg, harnessTimeoutMs = 70000) {
  let out = await Promise.race([
    page.evaluate(
      (c) => {
        // `page.evaluate` carries no Node scope -- see the module header. So
        // the Event is copied into a plain object and formatted over there.
        const snapshotEvent = (ev) => ({
          __event: {
            type: (ev && ev.type) || "",
            message: (ev && ev.message) || "",
            filename: (ev && ev.filename) || "",
            lineno: (ev && ev.lineno) || 0,
            colno: (ev && ev.colno) || 0,
            errorText:
              ev && ev.error
                ? String(ev.error && ev.error.stack ? ev.error.stack : ev.error)
                : "",
            own:
              ev && typeof ev === "object"
                ? Object.getOwnPropertyNames(ev).join(",")
                : "",
            str: String(ev),
          },
        });
        return new Promise((resolve) => {
          const w = new Worker(c.workerUrl);
          let latest = { done: false, lines: [] };
          w.onmessage = (ev) => {
            latest =
              ev.data && ev.data.done
                ? ev.data
                : { done: false, lines: (ev.data && ev.data.lines) || [] };
            if (ev.data && ev.data.done) resolve(ev.data);
          };
          w.onerror = (ev) =>
            resolve({ ...snapshotEvent(ev), done: true, ok: false, lines: [] });
          w.onmessageerror = (ev) =>
            resolve({ ...snapshotEvent(ev), done: true, ok: false, lines: [] });
          w.postMessage(c);
          setTimeout(
            () => resolve({ ...latest, done: true, ok: false, error: "timeout" }),
            c.timeoutMs - 5000,
          );
        });
      },
      cfg,
    ),
    sleep(harnessTimeoutMs).then(() => ({
      done: true, ok: false, lines: [], error: "harness timeout",
    })),
  ]);
  if (out.__event) {
    out.error = `worker error: ${describeEvent(out.__event)}`;
    out.lines = [];
  }
  return out;
}

// The absolute URLs a Worker needs, spelled out so a relative one cannot be
// mistaken for a working one. A Worker resolves a relative URL against the
// *Worker's* script URL rather than the page's.
export function wtCfg(base, httpPort, wsPort, extra = {}) {
  return {
    workerUrl: `${base}/host/wt/worker.js`,
    shimUrl: `${base}/host/wt/moonbit_wt.js`,
    // Loop #52: the known-hosts store's shim. It is a *separate* script rather
    // than part of `moonbit_wt.js` because it answers a different question --
    // "where did the pin go" rather than "give me bytes" -- and because a gate
    // that wants to see storage fail should be able to load one without the
    // other.
    khsShimUrl: `${base}/host/wt/moonbit_khs.js`,
    moduleUrl: `${base}/_build/js/debug/build/cmd/wt_ssh/wt_ssh.js`,
    url: `ws://127.0.0.1:${wsPort}/ssh`,
    nonce: "wt",
    timeoutMs: 60000,
    ...extra,
  };
}

export { path };