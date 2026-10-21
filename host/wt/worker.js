// Loop #32: browser Web Worker harness for the MoonBit js backend.
//
// The MoonBit `--target js` output is a classic script that ends in `})();`
// and references no Node global at all, so a Worker can load it with
// importScripts and no shim. That is what this harness exploits.
//
// The Worker owns the whole MoonBit side of the connection:
//
//   page  --postMessage(config)-->  worker
//                                          importScripts(host shim)
//                                          importScripts(MoonBit IIFE)
//                                          MoonBit main() reads __wt_cfg
//                                          MoonBit calls __wt_finish / __moonbit_wt
//   page  <--postMessage(result)--  worker
//
// Completion is signalled by MoonBit itself, through __wt_finish, rather than
// by the Worker guessing when the import settled. MoonBit's entry is an
// `async fn`, so it keeps running after importScripts has already returned;
// anything that assumed "import returned means done" would cut the
// connection off mid-handshake.

self.onmessage = function (e) {
  const cfg = e.data || {};
  globalThis.__wt_cfg = cfg;

  const lines = [];
  const nativeLog = console.log.bind(console);
  // The MoonBit module logs through console.log. Intercepting it is how the
  // page gets a transcript of what the MoonBit side actually did.
  console.log = function () {
    const text = Array.prototype.map.call(arguments, String).join(' ');
    lines.push(text);
    nativeLog(text);
  };

  function describe(err) {
    if (err && err.stack) return String(err.stack);
    return String(err);
  }

  function finish(payload) {
    clearInterval(watchdog);
    self.postMessage({ done: true, lines: lines, result: payload });
  }

  globalThis.__wt_finish = finish;
  // Anything rejected out of the async MoonBit main would otherwise vanish
  // into an unhandled rejection with no trace back to the page.
  self.onunhandledrejection = function (ev) {
    finish({ ok: false, error: 'unhandledrejection: ' + String(ev.reason) });
  };

  // A MoonBit handshake that hangs never reaches __wt_finish, so without this
  // the page sees a bare timeout and learns nothing about where it stopped.
  // Posting the transcript as it grows turns "hung" into "hung right after
  // this line", which is the difference between a five-minute and a five-second
  // debug.
  let lastCount = -1;
  const watchdog = setInterval(function () {
    if (lines.length === lastCount) return;
    lastCount = lines.length;
    self.postMessage({ done: false, lines: lines.slice() });
  }, 500);

  if (cfg.shimUrl) {
    try {
      importScripts(cfg.shimUrl);
    } catch (err) {
      finish({ ok: false, error: 'shim import failed: ' + describe(err) });
      return;
    }
  }

  // Loop #52: the known-hosts store shim.
  //
  // The comment here used to say this was "optional on purpose", and it was --
  // and that was wrong. `cmd/wt_ssh` reads the store on *every* connection when
  // no `known_hosts` text was given (`cfg_kh_policy` calls `@khstore.load`),
  // so a Worker without this shim has no `__moonbit_khs` to talk to, and the
  // client died with a TypeError instead of saying "nothing is pinned here".
  // The gates in this tier were written before `cfg_kh_policy` grew the store
  // read, so none of them passed the shim, and every browser run failed for a
  // reason that had nothing to do with what it was testing.
  //
  // So the default is now the shim that sits next to this script: a gate that
  // wants to measure "no store at all" passes an explicit empty string, which
  // is a different thing from "I did not think about it".
  const khsShimUrl = cfg.khsShimUrl === undefined ? './moonbit_khs.js' : cfg.khsShimUrl;
  if (khsShimUrl) {
    try {
      importScripts(khsShimUrl);
    } catch (err) {
      finish({ ok: false, error: 'khs shim import failed: ' + describe(err) });
      return;
    }
  }

  if (!cfg.moduleUrl) {
    finish({ ok: false, error: 'no moduleUrl in config' });
    return;
  }
  try {
    importScripts(cfg.moduleUrl);
  } catch (err) {
    finish({ ok: false, error: 'module import failed: ' + describe(err) });
  }
};
