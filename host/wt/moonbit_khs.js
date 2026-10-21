// Loop #52: IndexedDB shim for the MoonBit js backend.
//
// Exposes `globalThis.__moonbit_khs`, a promise-based key/value API that the
// MoonBit side calls through `extern "js"` (see `src/khstore/store.mbt`). Same
// shape as Loop #32's `__moonbit_wt` byte-stream shim, for the same reason: the
// browser API stays on this side of the FFI boundary and the MoonBit side never
// learns what storage is.
//
// **Why IndexedDB and not localStorage.** A Web Worker has no `localStorage`.
// That is not a policy or a permission, it is simply absent: `globalThis
// .localStorage` is `undefined` inside a Worker, so the property access throws a
// TypeError and no amount of `try` around the call makes it work. The only
// origin-scoped storage available in a Worker is IndexedDB (and Cache Storage),
// and of the two IndexedDB is the one meant for this. So a browser SSH client
// running its protocol in a Worker -- which is where this whole project points --
// has exactly one choice, and finding that out by writing `localStorage` and
// wondering why every save returns false is the expensive way to learn it.
//
// The first version of `src/khstore` did write to `localStorage`. It reported
// "NOT stored" on every connection, which was *correct* -- the failure was
// reported rather than swallowed -- and that is the only reason this was found
// at all rather than shipped as a feature that quietly did nothing.
//
// One object store, one database, keyed by host. No upgrade path is needed
// because there is nothing to migrate yet; when there is, `onupgradeneeded`
// becomes the place and this comment becomes history.

(function () {
  'use strict';

  const DB_NAME = 'moonbit.ssh.known_hosts';
  const DB_VERSION = 1;
  const STORE = 'pins';

  let dbPromise = null;

  function open() {
    if (dbPromise) return dbPromise;
    dbPromise = new Promise((resolve, reject) => {
      let req;
      try {
        req = indexedDB.open(DB_NAME, DB_VERSION);
      } catch (e) {
        reject(e);
        return;
      }
      req.onupgradeneeded = function () {
        const db = req.result;
        if (!db.objectStoreNames.contains(STORE)) {
          db.createObjectStore(STORE);
        }
      };
      req.onsuccess = function () { resolve(req.result); };
      req.onerror = function () { reject(req.error || new Error('indexedDB.open failed')); };
      req.onblocked = function () { reject(new Error('indexedDB.open blocked')); };
    });
    // A rejected cached promise would poison every later call, and the failure
    // modes here (storage disabled by policy, quota) do not fix themselves
    // within a session.
    dbPromise = dbPromise.catch((e) => {
      dbPromise = null;
      throw e;
    });
    return dbPromise;
  }

  function withStore(mode, fn) {
    return open().then(
      (db) =>
        new Promise((resolve, reject) => {
          let tx;
          try {
            tx = db.transaction(STORE, mode);
          } catch (e) {
            reject(e);
            return;
          }
          let result;
          tx.oncomplete = function () { resolve(result); };
          tx.onabort = tx.onerror = function () {
            reject(tx.error || new Error('indexedDB transaction failed'));
          };
          try {
            fn(tx.objectStore(STORE), (v) => { result = v; });
          } catch (e) {
            reject(e);
          }
        }),
    );
  }

  globalThis.__moonbit_khs = {
    /// Store `value` under `key`, replacing any previous entry.
    ///
    /// Resolves with whether the write landed. A refused write (private mode,
    /// quota, enterprise policy) resolves **false** rather than rejecting: the
    /// client asked "did this land", and "no" is an answer. Rejecting here
    /// would have surfaced as an unhandled rejection inside the MoonBit
    /// runtime -- a crash, for what is really a "the browser would not let me"
    /// -- and the driver's "tofu: NOT stored" line could then never be reached.
    save: function (key, value) {
      return withStore('readwrite', (store, done) => {
        store.put(value, key);
        done(true);
      }).then(
        (r) => r === true,
        () => false,
      );
    },

    /// Resolve with the stored value, or `null` when there is no entry.
    ///
    /// A storage that refuses to open also resolves `null`: the caller cannot
    /// tell "no pin here" from "no storage here", and both mean the same
    /// thing to the policy -- there is no pin, so an unpinned host is refused
    /// (fail closed). Turning a storage failure into a *missing* pin is safe;
    /// turning it into an *accepted* pin would not be.
    load: function (key) {
      return withStore('readonly', (store, done) => {
        const req = store.get(key);
        req.onsuccess = function () { done(req.result === undefined ? null : req.result); };
        req.onerror = function () { done(null); };
      }).then(
        (r) => r,
        () => null,
      );
    },

    /// Remove `key`. Resolves either way -- a key that was not there is already
    /// in the state the caller asked for.
    forget: function (key) {
      return withStore('readwrite', (store, done) => {
        store.delete(key);
        done(true);
      }).then(
        (r) => r,
        () => false,
      );
    },

    /// Whether storage works at all. Worth one call at startup: a browser can
    /// have IndexedDB present but refuse to open (private mode, enterprise
    /// policy), and the user should hear that from the client.
    probe: function () {
      return withStore('readwrite', (store, done) => {
        store.put(1, '__probe__');
        done(true);
      }).then(
        () => globalThis.__moonbit_khs.forget('__probe__').then(() => true, () => true),
        () => false,
      );
    },
  };
})();