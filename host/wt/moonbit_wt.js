// Loop #32: browser byte-stream shim for the MoonBit js backend.
//
// Exposes `globalThis.__moonbit_wt`, a promise-based byte-stream API that the
// MoonBit side calls through `extern "js"` (see `src/wt/ffi.mbt`). The
// contract is the same shape as Loop #31's blocking `src/tcp` -- open / send /
// read_exact / close -- which is what lets the SSH layer above stay identical
// between a Winsock socket and a browser session.
//
// Two browser transports, chosen by URL scheme:
//
//   https://...  WebTransport (HTTP/3). The right answer for a real
//                deployment, where the endpoint has a publicly trusted
//                certificate. Not usable against a locally-added
//                self-signed one: Chromium validates QUIC certificates
//                independently of the platform store and rejects them with
//                QUIC_TLS_CERTIFICATE_UNKNOWN regardless of
//                --ignore-certificate-errors or the SPKI pin list, while
//                accepting the very same certificate over plain HTTPS.
//
//   ws://...     WebSocket. No certificate at all, so the local end-to-end
//                test runs with zero system changes. It carries exactly the
//                same bytes, so everything above the transport is exercised
//                identically.
//
// MoonBit code does not branch on this: it opens a URL and gets a byte stream.

(function () {
  'use strict';

  const conns = new Map();
  let nextHandle = 1;

  function fail(msg) {
    const e = new Error(msg);
    e.__wt = true;
    return e;
  }

  // Shared byte-stream plumbing. Subclasses only provide a way to push bytes in
  // (`push`) and to write bytes out (`write`).
  class ByteStream {
    constructor(url) {
      this.url = url;
      this.buffer = new Uint8Array(0);
      this.offset = 0;
      // Resolvers waiting for read_exact, strictly one at a time. MoonBit's
      // transport reads sequentially, and two concurrent waiters would make
      // "who gets these bytes" depend on scheduling.
      this.waiter = null;
      this.eof = false;
      this.failure = null;
      this.writeChain = Promise.resolve();
    }

    push(chunk) {
      const live = this.buffer.subarray(this.offset);
      const merged = new Uint8Array(live.length + chunk.length);
      merged.set(live, 0);
      merged.set(chunk, live.length);
      this.buffer = merged;
      this.offset = 0;
      this.settle();
    }

    available() {
      return this.buffer.length - this.offset;
    }

    take(n) {
      const out = this.buffer.slice(this.offset, this.offset + n);
      this.offset += n;
      // Reclaim the consumed prefix once it dominates, otherwise a long session
      // grows this array without bound.
      if (this.offset > 0 && this.offset * 2 >= this.buffer.length) {
        this.buffer = this.buffer.slice(this.offset);
        this.offset = 0;
      }
      return out;
    }

    settle() {
      const w = this.waiter;
      if (!w) return;
      if (this.failure) {
        this.waiter = null;
        w.reject(this.failure);
        return;
      }
      if (this.available() >= w.n) {
        this.waiter = null;
        w.resolve(this.take(w.n));
        return;
      }
      if (this.eof) {
        this.waiter = null;
        w.reject(
          fail('eof after ' + this.available() + ' of ' + w.n + ' requested bytes')
        );
      }
    }

    die(msg) {
      if (!this.failure) this.failure = fail(msg);
      this.settle();
    }

    readExact(n) {
      if (this.failure) return Promise.reject(this.failure);
      if (this.waiter) return Promise.reject(fail('read_exact already in flight'));
      if (this.available() >= n) return Promise.resolve(this.take(n));
      if (this.eof) {
        return Promise.reject(
          fail('eof with ' + this.available() + ' of ' + n + ' requested bytes')
        );
      }
      return new Promise((resolve, reject) => {
        this.waiter = { n, resolve, reject };
      });
    }

    // Serialise writes: two concurrent writers on one stream throw, and the
    // SSH layer can have a write in flight while a read is outstanding.
    send(bytes) {
      this.writeChain = this.writeChain.then(() => this.write(bytes));
      return this.writeChain;
    }
  }

  class WebTransportStream extends ByteStream {
    async open() {
      this.transport = new WebTransport(this.url);
      this.transport.closed.then(
        () => this.die('transport closed'),
        () => this.die('transport closed')
      );
      await this.transport.ready;
      const stream = await this.transport.createBidirectionalStream();
      this.reader = stream.readable.getReader();
      this.writer = stream.writable.getWriter();
      this.pump();
    }

    // Continuously drain the stream into `buffer`. Resolving a waiter from
    // here is what turns chunked delivery into exact-length reads.
    pump() {
      const step = async () => {
        try {
          for (;;) {
            const { value, done } = await this.reader.read();
            if (done) {
              this.eof = true;
              this.settle();
              return;
            }
            if (value && value.length) this.push(value);
          }
        } catch (err) {
          this.die(String((err && err.message) || err));
        }
      };
      step();
    }

    write(bytes) {
      return this.writer.write(bytes);
    }

    close() {
      try {
        if (this.writer) this.writer.releaseLock();
      } catch (e) {
        /* already released */
      }
      try {
        if (this.transport) this.transport.close();
      } catch (e) {
        /* already closing */
      }
      return Promise.resolve();
    }
  }

  class WebSocketStream extends ByteStream {
    async open() {
      this.ws = new WebSocket(this.url);
      this.ws.binaryType = 'arraybuffer';
      await new Promise((resolve, reject) => {
        this.ws.onopen = resolve;
        this.ws.onerror = () => reject(fail('websocket failed: ' + this.url));
      });
      this.ws.onmessage = (ev) => {
        const data = ev.data;
        if (data instanceof ArrayBuffer) {
          if (data.byteLength) this.push(new Uint8Array(data));
        } else if (typeof data === 'string') {
          // Never expected; forwarding it would corrupt the byte stream.
          this.die('unexpected text frame from the relay');
        }
      };
      this.ws.onclose = () => {
        this.eof = true;
        this.settle();
      };
      this.ws.onerror = () => this.die('websocket error');
    }

    write(bytes) {
      return new Promise((resolve, reject) => {
        try {
          this.ws.send(bytes);
          resolve();
        } catch (err) {
          reject(err);
        }
      });
    }

    close() {
      try {
        if (this.ws) this.ws.close();
      } catch (e) {
        /* already closing */
      }
      return Promise.resolve();
    }
  }

  function make(url) {
    if (/^wss?:\/\//i.test(url)) return new WebSocketStream(url);
    return new WebTransportStream(url);
  }

  function get(handle) {
    const c = conns.get(handle);
    if (!c) throw fail('unknown connection handle ' + handle);
    return c;
  }

  globalThis.__moonbit_wt = {
    open: function (url) {
      const u = String(url);
      const c = make(u);
      return c.open().then(
        () => {
          const h = nextHandle++;
          conns.set(h, c);
          return h;
        },
        (err) => {
          throw fail('open failed: ' + String((err && err.message) || err));
        }
      );
    },

    send: function (handle, bytes) {
      return get(handle).send(bytes);
    },

    read_exact: function (handle, n) {
      return get(handle).readExact(n);
    },

    close: function (handle) {
      const c = conns.get(handle);
      if (!c) return Promise.resolve();
      conns.delete(handle);
      return c.close();
    },
  };
})();