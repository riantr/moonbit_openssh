// host/wt_mitm_bridge.mjs -- put the Loop #45 man in the middle behind a
// WebSocket, so `src/wtlive` can reach it.
//
// Why a bridge rather than a WebSocket man in the middle.
//
// `src/wt` picks its transport from the URL: `ws://` opens a WebSocket,
// anything else opens a real WebTransport (`moonbit_wt.js`). That choice is
// deliberate -- WebTransport needs a publicly trusted certificate and
// Chromium rejects a locally-added one on the QUIC path with
// QUIC_TLS_CERTIFICATE_UNKNOWN no matter which override flag is set, so
// WebTransport is untestable locally. A `ws://` URL carries exactly the same
// bytes, so everything above the transport is exercised identically.
//
// That leaves one question: who terminates the WebSocket. Implementing the SSH
// side again in Node would mean a second key exchange to trust, and the whole
// point of `host/sftp_mitm.py` is that paramiko does it. So this bridges
// WebSocket to TCP and forwards to the Python MITM unchanged:
//
//     browser Worker (MoonBit js)  --WebSocket-->  this bridge  --TCP-->  sftp_mitm.py
//
// It is `host/wt/ws_relay.py` with a different upstream. That is deliberate:
// the relay is already proven against a real sshd, and reusing the shape means
// the browser half is not a new thing being trusted for the first time.
//
// It forwards bytes and nothing else. It does not parse SSH, does not
// reassemble, does not count -- any of those would be a second implementation
// of something that already has one, and a place for the transcript to be
// quietly wrong in a way the gate could not see.
//
// Usage: node host/wt_mitm_bridge.mjs --listen-port P --target-port T
// Prints "listening <P> -> <T>" on stdout once bound.

import { createServer } from "node:http";
import net from "node:net";
import * as wsNs from "ws";

// This `ws` exposes its server class as **`WebSocketServer`**; older releases
// exposed it as `WebSocket.Server`. Writing `WebSocket.Server` here produced
// `TypeError: WebSocket.Server is not a constructor`, and the defensive
// fallback chain below produced a second, more confusing error ("could not
// find the WebSocket server class") -- which is worse than the first, because
// it points at the import rather than at the name.
//
// Both spellings are accepted, and the resolved class is checked once, at
// startup, so a future rename fails immediately with the real reason instead
// of surfacing as a connection that never arrives.
const WebSocketServer =
  wsNs.WebSocketServer ??
  wsNs.WebSocket?.Server ??
  wsNs.default?.WebSocketServer ??
  wsNs.default?.WebSocket?.Server;
if (typeof WebSocketServer !== "function") {
  throw new Error(
    "no WebSocket server class in the `ws` module; exports were: " +
      Object.keys(wsNs).join(", "),
  );
}

function arg(name, fallback) {
  const i = process.argv.indexOf(name);
  if (i < 0 || i + 1 >= process.argv.length) return fallback;
  return process.argv[i + 1];
}

const listenPort = Number(arg("--listen-port", "0"));
const targetPort = Number(arg("--target-port", "0"));
const targetHost = arg("--target-host", "127.0.0.1");
const path = arg("--path", "/ssh");

if (!listenPort || !targetPort) {
  console.error("usage: wt_mitm_bridge.mjs --listen-port P --target-port T");
  process.exit(2);
}

let connections = 0;

const server = createServer((_req, res) => {
  // A plain HTTP hit is almost always the Worker failing to find its page and
  // falling back to a request here. Saying so beats a bare 404 that reads like
  // a routing bug.
  res.writeHead(426, { "Content-Type": "text/plain" });
  res.end(
    "this port speaks WebSocket only -- the Worker's page is served over HTTP\n",
  );
});

const wss = new WebSocketServer({ server, path });

wss.on("connection", (ws) => {
  connections += 1;
  const upstream = net.connect(targetPort, targetHost);
  // Connecting happens lazily inside `net.connect`; any bytes the Worker sends
  // before the upstream is up are buffered by the OS and delivered on connect,
  // so there is nothing to wait for here and nothing to drop.

  // Set a sane default; the gate's client may stall on a half-open socket.
  ws.setNoDelay?.(true);
  upstream.setNoDelay?.(true);

  let closed = false;
  const shutdown = (why) => {
    if (closed) return;
    closed = true;
    try { ws.close(); } catch { /* already closing */ }
    try { upstream.destroy(); } catch { /* already gone */ }
    void why;
  };

  ws.on("message", (data) => {
    const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
    upstream.write(buf);
  });
  ws.on("close", () => shutdown("ws closed"));
  ws.on("error", () => shutdown("ws error"));

  upstream.on("data", (buf) => {
    if (ws.readyState === ws.OPEN) ws.send(buf);
  });
  upstream.on("close", () => shutdown("upstream closed"));
  upstream.on("error", () => shutdown("upstream error"));
});

server.listen(listenPort, "127.0.0.1", () => {
  const p = server.address().port;
  console.log(`listening ${p} -> ${targetHost}:${targetPort}${path}`);
});
