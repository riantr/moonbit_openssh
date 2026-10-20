// host/echo_server.mjs -- a TCP echo server, for Loop #76.
//
// The direct-tcpip forward needs a target on the other end. What it must do
// is one thing and do it exactly: send back the bytes it received, unchanged.
// A target that transformed the bytes would test the wrong thing -- the
// question here is whether the forwarded bytes arrive intact, not whether some
// protocol on top survived them.
//
// Deliberately not an HTTP server and deliberately not a "protocol" server:
// the bytes that come back are the bytes that went in, so the only thing the
// comparison can fail on is the forwarding.
//
// Usage: node host/echo_server.mjs <port>

import crypto from 'node:crypto';
import net from 'node:net';

const port = Number(process.argv[2] || 0);
if (!port) {
  console.error('usage: node host/echo_server.mjs <port>');
  process.exit(2);
}

const server = net.createServer((sock) => {
  // What this connection received, digested. The point is that the digest is
  // computed by the **far side of the forward**, so a gate can compare it
  // with what the client received without either of them having to agree on
  // what the payload was supposed to be. A payload the gate does not know by
  // heart can still be checked end to end: the target says what it got, the
  // client says what it got back, and the two digests have to match.
  const hash = crypto.createHash('sha256');
  let total = 0;
  sock.on('data', (b) => {
    total += b.length;
    hash.update(b);
    // The echo itself. Everything else in this file is bookkeeping.
    sock.write(b);
  });
  sock.on('end', () => {
    console.log(`ECHO ${total} ${hash.digest('hex')}`);
  });
  // A client that goes away mid-transfer is not this server's problem: the
  // forward's failure semantics are the client's to report, and a crash here
  // would take the evidence with it.
  sock.on('error', () => {});
});

server.listen(port, '127.0.0.1', () => {
  console.log(`echo server listening on 127.0.0.1:${port}`);
});

for (const sig of ['SIGINT', 'SIGTERM']) {
  process.on(sig, () => {
    server.close(() => process.exit(0));
  });
}
