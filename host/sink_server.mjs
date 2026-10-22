// host/sink_server.mjs -- a TCP server that reads, but never writes back, and
// only starts reading when it is told to.
//
// Usage: node host/sink_server.mjs <port> <go-file>
//
// ## Why it exists
//
// Loop #79's gate has to prove that a forward can move MORE bytes than the
// SSH channel window holds (the window is 2 MiB). Moving 4 MiB through a
// 2 MiB window means the window has to be exhausted and reopened at least
// once -- and that is exactly the path where the relay used to lose data:
// `stdin_take` clips the payload to the window and returns the rest, and the
// rest used to be dropped.
//
// To exercise that path the far end has to STOP reading for a while. If it
// reads as fast as it can, the window never closes and the path is never
// taken -- the test would pass without testing anything.
//
// So this server waits for a **file to appear** before it reads anything. The
// gate creates that file when it wants the transfer to finish. That is
// deterministic: no sleeps, no "wait long enough and hope".
//
// The socket has no 'data' listener until the release, which means Node never
// switches it to flowing mode and the kernel's receive buffer is what fills
// up -- exactly the situation the relay has to survive.
//
// It prints "SINK <bytes> <sha256>" when the connection ends, which is the
// far end's own account of what actually arrived -- the same idea as the
// echo server's "ECHO" line.

import crypto from "node:crypto";
import fs from "node:fs";
import net from "node:net";

const port = Number(process.argv[2] || 0);
const goFile = process.argv[3] || "";
if (!port || !goFile) {
  console.error("usage: node host/sink_server.mjs <port> <go-file>");
  process.exit(2);
}

const server = net.createServer((sock) => {
  const hash = crypto.createHash("sha256");
  let total = 0;

  const wait = setInterval(() => {
    if (!fs.existsSync(goFile)) return;
    clearInterval(wait);
    console.log("RELEASED");
    // Only now does the socket start moving bytes.
    sock.on("data", (b) => {
      total += b.length;
      hash.update(b);
    });
    sock.on("end", () => {
      console.log(`SINK ${total} ${hash.digest("hex")}`);
    });
    sock.on("error", () => {});
    sock.resume();
  }, 50);
});

server.listen(port, "127.0.0.1", () => {
  console.log(`sink server listening on 127.0.0.1:${port}`);
});

for (const sig of ["SIGINT", "SIGTERM"]) {
  process.on(sig, () => {
    server.close(() => process.exit(0));
  });
}
