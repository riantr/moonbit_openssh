#!/usr/bin/env python
"""Loop #32: a TCP echo server, used to test the transport on its own.

The point of layering the tests is that a failure has to name itself. Running
the whole stack against sshd means a bug in the WebTransport relay, a bug in
the JS shim and a bug in the MoonBit FFI all look identical -- "handshake
failed". Pointing the same relay at an echo server first isolates the transport
from SSH entirely: if the bytes come back unchanged, the transport is sound and
whatever fails next is above it.

Usage: python host/wt/echo_server.py --port 19090
"""

from __future__ import annotations

import argparse
import asyncio
import sys


async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while True:
            chunk = await reader.read(65536)
            if not chunk:
                break
            writer.write(chunk)
            await writer.drain()
    except (ConnectionResetError, OSError):
        pass
    finally:
        try:
            writer.close()
        except OSError:
            pass


async def main_async(args) -> int:
    server = await asyncio.start_server(handle, args.host, args.port)
    print(f"[echo] listening on {args.host}:{args.port}", flush=True)
    async with server:
        await server.serve_forever()
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=19090)
    args = ap.parse_args()
    try:
        return asyncio.run(main_async(args))
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(main())
