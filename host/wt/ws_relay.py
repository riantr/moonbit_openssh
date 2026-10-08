#!/usr/bin/env python
"""Loop #32: a WebSocket-to-TCP relay.

WebTransport needs a certificate the browser trusts, and Chromium will not
accept a locally-added one on the QUIC path -- it reports
QUIC_TLS_CERTIFICATE_UNKNOWN no matter which override flag is set, while
accepting the same certificate over plain HTTPS. That makes WebTransport
untestable locally without a real deployment's certificate.

WebSocket has no such requirement: ws:// on 127.0.0.1 needs no certificate at
all, so this relay lets the browser end-to-end test run with zero system
changes. It is the same byte stream the WebTransport relay carries, so
everything above the transport -- the MoonBit SSH client, the exchange hash,
the ECDSA verification -- is exercised identically.

    browser Worker (MoonBit js)  --WebSocket-->  this relay  --TCP-->  sshd

Usage: python host/wt/ws_relay.py --listen-port 8765 --target-port 22222
"""

from __future__ import annotations

import argparse
import asyncio
import sys

import websockets
from websockets.asyncio.server import serve


def log(msg: str) -> None:
    print(f"[ws-relay] {msg}", flush=True)


async def bridge(ws, target_host: str, target_port: int) -> None:
    try:
        reader, writer = await asyncio.open_connection(target_host, target_port)
    except OSError as exc:
        log(f"tcp connect failed: {exc}")
        await ws.close(code=1011, reason="cannot reach target")
        return
    log(f"client connected -> tcp {target_host}:{target_port}")

    async def ws_to_tcp() -> None:
        try:
            async for message in ws:
                if isinstance(message, str):
                    # The client never sends text, but refusing it is better
                    # than silently forwarding a UTF-8 encoding of something
                    # that was meant to be bytes.
                    log("ignoring a text frame: ssh is a byte stream")
                    continue
                writer.write(message)
                await writer.drain()
        except (websockets.ConnectionClosed, OSError):
            pass
        finally:
            try:
                writer.close()
            except OSError:
                pass

    async def tcp_to_ws() -> None:
        try:
            while True:
                chunk = await reader.read(65536)
                if not chunk:
                    break
                await ws.send(chunk)
        except (websockets.ConnectionClosed, OSError, ConnectionResetError):
            pass

    await asyncio.gather(ws_to_tcp(), tcp_to_ws())
    try:
        await ws.close()
    except websockets.ConnectionClosed:
        pass
    log("client disconnected")


async def main_async(args) -> int:
    async def handler(ws) -> None:
        await bridge(ws, args.target_host, args.target_port)

    async with serve(handler, args.listen_host, args.listen_port):
        log(
            f"websocket on ws://{args.listen_host}:{args.listen_port}"
            f" -> tcp {args.target_host}:{args.target_port}"
        )
        await asyncio.Future()  # run until cancelled
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen-host", default="127.0.0.1")
    ap.add_argument("--listen-port", type=int, default=8765)
    ap.add_argument("--target-host", default="127.0.0.1")
    ap.add_argument("--target-port", type=int, default=22222)
    args = ap.parse_args()
    try:
        return asyncio.run(main_async(args))
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(main())