#!/usr/bin/env python
"""Loop #32 debug: can an aioquic client reach the relay at all?

Chrome reporting CERTIFICATE_VERIFY_FAILED while the relay logs nothing is
contradictory: a failed TLS handshake should surface as a QUIC transport error
on the server. Silence points at the packets never arriving, which is a
different problem entirely and would make the certificate irrelevant.

This connects a plain aioquic HTTP/3 client -- no browser, no certificate
override -- and reports what actually happens.

Usage: python host/wt/relay_client_probe.py --port 8443 [--insecure]
"""

from __future__ import annotations

import argparse
import asyncio
import ssl
import sys

from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN, H3Connection, H3Event
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ProtocolNegotiated, ConnectionTerminated


class Probe(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.http: H3Connection | None = None
        self.outcome: str = "no event"
        # asyncio.Event is built in the running loop, not lazily on first use.
        # Creating the future later -- in wait_outcome -- meant an event that
        # arrived before the caller got around to awaiting would raise inside
        # _resolve and vanish, producing a permanent spurious timeout.
        self.reached = asyncio.Event()

    async def wait_outcome(self, timeout: float) -> str:
        try:
            await asyncio.wait_for(self.reached.wait(), timeout)
        except asyncio.TimeoutError:
            return "TIMEOUT: no event at all (packets may not be arriving)"
        return self.outcome

    def quic_event_received(self, event) -> None:
        if isinstance(event, ConnectionTerminated):
            self.outcome = f"TERMINATED code={event.error_code} reason={event.reason_phrase!r}"
            self.reached.set()
            return
        if isinstance(event, ProtocolNegotiated):
            self.outcome = f"ALPN negotiated: {event.alpn_protocol!r}"
            self.reached.set()
            return
        if self.http is None:
            self.http = H3Connection(self._quic)
        assert self.http is not None
        for http_event in self.http.handle_event(event):
            if isinstance(http_event, H3Event.HeadersReceived):
                status = dict(http_event.headers).get(b":status")
                self.outcome = f"HTTP {status!r}"
                self.reached.set()


async def main_async(args) -> int:
    configuration = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN)
    if args.insecure:
        configuration.verify_mode = ssl.CERT_NONE

    probes: list[Probe] = []

    def factory(*args, **kwargs):
        p = Probe(*args, **kwargs)
        probes.append(p)
        return p

    # wait_connected=True is the only correct setting here: with False,
    # aioquic calls `protocol.connect(addr, transmit=False)` and never puts a
    # single Initial on the wire, so the probe can only ever time out.
    try:
        async with connect(
            args.host,
            args.port,
            configuration=configuration,
            create_protocol=factory,
            wait_connected=True,
        ) as client:
            outcome = await probes[0].wait_outcome(args.timeout)
            print(f"result: {outcome}")
            return 0 if outcome.startswith("HTTP") else 1
    except Exception as exc:  # handshake failures raise here
        print(f"result: connect failed: {type(exc).__name__}: {exc}")
        return 1


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8443)
    ap.add_argument("--insecure", action="store_true")
    ap.add_argument("--timeout", type=float, default=8.0)
    args = ap.parse_args()
    try:
        return asyncio.run(main_async(args))
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(main())