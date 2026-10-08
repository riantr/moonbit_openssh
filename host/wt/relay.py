#!/usr/bin/env python
"""Loop #32: a local HTTP/3 + WebTransport server that relays to a TCP port.

This is the piece that makes the browser story testable. WebTransport gives a
browser a bidirectional byte stream with no plugins, no Flash and no native
code -- but only to a server that speaks HTTP/3. Neither the Node nor the
Python standard library has one, so this is built on aioquic.

    browser Worker (MoonBit js)  --WebTransport/HTTP3-->  this relay  --TCP-->  sshd

The relay is deliberately dumb: it does not parse SSH, it does not terminate
the SSH session's crypto, and it reorders nothing. Every byte the browser sends
is written to the TCP socket and every byte the socket produces is written
back. If the MoonBit client completes a handshake through this relay and the
ECDSA host key verifies, the browser really did speak SSH.

aioquic ships no WebTransport class. What it does ship is the plumbing:
`H3Connection` parses the extended CONNECT and reports WebTransport stream
payloads as `WebTransportStreamDataReceived`, and `send_data` writes a DATA
frame back. The session handling and the TCP bridge are implemented here.

Framing detail that matters: a WebTransport stream's payload rides inside an
HTTP/3 DATA frame, so *both* directions must go through H3Connection. Writing
raw bytes with `quic.send_stream_data` would put a length byte where the peer
expects a frame type, and the connection would be torn down.

Usage:
  python host/wt/relay.py --listen-port 8443 --target-port 22222 \
      --cert .loop32/cert.pem --key .loop32/key.pem
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys

from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.asyncio.server import serve
from aioquic.h3.connection import H3_ALPN, H3Connection, H3Event
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ProtocolNegotiated
from aioquic.quic.logger import QuicLogger
from aioquic.quic.packet import QuicProtocolVersion

# aioquic does not export this, but the draft mandates the header and Chrome
# checks for it before accepting the session.
WEBTRANSPORT_DRAFT_HEADER = b"sec-webtransport-http3-draft"

# :protocol=webtransport on the CONNECT, per WebTransport-over-HTTP/3.
CONNECT_WEBTRANSPORT_PROTOCOL = b"webtransport"


class _Stream:
    """One WebTransport bidirectional stream, bridged to one TCP connection.

    Inbound and outbound are separate coroutines over the same TCP connection.
    A single loop cannot do that: draining the inbound queue is synchronous
    while `reader.read` is not, so a combined loop would either busy-wait on
    the socket or stall the browser's writes behind a pending read.
    """

    def __init__(self) -> None:
        self.inbound: asyncio.Queue = asyncio.Queue()
        self.pump: asyncio.Task | None = None
        self.drain: asyncio.Task | None = None
        self.writer: asyncio.StreamWriter | None = None


class WebTransportSessionProtocol(QuicConnectionProtocol):
    """HTTP/3 connection that accepts WebTransport CONNECTs."""

    def __init__(self, *args, relay: "Relay", **kwargs):
        super().__init__(*args, **kwargs)
        self._relay = relay
        self._http: H3Connection | None = None
        # session_id -> stream_id -> _Stream
        self._sessions: dict[int, dict[int, _Stream]] = {}

    def quic_event_received(self, event) -> None:
        if isinstance(event, ProtocolNegotiated):
            self._http = H3Connection(self._quic)
        if self._http is not None:
            for http_event in self._http.handle_event(event):
                self._on_http_event(http_event)

    def error_received(self, exc) -> None:
        # Without this the only symptom is Chrome's generic "Opening
        # handshake failed", which says nothing about which side gave up.
        self._relay.log(f"quic error: {exc}")

    def connection_lost(self, exc) -> None:
        self._relay.log(f"connection lost: {exc}")

    def _on_http_event(self, event: H3Event) -> None:
        if isinstance(event, H3Event.HeadersReceived):
            self._on_connect(event)
        elif isinstance(event, H3Event.WebTransportStreamDataReceived):
            self._relay.on_stream_data(self, event)

    def _on_connect(self, event) -> None:
        if event.headers.get(b":protocol", b"") == CONNECT_WEBTRANSPORT_PROTOCOL:
            assert self._http is not None
            self._http.send_headers(
                event.stream_id,
                [(b":status", b"200"), (WEBTRANSPORT_DRAFT_HEADER, b"draft02")],
            )
            self._sessions[event.stream_id] = {}
            self._relay.log(f"session {event.stream_id} accepted")
        else:
            assert self._http is not None
            self._http.send_headers(
                event.stream_id,
                [(b":status", b"404"), (b"content-type", b"text/plain")],
            )
            self.quic.send_stream_data(
                event.stream_id, b"only webtransport is served here", end_stream=True
            )
        event.stream.reset()

    def streams(self, session_id: int) -> dict:
        return self._sessions.setdefault(session_id, {})

    def send_payload(self, stream_id: int, data: bytes, end_stream: bool = False) -> None:
        """Write an application payload as an HTTP/3 DATA frame."""
        if self._http is not None:
            self._http.send_data(stream_id, data, end_stream)

    def shutdown_session(self, session_id: int) -> None:
        for st in self.streams(session_id).values():
            if st.pump is not None:
                st.pump.cancel()
            if st.drain is not None:
                st.drain.cancel()
            if st.writer is not None:
                try:
                    st.writer.close()
                except OSError:
                    pass
        self._sessions.pop(session_id, None)


class Relay:
    """Bridges WebTransport streams to fresh TCP connections on one target."""

    def __init__(self, target_host: str, target_port: int):
        self.target_host = target_host
        self.target_port = target_port
        self.protocols: list[WebTransportSessionProtocol] = []

    def log(self, msg: str) -> None:
        print(f"[relay] {msg}", flush=True)

    def on_stream_data(self, protocol, event) -> None:
        st = protocol.streams(event.session_id).setdefault(event.stream_id, _Stream())
        # event.data is already the DATA frame payload: H3Connection unwrapped
        # the frame, so these are raw application bytes.
        st.inbound.put_nowait((event.data, event.stream_ended))
        if st.pump is None:
            if protocol not in self.protocols:
                self.protocols.append(protocol)
            st.pump = asyncio.get_event_loop().create_task(
                self._bridge(protocol, event.session_id, event.stream_id, st)
            )

    async def _bridge(
        self,
        protocol: WebTransportSessionProtocol,
        session_id: int,
        stream_id: int,
        st: _Stream,
    ) -> None:
        try:
            reader, writer = await asyncio.open_connection(self.target_host, self.target_port)
        except OSError as exc:
            self.log(f"tcp connect failed: {exc}")
            protocol.send_payload(stream_id, b"relay: cannot reach target", True)
            return
        st.writer = writer
        self.log(f"stream {stream_id} -> tcp {self.target_host}:{self.target_port}")
        st.drain = asyncio.get_event_loop().create_task(self._drain(writer, st))
        try:
            while True:
                chunk = await reader.read(65536)
                if not chunk:
                    break
                protocol.send_payload(stream_id, chunk)
        except asyncio.CancelledError:
            raise
        except (ConnectionResetError, OSError):
            pass
        finally:
            if st.drain is not None:
                st.drain.cancel()
            try:
                writer.close()
            except OSError:
                pass

    async def _drain(self, writer: asyncio.StreamWriter, st: _Stream) -> None:
        """Browser -> TCP."""
        try:
            while True:
                data, ended = await st.inbound.get()
                if data:
                    writer.write(data)
                await writer.drain()
                if ended:
                    try:
                        writer.close()
                    except OSError:
                        pass
                    return
        except asyncio.CancelledError:
            raise
        except (ConnectionResetError, OSError):
            pass

    def close(self) -> None:
        for p in list(self.protocols):
            for session_id in list(p._sessions.keys()):
                p.shutdown_session(session_id)
        self.protocols.clear()


async def main_async(args) -> int:
    logging.basicConfig(level=logging.WARNING)

    configuration = QuicConfiguration(
        is_client=False,
        alpn_protocols=H3_ALPN,
        # WebTransport requires datagrams; aioquic raises SettingsError on the
        # peer if ENABLE_WEBTRANSPORT is set without H3_DATAGRAM, so ask for
        # them up front.
        max_datagram_frame_size=65536,
    )
    configuration.load_cert_chain(args.cert, args.key)

    if args.version != "auto":
        wanted = (
            QuicProtocolVersion.VERSION_1
            if args.version == "1"
            else QuicProtocolVersion.VERSION_2
        )
        configuration.supported_versions = [wanted]

    if args.debug_quic:
        # QuicLogger takes no arguments; it writes qlog files named after its
        # CID prefix into the working directory. Use secrets_log_file for the
        # readable text trace instead -- it is what actually shows the frames.
        configuration.quic_logger = QuicLogger()
        configuration.secrets_log_file = args.debug_quic

    relay = Relay(args.target_host, args.target_port)

    def factory(*a, **kw):
        return WebTransportSessionProtocol(*a, relay=relay, **kw)

    # aioquic 1.x exposes `serve()`, which is the supported way to start a QUIC
    # endpoint. Do not hand-roll `create_datagram_endpoint` here: QuicServer is
    # a DatagramProtocol that multiplexes many connections off one socket, and
    # constructing it once and reusing that instance leaves the packet loop with
    # nothing to dispatch to. The symptom is a silent server -- the socket binds,
    # the port shows up in netstat, and no client ever gets an event.
    server = await serve(
        args.listen_host,
        args.listen_port,
        configuration=configuration,
        create_protocol=factory,
    )
    relay.log(
        f"http/3 webtransport on https://{args.listen_host}:{args.listen_port}"
        f" -> tcp {args.target_host}:{args.target_port}"
    )
    try:
        while True:
            await asyncio.sleep(3600)
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        relay.close()
        server.close()
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen-host", default="127.0.0.1")
    ap.add_argument("--listen-port", type=int, default=8443)
    ap.add_argument("--target-host", default="127.0.0.1")
    ap.add_argument("--target-port", type=int, default=22222)
    ap.add_argument(
        "--cert",
        default=".loop32/chain.pem",
        help="leaf+CA chain; a bare self-signed leaf is rejected on Chromium's "
        "QUIC path, so serve the chain",
    )
    ap.add_argument("--key", default=".loop32/key.pem")
    ap.add_argument(
        "--debug-quic",
        default="",
        help="log raw QUIC packets to this file (see aioquic.QuicLogger)",
    )
    ap.add_argument(
        "--version",
        default="auto",
        choices=["auto", "1", "2"],
        help="pin the QUIC version; 'auto' negotiates, which is what a "
        "browser will do anyway",
    )
    args = ap.parse_args()
    try:
        return asyncio.run(main_async(args))
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(main())
