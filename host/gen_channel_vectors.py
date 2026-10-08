"""Emit cmd/channel_test/vectors.mbt from host/channel_oracle.py.

Run:  python host/gen_channel_vectors.py

The oracle is the second independent implementation of the channel rules (the
first being OpenSSH's own C, which it quotes line by line); this file only
formats its output as MoonBit.  Nothing here is hand-transcribed.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import channel_oracle as O  # noqa: E402

OUT = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "cmd", "channel_test", "vectors.mbt",
)

HEADER = '''///| GENERATED FILE -- do not edit by hand.
///| Regenerate with: python host/gen_channel_vectors.py
///|
///| Source: host/channel_oracle.py.  That file re-derives every value from
///| OpenSSH's C (`channels.h:231-232`, `channels.c:2444-2462`,
///| `channels.c:3505-3523`, `channels.c:3126-3135`, `session.c:2344-2347`) and
///| cross-checks its own CHANNEL_OPEN / exec / EOF bytes against a live
///| paramiko session before any of this is written out.  So these are not
///| "what MoonBit happens to produce" -- they are what a server would have to
///| agree with.
///
///| `msg_type` is kept as a decimal Int and narrowed by the test, so a bad
///| vector fails as a number instead of as a Byte that silently wrapped.

///|
///| One packet on the wire.
///|
///| `fill_byte >= 0` means the payload is not stored inline: it is `fill_len`
///| copies of that byte behind the usual header.  A 48 x 32 KiB transcript is
///| 3 MiB of hex per copy, which made the file slow to parse on every backend
///| and useless as a diff.  `payload_len` is the full rebuilt length, header
///| included, so nothing about the case is quietly weakened.
pub(all) struct Packet {
  msg_type : Int
  payload_hex : String
  fill_byte : Int
  fill_len : Int
  fill_code : Int
  payload_len : Int
}

///| Captured stream.  Same trick as `Packet`: an empty `hex` means `len` copies
///| of `byte`.
pub(all) struct Stream {
  hex : String
  byte : Int
  len : Int
}

pub(all) struct PayloadCase {
  name : String
  sender : Int
  window : Int
  max_packet : Int
  open_hex : String
  exec_command : String
  exec_hex : String
  data_text : String
  data_hex : String
  extdata_code : Int
  extdata_text : String
  extdata_hex : String
  adjust_bytes : Int
  adjust_hex : String
  bare_hex : String
  exit_status_code : Int
  exit_status_hex : String
  open_failure_reason : Int
  open_failure_desc : String
  open_failure_hex : String
}

pub(all) struct WindowCase {
  name : String
  sizes : Array[Int]
  adjust_amounts : Array[Int]
  final_cur : Int
  final_consumed : Int
}

///|
///| One end-to-end transcript: what the server sends, what we must send back,
///| and what the client is left holding afterwards.
pub(all) struct SessionCase {
  name : String
  local_channel : Int
  remote_channel : Int
  packets : Array[Packet]
  replies : Array[Packet]
  stdout : Stream
  stderr : Stream
  exit_status : Int
  adjusts_sent : Int
  final_cur : Int
}

///|
/// One packet the *driver* sends, timed by how many server packets preceded it.
///
/// An interactive session is mostly the driver's decisions: pty-req only after
/// OPEN_CONFIRMATION, shell only after pty-req's reply, stdin whenever. Loop #35's
/// model only recorded what the state machine produced, which would have left
/// the whole request sequence untested.
pub(all) struct ClientSend {
  after : Int
  msg_type : Int
  payload_hex : String
}

///| One interactive transcript.
pub(all) struct ShellCase {
  name : String
  local_channel : Int
  remote_channel : Int
  packets : Array[Packet]
  client_sends : Array[ClientSend]
  replies : Array[Packet]
  stdout : Stream
  stderr : Stream
  exit_status : Int
  exit_signal : String
  success_count : Int
  failure_count : Int
  adjusts_sent : Int
  final_cur : Int
}

pub(all) struct ShellPayloadCase {
  name : String
  recipient : Int
  term : String
  cols : Int
  rows : Int
  width_px : Int
  height_px : Int
  modes_hex : String
  pty_req_hex : String
  shell_hex : String
  resize_cols : Int
  resize_rows : Int
  window_change_hex : String
  stdin_hex : String
  exit_signal_name : String
  exit_signal_core : Bool
  exit_signal_message : String
  exit_signal_hex : String
}

// MoonBit does not synthesise a constructor, and `pub(all)` fields are
// immutable, so each one gets an explicit builder.


pub fn ClientSend::new(
  after : Int,
  msg_type : Int,
  payload_hex : String,
) -> ClientSend {
  { after, msg_type, payload_hex, }
}

pub fn ShellCase::new(
  name : String,
  local_channel : Int,
  remote_channel : Int,
  packets : Array[Packet],
  client_sends : Array[ClientSend],
  replies : Array[Packet],
  stdout : Stream,
  stderr : Stream,
  exit_status : Int,
  exit_signal : String,
  success_count : Int,
  failure_count : Int,
  adjusts_sent : Int,
  final_cur : Int,
) -> ShellCase {
  {
    name,
    local_channel,
    remote_channel,
    packets,
    client_sends,
    replies,
    stdout,
    stderr,
    exit_status,
    exit_signal,
    success_count,
    failure_count,
    adjusts_sent,
    final_cur,
  }
}

pub fn ShellPayloadCase::new(
  name : String,
  recipient : Int,
  term : String,
  cols : Int,
  rows : Int,
  width_px : Int,
  height_px : Int,
  modes_hex : String,
  pty_req_hex : String,
  shell_hex : String,
  resize_cols : Int,
  resize_rows : Int,
  window_change_hex : String,
  stdin_hex : String,
  exit_signal_name : String,
  exit_signal_core : Bool,
  exit_signal_message : String,
  exit_signal_hex : String,
) -> ShellPayloadCase {
  {
    name,
    recipient,
    term,
    cols,
    rows,
    width_px,
    height_px,
    modes_hex,
    pty_req_hex,
    shell_hex,
    resize_cols,
    resize_rows,
    window_change_hex,
    stdin_hex,
    exit_signal_name,
    exit_signal_core,
    exit_signal_message,
    exit_signal_hex,
  }
}

pub fn Packet::new(
  msg_type : Int,
  payload_hex : String,
  fill_byte : Int,
  fill_len : Int,
  fill_code : Int,
  payload_len : Int,
) -> Packet {
  { msg_type, payload_hex, fill_byte, fill_len, fill_code, payload_len, }
}

pub fn Stream::new(hex : String, byte : Int, len : Int) -> Stream {
  { hex, byte, len, }
}

pub fn PayloadCase::new(
  name : String,
  sender : Int,
  window : Int,
  max_packet : Int,
  open_hex : String,
  exec_command : String,
  exec_hex : String,
  data_text : String,
  data_hex : String,
  extdata_code : Int,
  extdata_text : String,
  extdata_hex : String,
  adjust_bytes : Int,
  adjust_hex : String,
  bare_hex : String,
  exit_status_code : Int,
  exit_status_hex : String,
  open_failure_reason : Int,
  open_failure_desc : String,
  open_failure_hex : String,
) -> PayloadCase {
  {
    name,
    sender,
    window,
    max_packet,
    open_hex,
    exec_command,
    exec_hex,
    data_text,
    data_hex,
    extdata_code,
    extdata_text,
    extdata_hex,
    adjust_bytes,
    adjust_hex,
    bare_hex,
    exit_status_code,
    exit_status_hex,
    open_failure_reason,
    open_failure_desc,
    open_failure_hex,
  }
}

pub fn WindowCase::new(
  name : String,
  sizes : Array[Int],
  adjust_amounts : Array[Int],
  final_cur : Int,
  final_consumed : Int,
) -> WindowCase {
  { name, sizes, adjust_amounts, final_cur, final_consumed, }
}

pub fn SessionCase::new(
  name : String,
  local_channel : Int,
  remote_channel : Int,
  packets : Array[Packet],
  replies : Array[Packet],
  stdout : Stream,
  stderr : Stream,
  exit_status : Int,
  adjusts_sent : Int,
  final_cur : Int,
) -> SessionCase {
  {
    name,
    local_channel,
    remote_channel,
    packets,
    replies,
    stdout,
    stderr,
    exit_status,
    adjusts_sent,
    final_cur,
  }
}
'''


def lit(s):
    return '"%s"' % s


def packets(items, indent):
    pad = " " * indent
    if not items:
        return "[]"
    out = ["["]
    for it in items:
        out.append("%s  Packet::new(%d, %s, %d, %d, %d, %d),"
                   % (pad, it["type"], lit(it["payload_hex"]),
                      it["fill_byte"], it["fill_len"], it["fill_code"],
                      it["payload_len"]))
    out.append("%s]" % pad)
    return "\n".join(out)


def stream(s):
    return "Stream::new(%s, %d, %d)" % (lit(s["hex"]), s["byte"], s["len"])


def client_sends(items, indent):
    pad = " " * indent
    if not items:
        return "[]"
    out = ["["]
    for it in items:
        out.append("%s  ClientSend::new(%d, %d, %s)," %
                   (pad, it["after"], it["type"], lit(it["payload_hex"])))
    out.append("%s]" % pad)
    return "\n".join(out)


def ints(items):
    return "[" + ", ".join(str(i) for i in items) + "]"


def render(doc):
    parts = [HEADER]
    parts.append("\npub const KAT_CHAN_PACKET_DEFAULT : Int = %d"
                 % doc["chan_packet_default"])
    parts.append("pub const KAT_CHAN_WINDOW_DEFAULT : Int = %d"
                 % doc["chan_window_default"])

    # ---- per-message builders --------------------------------------------
    parts.append("\n///| One entry per message type, for two channel-number sets.\n"
                 "pub let kat_payload_cases : Array[PayloadCase] = [")
    for p in doc["payloads"]:
        parts.append("  PayloadCase::new(")
        for key in ("name",):
            parts.append("    %s," % lit(p[key]))
        for key in ("sender", "window", "max_packet"):
            parts.append("    %d," % p[key])
        parts.append("    %s," % lit(p["open_hex"]))
        parts.append("    %s," % lit(p["exec_command"]))
        parts.append("    %s," % lit(p["exec_hex"]))
        parts.append("    %s," % lit(p["data_text"]))
        parts.append("    %s," % lit(p["data_hex"]))
        parts.append("    %d," % p["extdata_code"])
        parts.append("    %s," % lit(p["extdata_text"]))
        parts.append("    %s," % lit(p["extdata_hex"]))
        parts.append("    %d," % p["adjust_bytes"])
        parts.append("    %s," % lit(p["adjust_hex"]))
        parts.append("    %s," % lit(p["bare_hex"]))
        parts.append("    %d," % p["exit_status_code"])
        parts.append("    %s," % lit(p["exit_status_hex"]))
        parts.append("    %d," % p["open_failure_reason"])
        parts.append("    %s," % lit(p["open_failure_desc"]))
        parts.append("    %s," % lit(p["open_failure_hex"]))
        parts.append("  ),")
    parts.append("]")

    # ---- window plans -----------------------------------------------------
    parts.append("\n///| How many WINDOW_ADJUSTs a given output shape produces, and\n"
                 "///| how many bytes each one carries.\n"
                 "pub let kat_window_cases : Array[WindowCase] = [")
    for w in doc["windows"]:
        amounts = [a["bytes"] for a in w["adjusts"]]
        parts.append("  WindowCase::new(")
        parts.append("    %s," % lit(w["name"]))
        parts.append("    %s," % ints(w["sizes"]))
        parts.append("    %s," % ints(amounts))
        parts.append("    %d," % w["final_cur"])
        parts.append("    %d," % w["final_consumed"])
        parts.append("  ),")
    parts.append("]")

    # ---- session transcripts ---------------------------------------------
    parts.append("\n///| Full transcripts.\n"
                 "///|\n"
                 "///| `exec_nonzero_ids` separates \"the recipient field of an inbound\n"
                 "///| packet is our channel\" from \"it is the peer's channel\".\n"
                 "///| `exec_bulk_window` separates sending the consumed total from\n"
                 "///| topping the window back up to full.\n"
                 "pub let kat_session_cases : Array[SessionCase] = [")
    for s in doc["sessions"]:
        parts.append("  SessionCase::new(")
        parts.append("    %s," % lit(s["name"]))
        parts.append("    %d," % s["local_channel"])
        parts.append("    %d," % s["remote_channel"])
        parts.append("    %s," % packets(s["packets"], 4))
        parts.append("    %s," % packets(s["replies"], 4))
        parts.append("    %s," % stream(s["stdout"]))
        parts.append("    %s," % stream(s["stderr"]))
        parts.append("    %d," % s["exit_status"])
        parts.append("    %d," % s["adjusts_sent"])
        parts.append("    %d," % s["final_cur"])
        parts.append("  ),")
    parts.append("]")

    return "\n".join(parts) + "\n"


def render_shell(doc):
    parts = []

    # ---- interactive payloads -------------------------------------------
    parts.append("\n///| One entry per interactive message, for two channel ids.\n"
                 "pub let kat_shell_payload_cases : Array[ShellPayloadCase] = [")
    for p in doc["shell_payloads"]:
        parts.append("  ShellPayloadCase::new(")
        parts.append("    %s," % lit(p["name"]))
        parts.append("    %d," % p["recipient"])
        parts.append("    %s," % lit(p["term"]))
        parts.append("    %d," % p["cols"])
        parts.append("    %d," % p["rows"])
        parts.append("    %d," % p["width_px"])
        parts.append("    %d," % p["height_px"])
        parts.append("    %s," % lit(p["modes_hex"]))
        parts.append("    %s," % lit(p["pty_req_hex"]))
        parts.append("    %s," % lit(p["shell_hex"]))
        parts.append("    %d," % p["resize_cols"])
        parts.append("    %d," % p["resize_rows"])
        parts.append("    %s," % lit(p["window_change_hex"]))
        parts.append("    %s," % lit(p["stdin_hex"]))
        parts.append("    %s," % lit(p["exit_signal_name"]))
        parts.append("    %s," % ("true" if p["exit_signal_core"] else "false"))
        parts.append("    %s," % lit(p["exit_signal_message"]))
        parts.append("    %s," % lit(p["exit_signal_hex"]))
        parts.append("  ),")
    parts.append("]")

    # ---- interactive transcripts ---------------------------------------
    parts.append("\n///| Interactive transcripts.  `shell_no_pty` is the one that\n"
                 "///| catches a driver which treats a refused pty-req as fatal\n"
                 "///| instead of falling back the way clientloop.c:2750 does;\n"
                 "///| `shell_resize` catches one that waits for a reply that\n"
                 "///| session.c:1843 never sends.\n"
                 "pub let kat_shell_cases : Array[ShellCase] = [")
    for s in doc["shell_sessions"]:
        parts.append("  ShellCase::new(")
        parts.append("    %s," % lit(s["name"]))
        parts.append("    %d," % s["local_channel"])
        parts.append("    %d," % s["remote_channel"])
        parts.append("    %s," % packets(s["packets"], 4))
        parts.append("    %s," % client_sends(s["client_sends"], 4))
        parts.append("    %s," % packets(s["replies"], 4))
        parts.append("    %s," % stream(s["stdout"]))
        parts.append("    %s," % stream(s["stderr"]))
        parts.append("    %d," % s["exit_status"])
        parts.append("    %s," % lit(s["exit_signal"] or ""))
        parts.append("    %d," % s["success_count"])
        parts.append("    %d," % s["failure_count"])
        parts.append("    %d," % s["adjusts_sent"])
        parts.append("    %d," % s["final_cur"])
        parts.append("  ),")
    parts.append("]")

    return "\n".join(parts) + "\n"


def main():
    doc = O.build_document()
    text = render(doc) + render_shell(doc)
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
    print("wrote %s (%d bytes, %d session vectors)"
          % (OUT, len(text.encode("utf-8")), len(doc["sessions"])))


if __name__ == "__main__":
    main()
