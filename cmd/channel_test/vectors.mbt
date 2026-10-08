///| GENERATED FILE -- do not edit by hand.
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


pub const KAT_CHAN_PACKET_DEFAULT : Int = 32768
pub const KAT_CHAN_WINDOW_DEFAULT : Int = 2097152

///| One entry per message type, for two channel-number sets.
pub let kat_payload_cases : Array[PayloadCase] = [
  PayloadCase::new(
    "open_s0",
    0,
    2097152,
    32768,
    "0000000773657373696f6e000000000020000000008000",
    "echo hi",
    "00000000000000046578656301000000076563686f206869",
    "abc",
    "0000000000000003616263",
    1,
    "oops",
    "0000000000000001000000046f6f7073",
    65536,
    "0000000000010000",
    "00000000",
    42,
    "000000000000000b657869742d737461747573000000002a",
    3,
    "no such session",
    "00000000000000030000000f6e6f20737563682073657373696f6e00000000",
  ),
  PayloadCase::new(
    "open_s3",
    3,
    2097152,
    32768,
    "0000000773657373696f6e000000030020000000008000",
    "echo hi",
    "00000003000000046578656301000000076563686f206869",
    "abc",
    "0000000300000003616263",
    1,
    "oops",
    "0000000300000001000000046f6f7073",
    65536,
    "0000000300010000",
    "00000003",
    42,
    "000000030000000b657869742d737461747573000000002a",
    3,
    "no such session",
    "00000003000000030000000f6e6f20737563682073657373696f6e00000000",
  ),
]

///| How many WINDOW_ADJUSTs a given output shape produces, and
///| how many bytes each one carries.
pub let kat_window_cases : Array[WindowCase] = [
  WindowCase::new(
    "small",
    [16],
    [],
    2097136,
    16,
  ),
  WindowCase::new(
    "exact_maxpacket",
    [32768],
    [],
    2064384,
    32768,
  ),
  WindowCase::new(
    "just_under_half",
    [1048568],
    [1048568],
    2097152,
    0,
  ),
  WindowCase::new(
    "past_half",
    [1048584],
    [1048584],
    2097152,
    0,
  ),
  WindowCase::new(
    "bulk_32k",
    [32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768, 32768],
    [131072, 131072, 131072, 131072, 131072, 131072, 131072, 131072, 131072, 131072, 131072, 131072],
    2097152,
    0,
  ),
  WindowCase::new(
    "many_small",
    [1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024],
    [99328, 99328, 99328, 99328, 99328, 99328, 99328, 99328, 99328, 99328, 99328],
    2063360,
    33792,
  ),
]

///| Full transcripts.
///|
///| `exec_nonzero_ids` separates "the recipient field of an inbound
///| packet is our channel" from "it is the peer's channel".
///| `exec_bulk_window` separates sending the consumed total from
///| topping the window back up to full.
pub let kat_session_cases : Array[SessionCase] = [
  SessionCase::new(
    "exec_ok",
    0,
    0,
    [
      Packet::new(91, "00000000000000000020000000008000", -1, 0, -1, 16),
      Packet::new(99, "00000000", -1, 0, -1, 4),
      Packet::new(94, "000000000000000668656c6c6f0a", -1, 0, -1, 14),
      Packet::new(98, "000000000000000b657869742d7374617475730000000000", -1, 0, -1, 24),
      Packet::new(96, "00000000", -1, 0, -1, 4),
      Packet::new(97, "00000000", -1, 0, -1, 4),
    ],
    [
      Packet::new(97, "00000000", -1, 0, -1, 4),
    ],
    Stream::new("68656c6c6f0a", -1, 6),
    Stream::new("", -1, 0),
    0,
    0,
    2097146,
  ),
  SessionCase::new(
    "exec_nonzero_exit",
    0,
    0,
    [
      Packet::new(91, "00000000000000000020000000008000", -1, 0, -1, 16),
      Packet::new(99, "00000000", -1, 0, -1, 4),
      Packet::new(94, "00000000000000077061727469616c", -1, 0, -1, 15),
      Packet::new(98, "000000000000000b657869742d737461747573000000002a", -1, 0, -1, 24),
      Packet::new(96, "00000000", -1, 0, -1, 4),
      Packet::new(97, "00000000", -1, 0, -1, 4),
    ],
    [
      Packet::new(97, "00000000", -1, 0, -1, 4),
    ],
    Stream::new("7061727469616c", -1, 7),
    Stream::new("", -1, 0),
    42,
    0,
    2097145,
  ),
  SessionCase::new(
    "exec_nonzero_ids",
    3,
    7,
    [
      Packet::new(91, "00000003000000070020000000008000", -1, 0, -1, 16),
      Packet::new(99, "00000003", -1, 0, -1, 4),
      Packet::new(94, "000000030000000668656c6c6f0a", -1, 0, -1, 14),
      Packet::new(98, "000000030000000b657869742d7374617475730000000000", -1, 0, -1, 24),
      Packet::new(96, "00000003", -1, 0, -1, 4),
      Packet::new(97, "00000003", -1, 0, -1, 4),
    ],
    [
      Packet::new(97, "00000007", -1, 0, -1, 4),
    ],
    Stream::new("68656c6c6f0a", -1, 6),
    Stream::new("", -1, 0),
    0,
    0,
    2097146,
  ),
  SessionCase::new(
    "exec_stderr",
    0,
    0,
    [
      Packet::new(91, "00000000000000000020000000008000", -1, 0, -1, 16),
      Packet::new(99, "00000000", -1, 0, -1, 4),
      Packet::new(94, "00000000000000046f75740a", -1, 0, -1, 12),
      Packet::new(95, "0000000000000001000000046572720a", -1, 0, -1, 16),
      Packet::new(98, "000000000000000b657869742d7374617475730000000003", -1, 0, -1, 24),
      Packet::new(96, "00000000", -1, 0, -1, 4),
      Packet::new(97, "00000000", -1, 0, -1, 4),
    ],
    [
      Packet::new(97, "00000000", -1, 0, -1, 4),
    ],
    Stream::new("6f75740a", -1, 4),
    Stream::new("6572720a", -1, 4),
    3,
    0,
    2097144,
  ),
  SessionCase::new(
    "exec_bulk_window",
    0,
    0,
    [
      Packet::new(91, "00000000000000000020000000008000", -1, 0, -1, 16),
      Packet::new(99, "00000000", -1, 0, -1, 4),
      Packet::new(94, "", 65, 32768, -1, 32776),
      Packet::new(94, "", 65, 32768, -1, 32776),
      Packet::new(94, "", 65, 32768, -1, 32776),
      Packet::new(94, "", 65, 32768, -1, 32776),
      Packet::new(94, "", 65, 32768, -1, 32776),
      Packet::new(94, "", 65, 32768, -1, 32776),
      Packet::new(94, "", 65, 32768, -1, 32776),
      Packet::new(94, "", 65, 32768, -1, 32776),
      Packet::new(94, "", 65, 32768, -1, 32776),
      Packet::new(94, "", 65, 32768, -1, 32776),
      Packet::new(94, "", 65, 32768, -1, 32776),
      Packet::new(94, "", 65, 32768, -1, 32776),
      Packet::new(94, "", 65, 32768, -1, 32776),
      Packet::new(94, "", 65, 32768, -1, 32776),
      Packet::new(94, "", 65, 32768, -1, 32776),
      Packet::new(94, "", 65, 32768, -1, 32776),
      Packet::new(94, "", 65, 32768, -1, 32776),
      Packet::new(94, "", 65, 32768, -1, 32776),
      Packet::new(94, "", 65, 32768, -1, 32776),
      Packet::new(94, "", 65, 32768, -1, 32776),
      Packet::new(94, "", 65, 32768, -1, 32776),
      Packet::new(94, "", 65, 32768, -1, 32776),
      Packet::new(94, "", 65, 32768, -1, 32776),
      Packet::new(94, "", 65, 32768, -1, 32776),
      Packet::new(94, "", 65, 32768, -1, 32776),
      Packet::new(94, "", 65, 32768, -1, 32776),
      Packet::new(94, "", 65, 32768, -1, 32776),
      Packet::new(94, "", 65, 32768, -1, 32776),
      Packet::new(94, "", 65, 32768, -1, 32776),
      Packet::new(94, "", 65, 32768, -1, 32776),
      Packet::new(94, "", 65, 32768, -1, 32776),
      Packet::new(94, "", 65, 32768, -1, 32776),
      Packet::new(94, "", 65, 32768, -1, 32776),
      Packet::new(94, "", 65, 32768, -1, 32776),
      Packet::new(94, "", 65, 32768, -1, 32776),
      Packet::new(94, "", 65, 32768, -1, 32776),
      Packet::new(94, "", 65, 32768, -1, 32776),
      Packet::new(94, "", 65, 32768, -1, 32776),
      Packet::new(94, "", 65, 32768, -1, 32776),
      Packet::new(94, "", 65, 32768, -1, 32776),
      Packet::new(94, "", 65, 32768, -1, 32776),
      Packet::new(94, "", 65, 32768, -1, 32776),
      Packet::new(94, "", 65, 32768, -1, 32776),
      Packet::new(94, "", 65, 32768, -1, 32776),
      Packet::new(94, "", 65, 32768, -1, 32776),
      Packet::new(94, "", 65, 32768, -1, 32776),
      Packet::new(94, "", 65, 32768, -1, 32776),
      Packet::new(94, "", 65, 32768, -1, 32776),
      Packet::new(98, "000000000000000b657869742d7374617475730000000000", -1, 0, -1, 24),
      Packet::new(96, "00000000", -1, 0, -1, 4),
      Packet::new(97, "00000000", -1, 0, -1, 4),
    ],
    [
      Packet::new(93, "0000000000020000", -1, 0, -1, 8),
      Packet::new(93, "0000000000020000", -1, 0, -1, 8),
      Packet::new(93, "0000000000020000", -1, 0, -1, 8),
      Packet::new(93, "0000000000020000", -1, 0, -1, 8),
      Packet::new(93, "0000000000020000", -1, 0, -1, 8),
      Packet::new(93, "0000000000020000", -1, 0, -1, 8),
      Packet::new(93, "0000000000020000", -1, 0, -1, 8),
      Packet::new(93, "0000000000020000", -1, 0, -1, 8),
      Packet::new(93, "0000000000020000", -1, 0, -1, 8),
      Packet::new(93, "0000000000020000", -1, 0, -1, 8),
      Packet::new(93, "0000000000020000", -1, 0, -1, 8),
      Packet::new(93, "0000000000020000", -1, 0, -1, 8),
      Packet::new(97, "00000000", -1, 0, -1, 4),
    ],
    Stream::new("", 65, 1572864),
    Stream::new("", -1, 0),
    0,
    12,
    2097152,
  ),
  SessionCase::new(
    "exec_stderr_window",
    0,
    0,
    [
      Packet::new(91, "00000000000000000020000000008000", -1, 0, -1, 16),
      Packet::new(99, "00000000", -1, 0, -1, 4),
      Packet::new(95, "", 69, 1048584, 1, 1048596),
      Packet::new(98, "000000000000000b657869742d7374617475730000000000", -1, 0, -1, 24),
      Packet::new(96, "00000000", -1, 0, -1, 4),
      Packet::new(97, "00000000", -1, 0, -1, 4),
    ],
    [
      Packet::new(93, "0000000000100008", -1, 0, -1, 8),
      Packet::new(97, "00000000", -1, 0, -1, 4),
    ],
    Stream::new("", -1, 0),
    Stream::new("", 69, 1048584),
    0,
    1,
    2097152,
  ),
  SessionCase::new(
    "exec_extdata_other",
    0,
    0,
    [
      Packet::new(91, "00000000000000000020000000008000", -1, 0, -1, 16),
      Packet::new(99, "00000000", -1, 0, -1, 4),
      Packet::new(94, "00000000000000046f75740a", -1, 0, -1, 12),
      Packet::new(95, "0000000000000002000000046f74700a", -1, 0, -1, 16),
      Packet::new(98, "000000000000000b657869742d7374617475730000000000", -1, 0, -1, 24),
      Packet::new(96, "00000000", -1, 0, -1, 4),
      Packet::new(97, "00000000", -1, 0, -1, 4),
    ],
    [
      Packet::new(97, "00000000", -1, 0, -1, 4),
    ],
    Stream::new("6f75740a", -1, 4),
    Stream::new("", -1, 0),
    0,
    0,
    2097148,
  ),
  SessionCase::new(
    "exec_exit_signal",
    0,
    0,
    [
      Packet::new(91, "00000000000000000020000000008000", -1, 0, -1, 16),
      Packet::new(99, "00000000", -1, 0, -1, 4),
      Packet::new(94, "00000000000000046f75740a", -1, 0, -1, 12),
      Packet::new(98, "000000000000000b657869742d7369676e616c00000000045445524d010000000000000003627965", -1, 0, -1, 40),
      Packet::new(96, "00000000", -1, 0, -1, 4),
      Packet::new(97, "00000000", -1, 0, -1, 4),
    ],
    [
      Packet::new(97, "00000000", -1, 0, -1, 4),
    ],
    Stream::new("6f75740a", -1, 4),
    Stream::new("", -1, 0),
    255,
    0,
    2097148,
  ),
  SessionCase::new(
    "exec_no_exit_status",
    0,
    0,
    [
      Packet::new(91, "00000000000000000020000000008000", -1, 0, -1, 16),
      Packet::new(99, "00000000", -1, 0, -1, 4),
      Packet::new(94, "00000000000000046f75740a", -1, 0, -1, 12),
      Packet::new(96, "00000000", -1, 0, -1, 4),
      Packet::new(97, "00000000", -1, 0, -1, 4),
    ],
    [
      Packet::new(97, "00000000", -1, 0, -1, 4),
    ],
    Stream::new("6f75740a", -1, 4),
    Stream::new("", -1, 0),
    255,
    0,
    2097148,
  ),
]

///| One entry per interactive message, for two channel ids.
pub let kat_shell_payload_cases : Array[ShellPayloadCase] = [
  ShellPayloadCase::new(
    "pty_s0",
    0,
    "xterm-256color",
    80,
    24,
    0,
    0,
    "8000009600810000960000",
    "00000000000000077074792d726571010000000e787465726d2d323536636f6c6f72000000500000001800000000000000000000000b8000009600810000960000",
    "00000000000000057368656c6c01",
    132,
    43,
    "000000000000000d77696e646f772d6368616e676500000000840000002b0000000000000000",
    "0000000000000003780d0a",
    "TERM",
    false,
    "terminated",
    "000000000000000b657869742d7369676e616c00000000045445524d00000000000000000a7465726d696e61746564",
  ),
  ShellPayloadCase::new(
    "pty_s7",
    7,
    "xterm-256color",
    80,
    24,
    0,
    0,
    "8000009600810000960000",
    "00000007000000077074792d726571010000000e787465726d2d323536636f6c6f72000000500000001800000000000000000000000b8000009600810000960000",
    "00000007000000057368656c6c01",
    132,
    43,
    "000000070000000d77696e646f772d6368616e676500000000840000002b0000000000000000",
    "0000000700000003780d0a",
    "TERM",
    false,
    "terminated",
    "000000070000000b657869742d7369676e616c00000000045445524d00000000000000000a7465726d696e61746564",
  ),
]

///| Interactive transcripts.  `shell_no_pty` is the one that
///| catches a driver which treats a refused pty-req as fatal
///| instead of falling back the way clientloop.c:2750 does;
///| `shell_resize` catches one that waits for a reply that
///| session.c:1843 never sends.
pub let kat_shell_cases : Array[ShellCase] = [
  ShellCase::new(
    "shell_pty_ok",
    0,
    0,
    [
      Packet::new(91, "00000000000000000020000000008000", -1, 0, -1, 16),
      Packet::new(99, "00000000", -1, 0, -1, 4),
      Packet::new(99, "00000000", -1, 0, -1, 4),
      Packet::new(94, "00000000000000086c6f6f7033360d0a", -1, 0, -1, 16),
      Packet::new(98, "000000000000000b657869742d7374617475730000000000", -1, 0, -1, 24),
      Packet::new(96, "00000000", -1, 0, -1, 4),
      Packet::new(97, "00000000", -1, 0, -1, 4),
    ],
    [
      ClientSend::new(0, 90, "0000000773657373696f6e000000000020000000008000"),
      ClientSend::new(1, 98, "00000000000000077074792d726571010000000e787465726d2d323536636f6c6f72000000500000001800000000000000000000000b8000009600810000960000"),
      ClientSend::new(2, 98, "00000000000000057368656c6c01"),
      ClientSend::new(3, 94, "000000000000000d6563686f206c6f6f7033360d0a"),
    ],
    [
      Packet::new(90, "0000000773657373696f6e000000000020000000008000", -1, 0, -1, 23),
      Packet::new(98, "00000000000000077074792d726571010000000e787465726d2d323536636f6c6f72000000500000001800000000000000000000000b8000009600810000960000", -1, 0, -1, 65),
      Packet::new(98, "00000000000000057368656c6c01", -1, 0, -1, 14),
      Packet::new(94, "000000000000000d6563686f206c6f6f7033360d0a", -1, 0, -1, 21),
      Packet::new(97, "00000000", -1, 0, -1, 4),
    ],
    Stream::new("6c6f6f7033360d0a", -1, 8),
    Stream::new("", -1, 0),
    0,
    "",
    2,
    0,
    0,
    2097144,
  ),
  ShellCase::new(
    "shell_no_pty",
    0,
    0,
    [
      Packet::new(91, "00000000000000000020000000008000", -1, 0, -1, 16),
      Packet::new(100, "00000000", -1, 0, -1, 4),
      Packet::new(99, "00000000", -1, 0, -1, 4),
      Packet::new(94, "00000000000000076e6f7074790d0a", -1, 0, -1, 15),
      Packet::new(98, "000000000000000b657869742d7374617475730000000000", -1, 0, -1, 24),
      Packet::new(96, "00000000", -1, 0, -1, 4),
      Packet::new(97, "00000000", -1, 0, -1, 4),
    ],
    [
      ClientSend::new(0, 90, "0000000773657373696f6e000000000020000000008000"),
      ClientSend::new(1, 98, "00000000000000077074792d726571010000000e787465726d2d323536636f6c6f72000000500000001800000000000000000000000b8000009600810000960000"),
      ClientSend::new(2, 98, "00000000000000057368656c6c01"),
      ClientSend::new(3, 94, "000000000000000c6563686f206e6f7074790d0a"),
    ],
    [
      Packet::new(90, "0000000773657373696f6e000000000020000000008000", -1, 0, -1, 23),
      Packet::new(98, "00000000000000077074792d726571010000000e787465726d2d323536636f6c6f72000000500000001800000000000000000000000b8000009600810000960000", -1, 0, -1, 65),
      Packet::new(98, "00000000000000057368656c6c01", -1, 0, -1, 14),
      Packet::new(94, "000000000000000c6563686f206e6f7074790d0a", -1, 0, -1, 20),
      Packet::new(97, "00000000", -1, 0, -1, 4),
    ],
    Stream::new("6e6f7074790d0a", -1, 7),
    Stream::new("", -1, 0),
    0,
    "",
    1,
    1,
    0,
    2097145,
  ),
  ShellCase::new(
    "shell_resize",
    0,
    0,
    [
      Packet::new(91, "00000000000000000020000000008000", -1, 0, -1, 16),
      Packet::new(99, "00000000", -1, 0, -1, 4),
      Packet::new(99, "00000000", -1, 0, -1, 4),
      Packet::new(94, "0000000000000009726573697a65640d0a", -1, 0, -1, 17),
      Packet::new(98, "000000000000000b657869742d7374617475730000000000", -1, 0, -1, 24),
      Packet::new(96, "00000000", -1, 0, -1, 4),
      Packet::new(97, "00000000", -1, 0, -1, 4),
    ],
    [
      ClientSend::new(0, 90, "0000000773657373696f6e000000000020000000008000"),
      ClientSend::new(1, 98, "00000000000000077074792d726571010000000e787465726d2d323536636f6c6f72000000500000001800000000000000000000000b8000009600810000960000"),
      ClientSend::new(2, 98, "00000000000000057368656c6c01"),
      ClientSend::new(3, 98, "000000000000000d77696e646f772d6368616e676500000000840000002b0000000000000000"),
      ClientSend::new(3, 94, "000000000000000e6563686f20726573697a65640d0a"),
    ],
    [
      Packet::new(90, "0000000773657373696f6e000000000020000000008000", -1, 0, -1, 23),
      Packet::new(98, "00000000000000077074792d726571010000000e787465726d2d323536636f6c6f72000000500000001800000000000000000000000b8000009600810000960000", -1, 0, -1, 65),
      Packet::new(98, "00000000000000057368656c6c01", -1, 0, -1, 14),
      Packet::new(98, "000000000000000d77696e646f772d6368616e676500000000840000002b0000000000000000", -1, 0, -1, 38),
      Packet::new(94, "000000000000000e6563686f20726573697a65640d0a", -1, 0, -1, 22),
      Packet::new(97, "00000000", -1, 0, -1, 4),
    ],
    Stream::new("726573697a65640d0a", -1, 9),
    Stream::new("", -1, 0),
    0,
    "",
    2,
    0,
    0,
    2097143,
  ),
  ShellCase::new(
    "shell_exit_signal",
    0,
    0,
    [
      Packet::new(91, "00000000000000000020000000008000", -1, 0, -1, 16),
      Packet::new(99, "00000000", -1, 0, -1, 4),
      Packet::new(99, "00000000", -1, 0, -1, 4),
      Packet::new(94, "000000000000000c5465726d696e617465640d0a", -1, 0, -1, 20),
      Packet::new(98, "000000000000000b657869742d7369676e616c00000000045445524d00000000000000000a7465726d696e61746564", -1, 0, -1, 47),
      Packet::new(96, "00000000", -1, 0, -1, 4),
      Packet::new(97, "00000000", -1, 0, -1, 4),
    ],
    [
      ClientSend::new(0, 90, "0000000773657373696f6e000000000020000000008000"),
      ClientSend::new(1, 98, "00000000000000077074792d726571010000000e787465726d2d323536636f6c6f72000000500000001800000000000000000000000b8000009600810000960000"),
      ClientSend::new(2, 98, "00000000000000057368656c6c01"),
      ClientSend::new(3, 94, "000000000000000f6b696c6c202d5445524d2024240d0a"),
    ],
    [
      Packet::new(90, "0000000773657373696f6e000000000020000000008000", -1, 0, -1, 23),
      Packet::new(98, "00000000000000077074792d726571010000000e787465726d2d323536636f6c6f72000000500000001800000000000000000000000b8000009600810000960000", -1, 0, -1, 65),
      Packet::new(98, "00000000000000057368656c6c01", -1, 0, -1, 14),
      Packet::new(94, "000000000000000f6b696c6c202d5445524d2024240d0a", -1, 0, -1, 23),
      Packet::new(97, "00000000", -1, 0, -1, 4),
    ],
    Stream::new("5465726d696e617465640d0a", -1, 12),
    Stream::new("", -1, 0),
    255,
    "TERM",
    2,
    0,
    0,
    2097140,
  ),
  ShellCase::new(
    "shell_nonzero_ids",
    3,
    7,
    [
      Packet::new(91, "00000003000000070020000000008000", -1, 0, -1, 16),
      Packet::new(99, "00000003", -1, 0, -1, 4),
      Packet::new(99, "00000003", -1, 0, -1, 4),
      Packet::new(94, "0000000300000003780d0a", -1, 0, -1, 11),
      Packet::new(98, "000000030000000b657869742d7374617475730000000000", -1, 0, -1, 24),
      Packet::new(96, "00000003", -1, 0, -1, 4),
      Packet::new(97, "00000003", -1, 0, -1, 4),
    ],
    [
      ClientSend::new(0, 90, "0000000773657373696f6e000000030020000000008000"),
      ClientSend::new(1, 98, "00000003000000077074792d7265710100000005787465726d000000640000002800000000000000000000000b8000009600810000960000"),
      ClientSend::new(2, 98, "00000003000000057368656c6c01"),
      ClientSend::new(3, 94, "0000000300000003780d0a"),
    ],
    [
      Packet::new(90, "0000000773657373696f6e000000030020000000008000", -1, 0, -1, 23),
      Packet::new(98, "00000003000000077074792d7265710100000005787465726d000000640000002800000000000000000000000b8000009600810000960000", -1, 0, -1, 56),
      Packet::new(98, "00000003000000057368656c6c01", -1, 0, -1, 14),
      Packet::new(94, "0000000300000003780d0a", -1, 0, -1, 11),
      Packet::new(97, "00000007", -1, 0, -1, 4),
    ],
    Stream::new("780d0a", -1, 3),
    Stream::new("", -1, 0),
    0,
    "",
    2,
    0,
    0,
    2097149,
  ),
  ShellCase::new(
    "shell_bulk_banner",
    0,
    0,
    [
      Packet::new(91, "00000000000000000020000000008000", -1, 0, -1, 16),
      Packet::new(99, "00000000", -1, 0, -1, 4),
      Packet::new(99, "00000000", -1, 0, -1, 4),
      Packet::new(94, "", 27, 1048584, -1, 1048592),
      Packet::new(98, "000000000000000b657869742d7374617475730000000000", -1, 0, -1, 24),
      Packet::new(96, "00000000", -1, 0, -1, 4),
      Packet::new(97, "00000000", -1, 0, -1, 4),
    ],
    [
      ClientSend::new(0, 90, "0000000773657373696f6e000000000020000000008000"),
      ClientSend::new(1, 98, "00000000000000077074792d726571010000000e787465726d2d323536636f6c6f72000000500000001800000000000000000000000b8000009600810000960000"),
      ClientSend::new(2, 98, "00000000000000057368656c6c01"),
    ],
    [
      Packet::new(90, "0000000773657373696f6e000000000020000000008000", -1, 0, -1, 23),
      Packet::new(98, "00000000000000077074792d726571010000000e787465726d2d323536636f6c6f72000000500000001800000000000000000000000b8000009600810000960000", -1, 0, -1, 65),
      Packet::new(98, "00000000000000057368656c6c01", -1, 0, -1, 14),
      Packet::new(93, "0000000000100008", -1, 0, -1, 8),
      Packet::new(97, "00000000", -1, 0, -1, 4),
    ],
    Stream::new("", 27, 1048584),
    Stream::new("", -1, 0),
    0,
    "",
    2,
    0,
    1,
    2097152,
  ),
]
