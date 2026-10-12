///| GENERATED FILE -- do not edit by hand.
///
/// Regenerate: python host/gen_fault_vectors.py <oracle.json> <out.mbt>
///
/// Every inbound payload and every expected request below comes from
/// `host/sftp_fault_oracle.py`, which is an independent implementation
/// written from the SFTP v3 draft and OpenSSH's error branches with no
/// reference to `src/sftp`.  The oracle refuses to emit this file unless its
/// own run of each scenario agrees with the hand-written expectation, so a
/// scenario cannot silently become "whatever the implementation does".
///
/// Four copies of this table are generated from that one JSON, and they must
/// stay identical -- same scenarios, same expectations -- so that a difference
/// between two layers is a transport bug and not two different test sets:
///
///   cmd/proton_gui/fault_vectors.mbt  fed straight to `SftpSession`
///   cmd/sftp_fault/vectors.mbt        re-sliced through the channel layer
///   cmd/sftp_mitm/vectors.mbt         over a real socket, behind a MITM
///   cmd/wt_ssh/fault_vectors.mbt      in a browser Worker, over WebSocket

pub(all) struct Op {
  /// 0 realpath, 1 stat, 4 writefile, 9 rename
  kind : Int
  path : String
  ///| the rename target, or the hex payload of a writefile
  arg : String
}

pub(all) struct FaultCase {
  name : String
  intent : String
  ops : Array[Op]
  ///| inbound CHANNEL_DATA payloads, as hex
  feeds : Array[String]
  ///| the requests we must emit, as hex
  requests : Array[String]
  ///| one rendered line per result, the way `cmd/sftp_test` renders them
  results : Array[String]
  expect_done : Bool
  expect_failed : Bool
  expect_reason : String
  ///| CHANNEL_DATA cut points the channel-layer driver must reproduce this
  ///| case at. Re-slicing the inbound stream must not change the answer --
  ///| that is the invariant `src/sftp/stream.mbt` exists to hold.
  chop_sizes : Array[Int]
}

pub let fault_cases : Array[FaultCase] = [
  {
    name: "status_before_version",
    intent: "A STATUS arriving before VERSION must be ignored, not fatal.",
    ops: [{ kind: 0, path: ".", arg: "" }],
    feeds: ["0000001a65000000010000000200000009746f6f206561726c7900000000", "000000050200000003", "000000216800000001000000010000000c2f433a2f55736572732f68700000000000000000"],
    requests: ["000000050100000003", "0000000a1000000001000000012e"],
    results: ["realpath=2f433a2f55736572732f6870"],
    expect_done: true,
    expect_failed: false,
    expect_reason: "",
    chop_sizes: [1, 3, 7, 64],
  },
  {
    name: "wrong_request_id",
    intent: "A reply to an abandoned request is dropped, and the session stays usable.",
    ops: [{ kind: 0, path: ".", arg: "" }],
    feeds: ["000000050200000003", "00000019650000006300000004000000086e6f74206d696e6500000000", "00000016680000000100000001000000012f0000000000000000"],
    requests: ["000000050100000003", "0000000a1000000001000000012e"],
    results: ["realpath=2f"],
    expect_done: true,
    expect_failed: false,
    expect_reason: "",
    chop_sizes: [1, 3, 7, 64],
  },
  {
    name: "malformed_write_reply",
    intent: "DATA where a WRITE expects a STATUS: reported as unexpected, and the handle is still closed.",
    ops: [{ kind: 4, path: "f.txt", arg: "cafe" }],
    feeds: ["000000050200000003", "0000000a66000000010000000168", "0000000b670000000200000002aabb", "000000116500000003000000000000000000000000"],
    requests: ["000000050100000003", "00000016030000000100000005662e7478740000001a00000000", "0000001806000000020000000168000000000000000000000002cafe", "0000000a04000000030000000168"],
    results: ["failed=code=-1:msg=756e65787065637465642044617461"],
    expect_done: true,
    expect_failed: false,
    expect_reason: "",
    chop_sizes: [1, 3, 7, 64],
  },
  {
    name: "write_eof_status",
    intent: "EOF as the answer to a WRITE is a failure, never a success.",
    ops: [{ kind: 4, path: "f.txt", arg: "cafe" }],
    feeds: ["000000050200000003", "0000000a66000000010000000168", "0000001465000000020000000100000003656f6600000000", "000000116500000003000000000000000000000000"],
    requests: ["000000050100000003", "00000016030000000100000005662e7478740000001a00000000", "0000001806000000020000000168000000000000000000000002cafe", "0000000a04000000030000000168"],
    results: ["failed=code=1:msg=656f66"],
    expect_done: true,
    expect_failed: false,
    expect_reason: "",
    chop_sizes: [1, 3, 7, 64],
  },
  {
    name: "ext_absent_falls_back_to_v3",
    intent: "Six extensions advertised, none of them the rename one: the RENAME that goes out must be FXP_RENAME, not FXP_EXTENDED.",
    ops: [{ kind: 9, path: "a", arg: "b" }],
    feeds: ["000000ad02000000030000001373746174766673406f70656e7373682e636f6d0000000132000000146673746174766673406f70656e7373682e636f6d000000013200000014686172646c696e6b406f70656e7373682e636f6d0000000131000000116673796e63406f70656e7373682e636f6d0000000131000000146c73657473746174406f70656e7373682e636f6d0000000131000000126c696d697473406f70656e7373682e636f6d0000000131", "000000116500000001000000000000000000000000"],
    requests: ["000000050100000003", "0000000f120000000100000001610000000162"],
    results: ["changed"],
    expect_done: true,
    expect_failed: false,
    expect_reason: "",
    chop_sizes: [1, 3, 7, 64],
  },
  {
    name: "ext_present_sends_extended",
    intent: "The rename extension named in VERSION: FXP_EXTENDED carries the name, then the two paths and nothing else.",
    ops: [{ kind: 9, path: "a", arg: "b" }],
    feeds: ["00000026020000000300000018706f7369782d72656e616d65406f70656e7373682e636f6d0000000131", "000000116500000001000000000000000000000000"],
    requests: ["000000050100000003", "0000002bc80000000100000018706f7369782d72656e616d65406f70656e7373682e636f6d00000001610000000162"],
    results: ["changed"],
    expect_done: true,
    expect_failed: false,
    expect_reason: "",
    chop_sizes: [1, 3, 7, 64],
  },
  {
    name: "ext_unknown_is_op_unsupported",
    intent: "A server that advertises the extension and then refuses it answers UNSUPPORTED; that is a result, not a dead session.",
    ops: [{ kind: 9, path: "a", arg: "b" }],
    feeds: ["00000026020000000300000018706f7369782d72656e616d65406f70656e7373682e636f6d0000000131", "00000026650000000100000008000000154f7065726174696f6e20756e737570706f7274656400000000"],
    requests: ["000000050100000003", "0000002bc80000000100000018706f7369782d72656e616d65406f70656e7373682e636f6d00000001610000000162"],
    results: ["failed=code=8:msg=4f7065726174696f6e20756e737570706f72746564"],
    expect_done: true,
    expect_failed: false,
    expect_reason: "",
    chop_sizes: [1, 3, 7, 64],
  },
  {
    name: "oversize_length_prefix",
    intent: "A length prefix above SFTP_MAX_MSG_LENGTH is refused before anything is sized from it.",
    ops: [{ kind: 0, path: ".", arg: "" }],
    feeds: ["000000050200000003", "00100000690000000100000000"],
    requests: ["000000050100000003", "0000000a1000000001000000012e"],
    results: [],
    expect_done: false,
    expect_failed: true,
    expect_reason: "framing: Unexpected",
    chop_sizes: [1, 3, 7, 64],
  },
  {
    name: "truncated_attrs",
    intent: "ATTRS claiming a size it does not carry: unparsable, and fatal, because we no longer know where we are.",
    ops: [{ kind: 1, path: "f.txt", arg: "" }],
    feeds: ["000000050200000003", "00000009690000000100000001"],
    requests: ["000000050100000003", "0000000e110000000100000005662e747874"],
    results: [],
    expect_done: false,
    expect_failed: true,
    expect_reason: "unparsable reply: Truncated",
    chop_sizes: [1, 3, 7, 64],
  },
  {
    name: "status_trailing_data",
    intent: "One byte after the language tag is enough to refuse the whole packet rather than accept the fields we happened to read.",
    ops: [{ kind: 0, path: ".", arg: "" }],
    feeds: ["000000050200000003", "00000016650000000100000004000000046e6f70650000000000"],
    requests: ["000000050100000003", "0000000a1000000001000000012e"],
    results: [],
    expect_done: false,
    expect_failed: true,
    expect_reason: "unparsable reply: TrailingData",
    chop_sizes: [1, 3, 7, 64],
  },
]
