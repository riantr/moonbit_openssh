///| src/bpacket 的白盒单测
///
/// 之前这个包里只有一个 `bpacket_test.mbt`,里面是辅助函数而没有
/// `test {}` 声明。更糟的是调用方式也错了:`moon test -p src/bpacket` 在
/// 这个 moon 版本上把 `-p` 当成别的选项,于是报 **0 tests**;而
/// `host/verify_loop33.mjs` 那条检查恰好写成 `passed === total &&
/// failed === '0'`,0/0 一路绿灯。正确写法是 `moon test src/bpacket`
/// (PATH,不是 -p),它立刻报出了 13 个 sha256 测试——也就是说这层回归
/// 当时根本没被跑到。
///
/// 这里补的是真正会红的那几条:初始 KEX 标志的生命周期,以及 seqnr 回绕
/// 在「初始 KEX 期间」和「之后」两种状态下的不同后果——后者正是
/// `kex.c:567` 清 `KEX_INITIAL` 所换来的。

///|
/// 造一个初始 KEX 期间、序号停在 2^32-1 的发送上下文
///
/// 下一次 bump 就会回绕到 0,正好落在 packet.c:1363-1367 的检查上。
fn send_ctx_before_wrap() -> SendCtx {
  SendCtx::make(Unencrypted, 0xFFFFFFFFU, false, true)
}

///|
/// 同上,接收方向
fn recv_ctx_before_wrap() -> RecvCtx {
  RecvCtx::make(Unencrypted, 0xFFFFFFFFU, false, true)
}

///|
fn empty_pad() -> FixedArray[Byte] {
  FixedArray::make(16, b'\x00')
}

///|
/// 造一帧合法的明文包,用来把 RecvCtx 一路送到序号推进那一步
///
/// recv 侧的回绕检查在**包完全解析之后**才发生(packet.c:1778-1788 在
/// padlen/type 解析之前,长度/对齐/MAC 更靠前),所以随手喂 16 个零字节只会
/// 得到 `BadLength(0)` —— 那条路径根本到不了被测的分支。发送侧刻意关掉
/// initial_kex,否则它自己先死在 SeqnrWrapFatal 上。
fn valid_frame() -> FixedArray[Byte] {
  let s = SendCtx::make(Unencrypted, 0xFFFFFFFFU, false, false)
  match s.emit(b'\x0a', FixedArray::from_array([b'h', b'i']), empty_pad()) {
    Ok(pkt) => pkt.wire
    SeqnrWrapFatal => abort("unreachable: initial_kex is off")
  }
}

///|
test "initial_kex 默认为 true(两端都是)" {
  assert_true(SendCtx::new().in_initial_kex())
  assert_true(RecvCtx::new().in_initial_kex())
}

///|
test "end_initial_kex 清掉标志(两端都是)" {
  let s = SendCtx::new()
  let r = RecvCtx::new()
  s.end_initial_kex()
  r.end_initial_kex()
  assert_false(s.in_initial_kex())
  assert_false(r.in_initial_kex())
}

///|
test "初始 KEX 期间 send 侧 seqnr 回绕必须致命" {
  assert_true(
    send_ctx_before_wrap().emit(
      b'\x0a',
      FixedArray::make(0, b'\x00'),
      empty_pad(),
    )
    is SeqnrWrapFatal,
  )
}

///|
test "初始 KEX 期间 recv 侧 seqnr 回绕必须致命" {
  let r = recv_ctx_before_wrap()
  assert_true(r.recv(valid_frame()).event is Failed(SeqnrWrapInitial))
}

///|
test "end_initial_kex 之后 send 侧回绕被允许且 seqnr 归零" {
  let s = send_ctx_before_wrap()
  s.end_initial_kex()
  assert_true(
    s.emit(b'\x0a', FixedArray::make(0, b'\x00'), empty_pad()) is Ok(_),
  )
  assert_eq(s.seqnr(), 0U)
}

///|
test "end_initial_kex 之后 recv 侧回绕不再致命" {
  // packet.c:1363-1367 的致命条件里带着 KEX_INITIAL;清掉之后回绕只是
  // 正常地归零,这正是 kex.c:567 那一步买来的东西。同一帧在初始 KEX 下是
  // SeqnrWrapInitial,清掉标志后必须变成一个正常解出来的包。
  let r = recv_ctx_before_wrap()
  r.end_initial_kex()
  let ev = r.recv(valid_frame()).event
  match ev {
    // 落到别的分支(这里只可能是长度/对齐/格式)才是对的;包本身是合法的,
    // 所以它**必须**被解出来。
    Packet(_, t, _) => assert_eq(t, b'\x0a')
    _ => panic()
  }
  assert_eq(r.seqnr(), 0U)
}

///|
test "end_initial_kex 幂等" {
  let s = SendCtx::new()
  s.end_initial_kex()
  s.end_initial_kex()
  assert_false(s.in_initial_kex())
  let r = RecvCtx::new()
  r.end_initial_kex()
  r.end_initial_kex()
  assert_false(r.in_initial_kex())
}

///|
test "严格模式下 end_initial_kex 不动 seqnr" {
  // 与 strict-kex 的 seqnr 归零是两件不同的事:一个清 KEX_INITIAL,一个把
  // 序号打回 0(packet.c:1376-1379)。混在一起会让「为什么不重置」这个问题
  // 没法单独回答。
  let s = SendCtx::make(Unencrypted, 7U, true, true)
  s.end_initial_kex()
  assert_eq(s.seqnr(), 7U)
  assert_false(s.in_initial_kex())
}
