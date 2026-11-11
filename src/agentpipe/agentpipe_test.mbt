///|
/// Loop #89: the named pipe transport, tested.
///
/// This is the layer that talks to the Windows API.  Everything above it
/// -- the protocol, the server, the driver -- is plain MoonBit, and plain
/// MoonBit is tested by the unit tests.  **This layer is not**, and it is
/// the layer where a mistake turns into a hang: a pipe that is created in
/// MESSAGE mode instead of BYTE mode delivers the bytes in pieces, and a
/// reader that assumes a whole message arrives blocks forever.
///
/// **The round trip is NOT here, and that is a fact about the platform
/// rather than a gap in the tests.**  A named pipe's client BLOCKS in
/// `CreateFile` until the server calls `ConnectNamedPipe`, and the server
/// BLOCKS in `ConnectNamedPipe` until a client connects.  So the two ends
/// have to be in different threads -- and MoonBit's `async` is a
/// single-threaded cooperative scheduler, so a blocking C call in it
/// blocks the whole program:
///
///     client: CreateFile   -> waits for the server's ConnectNamedPipe
///     server: ConnectNamedPipe -> waits for a client
///
/// One process cannot do both.  **The round trip is tested where it can
/// be: in the gate**, which runs the agent and the client as two
/// processes -- which is how the real tools use it anyway.
///
/// So the tests here are about the parts that a single process CAN check,
/// and those are exactly the parts where a wrong answer is a hang:
///
///   * a pipe that does not exist is "not there" at once, not a wait;
///   * a name that is taken is taken, and the second agent says so;
///   * a closed pipe writes nothing and reads nothing.
///
/// **These tests are native only.**  A named pipe is a Windows thing; the
/// js and wasm targets have no way to make one, and their stub is tested
/// in `agentpipe_stub_test.mbt`.

///|
/// 一个还没有人用的管道。
///
/// **名字必须是新的,而这件事是管道自己保证的**:创建的时候带了
/// `FILE_FLAG_FIRST_PIPE_INSTANCE`,所以一个已经有人在用的名字**建不
/// 出来**——第二个 agent 会得到「名字被占了」,而不是悄悄地做出第二个
/// 实例、然后和第一个分掉各自的客户端。
///
/// 所以这里一个名字一个名字地试,直到有一个建得出来。**这不只是为了
/// 好看**:两个进程同时跑这一组测试是可能的(一个在门禁里,一个在本地
/// 的回归里),而一个会撞到另一个的管道名的测试会以一种和代码毫无关系
/// 的方式红掉。
fn a_fresh_pipe(tag : String) -> (@agentpipe.AgentPipe, String) {
  let mut n = 0
  while n < 64 {
    let name = "\\\\.\\pipe\\openssh-moonbit-test-" + tag + "-" + n.to_string()
    match @agentpipe.agent_pipe_server_create(name) {
      Some(p) => return (p, name)
      None => n = n + 1
    }
  }
  abort("no free pipe name")
}

///|
/// 一个没有客户端的管道,连上去是「没有」,不是「卡住」。
///
/// **这一条是真实工具的句子背后的那件事。**  没有 agent 的时候,真实
/// 的 `ssh-add` 说 `Error connecting to agent: No such file or directory`
/// 并且退出码是 2——它**没有**去等一个不会来的 agent。
///
/// **一个会等一个不会来的东西的工具就是一个挂着的工具**,而一个挂着
/// 的工具在脚本里看起来和一个慢的工具一模一样。
test "connecting to a pipe that is not there fails at once" {
  let name = "\\\\.\\pipe\\openssh-moonbit-test-there-is-no-such-pipe"
  assert_true(@agentpipe.agent_pipe_connect(name) is None)
}

///|
/// 一个名字只能被一个 agent 用。
///
/// **这是 `FILE_FLAG_FIRST_PIPE_INSTANCE` 的直接后果**,而它是一件该有
/// 明确说法的事:第二个 agent 拿同一个名字,应该**失败**,而不是做出
/// 第二个实例、然后和第一个分掉各自的客户端。
///
/// 一个 agent 拿着两个名字去服务两个客户端,每一个客户端连到哪一个
/// agent 是不确定的——所以「一个名字一个 agent」不是洁癖,是正确性。
test "a name can only be used by one agent" {
  let (first, name) = a_fresh_pipe("exclusive")
  // 第二个 agent 拿同一个名字:失败。
  assert_true(@agentpipe.agent_pipe_server_create(name) is None)
  first.close()
}

///|
/// 关掉的管道不能再写,再读也没有东西。
///
/// **读一个已经关掉的管道返回 None,而不是空数组。** 这两件事对调用
/// 方是不同的:None 是「管道没了」,空数组是「管道还在,现在没有
/// 字节」。
test "a closed pipe writes nothing and reads nothing" {
  let (server, _) = a_fresh_pipe("closed")
  server.close()
  // 写:失败。
  assert_false(server.write(FixedArray::from_array([1, 2, 3])))
  // 读:没有。
  assert_true(server.read_exact(3) is None)
  assert_eq(server.read_some(3).length(), 0)
}

///|
/// 写一个空的缓冲区是成功的——**没有字节要写**,不是写失败了。
///
/// 这一点在协议里是常见的:空载荷的消息(`REQUEST_IDENTITIES`、
/// `REMOVE_ALL_IDENTITIES`)就是用零字节的载荷发出去的,而一个把
/// 「零字节」当成「失败」的写函数会把那些消息变成失败。
test "writing nothing succeeds" {
  let (server, _) = a_fresh_pipe("empty-write")
  assert_true(server.write(FixedArray::make(0, b'\x00')))
  server.close()
}

///|
/// 关两次不是错误。
///
/// 句柄是 Windows 的 HANDLE,关两次就是对同一个句柄关两次——而
/// 句柄可能已经被回收,拿它去关一次别的资源是**真的**坏事。所以
/// 「已经关了」这个状态是记着的。
test "closing twice is not an error" {
  let (server, _) = a_fresh_pipe("double-close")
  server.close()
  server.close()
}
