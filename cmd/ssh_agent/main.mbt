///| cmd/ssh_agent -- Loop #89: an SSH agent of our own.
///
///     ssh_agent [--socket <pipe>] [--key <file> ...]
///
/// 这个进程**持有密钥**,并且回答关于它们的请求。客户端是
/// `ssh-add`,以及任何会走 agent 认证的 SSH 客户端。
///
/// 它和 OpenSSH 的 agent 有同一个协议,但**不是同一个东西**:
/// OpenSSH 的 agent 在 Windows 上是一个**服务**(`ssh-agent.exe` 说
/// 「unable to start ssh-agent service」),而这里是一个普通的进程。
/// 这一点很重要:一个服务是这台机器上的东西,一个进程是可以随手起的,
/// 测完就关掉的。
///
/// ## 管道,不是套接字
///
/// `SSH_AUTH_SOCK` 在这台机器上指的是一个**命名管道**
/// (`\\.\pipe\...`)。真实的 `ssh-add` 拒绝一个 TCP 地址,连都不连:
///
///     $ SSH_AUTH_SOCK=127.0.0.1:1234 ssh-add -l
///     Error connecting to agent: No such file or directory
///
/// 所以 agent 的传输是 `src/agentpipe` 里的命名管道,不是 `src/tcp`。
///
/// ## 一把钥匙一把钥匙地加
///
/// 密钥**不进磁盘**。agent 起来的时候是空的,用 `-a` 加进去,或者
/// 用 `ssh-add` 加。进程退出,钥匙就没了——这和 OpenSSH 的 agent
/// 在同一台机器上的行为一致(它的钥匙在注册表里,但那是这台机器的
/// 这一个用户,不是一张可以带走的卡)。
///
/// ## 一次一个客户端
///
/// 命名管道的一个句柄一次只服务一个客户端。这个 agent 一次服务一个,
/// 而够用:`ssh-add` 发一条请求、读一条回答、然后关掉。

///|
/// 默认的管道名。
///
/// 它在 OpenSSH 的命名家族里(`openssh-ssh-agent` 开头),这样一个
/// 指着 `SSH_AUTH_SOCK` 的脚本不用改就知道自己连的是哪一类东西。
const DEFAULT_SOCKET : String = "\\\\.\\pipe\\openssh-ssh-agent-moonbit"

///|
/// 主函数。
///
/// ## 为什么没有短选项
///
/// **每一个 OpenSSH `ssh-agent` 的短选项都已经有别的意思了**,而我们
/// 这个程序和它叫同一个名字:
///
///   * `ssh-agent -s` 是「按 sh 的语法打印环境变量」,不是一个套接字;
///   * `ssh-agent -a` 是「绑到这个地址上」,不是一个密钥文件;
///   * `ssh-agent -D` 是「留在前台」,`-d` 是「调试」,`-k` 是「杀掉」。
///
/// 一个和它继承的名字用同一个字母、却表示别的东西的工具,**是在对自己
/// 的接口说谎**:`ssh-agent -s \\.\pipe\x` 在真实工具里是一句语法错误,
/// 在这里却会启动一个 agent。所以这里只有长选项,而长选项没有历史包袱。
///
/// 客户端那边**没有**这个选项:**`SSH_AUTH_SOCK` 就是客户端找 agent 的
/// 方式**,真实的 `ssh-add` 只认它。
async fn main {
  let argv = @env.args()
  let mut socket = DEFAULT_SOCKET
  let key_files : Array[String] = []
  let mut i = 1
  while i < argv.length() {
    let a = argv[i]
    if a == "--socket" || a == "--key" {
      // **缺参数和「不认识这个参数」是两件事。**  `--socket` 落在末尾
      // 的时候,工具知道用户想说什么,只是没说完——说「unexpected
      // argument」会把责任推给一个其实说对了的词。
      if i + 1 >= argv.length() {
        eprintln("ssh_agent: " + a + " requires an argument")
        eprintln("usage: ssh_agent [--socket <pipe>] [--key <file> ...]")
        @env.exit(1)
      }
      i = i + 1
      if a == "--socket" {
        socket = argv[i]
      } else {
        key_files.push(argv[i])
      }
    } else if a == "--help" {
      println("usage: ssh_agent [--socket <pipe>] [--key <file> ...]")
      return
    } else {
      // **短选项不是一个可以忽略的东西。**  一个认识 `-a` 却把它当成
      // 别的东西的工具,和一个认识 `-a` 却把它当垃圾扔掉的工具,都是
      // 在骗人——所以这里说清楚「这个字母属于别的意义」。
      if a.has_prefix("-") && !a.has_prefix("--") {
        eprintln(
          "ssh_agent: no short options: every ssh-agent short option already means something else",
        )
      } else {
        eprintln("ssh_agent: unexpected argument: " + a)
      }
      eprintln("usage: ssh_agent [--socket <pipe>] [--key <file> ...]")
      @env.exit(1)
    }
    i = i + 1
  }
  let store = @agentserver.AgentStore::new()
  for f in key_files {
    match load_key(f) {
      None => {
        eprintln("ssh_agent: cannot load " + f)
        @env.exit(1)
      }
      Some(key) => {
        if !@agentserver.key_is_consistent(key) {
          eprintln("ssh_agent: " + f + " does not hold a matching key pair")
          @env.exit(1)
        }
        if !store.add(key) {
          eprintln("ssh_agent: " + f + " is already in the agent")
          @env.exit(1)
        }
      }
    }
  }
  let pipe = match @agentpipe.agent_pipe_server_create(socket) {
    None => {
      eprintln("ssh_agent: cannot create the pipe " + socket)
      @env.exit(1)
    }
    Some(p) => p
  }
  // Unix 的 agent 把它自己的地址告诉 shell,Windows 上的 agent 是
  // 一个服务,客户端从注册表里找它。这里把地址打印出来,和 Unix 的
  // 做法一样:客户端需要知道往哪儿连。
  println("SSH_AUTH_SOCK=" + socket + "; export SSH_AUTH_SOCK;")
  serve(pipe, store)
}

///|
/// 一直服务下去。
///
/// 每个客户端:等它连上,读一条请求、答一条,直到它关掉为止。
///
/// **管道不属于任何一个连接。**  一个客户端走了,管道还在——下一个
/// 客户端还要用它。`agent_pipe_server_accept` 会先把上一个客户端断开
/// 再等下一个,所以这里**不能**在每个客户端之后把管道关掉:关掉的是
/// 句柄,句柄没了,管道就没了,而下一个客户端连的是一个不存在的管道,
/// 报出来的是「No such file or directory」——**一句和真实原因无关的话**。
fn serve(pipe : @agentpipe.AgentPipe, store : @agentserver.AgentStore) -> Unit {
  while true {
    if !@agentpipe.agent_pipe_server_accept(pipe) {
      break
    }
    let chan = channel_of(pipe)
    serve_one(chan, store)
  }
  pipe.close()
}

///|
/// 服务一个客户端,直到它断开。
fn serve_one(
  chan : @agent.AgentChannel,
  store : @agentserver.AgentStore,
) -> Unit {
  while true {
    let msg = match @agent.agent_read_message(chan) {
      None => return
      Some(m) => m
    }
    let (reply_type, reply_payload) = @agentserver.agent_server_handle(
      store,
      msg.0,
      msg.1,
    )
    if !(chan.write)(@agent.agent_frame(reply_type, reply_payload)) {
      return
    }
  }
}

///|
/// 把管道包成 agent 通道。
///
/// **这一层包装是驱动的事,不是协议的事**:`src/agent` 只认这三个闭包,
/// 它不知道命名管道是什么。这正是它能在命名管道、TCP 和内存缓冲上
/// 复用的原因。
fn channel_of(pipe : @agentpipe.AgentPipe) -> @agent.AgentChannel {
  {
    write: fn(d) { pipe.write(d) },
    read_exact: fn(n) { pipe.read_exact(n) },
    close: fn() { pipe.close() },
  }
}

///|
/// 读一把私钥文件,变成 agent 持有的那把钥匙。
///
/// 私钥文件的格式是 `src/keyfile` 的事情:那个包知道怎么解口令、
/// 怎么把公钥 blob 和私钥 blob 拆出来。这个驱动只负责把它们摆好。
async fn load_key(path : String) -> @agentserver.AgentKey? {
  if !@fs.exists(path) {
    return None
  }
  let data = @fs.read_file(path) catch { _ => return None }
  let text = data.text()
  match @keyfile.parse_private_file(text) {
    @keyfile.Ed25519(pair, comment) => {
      // 私钥 blob 的形状是 `u32 64` + 64 字节 = seed || 公钥,
      // 和 OpenSSH 写进 ADD_IDENTITY 的是同一形状(实测)。
      let sk = pair.sk
      let blob : FixedArray[Byte] = FixedArray::make(4 + 64, b'\x00')
      blob[0] = 0
      blob[1] = 0
      blob[2] = 0
      blob[3] = 64
      for k = 0; k < 64; k = k + 1 {
        blob[4 + k] = sk[k]
      }
      Some(@agentserver.AgentKey::{
        key_blob: @keyfile.ed25519_public_blob(pair.pk),
        private_blob: blob,
        comment,
      })
    }
    _ => None
  }
}
