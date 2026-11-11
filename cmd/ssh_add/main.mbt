///| cmd/ssh_add -- Loop #89: add a key to the agent, and list what is in it.
///
///     ssh_add [-l] [-L] [-d] [-D] [-q] [file ...]
///
/// **找 agent 用的是 `SSH_AUTH_SOCK`,不是一个选项。**  真实的
/// `ssh-add` 只认这个环境变量,而它的 `-s` 是**智能卡**的 PKCS#11
/// provider——所以这个工具没有 `-s`。
///
/// 这个工具和 agent 说话。它**不持有**密钥:密钥在 agent 那边,这里
/// 只是把一把钥匙递进去,或者把一份清单要出来。
///
/// ## 消息和句子都是量出来的
///
/// 真实的 `ssh-add` 是这里的判官。`.loop89/probe_add_proto.py` 是一个
/// 用 ctypes 写的桩 agent,它在命名管道上接真实的 `ssh-add`,把它发的
/// 每一个字节打印出来。于是下面这些句子和退出码都是实测的,不是照着
/// OpenSSH 的源码背的:
///
///   * 没有 agent:`Error connecting to agent: No such file or directory`
///     到 stderr,退出码 **2**。
///   * agent 拒绝:`error fetching identities: agent refused operation`
///     到 stderr,退出码 **1**。
///   * agent 里一把钥匙都没有:`The agent has no identities.` 到
///     **stdout**(不是 stderr!),退出码仍然是 1。
///   * 加一把钥匙:`Identity added: <path> (<comment>)` 到 **stderr**。
///   * 删一把钥匙:`Identity removed: <path> <TYPE> (<comment>)` 到
///     stderr。
///   * 删掉所有:`All identities removed.` 到 stderr。
///
/// ## `-l` 和 `-L` 的区别
///
/// `-l` 打印**指纹**:`<位数> <指纹> <注释> (<类型>)`,比如
/// `256 SHA256:... probe@loop89 (ED25519)`。
///
/// `-L` 打印**公钥行**:`ssh-ed25519 <base64> <注释>`。
///
/// **注释为空的时候,`-L` 有一个尾随空格。**  OpenSSH 是先打印公钥行、
/// 再打印 `" " + 注释`,所以空格是无条件的;而 `.pub` 文件那一行在
/// 注释为空时是没有尾随空格的。这两件事不一样,门禁比的就是这个。

///|
/// 主函数。
async fn main {
  let argv = @env.args()
  let mut list = false
  let mut list_public = false
  let mut delete_all = false
  let mut deleting = false
  let mut quiet = false
  let files : Array[String] = []
  let mut i = 1
  while i < argv.length() {
    let a = argv[i]
    if a == "-l" {
      list = true
    } else if a == "-L" {
      list_public = true
    } else if a == "-D" {
      delete_all = true
    } else if a == "-d" {
      deleting = true
    } else if a == "-q" {
      quiet = true
    } else if a == "-s" || a == "-e" || a == "-S" {
      // **`-s` `-e` `-S` 是 OpenSSH 的智能卡选项,不是「agent 在哪」。**
      //
      // 实测(`.loop89/probe_dash_s2.py`,对着我们自己的 agent):
      //
      //   * `ssh-add -s <provider>` **挂住**:它要一个 PIN,在终端上问,
      //     没有终端就一直等。6 秒被 kill,一个字节都没输出。
      //   * `ssh-add -s` 没有参数:`option requires an argument -- s`,
      //     而它自己的 usage 里写着 `ssh-add -s pkcs11`。
      //   * `ssh-add -e <provider>`:`Could not remove card "<path>":
      //     agent refused operation`,退出码 1。
      //
      // 所以 `-s` 的语义是 **PKCS#11 provider**,而这个仓库没有任何
      // 智能卡支持。**一个做不到的选项要说不做,而不是不声不响地
      // 换个意思**——后者会让一句 `ssh-add -s pkcs11` 变成一次成功。
      eprintln(
        "ssh_add: " +
        a +
        " is for a PKCS#11 smartcard, which this tool does not support",
      )
      @env.exit(1)
    } else if a.has_prefix("-") {
      // **剩下的还有一个区别要说清楚。**
      //
      // `-c` `-t` `-k` `-K` `-X` `-x` `-E` `-T` `-v` 都是**真实的**
      // `ssh-add` 选项(它的 usage 里就列着 `[-cDdKkLlqvXx] [-E
      // fingerprint_hash] [-t life]`),只是这个工具没有实现。对一个
      // 真实存在的选项说「unknown option」也是在对接口说谎——只不过
      // 谎小一点。所以说的是「有这个选项,这个工具没做」。
      //
      // 而**不是任何选项**的东西,仍然说 unknown。
      if is_a_real_option_this_tool_does_not_implement(a) {
        eprintln(
          "ssh_add: " +
          a +
          " is a real ssh-add option, and this tool does not implement it",
        )
        @env.exit(1)
      }
      eprintln("ssh_add: unknown option: " + a)
      eprintln("usage: ssh_add [-lLq] [-d] [-D] [file ...]")
      @env.exit(1)
    } else {
      files.push(a)
    }
    i = i + 1
  }
  // 一个动作。
  //
  // OpenSSH 的 `ssh-add` 说「Invalid combination of actions」,而且
  // 用的是 `fatal()`——所以句首有程序名,退出码是 1。
  let actions = (if list { 1 } else { 0 }) +
    (if list_public { 1 } else { 0 }) +
    (if delete_all { 1 } else { 0 })
  if actions > 1 {
    eprintln("ssh_add: Invalid combination of actions")
    @env.exit(1)
  }
  // **客户端用什么找 agent,是 `SSH_AUTH_SOCK` 说了算。**
  //
  // 真实的 `ssh-add` 只认这个环境变量:它的二进制里就写着
  // `SSH_AUTH_SOCK=\\.\pipe\openssh-ssh-agent`。所以这里**没有**
  // 一个「agent 在哪」的命令行选项——`-s` 那个字母已经被 OpenSSH
  // 用在智能卡上了(见上面),而再发明一个别的字母只是把同一个
  // 混乱换个地方。
  let sock = match @env.get_env_var("SSH_AUTH_SOCK") {
    None => {
      // 实测:没有 SSH_AUTH_SOCK 时,真实的 `ssh-add` 说的是这一句,
      // 退出码 2。
      eprintln("Error connecting to agent: No such file or directory")
      @env.exit(2)
    }
    Some(s) => s
  }
  let pipe = match @agentpipe.agent_pipe_connect(sock) {
    None => {
      eprintln("Error connecting to agent: No such file or directory")
      @env.exit(2)
    }
    Some(p) => p
  }
  let chan = channel_of(pipe)
  if list || list_public {
    list_identities(chan, list_public)
  } else if delete_all {
    delete_all_identities(chan, quiet)
  } else {
    let targets = if files.length() == 0 { default_files() } else { files }
    let mut failed = false
    for f in targets {
      if !handle_file(chan, f, deleting, quiet) {
        failed = true
      }
    }
    (chan.close)()
    if failed {
      @env.exit(1)
    }
  }
}

///|
/// 把管道包成 agent 通道。
///
/// **这一层包装是驱动的事,不是协议的事**:`src/agent` 只认这三个闭包。
fn channel_of(pipe : @agentpipe.AgentPipe) -> @agent.AgentChannel {
  {
    write: fn(d) { pipe.write(d) },
    read_exact: fn(n) { pipe.read_exact(n) },
    close: fn() { pipe.close() },
  }
}

///|
/// 列出 agent 里的身份。
///
/// `public_keys` 决定打印指纹还是打印公钥行。
///
/// **没有身份的时候,那句「The agent has no identities.」是 stdout,
/// 而且退出码是 1。**  OpenSSH 那里是一个 `printf`(ssh-add.c:544),
/// 而 `list_identities` 返回 -1 让整个进程退出 1。
///
/// **拿不到清单的时候是另一回事**:那是 stderr 上的
/// `error fetching identities: <why>`,也是退出码 1。两句都在 stderr
/// 之外的差别,是因为「agent 说它没有」和「agent 没了」是不同的事。
fn list_identities(chan : @agent.AgentChannel, public_keys : Bool) -> Unit {
  let identities = match @agent.agent_list_identities(chan) {
    None => {
      eprintln("error fetching identities: agent refused operation")
      @env.exit(1)
    }
    Some(v) => v
  }
  if identities.length() == 0 {
    println("The agent has no identities.")
    @env.exit(1)
  }
  for id in identities {
    if public_keys {
      println(@keyfile.public_line_of_blob(id.key_blob, id.comment))
    } else {
      println(
        "256 " +
        @keyfile.fingerprint_of_blob(id.key_blob) +
        " " +
        id.comment +
        " (ED25519)",
      )
    }
  }
}

///|
/// 删掉所有身份。
///
/// **成功的那句在 stderr 上。**  OpenSSH 的 `delete_all` 是
/// `fprintf(stderr, "All identities removed.\n")`。
fn delete_all_identities(chan : @agent.AgentChannel, quiet : Bool) -> Unit {
  let ok = match @agent.agent_remove_all_identities(chan) {
    None => false
    Some(v) => v
  }
  (chan.close)()
  if !ok {
    eprintln("Failed to remove all identities.")
    @env.exit(1)
  }
  if !quiet {
    eprintln("All identities removed.")
  }
}

///|
/// 处理一个文件:加进去,或者从 agent 里删掉。
async fn handle_file(
  chan : @agent.AgentChannel,
  path : String,
  deleting : Bool,
  quiet : Bool,
) -> Bool {
  let key = match load_key(path) {
    None => {
      eprintln("Could not add identity \"" + path + "\": invalid format")
      return false
    }
    Some(k) => k
  }
  if deleting {
    let ok = match @agent.agent_remove_identity(chan, key.key_blob) {
      None => false
      Some(v) => v
    }
    if !ok {
      eprintln(
        "Could not remove identity \"" + path + "\": agent refused operation",
      )
      return false
    }
    if !quiet {
      eprintln(
        "Identity removed: " +
        path +
        " " +
        key.key_type +
        " (" +
        key.comment_text +
        ")",
      )
    }
    return true
  }
  let ok = match
    @agent.agent_add_identity(
      chan,
      key.key_blob,
      key.private_blob,
      key.comment_text,
    ) {
    None => false
    Some(v) => v
  }
  if !ok {
    eprintln("Could not add identity \"" + path + "\": agent refused operation")
    return false
  }
  if !quiet {
    eprintln("Identity added: " + path + " (" + key.comment_text + ")")
  }
  true
}

///|
/// 一把从文件里读出来的钥匙。
struct LoadedKey {
  key_blob : FixedArray[Byte]
  private_blob : FixedArray[Byte]
  comment_text : String
  key_type : String
}

///|
/// 这是不是一个**真实存在的** `ssh-add` 选项,而这个工具没有实现。
///
/// 名单来自真实工具的 usage 文本(实测):
///
///     usage: ssh-add [-cDdKkLlqvXx] [-E fingerprint_hash] [-S provider]
///                    [-t life] [file ...]
///
/// 已经实现的(所以不在这里):`-l` `-L` `-d` `-D` `-q`。
/// 智能卡那一族(`-s` `-e` `-S`)有它们自己的一句,也不在这里。
///
/// **这个函数存在的理由**是把「有这个选项但我们没做」和「根本没有这个
/// 选项」分开。两件事都用一句「unknown option」回答,就是把一件关于
/// 我们自己的事实说成了一件关于用户的事实。
fn is_a_real_option_this_tool_does_not_implement(a : String) -> Bool {
  a == "-c" ||
  a == "-t" ||
  a == "-k" ||
  a == "-K" ||
  a == "-X" ||
  a == "-x" ||
  a == "-E" ||
  a == "-T" ||
  a == "-v"
}

///|
/// 读一把私钥文件。
///
/// **加密的钥匙这里读不了。**  OpenSSH 的 `ssh-add` 在终端上问口令;
/// 这个工具没有终端,而**一个等着一个不会来的答案的工具就是一个挂着的
/// 工具**,所以它拒绝,并说清是哪一个文件。
async fn load_key(path : String) -> LoadedKey? {
  if !@fs.exists(path) {
    return None
  }
  let data = @fs.read_file(path) catch { _ => return None }
  let text = data.text()
  match @keyfile.parse_private_file(text) {
    @keyfile.Ed25519(pair, comment) => {
      // 私钥 blob 的形状是 `u32 64` + 64 字节 = seed || 公钥,
      // 和 OpenSSH 写进 ADD_IDENTITY 的是同一形状(实测)。
      let blob = private_blob_of(pair)
      Some(LoadedKey::{
        key_blob: @keyfile.ed25519_public_blob(pair.pk),
        private_blob: blob,
        comment_text: comment,
        key_type: "ED25519",
      })
    }
    @keyfile.Unsupported(_) => None
    _ => None
  }
}

///|
/// 私钥 blob:`u32 64` + 64 字节。
fn private_blob_of(pair : @keyfile.Ed25519KeyPair) -> FixedArray[Byte] {
  let blob : FixedArray[Byte] = FixedArray::make(4 + 64, b'\x00')
  blob[0] = 0
  blob[1] = 0
  blob[2] = 0
  blob[3] = 64
  for k = 0; k < 64; k = k + 1 {
    blob[4 + k] = pair.sk[k]
  }
  blob
}

///|
/// 没有给文件时的默认文件。
///
/// OpenSSH 试的是一串默认名字(`readconf.c` 的 `default_files`):
/// `id_rsa`、`id_dsa`、`id_ecdsa`、`id_ed25519`……
///
/// **这个仓库只有 ed25519**,所以只有 `id_ed25519` 一个候选。少了的那些
/// 不会让结果不一样:这个仓库根本读不了 RSA 和 DSA 的私钥文件。
async fn default_files() -> Array[String] {
  let home = match @env.get_env_var("HOME") {
    None =>
      match @env.get_env_var("USERPROFILE") {
        None => return []
        Some(h) => h
      }
    Some(h) => h
  }
  let path = home + "/.ssh/id_ed25519"
  if @fs.exists(path) {
    [path]
  } else {
    []
  }
}
