///| cmd/ssh_keyscan -- Loop #82: ssh-keyscan, the host key without authenticating.
///

///|
///     ssh_keyscan [-p port] [-t type] host [host ...]
///
/// 打印的是 known_hosts 行,和 OpenSSH 自己的 ssh-keyscan **一字不差**:
///
///     [127.0.0.1]:22302 ssh-rsa AAAA...
///     [127.0.0.1]:22302 ecdsa-sha2-nistp256 AAAA...
///     [127.0.0.1]:22302 ssh-ed25519 AAAA...
///
/// ## 它和普通客户端最要紧的差别:不认证
///
/// 这个工具**只做 KEX**。拿到主机密钥就断开,一个字节的凭据都不递出去。
/// OpenSSH 的 ssh-keyscan 也是这样(`ssh-keyscan.c` 的 `keygrab_ssh2`:
/// 「do the key-exchange until an error occurs or until the
/// key_print_wrapper() callback sets c_done」)。
///
/// 用途决定了这个性质:这个工具的用途是「在还没决定信不信这台主机之前,先看看
/// 它有什么密钥」。一次认证尝试会把用户凭据递出去,而那正是这个工具要避免的。
///
/// 门禁不靠「客户端没报错」来证明这一点,而是靠**服务端自己的日志**:扫描连接
/// 在服务端那边一条 userauth 记录都不该有。
///
/// ## 一条连接扫一种密钥类型
///
/// 一次握手只协商出**一把**主机密钥,所以要拿到服务端的几把密钥,得几种类型
/// 各连一次。OpenSSH 的 ssh-keyscan 就是这么做的(`keygrab_ssh2` 里那几段
/// `myproposal[PROPOSAL_SERVER_HOST_KEY_ALGS] = ...`),本客户端照做。
///
/// 输出行的**顺序**也跟着 OpenSSH 的类型顺序走(RSA、ECDSA、Ed25519——那正是
/// `ssh-keyscan.c` 里 `KT_MIN..KT_MAX` 的顺序)。

///|
/// 一次扫描要提议的主机密钥算法
struct ScanType {
  /// 用户写的短名(rsa / ecdsa / ed25519)
  name : String
  /// 这一类连接在 KEXINIT 里写的主机密钥算法列表
  algs : String
}

///|
/// 默认扫的三种类型,顺序和 OpenSSH 一样。
///
/// OpenSSH 10.4 的默认集合还包含 FIDO(sk-ecdsa / sk-ed25519)和 ML-DSA。
/// 本客户端不扫它们:这两种算法**验不了**,一把验不了的密钥写进 known_hosts
/// 是有害的——那会让人以为这把钥匙是被验过的。少了它们,输出行不变(服务端
/// 没有那两种密钥,OpenSSH 扫它们也只会得到一个失败)。
///
/// 每一类里少了的名字也写在 `type_algs` 里:少一个名字的后果是「服务端**只有**
/// 那把密钥时,OpenSSH 扫得到、本客户端扫不到」,其余情况完全一样。
fn default_types() -> Array[ScanType] {
  [
    ScanType::{ name: "rsa", algs: "rsa-sha2-512,rsa-sha2-256", },
    ScanType::{
      name: "ecdsa",
      algs: "ecdsa-sha2-nistp256,ecdsa-sha2-nistp384",
    },
    ScanType::{ name: "ed25519", algs: "ssh-ed25519", },
  ]
}

///|
/// 短名 -> 这一类连接要提议的主机密钥算法。
///
/// 每一类都和 OpenSSH 的列表对齐,只少掉本客户端**验不了**的名字:
///
///   * RSA:OpenSSH 还提议 `ssh-rsa`(SHA-1)。本客户端没有 SHA-1。
///   * ECDSA:OpenSSH 还提议 `ecdsa-sha2-nistp521`。本客户端没有 P-521。
///
/// 少掉的名字都是**排在后面**的,所以服务端挑中的那把钥匙在两边是同一把。
fn type_algs(name : String) -> String? {
  if name == "rsa" {
    Some("rsa-sha2-512,rsa-sha2-256")
  } else if name == "ecdsa" {
    Some("ecdsa-sha2-nistp256,ecdsa-sha2-nistp384")
  } else if name == "ed25519" {
    Some("ssh-ed25519")
  } else {
    None
  }
}

///|
/// DH 私有指数。
///
/// 真正的客户端从 CSPRNG 取,每次连接都不一样。这里固定成一个常量,是为了
/// 让字节级对拍有意义——和 `cmd/ssh_live` 用的是同一个理由、同一个值。
fn fixed_x() -> @bigint.BigNat {
  let bytes : FixedArray[Byte] = FixedArray::from_array([
    0x5A, 0x17, 0xC3, 0x9E, 0x44, 0xB2, 0x6D, 0xF1, 0x08, 0xA7, 0x35, 0xCC, 0x91,
    0x2E, 0x60, 0xD3, 0x74, 0x18, 0x9F, 0xE2, 0x50, 0xB7, 0xC6, 0x3D, 0x81, 0x0A,
    0xF5, 0x29, 0x64, 0xC8, 0x7B, 0x1E,
  ])
  @bigint.BigNat::from_bytes_be(bytes)
}

///|
/// 扫一个主机的一种类型,打印它找到的密钥。
///
/// 返回这一类有没有找到密钥。
fn scan_one(host : String, port : Int32, t : ScanType) -> Bool {
  match @tcp.TcpConn::connect(host, port) {
    None => {
      eprintln("result: CONNECT_FAILED " + host + ":" + port.to_string())
      false
    }
    Some(conn) => {
      let outcome = @sshclient.live_keyscan(
        conn,
        fixed_x(),
        @knownhosts.KnownHostsPolicy::skip(),
        t.algs,
      )
      conn.close()
      match outcome {
        @sshclient.Scanned(r) => {
          // 注释行进 stderr,和两个装了机的 OpenSSH(ssh-keyscan 8.0p1 与 9.x)
          // 实测的行为一致。10.4 的源码把它写进了 stdout——那是一次版本之间的
          // 变化,而**已装机的两个版本才是门禁要对拍的那个**。
          //
          // 注释里的主机名是**原样**的(OpenSSH 的 `conprocess` 用 `c->c_name`),
          // 小写化只作用在 known_hosts 行上(`keyprint_one`)。
          eprintln("# " + host + ":" + port.to_string() + " " + r.server_ident)
          let line = @knownhosts.KnownHostEntry::to_line(
            @knownhosts.keyscan_host_field(host, port),
            r.hostkey_type,
            r.hostkey_blob,
          )
          println(line)
          true
        }
        @sshclient.Failed(e) => {
          let why = match e {
            @sshclient.HandshakeFailed(h) => live_error_name(h)
            @sshclient.NoHostKey => "NoHostKey"
          }
          eprintln("result: SCAN_FAILED " + t.name + " " + why)
          false
        }
      }
    }
  }
}

///|
/// 握手失败的错误名
///
/// 这一份标签住在 `src/sshclient`(`live_error_label`):两个驱动给同一个错误
/// 起同一个名字,只可能有一份实现。
fn live_error_name(e : @sshclient.LiveError) -> String {
  @sshclient.live_error_label(e)
}

///|
fn main {
  let argv = @env.args()
  let port = int_arg(argv, "-p", 22)
  let hosts : Array[String] = []
  let type_names : Array[String] = []
  let mut i = 1
  while i < argv.length() {
    if argv[i] == "-p" && i + 1 < argv.length() {
      // 端口在前面已经读过了;这一段只是把它跳过去。
      i = i + 2
      continue
    }
    if argv[i] == "-t" && i + 1 < argv.length() {
      let list = argv[i + 1]
      for part in list.split(",") {
        type_names.push(part.to_owned())
      }
      i = i + 2
      continue
    }
    if argv[i].has_prefix("-") {
      eprintln("result: BAD_USAGE")
      eprintln("usage: ssh_keyscan [-p port] [-t type] host [host ...]")
      return
    }
    hosts.push(argv[i])
    i = i + 1
  }
  if hosts.length() == 0 {
    eprintln("result: BAD_USAGE")
    eprintln("usage: ssh_keyscan [-p port] [-t type] host [host ...]")
    return
  }
  // 类型:给了 `-t` 就用给的,没给就扫默认的三种。
  let types : Array[ScanType] = []
  if type_names.length() == 0 {
    for t in default_types() {
      types.push(t)
    }
  } else {
    for name in type_names {
      match type_algs(name) {
        None => {
          eprintln("result: UNKNOWN_KEY_TYPE " + name)
          return
        }
        Some(algs) => types.push(ScanType::{ name, algs, })
      }
    }
  }
  // 一个类型都没扫到密钥要**说出来**——静默地什么都不打,和「扫到了但没打印」
  // 长得一模一样(OpenSSH 的 `found_one ? 0 : 1` 就是这个区别)。
  let mut found = false
  for host in hosts {
    for t in types {
      if scan_one(host, port, t) {
        found = true
      }
    }
  }
  if !found {
    eprintln("result: NO_KEYS")
  }
}

///|
/// 读一个整型参数
fn int_arg(argv : Array[String], flag : String, fallback : Int32) -> Int32 {
  let mut i = 1
  while i < argv.length() {
    if argv[i] == flag && i + 1 < argv.length() {
      let text = argv[i + 1]
      let v = parse_int(text)
      if v >= 0 {
        return v
      }
      eprintln("result: BAD_PORT " + text)
      return fallback
    }
    i = i + 1
  }
  fallback
}

///|
/// 十进制字符串转整数,认不出来返回 -1
fn parse_int(text : String) -> Int32 {
  if text.length() == 0 {
    return -1
  }
  let mut value = 0
  let mut i = 0
  while i < text.length() {
    let c = text[i].to_int()
    if c < 48 || c > 57 {
      return -1
    }
    value = value * 10 + (c - 48)
    i = i + 1
  }
  value
}
