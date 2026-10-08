///| cmd/wt_ssh -- Loop #32 G3: SSH transport handshake inside a browser.

///|

///|   Runs the same protocol as cmd/ssh_live, but over a browser transport

///|   (WebTransport or WebSocket, chosen by the URL the Worker passes in) and

///|   inside a Web Worker. `result: ESTABLISHED` means a real OpenSSH server

///|   accepted the handshake, our client computed the same exchange hash it

///|   did, and it signed that hash with an ECDSA P-256 host key that our own

///|   verifier accepted -- all inside the browser.
///

///|   The DH private exponent is fixed for a reproducible transcript, exactly

///|   as in cmd/ssh_live. A production client draws it from the CSPRNG and

///|   never reuses it.

///|

///| Read one value out of the bootstrap-supplied config global. A browser has

///| no argv, so configuration arrives this way rather than through @env.args

///|
/// (which would drag a `__moonbit_fs_unstable` import into the Worker).
extern "js" fn cfg(name : String) -> String = "((n) => (globalThis.__wt_cfg && globalThis.__wt_cfg[n] != null) ? String(globalThis.__wt_cfg[n]) : '')"

///|

///| Hand the result back to the Worker. MoonBit's entry is an `async fn`, so

///|
/// the Worker cannot treat "importScripts returned" as completion.
extern "js" fn wt_finish(ok : Bool, detail : String) -> Unit = "((ok, detail) => { globalThis.__wt_finish({ ok: ok, detail: detail }) })"

///|
fn fixed_x() -> @bigint.BigNat {
  let bytes : FixedArray[Byte] = FixedArray::from_array([
    0x5A, 0x17, 0xC3, 0x9E, 0x44, 0xB2, 0x6D, 0xF1, 0x08, 0xA7, 0x35, 0xCC, 0x91,
    0x2E, 0x60, 0xD3, 0x74, 0x18, 0x9F, 0xE2, 0x50, 0xB7, 0xC6, 0x3D, 0x81, 0x0A,
    0xF5, 0x29, 0x64, 0xC8, 0x7B, 0x1E,
  ])
  @bigint.BigNat::from_bytes_be(bytes)
}

///|
fn error_name(e : @wtlive.WtLiveError) -> String {
  match e {
    ConnectFailed(_) => "ConnectFailed"
    NoServerIdent => "NoServerIdent"
    KexinitSendFailed => "KexinitSendFailed"
    NoPeerKexinit => "NoPeerKexinit"
    KexinitParseFailed => "KexinitParseFailed"
    NoAgreement(_) => "NoAgreement"
    EcdhInitSendFailed => "EcdhInitSendFailed"
    NoEcdhReply => "NoEcdhReply"
    EcdhReplyMalformed => "EcdhReplyMalformed"
    HostkeyInvalid => "HostkeyInvalid"
    SignatureInvalid(_) => "SignatureInvalid"
    NewkeysSendFailed => "NewkeysSendFailed"
    NoNewkeys => "NoNewkeys"
    BadPacket(w) => "BadPacket:" + w
  }
}

///|
fn session_error_name(e : @wtlive.WtSessionError) -> String {
  match e {
    @wtlive.HandshakeFailed(h) => "handshake:" + error_name(h)
    @wtlive.NoServiceAccept => "NoServiceAccept"
    @wtlive.UnexpectedService(s) => "UnexpectedService:" + s
    @wtlive.BadPacket(w) => "BadPacket:" + w
  }
}

///|
/// Loop #34 的测试私钥:即 RFC 6979 A.2.5 公布的 NIST P-256 key。
///
/// 与 cmd/ssh_live 用的是同一把,这样浏览器路径和原生路径签出来的公钥
/// 才能和同一份 authorized_keys 对上——两边用不同的私钥就没有可比性。
/// 这把私钥印在 RFC 原文里,**绝不能**用在真实主机上。
fn test_auth_key() -> @bigint.BigNat {
  let bytes : FixedArray[Byte] = FixedArray::from_array([
    0xC9, 0xAF, 0xA9, 0xD8, 0x45, 0xBA, 0x75, 0x16, 0x6B, 0x5C, 0x21, 0x57, 0x67,
    0xB1, 0xD6, 0x93, 0x4E, 0x50, 0xC3, 0xDB, 0x36, 0xE8, 0x9B, 0x12, 0x7B, 0x8A,
    0x62, 0x2B, 0x12, 0x0F, 0x67, 0x21,
  ])
  @bigint.BigNat::from_bytes_be(bytes)
}

///|
/// AuthRejected 携带的三样证据原样打印,理由字段不在这一层被拼进字符串里,
/// 它得能被单独解析。
fn print_auth_rejection(e : @wtlive.WtAuthError) -> Unit {
  match e {
    @wtlive.AuthRejected(r, sb, sg) => {
      println("result: USERAUTH_FAILURE")
      println("reason: " + r)
      println("signed_blob: " + sb)
      println("sig_blob: " + sg)
    }
    _ => ()
  }
}

///|
fn auth_error_name(e : @wtlive.WtAuthError) -> String {
  match e {
    @wtlive.HandshakeFailed(h) => "handshake:" + error_name(h)
    @wtlive.NoServiceAccept => "NoServiceAccept"
    @wtlive.UnexpectedService(s) => "UnexpectedService:" + s
    @wtlive.SignFailed => "SignFailed"
    @wtlive.NoAuthReply => "NoAuthReply"
    @wtlive.AuthRejected(_, _, _) => "AuthRejected"
    @wtlive.BadPacket(w) => "BadPacket:" + w
  }
}

///|

///| `async fn main` because awaiting is itself an async operation, and MoonBit

///|
/// tracks asyncness statically: a sync `fn main` may not touch the transport.
///|
/// 原始字节打进标记块,和 cmd/ssh_live 同一套标记,好让两条路径的输出能直接
/// 逐行对比。验证脚本只读上面那几行数字。
fn wt_print_bytes(b : FixedArray[Byte]) -> Unit {
  if b.length() == 0 {
    return
  }
  let n = if b.length() > 128 { 128 } else { b.length() }
  let sb = StringBuilder()
  for i = 0; i < n; i = i + 1 {
    sb.write_char(Int::unsafe_to_char(b[i].to_int()))
  }
  println("--- raw ---")
  println(sb.to_string())
  if n < b.length() {
    println("--- raw truncated at 128 of " + b.length().to_string() + " ---")
  }
  println("--- end raw ---")
}

fn wt_exec_error_name(e : @wtlive.WtExecError) -> String {
  match e {
    NoSessionState => "NoSessionState"
    Malformed(m) => "Malformed(" + m + ")"
    OpenFailed(r, d) => "OpenFailed(" + r.to_string() + ", " + d + ")"
    ExecRejected => "ExecRejected"
    SendFailed => "SendFailed"
    BadPacket(w) => "BadPacket(" + w + ")"
    Closed => "Closed"
    TooManyPackets => "TooManyPackets"
  }
}

///|
async fn main {
  let url = cfg("url")
  // The Worker passes `session: 1` for the Loop #33 run. A config lookup
  // rather than argv, because a browser has no argv.
  let want_session = cfg("session") == "1" || cfg("session") == "true"
  // Loop #34: `auth: 1` goes all the way to SSH_MSG_USERAUTH_SUCCESS.
  let want_auth = cfg("auth") == "1" || cfg("auth") == "true"
  // Loop #35: `exec: <command>` runs a remote command and reads back its
  // stdout / stderr / exit-status.
  let exec_cmd = cfg("exec")
  if exec_cmd != "" {
    let user = cfg("user")
    let uname = if user == "" { "hp" } else { user }
    println("=== Loop #35 exec in a browser Worker ===")
    println("transport_url: " + url)
    println("user: " + uname)
    println("command: " + exec_cmd)
    let econn = @wt.WtConn::connect(url) catch {
      _ => {
        println("result: FAILED")
        println("error: ConnectFailed")
        wt_finish(false, "connect failed")
        return
      }
    }
    println("transport: connected")
    let outcome = @wtlive.wt_live_exec(
      econn,
      fixed_x(),
      uname,
      test_auth_key(),
      exec_cmd,
    )
    match outcome {
      @wtlive.Done(r) => {
        println("result: EXEC_DONE")
        println("stdout_len: " + r.stdout.length().to_string())
        println("stdout_sha256: " + @ecdsa.bytes_to_hex(@sha256.sha256(r.stdout)))
        println("stderr_len: " + r.stderr.length().to_string())
        println("stderr_sha256: " + @ecdsa.bytes_to_hex(@sha256.sha256(r.stderr)))
        println("exit_status: " + r.exit_status.to_string())
        println("remote_id: " + r.remote_id.to_string())
        println("adjusts_sent: " + r.adjusts_sent.to_string())
        println("total_sent_bytes: " + r.sent_bytes.to_string())
        println("total_recv_bytes: " + r.recv_bytes.to_string())
        wt_print_bytes(r.stdout)
        wt_print_bytes(r.stderr)
      }
      @wtlive.AuthFailed(e) => {
        println("result: AUTH_FAILED")
        print_auth_rejection(e)
        println("error: " + auth_error_name(e))
      }
      @wtlive.ChannelFailed(e) => {
        println("result: CHANNEL_FAILED")
        println("error: " + wt_exec_error_name(e))
      }
    }
    econn.close()
    wt_finish(true, "done")
    return
  }
  if want_auth {
    let user = cfg("user")
    let uname = if user == "" { "hp" } else { user }
    println("=== Loop #34 publickey auth in a browser Worker ===")
    println("transport_url: " + url)
    println("user: " + uname)
    let aconn = @wt.WtConn::connect(url) catch {
      _ => {
        println("result: FAILED")
        println("error: ConnectFailed")
        wt_finish(false, "connect failed")
        return
      }
    }
    println("transport: connected")
    match @wtlive.wt_live_auth(aconn, fixed_x(), uname, test_auth_key()) {
      @wtlive.Authenticated(r) => {
        println("result: USERAUTH_SUCCESS")
        println("user: " + r.user)
        println("method: " + r.method)
        println("key_type: " + r.key_type)
        println("session_id_head: " + r.session.session_id_head)
        println("signed_blob: " + r.signed_blob_hex)
        println("sig_blob: " + r.sig_blob_hex)
        println("request: " + r.request_hex)
        println("handshake_sent_bytes: " + r.session.handshake.sent_bytes.to_string())
        println("handshake_recv_bytes: " + r.session.handshake.recv_bytes.to_string())
        println("total_sent_bytes: " + r.session.sent_bytes.to_string())
        println("total_recv_bytes: " + r.session.recv_bytes.to_string())
      }
      @wtlive.Failed(e) => {
        print_auth_rejection(e)
        if auth_error_name(e) != "AuthRejected" {
          println("result: FAILED")
          println("error: " + auth_error_name(e))
        }
      }
    }
    aconn.close()
    wt_finish(true, "done")
    return
  }
  if want_session {
    println("=== Loop #33 encrypted session in a browser Worker ===")
    println("transport_url: " + url)
    let sconn = @wt.WtConn::connect(url) catch {
      _ => {
        println("result: FAILED")
        println("error: ConnectFailed")
        wt_finish(false, "connect failed")
        return
      }
    }
    println("transport: connected")
    match @wtlive.wt_live_session(sconn, fixed_x()) {
      @wtlive.ServiceAccepted(r) => {
        println("result: SERVICE_ACCEPTED")
        println("service: " + r.service_name)
        println("accepted: " + r.accepted_service)
        println("we_need: " + r.we_need.to_string())
        println("cipher_ctos: " + r.handshake.cipher_ctos)
        println("mac_ctos: " + r.handshake.mac_ctos)
        println("key_tag: " + r.key_tag)
        println("session_id_head: " + r.session_id_head)
        println("handshake_sent_bytes: " + r.handshake.sent_bytes.to_string())
        println("handshake_recv_bytes: " + r.handshake.recv_bytes.to_string())
        println("total_sent_bytes: " + r.sent_bytes.to_string())
        println("total_recv_bytes: " + r.recv_bytes.to_string())
      }
      @wtlive.Failed(e) => {
        println("result: FAILED")
        println("error: " + session_error_name(e))
      }
    }
    sconn.close()
    wt_finish(true, "done")
    return
  }
  println("=== Loop #32 SSH transport handshake in a browser Worker ===")
  println("transport_url: " + url)
  let conn = @wt.WtConn::connect(url) catch {
    e => {
      println("result: FAILED")
      println("error: ConnectFailed")
      wt_finish(false, "connect failed")
      return
    }
  }
  println("transport: connected")
  match @wtlive.wt_live_handshake(conn, fixed_x()) {
    @wtlive.Established(r) => {
      println("result: ESTABLISHED")
      println("server_ident: " + r.server_ident)
      println("client_ident: " + r.client_ident)
      println("kex_alg: " + r.kex_alg)
      println("hostkey_alg: " + r.hostkey_alg)
      println("hostkey_type: " + r.hostkey_type)
      println("hostkey_bits: " + r.hostkey_bits.to_string())
      println("cipher_ctos: " + r.cipher_ctos)
      println("cipher_stoc: " + r.cipher_stoc)
      println("mac_ctos: " + r.mac_ctos)
      println("mac_stoc: " + r.mac_stoc)
      println("hostkey_blob_hex: " + @ecdsa.bytes_to_hex(r.hostkey_blob))
      println("exchange_hash: " + @ecdsa.bytes_to_hex(r.exchange_hash))
      println("shared_secret_head: " + r.shared_secret_head)
      println("sent_bytes: " + r.sent_bytes.to_string())
      println("recv_bytes: " + r.recv_bytes.to_string())
    }
    @wtlive.Failed(e) => {
      println("result: FAILED")
      println("error: " + error_name(e))
      // On a signature failure the exchange hash is the whole question, so
      // print it: an independent implementation can recompute H from the same
      // transcript and the two either agree or name the divergence.
      match e {
        @wtlive.SignatureInvalid(h) =>
          println("exchange_hash: " + @ecdsa.bytes_to_hex(h))
        _ => ()
      }
    }
  }
  conn.close()
  wt_finish(true, "done")
}
