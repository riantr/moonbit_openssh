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
  }
}

///|
fn session_error_name(e : @wtlive.WtSessionError) -> String {
  match e {
    @wtlive.HandshakeFailed(h) => "handshake:" + error_name(h)
    @wtlive.NoServiceAccept => "NoServiceAccept"
    @wtlive.UnexpectedService(s) => "UnexpectedService:" + s
  }
}

///|

///| `async fn main` because awaiting is itself an async operation, and MoonBit

///|
/// tracks asyncness statically: a sync `fn main` may not touch the transport.
async fn main {
  let url = cfg("url")
  // The Worker passes `session: 1` for the Loop #33 run. A config lookup
  // rather than argv, because a browser has no argv.
  let want_session = cfg("session") == "1" || cfg("session") == "true"
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
        println("key_head: " + r.key_head)
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
