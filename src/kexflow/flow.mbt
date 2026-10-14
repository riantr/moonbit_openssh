///| kexgen 瀹㈡埛绔祦绋?input_kex_gen_reply 绮剧‘搴忚浆鍐?
///
/// 瀵瑰簲 OpenSSH kexgen.c :99-127(kex_gen_client)/:131-233
/// (input_kex_gen_reply)涓?kex.c choose_conf 鏃跺簭銆?/// 绾秷鎭眰:甯у皝瑁?鍔犲瘑鍒囨崲褰?bpacket 涓庤皟鐢ㄦ柟(architect 搂3)銆?
///|
/// SSH2_MSG_KEXINIT(ssh2.h)
pub const KX_MSG_KEXINIT : Byte = b'\x14'

///|
/// SSH2_MSG_KEX_ECDH_INIT(ssh2.h)
pub const KX_MSG_KEX_ECDH_INIT : Byte = b'\x1e'

///|
/// SSH2_MSG_KEX_ECDH_REPLY(ssh2.h)
pub const KX_MSG_KEX_ECDH_REPLY : Byte = b'\x1f'

///|
/// SSH2_MSG_NEWKEYS(ssh2.h;涓?bpacket.MSG_NEWKEYS 鍚屽€?娑堟伅灞傝嚜鎸佸父閲?
pub const KX_MSG_NEWKEYS : Byte = b'\x15'

///|
/// 娴佺▼閿欒(鎵佸钩涓冨€?Loop #13 鏂板 HostKeyMismatch/HostKeyUnknown)
pub(all) enum FlowError {
  /// Loop #61: the proposal names a KEX or host key algorithm this client
  /// cannot execute.
  ///
  /// This used to be reported as `ProtocolError`, which means "the peer's
  /// bytes are malformed". The two send you to completely different places:
  /// one to a packet capture, the other to the algorithm tables. The tree
  /// already made this split once, for `@cert-authority` -- `HostKeyCertAuthority`
  /// is its own variant precisely because reporting it as `HostKeyMismatch`
  /// walks the user straight into `--kh-tofu`, which is the opposite of the fix.
  /// Same rule, second application.
  ///
  /// Direction matters: this says **our** proposal over-promised. A *peer*
  /// naming something we lack is fine -- `negotiate` takes the intersection and
  /// lands on something we can run, so it never reaches here. The variant
  /// exists so the defect fails in development rather than the first time
  /// somebody runs a handshake in production.
  AlgorithmNotRunnable(String)
  /// Loop #61: the negotiated cipher or MAC has no packet-layer path.
  ///
  /// Kept separate from `AlgorithmNotRunnable` because the owner differs: this
  /// one is fixed in `src/bpacket`, the other by changing a proposal. Merging
  /// them would erase the question of *who* has to act.
  CipherNotRunnable(String)
  /// 鎻愭/娑堟伅缁撴瀯闂(鐭?buffer銆佸熬闅忔畫浣欍€乵sg type 閿欍€佸崗鍟嗙粨鏋滈潪鏈瓙闆?
  ProtocolError
  /// 瀵圭鎻愭涓庢垜鏂规棤鍏叡绠楁硶(navigator 搂1 match_list 鍒嗙被)
  NoAgreement(NegotiationError)
  /// K_S blob 瑙ｆ瀽澶辫触(hostkey from_blob 鎷掔粷)
  HostkeyInvalid
  /// 楠岀澶辫触(鍚?alg TypeMismatch / trailing / len 鍩?/ 瀵嗙爜瀛﹀け璐?
  SignatureInvalid
  /// x25519 鍏变韩瀵嗛挜鍏ㄩ浂(KEY_INVALID_EC_VALUE)
  SharedSecretInvalid
  /// hostname 鍛戒腑浣?key 瀛楄妭涓嶅尮閰?Loop #13 鎺ュ叆)
  HostKeyMismatch(String)
  /// strict_kex 涓?hostname 鏈湪 known_hosts(Loop #13 鎺ュ叆)
  HostKeyUnknown(String)
  /// Loop #51: hostname 只被 `@cert-authority` 命中,而本客户端不验证主机证书。
  ///
  /// 和 `HostKeyMismatch` 分开:后者是「有人在中间」的真指控,而这一条是
  /// 「这个客户端答不上来」。报成前者会让用户照着 HOST_CHANGED 的流程去加
  /// `--kh-tofu`,那正好是在关掉保护。
  HostKeyCertAuthority(String)
}

///|
/// 客户端配置(cookie 注入式确定性,决策 D5)
pub(all) struct FlowConfig {
  version_client : FixedArray[Byte] // V_C(不含换行)
  version_server : FixedArray[Byte] // V_S(不含换行)
  cookie : FixedArray[Byte] // 16B
  client_seed : FixedArray[Byte] // x25519 标量种子(32B,API 内 clamp)
  strict_kex : Bool
  /// Loop #13 接入:用于 host_key_check
  hostname : String
  /// Loop #14 接入:调用方的连接端口 0 = SSH default 22
  host_port : Int
  /// Loop #13 接入:known_hosts 条目;空数组 = 跳过检查
  knownhosts_entries : Array[@knownhosts.KnownHostEntry]
}

///|
pub fn FlowConfig::make(
  version_client : FixedArray[Byte],
  version_server : FixedArray[Byte],
  cookie : FixedArray[Byte],
  client_seed : FixedArray[Byte],
  strict_kex : Bool,
  hostname : String,
  host_port : Int,
  knownhosts_entries : Array[@knownhosts.KnownHostEntry],
) -> FlowConfig {
  { version_client, version_server, cookie, client_seed, strict_kex, hostname, host_port, knownhosts_entries, }
}

///|
/// start() 浜х墿:鎴戞柟 I_C + e + 寰呭彂 INIT 娑堟伅浣嶃€嶉〉?
pub(all) struct StartedFlow {
  ic_payload : FixedArray[Byte] // 鎴戞柟 KEXINIT payload(type 鍚?= I_C
  e_pub : FixedArray[Byte] // 瀹㈡埛绔复鏃跺叕閽?32B
  init_msg : FixedArray[Byte] // type30 鈥?string(e)(甯у眰涔嬪墠鐨勬秷鎭綋)
  cfg_snapshot_strict : Bool // 渚涜皟鐢ㄦ柟鏋勯€?bpacket ctx(strict 閫忎紶)
}

///|
/// kex_gen_client:鐢熸垚涓存椂瀵瑰苟鍙?INIT(kexgen.c:99-127)
pub fn flow_start(cfg : FlowConfig, my : Proposal) -> StartedFlow {
  let ic = kexinit_payload(cfg.cookie, my)
  let e = @kexc25519.c25519_keygen(cfg.client_seed)
  let init_msg = kf_cat([
    FixedArray::from_array([KX_MSG_KEX_ECDH_INIT]),
    kf_wstr(e),
  ])
  { ic_payload: ic, e_pub: e, init_msg, cfg_snapshot_strict: cfg.strict_kex, }
}

///|
/// 鎴愬姛浜х墿
pub(all) struct Established {
  session_id : FixedArray[Byte] // initial:kex_derive_keys 瀛?H(kex.c:1143)
  keys : @kexc25519.DerivedKeys // 鍏瘑閽?AEAD 鍙秷璐?enc_ctos/stoc)
  newkeys_msg : FixedArray[Byte] // type21 绌轰綋
}

///|
pub(all) enum ReplyOutcome {
  Established(Established)
  Failed(FlowError)
}

///|
fn kf_cat(parts : Array[FixedArray[Byte]]) -> FixedArray[Byte] {
  let mut total = 0
  for p in parts {
    total = total + p.length()
  }
  let out : FixedArray[Byte] = FixedArray::make(total, b'\x00')
  let mut off = 0
  for p in parts {
    for i = 0; i < p.length(); i = i + 1 {
      out[off + i] = p[i]
    }
    off = off + p.length()
  }
  out
}

///|
fn kf_wstr(b : FixedArray[Byte]) -> FixedArray[Byte] {
  let n = b.length()
  let len_arr : FixedArray[Byte] = FixedArray::make(4, b'\x00')
  let u : UInt = n.reinterpret_as_uint()
  len_arr[0] = ((u >> 24) & 0xFFU).to_byte()
  len_arr[1] = ((u >> 16) & 0xFFU).to_byte()
  len_arr[2] = ((u >> 8) & 0xFFU).to_byte()
  len_arr[3] = (u & 0xFFU).to_byte()
  kf_cat([len_arr, b])
}

///|
fn kf_bytes_eq(a : FixedArray[Byte], b : FixedArray[Byte]) -> Bool {
  if a.length() != b.length() {
    return false
  }
  for i = 0; i < a.length(); i = i + 1 {
    if a[i] != b[i] {
      return false
    }
  }
  true
}

///|
/// REPLY 澶勭悊(input_kex_gen_reply:131-233 涓€涓€瀵瑰簲):
/// 鍗忓晢(C 鍦?input_kexinit 鍐呭厛瀹屾垚)鈫?瑙ｆ瀽涓夋 鈫?hostkey 瑙ｆ瀽 鈫?/// 鍏变韩瀵嗛挜(鍏ㄩ浂鎷?鈫?H 鈫?sshkey_verify 鈫?娲剧敓銆?
pub fn flow_on_reply(
  started : StartedFlow,
  cfg : FlowConfig,
  my : Proposal,
  peer_ic_payload : FixedArray[Byte],
  reply_msg : FixedArray[Byte],
) -> ReplyOutcome {
  // ---- kex_input_kexinit + kex_choose_conf(REPLY 鍓嶇殑鏃跺簭)----
  // Loop #61: check the *proposal* before using anything it says. The old code
  // only checked the negotiated outcome, and only for kex and hostkey -- so an
  // unrunnable cipher survived all the way to key derivation, where the
  // hardcoded FLOW_WE_NEED below quietly produced a chacha-length key.
  match check_proposal_runnable(my) {
    None => ()
    Some(bad) => return Failed(AlgorithmNotRunnable(bad))
  }
  let peer_init = match parse_kexinit(peer_ic_payload) {
    Some(p) => p
    None => return Failed(ProtocolError)
  }
  let neg = match negotiate(my, peer_init) {
    Ok(n) => n
    Err(e) => return Failed(NoAgreement(e))
  }
  // 瀛愰泦鍗曠畻娉?鍗忓晢鍑虹殑 hostkey 蹇呴』鏄湰瀹炵幇鏀寔鐨?ssh-ed25519
  // Loop #61: this flow implements exactly one KEX and exactly one host key
  // algorithm, so anything else is a capability gap on our side, not a
  // protocol violation by the peer. `AlgorithmNotRunnable`, not
  // `ProtocolError`.
  if neg.kex_alg != "curve25519-sha256" {
    return Failed(AlgorithmNotRunnable("kex:" + neg.kex_alg))
  }
  if neg.hostkey_alg != "ssh-ed25519" {
    return Failed(AlgorithmNotRunnable("hostkey:" + neg.hostkey_alg))
  }
  // Loop #61: the negotiated cipher and MAC have to be ones `src/bpacket` can
  // actually run. `transport_params` aborts on anything else, so the check has
  // to come first -- and it is a separate error because the fix lives in a
  // different package.
  if !@bpacket.cipher_needs_mac(neg.cipher_ctos) &&
    !@bpacket.is_runnable_cipher(neg.cipher_ctos) {
    return Failed(CipherNotRunnable(neg.cipher_ctos))
  }
  if @bpacket.cipher_needs_mac(neg.cipher_ctos) &&
    !@bpacket.is_runnable_mac(neg.mac_ctos) {
    return Failed(CipherNotRunnable(neg.mac_ctos))
  }
  // ---- input_kex_gen_reply ----
  // msg type 瀛楄妭蹇呴』涓?31(:135 dispatch 淇濊瘉;姝ゅ鏄惧紡鏍￠獙)
  if reply_msg.length() < 1 || reply_msg[0] != KX_MSG_KEX_ECDH_REPLY {
    return Failed(ProtocolError)
  }
  let body = kf_slice(reply_msg, 1, reply_msg.length())
  let rep = match @kexc25519.parse_reply(body) {
    Some(r) => r
    None => return Failed(ProtocolError) // 灏鹃殢/闀垮害杩濊(:163 get_end 绛?
  }
  // :138-152 sshkey_fromb + kex_verify_host_key
  // (淇′换鍥炶皟鑼冨洿澶?鎺ュ彈浠讳綍鍙В鏋愮殑 ed25519 涓绘満閽?navigator 搂6)
  let hostkey = match @hostkey.HostKey::from_blob(rep.hostkey_blob) {
    @hostkey.Parsed(@hostkey.Ed25519Key(pk)) => pk
    _ => return Failed(HostkeyInvalid)
  }
  // :156-186 c25519_dec:鍏变韩瀵嗛挜 mpint(鍏ㄩ浂鍦?Loop#9 宸叉嫆 鈫?None)
  let shared_mpint = match
    @kexc25519.c25519_shared_key_mpint(cfg.client_seed, rep.server_pub) {
    Some(k) => k
    None => return Failed(SharedSecretInvalid)
  }
  // :188-204 kex_gen_hash 鈫?H
  let inputs = @kexc25519.ExchangeInputs::make(
    cfg.version_client,
    cfg.version_server,
    started.ic_payload,
    peer_ic_payload,
  )
  let h = @kexc25519.kex_gen_hash(
    inputs,
    rep.hostkey_blob,
    started.e_pub,
    rep.server_pub,
    shared_mpint,
  )
  // :206-210 sshkey_verify(hostkey_alg 鍗忓晢鍊煎凡闄愬畾 ed25519;
  //   sig 鍐?alg 绮剧‘鍖归厤鐢?hostkey 灞傝礋璐?鈫?TypeMismatch 褰掑苟 SignatureInvalid)
  match
    @hostkey.HostKey::verify(@hostkey.Ed25519Key(hostkey), h, rep.sig_blob) {
    @hostkey.Accepted => ()
    _ => return Failed(SignatureInvalid)
  }
  // ---- Loop #13 step 6.5: host_key_check ----
  // 入参 cfg.knownhosts_entries 可空（空数组 = 跳过检查）; bytesters_hostname 必须非空
  if cfg.knownhosts_entries.length() > 0 {
    let host_status = @knownhosts.check_host_key_strict(
      cfg.knownhosts_entries, cfg.hostname, cfg.host_port, rep.hostkey_blob, cfg.strict_kex,
    )
    match host_status {
      @knownhosts.Ok => ()
      @knownhosts.Mismatch => return Failed(HostKeyMismatch(cfg.hostname))
      @knownhosts.Unknown =>
        if cfg.strict_kex {
          return Failed(HostKeyUnknown(cfg.hostname))
        }
      @knownhosts.CertAuthority => return Failed(HostKeyCertAuthority(cfg.hostname))
      @knownhosts.InvalidEntry => return Failed(ProtocolError)
    }
  }
  // :212-213 kex_derive_keys(initial:session_id=H)+ NEWKEYS 缁勫寘
  // Loop #61: the derivation length comes from the packet layer's parameter
  // table, not from a constant. `FLOW_WE_NEED` was 64 -- correct for
  // chacha20-poly1305 and silently wrong for anything else, and it was the
  // reason an unrunnable cipher produced a *successful* `Established` with a
  // key of the wrong length rather than an error.
  let (we_key, _we_block, _we_iv, we_mac) = @bpacket.transport_params(
    neg.cipher_ctos,
    neg.mac_ctos,
  )
  let mut we_need = we_key
  if we_mac > we_need {
    we_need = we_mac
  }
  // Loop #61: argument order. `derive_keys(hash, shared_secret_mpint, we_need)`
  // and internally `derive_single` concatenates K || H || letter || session_id
  // (RFC 4253 7.2). This call site passed them the other way round, so K1 was
  // HASH(H || K || letter || H) and `session_id` came back as the shared secret.
  // The `session_id == h` invariant two lines below then always failed, and the
  // failure was reported as `ProtocolError` -- "the peer's bytes are malformed"
  // -- for a bug that is entirely ours.
  //
  // Nothing caught it because this function has no caller. `ssh_full_ws` calls
  // `flow_start` and stops there. A function that has never run cannot have
  // been tested, and its three defects -- this one, the hardcoded FLOW_WE_NEED,
  // and the absent cipher guard -- are the reason. The type system cannot help
  // either: both parameters are `FixedArray[Byte]`.
  let keys = @kexc25519.derive_keys(h, shared_mpint, we_need)
  if !kf_bytes_eq(keys.session_id, h) {
    // initial 鍦烘櫙鎭掔瓑;闃插尽鎬ф柇瑷€(娲剧敓灞傚绾︽紓绉诲嵆鏆撮湶)
    return Failed(ProtocolError)
  }
  Established({
    session_id: keys.session_id,
    keys,
    newkeys_msg: FixedArray::from_array([KX_MSG_NEWKEYS]),
  })
}

///|
fn kf_slice(
  src : FixedArray[Byte],
  start : Int,
  end_ : Int,
) -> FixedArray[Byte] {
  let n = end_ - start
  let out : FixedArray[Byte] = FixedArray::make(n, b'\x00')
  for i = 0; i < n; i = i + 1 {
    out[i] = src[start + i]
  }
  out
}
