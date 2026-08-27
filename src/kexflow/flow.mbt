///| kexgen 客户端流程(input_kex_gen_reply 精确序转写)
///
/// 对应 OpenSSH kexgen.c :99-127(kex_gen_client)/:131-233
/// (input_kex_gen_reply)与 kex.c choose_conf 时序。
/// 纯消息层:帧封装/加密切换归 bpacket 与调用方(architect §3)。

///| SSH2_MSG_KEXINIT(ssh2.h)
pub const KX_MSG_KEXINIT : Byte = b'\x14'

///| SSH2_MSG_KEX_ECDH_INIT(ssh2.h)
pub const KX_MSG_KEX_ECDH_INIT : Byte = b'\x1e'

///| SSH2_MSG_KEX_ECDH_REPLY(ssh2.h)
pub const KX_MSG_KEX_ECDH_REPLY : Byte = b'\x1f'

///| SSH2_MSG_NEWKEYS(ssh2.h;与 bpacket.MSG_NEWKEYS 同值,消息层自持常量)
pub const KX_MSG_NEWKEYS : Byte = b'\x15'

///|
/// chachapoly 方向密钥总长(cipher.c 表:key_len=64=chacha32+poly头32;
/// AEAD 下 iv_len=0、mac 不用 → we_need=64,kex.c choose_enc MAXIMUM 逻辑)
const FLOW_WE_NEED : Int = 64

///| 流程错误(扁平五值,决策 D2)
pub(all) enum FlowError {
  /// 提案/消息结构问题(短 buffer、尾随残余、msg type 错、协商结果非本子集)
  ProtocolError
  /// 对端提案与我方无公共算法(navigator §1 match_list 分类)
  NoAgreement(NegotiationError)
  /// K_S blob 解析失败(hostkey from_blob 拒绝)
  HostkeyInvalid
  /// 验签失败(含 alg TypeMismatch / trailing / len 域 / 密码学失败)
  SignatureInvalid
  /// x25519 共享密钥全零(KEY_INVALID_EC_VALUE)
  SharedSecretInvalid
}

///| 客户端配置(cookie 注入式确定性,决策 D5)
pub(all) struct FlowConfig {
  version_client : FixedArray[Byte] // V_C(不含换行)
  version_server : FixedArray[Byte] // V_S(不含换行)
  cookie : FixedArray[Byte] // 16B
  client_seed : FixedArray[Byte] // x25519 标量种子(32B,API 内 clamp)
  strict_kex : Bool
}

///|
pub fn FlowConfig::make(
  version_client : FixedArray[Byte],
  version_server : FixedArray[Byte],
  cookie : FixedArray[Byte],
  client_seed : FixedArray[Byte],
  strict_kex : Bool,
) -> FlowConfig {
  if cookie.length() != KEX_COOKIE_LEN {
    abort("FlowConfig: cookie must be \{KEX_COOKIE_LEN} bytes")
  }
  if client_seed.length() != 32 {
    abort("FlowConfig: client_seed must be 32 bytes")
  }
  { version_client, version_server, cookie, client_seed, strict_kex }
}

///| start() 产物:我方 I_C + e + 待发 INIT 消息体
pub(all) struct StartedFlow {
  ic_payload : FixedArray[Byte] // 我方 KEXINIT payload(type 后)= I_C
  e_pub : FixedArray[Byte] // 客户端临时公钥 32B
  init_msg : FixedArray[Byte] // type30 ‖ string(e)(帧层之前的消息体)
  cfg_snapshot_strict : Bool // 供调用方构造 bpacket ctx(strict 透传)
}

///|
/// kex_gen_client:生成临时对并发 INIT(kexgen.c:99-127)
pub fn flow_start(cfg : FlowConfig, my : Proposal) -> StartedFlow {
  let ic = kexinit_payload(cfg.cookie, my)
  let e = @kexc25519.c25519_keygen(cfg.client_seed)
  let init_msg = kf_cat([
    FixedArray::from_array([KX_MSG_KEX_ECDH_INIT]),
    kf_wstr(e),
  ])
  { ic_payload: ic, e_pub: e, init_msg, cfg_snapshot_strict: cfg.strict_kex }
}

///| 成功产物
pub(all) struct Established {
  session_id : FixedArray[Byte] // initial:kex_derive_keys 存 H(kex.c:1143)
  keys : @kexc25519.DerivedKeys // 六密钥(AEAD 只消费 enc_ctos/stoc)
  newkeys_msg : FixedArray[Byte] // type21 空体
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

///| REPLY 处理(input_kex_gen_reply:131-233 一一对应):
/// 协商(C 在 input_kexinit 内先完成)→ 解析三段 → hostkey 解析 →
/// 共享密钥(全零拒)→ H → sshkey_verify → 派生。
pub fn flow_on_reply(
  started : StartedFlow,
  cfg : FlowConfig,
  my : Proposal,
  peer_ic_payload : FixedArray[Byte],
  reply_msg : FixedArray[Byte],
) -> ReplyOutcome {
  // ---- kex_input_kexinit + kex_choose_conf(REPLY 前的时序)----
  let peer_init = match parse_kexinit(peer_ic_payload) {
    Some(p) => p
    None => return Failed(ProtocolError)
  }
  let neg = match negotiate(my, peer_init) {
    Ok(n) => n
    Err(e) => return Failed(NoAgreement(e))
  }
  // 子集单算法:协商出的 hostkey 必须是本实现支持的 ssh-ed25519
  if neg.kex_alg != "curve25519-sha256" || neg.hostkey_alg != "ssh-ed25519" {
    return Failed(ProtocolError)
  }
  // ---- input_kex_gen_reply ----
  // msg type 字节必须为 31(:135 dispatch 保证;此处显式校验)
  if reply_msg.length() < 1 || reply_msg[0] != KX_MSG_KEX_ECDH_REPLY {
    return Failed(ProtocolError)
  }
  let body = kf_slice(reply_msg, 1, reply_msg.length())
  let rep = match @kexc25519.parse_reply(body) {
    Some(r) => r
    None => return Failed(ProtocolError) // 尾随/长度违规(:163 get_end 等)
  }
  // :138-152 sshkey_fromb + kex_verify_host_key
  // (信任回调范围外:接受任何可解析的 ed25519 主机钥,navigator §6)
  let hostkey = match @hostkey.HostKey::from_blob(rep.hostkey_blob) {
    @hostkey.Parsed(@hostkey.Ed25519Key(pk)) => pk
    _ => return Failed(HostkeyInvalid)
  }
  // :156-186 c25519_dec:共享密钥 mpint(全零在 Loop#9 已拒 → None)
  let shared_mpint = match @kexc25519.c25519_shared_key_mpint(
      cfg.client_seed,
      rep.server_pub,
    ) {
    Some(k) => k
    None => return Failed(SharedSecretInvalid)
  }
  // :188-204 kex_gen_hash → H
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
  // :206-210 sshkey_verify(hostkey_alg 协商值已限定 ed25519;
  //   sig 内 alg 精确匹配由 hostkey 层负责 → TypeMismatch 归并 SignatureInvalid)
  match @hostkey.HostKey::verify(
      @hostkey.Ed25519Key(hostkey),
      h,
      rep.sig_blob,
    ) {
    @hostkey.Accepted => ()
    _ => return Failed(SignatureInvalid)
  }
  // :212-213 kex_derive_keys(initial:session_id=H)+ NEWKEYS 组包
  let keys = @kexc25519.derive_keys(shared_mpint, h, FLOW_WE_NEED)
  if !kf_bytes_eq(keys.session_id, h) {
    // initial 场景恒等;防御性断言(派生层契约漂移即暴露)
    return Failed(ProtocolError)
  }
  Established({
    session_id: keys.session_id,
    keys,
    newkeys_msg: FixedArray::from_array([KX_MSG_NEWKEYS]),
  })
}

///|
fn kf_slice(src : FixedArray[Byte], start : Int, end_ : Int) -> FixedArray[Byte] {
  let n = end_ - start
  let out : FixedArray[Byte] = FixedArray::make(n, b'\x00')
  for i = 0; i < n; i = i + 1 {
    out[i] = src[start + i]
  }
  out
}
