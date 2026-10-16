///| KEXINIT 提案构造/解析/协商
///
/// 对应 OpenSSH kex.c kex_prop2buf(:146-170)/ kex_buf2prop /
/// match.c match_list(:313 first-match 语义)。
/// 行号引用见 docs/kexflow/navigator.md §1。

///|
/// cookie 长度(kex.h KEX_COOKIE_LEN)
pub const KEX_COOKIE_LEN : Int32 = 16

///|
/// 提案十类目(kex.h PROPOSAL_* 顺序)
pub(all) struct Proposal {
  kex_algs : String
  hostkey_algs : String
  enc_ctos : String
  enc_stoc : String
  mac_ctos : String
  mac_stoc : String
  comp_ctos : String
  comp_stoc : String
  lang_ctos : String
  lang_stoc : String
}

///|
/// strict-kex 扩展标记(rfc8308-ish OpenSSH 惯例;
/// C:kex_proposal_populate_entries 追加于 kex 列表尾)
const KEX_STRICT_MARKER_C : String = "kex-strict-c-v00@openssh.com"

///|
/// 本实现子集的客户端默认提案。
///
/// mac 类目按 OpenSSH 默认表前两项发送(AEAD 下协商结果弃用,
/// 决策 D3);comp none;lang 空;follows 恒 false(决策 D4)。
/// Loop #60: the MAC list is no longer "the first two entries of OpenSSH's
/// default table". `hmac-sha2-256-etm@openssh.com` used to lead it, and
/// `src/bpacket` has no EtM branch at all (packet_ctx.mbt:32) -- the name was
/// harmless only because the cipher below is an AEAD, where the MAC is never
/// computed. That is a coincidence, not a property: change one line of
/// `enc_ctos` to `aes128-ctr` and `negotiate` hands back the EtM name (its
/// first-match scan runs over *our* list), `we_need_for` aborts, and the
/// client that was "advertising OpenSSH's defaults" cannot complete a
/// handshake it just agreed to. The list now carries only what
/// `@bpacket.check_runnable` accepts.
pub fn Proposal::default_client(strict_kex : Bool) -> Proposal {
  let kex = if strict_kex {
    "curve25519-sha256,\{KEX_STRICT_MARKER_C}"
  } else {
    "curve25519-sha256"
  }
  {
    kex_algs: kex,
    hostkey_algs: "ssh-ed25519",
    enc_ctos: "chacha20-poly1305@openssh.com",
    enc_stoc: "chacha20-poly1305@openssh.com",
    mac_ctos: "hmac-sha2-256",
    mac_stoc: "hmac-sha2-256",
    comp_ctos: "none",
    comp_stoc: "none",
    lang_ctos: "",
    lang_stoc: "",
  }
}

///|
/// ASCII 字符串转 bytes(提案常量专用)
fn pf_ascii(s : String) -> FixedArray[Byte] {
  let a : FixedArray[Byte] = FixedArray::make(s.length(), b'\x00')
  for i = 0; i < s.length(); i = i + 1 {
    a[i] = (s[i].to_int() & 0xFF).to_byte()
  }
  a
}

///|
fn pf_cat(parts : Array[FixedArray[Byte]]) -> FixedArray[Byte] {
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
fn pf_u32(v : Int32) -> FixedArray[Byte] {
  let a : FixedArray[Byte] = FixedArray::make(4, b'\x00')
  let u : UInt32 = v.reinterpret_as_uint()
  a[0] = ((u >> 24) & 0xFFU).to_byte()
  a[1] = ((u >> 16) & 0xFFU).to_byte()
  a[2] = ((u >> 8) & 0xFFU).to_byte()
  a[3] = (u & 0xFFU).to_byte()
  a
}

///|
/// RFC 4251 string(cstring 同布局)
fn pf_wstr(b : FixedArray[Byte]) -> FixedArray[Byte] {
  pf_cat([pf_u32(b.length()), b])
}

///|
/// KEXINIT payload(kex_prop2buf 布局,**不含** type 字节):
///   cookie(16) ‖ 10×string(类目序) ‖ u8(follows=0) ‖ u32(reserved=0)
pub fn kexinit_payload(
  cookie : FixedArray[Byte],
  p : Proposal,
) -> FixedArray[Byte] {
  if cookie.length() != KEX_COOKIE_LEN {
    abort("kexinit_payload: cookie must be \{KEX_COOKIE_LEN} bytes")
  }
  let fields : Array[String] = [
    p.kex_algs,
    p.hostkey_algs,
    p.enc_ctos,
    p.enc_stoc,
    p.mac_ctos,
    p.mac_stoc,
    p.comp_ctos,
    p.comp_stoc,
    p.lang_ctos,
    p.lang_stoc,
  ]
  let parts : Array[FixedArray[Byte]] = [cookie]
  for i = 0; i < fields.length(); i = i + 1 {
    parts.push(pf_wstr(pf_ascii(fields[i])))
  }
  parts.push(FixedArray::from_array([b'\x00'])) // first_kex_packet_follows
  parts.push(pf_u32(0)) // reserved
  pf_cat(parts)
}

///|
/// 解析对端 KEXINIT payload(kex_buf2prop 子集)
pub(all) struct PeerKexInit {
  cookie : FixedArray[Byte]
  kex_algs : String
  hostkey_algs : String
  enc_ctos : String
  enc_stoc : String
  mac_ctos : String
  mac_stoc : String
  comp_ctos : String
  comp_stoc : String
  lang_ctos : String
  lang_stoc : String
  follows : Bool
}

///|
fn pf_bytes_to_string(b : FixedArray[Byte]) -> String {
  // 提案类目是 ASCII 名单;逐字节构造(非 UTF-8 校验,与 C 的 char* 透传一致)
  let sb = StringBuilder()
  for i = 0; i < b.length(); i = i + 1 {
    sb.write_char(Int32::unsafe_to_char(b[i].to_int()))
  }
  sb.to_string()
}

///|
/// 解析失败(短 buffer / 尾随残余)→ None
pub fn parse_kexinit(payload : FixedArray[Byte]) -> PeerKexInit? {
  let len = payload.length()
  if len < KEX_COOKIE_LEN + 1 {
    return None
  }
  // cookie(16)
  let cookie : FixedArray[Byte] = FixedArray::make(KEX_COOKIE_LEN, b'\x00')
  for i = 0; i < KEX_COOKIE_LEN; i = i + 1 {
    cookie[i] = payload[i]
  }
  let mut off = KEX_COOKIE_LEN
  // 10 strings
  let strs : Array[FixedArray[Byte]] = []
  for _i = 0; _i < 10; _i = _i + 1 {
    if off + 4 > len {
      return None
    }
    let slen = ((payload[off].to_uint() << 24) |
    (payload[off + 1].to_uint() << 16) |
    (payload[off + 2].to_uint() << 8) |
    payload[off + 3].to_uint()).reinterpret_as_int()
    off = off + 4
    if slen < 0 || off + slen > len {
      return None
    }
    let s : FixedArray[Byte] = FixedArray::make(slen, b'\x00')
    for j = 0; j < slen; j = j + 1 {
      s[j] = payload[off + j]
    }
    off = off + slen
    strs.push(s)
  }
  // u8 follows
  if off >= len {
    return None
  }
  let follows = payload[off].to_int()
  off = off + 1
  // u32 reserved
  if off + 4 > len {
    return None
  }
  off = off + 4
  // 尾随残余检查
  if off != len {
    return None
  }
  Some({
    cookie,
    kex_algs: pf_bytes_to_string(strs[0]),
    hostkey_algs: pf_bytes_to_string(strs[1]),
    enc_ctos: pf_bytes_to_string(strs[2]),
    enc_stoc: pf_bytes_to_string(strs[3]),
    mac_ctos: pf_bytes_to_string(strs[4]),
    mac_stoc: pf_bytes_to_string(strs[5]),
    comp_ctos: pf_bytes_to_string(strs[6]),
    comp_stoc: pf_bytes_to_string(strs[7]),
    lang_ctos: pf_bytes_to_string(strs[8]),
    lang_stoc: pf_bytes_to_string(strs[9]),
    follows: follows != 0,
  })
}

///|
/// 协商错误类目(C: SSH_ERR_NO_*_ALG_MATCH 分类学,子集四类)
pub(all) enum NegotiationError {
  NoKexAlg
  NoHostkeyAlg
  NoCipherAlg
  NoMacAlg
  NoCompAlg
}

///|
/// 协商结果(本子集关心的四个字段;MAC 在 AEAD 下不产出)
pub(all) struct Negotiated {
  kex_alg : String
  hostkey_alg : String
  cipher_ctos : String
  cipher_stoc : String
  mac_ctos : String
  mac_stoc : String
  comp_ctos : String
  comp_stoc : String
}

///|
/// 逗号分隔名表的 first-match(match.c match_list):
/// 返回客户端列表中第一个也出现在服务端列表的项
fn pf_match_list(client : String, server : String) -> String? {
  let s_names : Array[String] = []
  // 服务端列表拆分
  let mut start = 0
  for i = 0; i <= server.length(); i = i + 1 {
    if i == server.length() || server[i] == ',' {
      if i > start {
        s_names.push(server[start:i].to_owned())
      }
      start = i + 1
    }
  }
  // 客户端列表顺序扫描
  start = 0
  for i = 0; i <= client.length(); i = i + 1 {
    if i == client.length() || client[i] == ',' {
      if i > start {
        let cand = client[start:i].to_owned()
        for j = 0; j < s_names.length(); j = j + 1 {
          if cand == s_names[j] {
            return Some(cand)
          }
        }
      }
      start = i + 1
    }
  }
  None
}

///|
/// 逐类目协商;任一必需类目无交集 → 对应错误
pub fn negotiate(
  my : Proposal,
  peer : PeerKexInit,
) -> Result[Negotiated, NegotiationError] {
  let kex = pf_match_list(my.kex_algs, peer.kex_algs)
  let kex = match kex {
    Some(s) => s
    None => return Err(NoKexAlg)
  }
  let hk = pf_match_list(my.hostkey_algs, peer.hostkey_algs)
  let hk = match hk {
    Some(s) => s
    None => return Err(NoHostkeyAlg)
  }
  let ecc = pf_match_list(my.enc_ctos, peer.enc_ctos)
  let ecc = match ecc {
    Some(s) => s
    None => return Err(NoCipherAlg)
  }
  let ecs = pf_match_list(my.enc_stoc, peer.enc_stoc)
  let ecs = match ecs {
    Some(s) => s
    None => return Err(NoCipherAlg)
  }
  let cc = pf_match_list(my.comp_ctos, peer.comp_ctos)
  let cc = match cc {
    Some(s) => s
    None => return Err(NoCompAlg)
  }
  let cs = pf_match_list(my.comp_stoc, peer.comp_stoc)
  let cs = match cs {
    Some(s) => s
    None => return Err(NoCompAlg)
  }
  // MAC is negotiated like any other list. It was previously dropped because
  // the only cipher this client offered was an AEAD, where MAC is implicit;
  // Loop #31 negotiates aes128-ctr + hmac-sha2-256, so the agreed name is
  // needed to derive the right keys.
  let mc = pf_match_list(my.mac_ctos, peer.mac_ctos)
  let mc = match mc {
    Some(s) => s
    None => return Err(NoMacAlg)
  }
  let ms = pf_match_list(my.mac_stoc, peer.mac_stoc)
  let ms = match ms {
    Some(s) => s
    None => return Err(NoMacAlg)
  }
  Ok({
    kex_alg: kex,
    hostkey_alg: hk,
    cipher_ctos: ecc,
    cipher_stoc: ecs,
    mac_ctos: mc,
    mac_stoc: ms,
    comp_ctos: cc,
    comp_stoc: cs,
  })
}
