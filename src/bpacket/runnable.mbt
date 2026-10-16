///| Loop #60: the authoritative list of algorithms this transport can RUN.
///

///|
///
/// `Mode` has exactly three constructors (packet_ctx.mbt:34-38), so there are
/// exactly two encrypted transports behind them:
///
/// | cipher                          | Mode         | packet-layer files             |
/// |---------------------------------|--------------|--------------------------------|
/// | `chacha20-poly1305@openssh.com` | `Aead`       | chacha_*.mbt + poly1305_*.mbt   |
/// | `aes128-ctr`                    | `MacEncrypt` | aes_ctr_mac.mbt                |
///
/// and exactly one MAC that the `MacEncrypt` branch knows how to compute.
/// Everything else is a name this client can spell but not run.
///
/// Two questions live here, and they are not the same question:
///
/// 1. `transport_params(cipher, mac)` -- given the pair that was *negotiated*,
///    what does the packet layer actually do? For an AEAD cipher the MAC is
///    never consulted (`maclen_of(Aead(_)) == 0`, packet_ctx.mbt:77-83), so the
///    MAC argument is irrelevant and an unknown MAC name is not an error.
///
/// 2. `check_runnable(cipher, mac)` -- is this *proposal* honorable? Every name
///    the client puts on the wire is a promise. This rejects an unrunnable MAC
///    name even under an AEAD cipher, because the promise is about the client,
///    not about the cipher it happens to pick today.
///
/// Keeping these separate is the whole point. `default_client` shipped
/// `hmac-sha2-256-etm@openssh.com` under an AEAD cipher and was therefore
/// harmless -- not because the design was right, but because the cipher made
/// the lie invisible. Question 1 cannot see that. Question 2 can.
pub(all) enum TransportFamily {
  AeadChachaPoly1305
  MacEncryptAes128CtrHmacSha256
}

///|
/// The two cipher names this transport has a `Mode` constructor for.
pub fn runnable_cipher_names() -> Array[String] {
  ["chacha20-poly1305@openssh.com", "aes128-ctr"]
}

///|
/// The MAC names this transport can compute under `MacEncrypt`.
///
/// Empty for an AEAD cipher, which carries no separate MAC -- this list is the
/// answer to "which MAC could this client actually run", not "which MAC will
/// this proposal use".
pub fn runnable_mac_names() -> Array[String] {
  ["hmac-sha2-256"]
}

///|
/// Which `Mode` branch backs this cipher name, or `None` if there is none.
///
/// `aes128-gcm@openssh.com` and `aes256-gcm@openssh.com` are deliberately
/// `None`: `src/aes` implements GCM, but nothing in `src/bpacket` has a branch
/// that frames a GCM packet, so "the primitive exists" is not "the transport
/// runs it". That distinction is the one this file exists to keep.
pub fn transport_family(cipher : String) -> TransportFamily? {
  if cipher == "chacha20-poly1305@openssh.com" {
    Some(AeadChachaPoly1305)
  } else if cipher == "aes128-ctr" {
    Some(MacEncryptAes128CtrHmacSha256)
  } else {
    None
  }
}

///|
/// Does this cipher consume a separate MAC? (cipher.c:93 the second column)
pub fn cipher_needs_mac(cipher : String) -> Bool {
  match transport_family(cipher) {
    Some(AeadChachaPoly1305) => false
    Some(MacEncryptAes128CtrHmacSha256) => true
    None => false
  }
}

///|
/// Whether a negotiated cipher name has a `Mode` branch here.
pub fn is_runnable_cipher(cipher : String) -> Bool {
  transport_family(cipher) is Some(_)
}

///|
/// Whether this transport can compute this MAC under `MacEncrypt`.
pub fn is_runnable_mac(mac : String) -> Bool {
  for n in runnable_mac_names() {
    if n == mac {
      return true
    }
  }
  false
}

///|
/// `(key_len, block_size, iv_len, mac_key_len)` for a negotiated pair.
///
/// Column order is OpenSSH's `struct sshcipher` (cipher.c:83-88):
/// `(name, block_size, key_len, iv_len, auth_len, flags, evp)`. Two rows matter:
///
/// ```
/// cipher.c:93   { "aes128-ctr", 16, 16, 0, 0, 0, EVP_aes_128_ctr }
/// cipher.c:105  { "chacha20-poly1305@openssh.com",
///                          8, 64, 0, 16, CFLAG_CHACHAPOLY, NULL }
/// ```
///
/// `iv_len` is the **effective** length from `cipher_ivlen` (cipher.c:170-178),
/// not the raw table column. For aes128-ctr the column says 0 and `cipher_ivlen`
/// falls back to `block_size`, giving 16 -- which is why `AesCtrMacCtx::new`
/// wants a 16-byte counter. For chacha20-poly1305 the `CFLAG_CHACHAPOLY` test
/// makes it return the column verbatim, 0: the sequence number is the nonce and
/// no IV is derived at all. Substituting 16 there would hand `derive_keys` an
/// IV it must not consume.
///
/// `mac_key_len` is 0 for the AEAD because it carries no separate MAC; that
/// matches `authlen_of(Aead(_)) == 16` (packet_ctx.mbt:64-70) against the
/// table's `auth_len` of 16.
///
/// Aborts on a cipher with no `Mode` branch. This is the loud half of the fix:
/// before Loop #60 `we_need_for` (sshclient/live.mbt) accepted four ciphers and
/// five MACs, then `live.mbt` truncated the derived key to 16 bytes and built
/// an `AesCtrMacCtx` regardless. A proposal naming `aes256-ctr` would therefore
/// have run **aes128-ctr with the first 16 bytes of a 256-bit key** and said
/// nothing. That was latent -- no live proposal offered it -- but it was one
/// line away from being live, and it failed open rather than closed.
pub fn transport_params(
  cipher : String,
  mac : String,
) -> (Int32, Int32, Int32, Int32) {
  match transport_family(cipher) {
    Some(AeadChachaPoly1305) => (64, 8, 0, 0)
    Some(MacEncryptAes128CtrHmacSha256) =>
      if mac == "hmac-sha2-256" {
        (16, 16, 16, 32)
      } else {
        abort("transport_params: cipher " + cipher + " cannot run mac " + mac)
      }
    None => abort("transport_params: no packet-layer path for cipher " + cipher)
  }
}

///|
/// Authentication **tag** length carried on the wire for this cipher -- the
/// counterpart of OpenSSH's `auth_len` column (cipher.c).
///
/// This is a different quantity from both `maclen_of` (packet_ctx.mbt:77-83,
/// 32 for the encrypt-and-MAC path) and the `mac_key_len` slot of
/// `transport_params` (a key length). In OpenSSH's model `auth_len` is the AEAD
/// tag only: `aes128-ctr` has `auth_len` 0 and carries a separate 32-byte MAC,
/// so returning 32 here would be wrong in a way that looks right.
///
/// Loop #60's gate caught exactly that -- the first version returned 32 for
/// aes128-ctr and the C table said 0.
pub fn authlen_for(cipher : String) -> Int32 {
  match transport_family(cipher) {
    Some(AeadChachaPoly1305) => 16
    Some(MacEncryptAes128CtrHmacSha256) => 0
    None => abort("authlen_for: no packet-layer path for cipher " + cipher)
  }
}

///|
/// Split a comma-separated proposal list into its names.
///
/// Proposal names are ASCII and never empty, but an empty category is a legal
/// wire value (`lang_ctos` is "" in `default_client`), so it yields no names
/// rather than one empty name.
fn split_alg_list(list : String) -> Array[String] {
  let out : Array[String] = []
  let mut start = 0
  for i = 0; i <= list.length(); i = i + 1 {
    if i == list.length() || list[i] == ',' {
      if i > start {
        out.push(list[start:i].to_owned())
      }
      start = i + 1
    }
  }
  out
}

///|
/// The first name in `cipher_list` that has no `Mode` branch, or `None`.
///
/// This is the raw material for the Loop #60 invariant. It is deliberately a
/// separate pass from `check_runnable` so a caller can report **every**
/// offending name rather than stopping at the first.
pub fn first_unrunnable_cipher(cipher_list : String) -> String? {
  for name in split_alg_list(cipher_list) {
    if !is_runnable_cipher(name) {
      return Some(name)
    }
  }
  None
}

///|
/// The first name in `mac_list` this transport cannot compute, or `None`.
pub fn first_unrunnable_mac(mac_list : String) -> String? {
  for name in split_alg_list(mac_list) {
    if !is_runnable_mac(name) {
      return Some(name)
    }
  }
  None
}

///|
/// Is this proposal honorable? `None` when it is, else the first name that
/// over-promises.
///
/// An empty cipher list answers `None` -- offering nothing is not a false
/// promise, it is an immediate `NoCipherAlg` at negotiation time, which is a
/// different failure with an existing error path.
pub fn check_runnable(cipher_list : String, mac_list : String) -> String? {
  match first_unrunnable_cipher(cipher_list) {
    Some(bad) => Some("cipher:" + bad)
    None =>
      match first_unrunnable_mac(mac_list) {
        Some(bad) => Some("mac:" + bad)
        None => None
      }
  }
}

///|
/// The MAC `negotiate` would actually pick for `cipher`, given a client's list.
///
/// `kexflow::pf_match_list` scans the **client's** list first, so the first
/// runnable name a client offers is the one it will be handed whenever the
/// server also supports it. That makes "what did I promise under this cipher"
/// a question about the client's own ordering, and it is why an unrunnable name
/// at position 0 (`hmac-sha2-256-etm@openssh.com` in `default_client`) is worse
/// than one at position 1.
pub fn selected_mac(cipher : String, client_mac_list : String) -> String? {
  if !cipher_needs_mac(cipher) {
    return None
  }
  for name in split_alg_list(client_mac_list) {
    if is_runnable_mac(name) {
      return Some(name)
    }
  }
  None
}
