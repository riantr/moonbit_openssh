///| DH group 14 KEX computation (Loop #26 G2)
///
/// RFC 4253 §8 SSH-DH-SHA256 KEX:
///   1. Client generates random x (1 < x < p-1)
///   2. Client computes e = g^x mod p
///   3. Server generates random y, computes f = g^y mod p
///   4. Client computes K = f^x mod p
///   5. Server computes K = e^y mod p (same K)
///   6. Both compute exchange hash H = SHA-256(V_C || V_S || I_C || I_S || K_S || e || f || K)
///   7. H is signed by server with host key (Loop #27+)

///|
/// DH public value: e = g^x mod p
///
///   The prime is fixed per group, so callers doing several exponentiations
///   against the same group should build a Montgomery context once with
///   `dh_ctx` and use `dh_pub_ctx` / `dh_shared_ctx` instead. That avoids
///   recomputing n' and R^2 for each of the three modexps an SSH-DH exchange
///   performs (e, f, and the shared secret).
pub fn dh_pub(
  g : @bigint.BigNat,
  x : @bigint.BigNat,
  p : @bigint.BigNat,
) -> @bigint.BigNat {
  @bigint.BigNat::mod_pow_auto(g, x, p)
}

///|
/// DH shared secret: K = f^x mod p
pub fn dh_shared(
  f : @bigint.BigNat,
  x : @bigint.BigNat,
  p : @bigint.BigNat,
) -> @bigint.BigNat {
  @bigint.BigNat::mod_pow_auto(f, x, p)
}

///|
/// Build a reusable Montgomery context for a DH group prime.
pub fn dh_ctx(p : @bigint.BigNat) -> @bigint.MontCtx {
  let k = p.limb64_len()
  @bigint.MontCtx::new(p.to_limbs64(k), k)
}

///|
/// DH public value using a pre-built context.
pub fn dh_pub_ctx(
  ctx : @bigint.MontCtx,
  g : @bigint.BigNat,
  x : @bigint.BigNat,
) -> @bigint.BigNat {
  @bigint.mont_pow_with(ctx, g, x)
}

///|
/// DH shared secret using a pre-built context.
pub fn dh_shared_ctx(
  ctx : @bigint.MontCtx,
  f : @bigint.BigNat,
  x : @bigint.BigNat,
) -> @bigint.BigNat {
  @bigint.mont_pow_with(ctx, f, x)
}

///|
/// RFC 4253 §8 exchange hash
///   H = SHA-256(V_C || V_S || I_C || I_S || K_S || e || f || K)
///   where V_C/V_S = SSH version strings (e.g. "SSH-2.0-OpenSSH_9.0")
///   I_C/I_S = KEXINIT payload bytes
///   K_S = server host key blob (mpint format)
///   e/f/K = DH public values / shared secret (mpint format)
pub fn exchange_hash(
  v_c : FixedArray[Byte],
  v_s : FixedArray[Byte],
  i_c : FixedArray[Byte],
  i_s : FixedArray[Byte],
  k_s : FixedArray[Byte],
  e : FixedArray[Byte],
  f : FixedArray[Byte],
  k : FixedArray[Byte],
) -> FixedArray[Byte] {
  // Concatenate
  let total_len = v_c.length() +
    v_s.length() +
    i_c.length() +
    i_s.length() +
    k_s.length() +
    e.length() +
    f.length() +
    k.length()
  let buf : FixedArray[Byte] = FixedArray::make(total_len, b'\x00')
  let mut off = 0
  let mut i = 0
  while i < v_c.length() {
    buf[off + i] = v_c[i]
    i = i + 1
  }
  off = off + v_c.length()
  i = 0
  while i < v_s.length() {
    buf[off + i] = v_s[i]
    i = i + 1
  }
  off = off + v_s.length()
  i = 0
  while i < i_c.length() {
    buf[off + i] = i_c[i]
    i = i + 1
  }
  off = off + i_c.length()
  i = 0
  while i < i_s.length() {
    buf[off + i] = i_s[i]
    i = i + 1
  }
  off = off + i_s.length()
  i = 0
  while i < k_s.length() {
    buf[off + i] = k_s[i]
    i = i + 1
  }
  off = off + k_s.length()
  i = 0
  while i < e.length() {
    buf[off + i] = e[i]
    i = i + 1
  }
  off = off + e.length()
  i = 0
  while i < f.length() {
    buf[off + i] = f[i]
    i = i + 1
  }
  off = off + f.length()
  i = 0
  while i < k.length() {
    buf[off + i] = k[i]
    i = i + 1
  }
  @sha256.sha256(buf)
}
