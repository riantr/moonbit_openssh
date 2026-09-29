///| BigNat basic ops (Loop #26 G1)
///
/// 32-bit limbs (UInt), little-endian word order.
/// limbs[0] = LSB, limbs[len-1] = MSB.
///
/// Unsigned only (negative not supported for Loop #26/27 use cases).
///
/// Why UInt (32-bit) limbs:
///   - UInt * UInt = UInt (32-bit, no overflow during single mul)
///   - For schoolbook mul: 32*32 = 64-bit product, accumulated via UInt64
///   - For DH group 14 (256 bytes = 2048 bits), n_limbs = 64

// ============================================================================
// BigNat struct + constructors
// ============================================================================

///| Multi-precision unsigned natural (limbs little-endian, limbs[0] = LSB)
pub struct BigNat {
  limbs : FixedArray[UInt]
  len : Int
}

///| Construct BigNat from UInt64
pub fn BigNat::from_uint64(v : UInt64) -> BigNat {
  let limbs : FixedArray[UInt] = FixedArray::make(2, 0U)
  limbs[0] = (v & 0xFFFFFFFFUL).to_uint()
  limbs[1] = (v >> 32).to_uint()
  let mut len = 2
  while len > 0 && limbs[len - 1] == 0U {
    len = len - 1
  }
  if len == 0 { len = 1 }
  { limbs, len }
}

///| Construct BigNat from little-endian bytes
pub fn BigNat::from_bytes_le(bytes : FixedArray[Byte]) -> BigNat {
  let n_limbs = (bytes.length() + 3) / 4
  let limbs : FixedArray[UInt] = FixedArray::make(if n_limbs < 1 { 1 } else { n_limbs }, 0U)
  let mut i = 0
  while i < bytes.length() {
    let limb_idx = i / 4
    let byte_idx = i % 4
    let byte_v : UInt = bytes[i].to_uint()
    limbs[limb_idx] = limbs[limb_idx] | (byte_v << (byte_idx * 8))
    i = i + 1
  }
  let mut len = limbs.length()
  while len > 0 && limbs[len - 1] == 0U {
    len = len - 1
  }
  { limbs, len }
}

///| Construct BigNat from big-endian bytes (RFC 4251 SSH wire format)
pub fn BigNat::from_bytes_be(bytes : FixedArray[Byte]) -> BigNat {
  let n_limbs = (bytes.length() + 3) / 4
  let limbs : FixedArray[UInt] = FixedArray::make(if n_limbs < 1 { 1 } else { n_limbs }, 0U)
  let mut i = 0
  let mut bi = bytes.length() - 1
  while i < bytes.length() {
    let limb_idx = i / 4
    let byte_idx = i % 4
    let byte_v : UInt = bytes[bi].to_uint()
    limbs[limb_idx] = limbs[limb_idx] | (byte_v << (byte_idx * 8))
    i = i + 1
    bi = bi - 1
  }
  let mut len = limbs.length()
  while len > 0 && limbs[len - 1] == 0U {
    len = len - 1
  }
  { limbs, len }
}

///| BigNat -> big-endian bytes (RFC 4251 SSH wire format)
pub fn BigNat::to_bytes_be(self : BigNat) -> FixedArray[Byte] {
  if self.len == 0 {
    return FixedArray::make(0, b'\x00')
  }
  let top_limb = self.limbs[self.len - 1]
  let mut top_byte_idx : Int = 3
  while top_byte_idx > 0 && ((top_limb >> (top_byte_idx * 8)) & 0xFFU) == 0U {
    top_byte_idx = top_byte_idx - 1
  }
  let byte_len = (self.len - 1) * 4 + top_byte_idx + 1
  let bytes : FixedArray[Byte] = FixedArray::make(byte_len, b'\x00')
  // Write MSB first: bytes[0] is the most significant byte (top of top limb)
  let mut bi = 0
  // Write top limb bytes from top_byte_idx down to 0
  let mut ti = top_byte_idx
  while ti >= 0 {
    // Shift right by ti*8 bits and take low byte
    let shifted : UInt = top_limb >> (ti * 8)
    let masked : UInt = shifted & 0xFFU
    bytes[bi] = masked.to_byte()
    bi = bi + 1
    ti = ti - 1
  }
  // Write remaining limbs (top-1 down to 0) each as 4 bytes high-to-low
  let mut li = self.len - 2
  while li >= 0 {
    let v = self.limbs[li]
    bytes[bi + 0] = ((v >> 24) & 0xFFU).to_byte()
    bytes[bi + 1] = ((v >> 16) & 0xFFU).to_byte()
    bytes[bi + 2] = ((v >> 8) & 0xFFU).to_byte()
    bytes[bi + 3] = (v & 0xFFU).to_byte()
    bi = bi + 4
    li = li - 1
  }
  bytes
}

///| SSH wire mpint encoding (RFC 4251 搂5)
pub fn BigNat::mpint_encode(self : BigNat) -> FixedArray[Byte] {
  let bytes = self.to_bytes_be()
  let needs_leading = bytes.length() > 0 && (bytes[0].to_int() & 0x80) != 0
  let payload_len = if needs_leading { bytes.length() + 1 } else { bytes.length() }
  let total_len = 4 + payload_len
  let out : FixedArray[Byte] = FixedArray::make(total_len, b'\x00')
  let len_u : UInt64 = payload_len.reinterpret_as_uint().to_uint64()
  out[0] = ((len_u >> 24) & 0xFFUL).to_byte()
  out[1] = ((len_u >> 16) & 0xFFUL).to_byte()
  out[2] = ((len_u >> 8) & 0xFFUL).to_byte()
  out[3] = (len_u & 0xFFUL).to_byte()
  if needs_leading {
    out[4] = b'\x00'
    let mut i = 0
    while i < bytes.length() {
      out[5 + i] = bytes[i]
      i = i + 1
    }
  } else {
    let mut i = 0
    while i < bytes.length() {
      out[4 + i] = bytes[i]
      i = i + 1
    }
  }
  out
}

// ============================================================================
// Basic ops (BigNat) -- schoolbook O(n^2)
// ============================================================================

///| Compare: -1 if a < b, 0 if a == b, +1 if a > b
pub fn BigNat::cmp(a : BigNat, b : BigNat) -> Int {
  if a.len != b.len {
    if a.len < b.len { return -1 } else { return 1 }
  }
  let mut i = a.len - 1
  while i >= 0 {
    if a.limbs[i] != b.limbs[i] {
      if a.limbs[i] < b.limbs[i] { return -1 } else { return 1 }
    }
    i = i - 1
  }
  0
}

///| BigNat is zero
pub fn BigNat::is_zero(self : BigNat) -> Bool {
  if self.len == 0 { return true }
  let mut i = 0
  while i < self.len {
    if self.limbs[i] != 0U { return false }
    i = i + 1
  }
  true
}

///| BigNat bit length (e.g. 0 -> 0, 1 -> 1, 0xff -> 8)
pub fn BigNat::bit_length(self : BigNat) -> Int {
  if self.len == 0 { return 0 }
  let top = self.limbs[self.len - 1]
  let mut bits = (self.len - 1) * 32
  let mut v = top
  while v > 0U {
    bits = bits + 1
    v = v >> 1
  }
  bits
}

///| BigNat + BigNat -> BigNat (assumes result length <= max(a.len, b.len) + 1)
pub fn BigNat::add(a : BigNat, b : BigNat) -> BigNat {
  let max_len = if a.len > b.len { a.len } else { b.len }
  let out_len = max_len + 1
  let out : FixedArray[UInt] = FixedArray::make(out_len, 0U)
  let mut carry : UInt64 = 0UL
  let mut i = 0
  while i < out_len {
    let a_val : UInt64 = if i < a.len { a.limbs[i].to_uint64() } else { 0UL }
    let b_val : UInt64 = if i < b.len { b.limbs[i].to_uint64() } else { 0UL }
    let sum : UInt64 = a_val + b_val + carry
    out[i] = (sum & 0xFFFFFFFFUL).to_uint()
    carry = sum >> 32
    i = i + 1
  }
  let mut new_len = out_len
  while new_len > 0 && out[new_len - 1] == 0U {
    new_len = new_len - 1
  }
  { limbs: out, len: new_len }
}

///| BigNat - BigNat -> BigNat (a >= b)
pub fn BigNat::sub(a : BigNat, b : BigNat) -> BigNat {
  if BigNat::cmp(a, b) < 0 {
    abort("BigNat::sub: a < b (negative not supported)")
  }
  let out_len = if a.len > 1 { a.len } else { 1 }
  let out : FixedArray[UInt] = FixedArray::make(out_len, 0U)
  let mut borrow : Int64 = 0L
  let mut i = 0
  while i < a.len {
    let b_val : Int64 = if i < b.len { b.limbs[i].to_int64() } else { 0L }
    let a_val : Int64 = a.limbs[i].to_int64()
    let diff : Int64 = a_val - b_val - borrow
    if diff < 0L {
      out[i] = ((diff + 0x100000000L).reinterpret_as_uint64() & 0xFFFFFFFFUL).to_uint()
      borrow = 1L
    } else {
      out[i] = (diff.reinterpret_as_uint64() & 0xFFFFFFFFUL).to_uint()
      borrow = 0L
    }
    i = i + 1
  }
  let mut new_len = a.len
  while new_len > 0 && out[new_len - 1] == 0U {
    new_len = new_len - 1
  }
  { limbs: out, len: new_len }
}

///| BigNat * BigNat -> BigNat (schoolbook, O(n*m))
///   32-bit limbs: 32*32 = 64-bit product, accumulated via UInt64 with multi-limb carry propagation
pub fn BigNat::mul(a : BigNat, b : BigNat) -> BigNat {
  if a.len == 0 || b.len == 0 {
    return BigNat::from_uint64(0UL)
  }
  let out_len = a.len + b.len
  let acc : FixedArray[UInt64] = FixedArray::make(out_len, 0UL)
  let mut i = 0
  while i < a.len {
    let a_val : UInt64 = a.limbs[i].to_uint64()
    if a_val > 0UL {
      let mut j = 0
      while j < b.len {
        let b_val : UInt64 = b.limbs[j].to_uint64()
        let prod : UInt64 = a_val * b_val
        let pos = i + j
        let cur = acc[pos]
        let sum1 = cur + prod
        acc[pos] = sum1
        if sum1 < cur || sum1 < prod {
          let mut k = pos + 1
          let mut c : UInt64 = 1UL
          while c > 0UL && k < out_len {
            let prev = acc[k]
            let new_v = prev + c
            acc[k] = new_v
            if new_v >= prev {
              c = 0UL
            }
            k = k + 1
          }
        }
        j = j + 1
      }
    }
    i = i + 1
  }
  let final_len = out_len + 1
  let final_out : FixedArray[UInt] = FixedArray::make(final_len, 0U)
  let mut carry64 : UInt64 = 0UL
  let mut k2 = 0
  while k2 < out_len {
    let v : UInt64 = acc[k2] + carry64
    final_out[k2] = (v & 0xFFFFFFFFUL).to_uint()
    carry64 = v >> 32
    k2 = k2 + 1
  }
  final_out[out_len] = carry64.to_uint()
  let mut new_len = final_out.length()
  while new_len > 0 && final_out[new_len - 1] == 0U {
    new_len = new_len - 1
  }
  { limbs: final_out, len: new_len }
}

///| BigNat % BigNat (a mod b) -- schoolbook long division (Knuth Algorithm D simplified)
///   Algorithm:
///     1. Normalize: shift b left by s bits such that b's top limb's MSB is 1.
///     2. For each limb position from high to low of normalized a:
///        - Estimate q_hat from top 2 limbs of remainder
///        - Multiply b by q_hat, subtract from remainder
///     3. Shift remainder right by s bits to get result.
pub fn BigNat::mod(a : BigNat, b : BigNat) -> BigNat {
  if b.len == 0 {
    abort("BigNat::mod: divide by zero")
  }
  if BigNat::cmp(a, b) < 0 {
    return { limbs: a.limbs, len: a.len }
  }
  // 1. Normalize: find s such that b_top has MSB set
  let mut s : Int = 0
  let b_top = b.limbs[b.len - 1]
  let mut v = b_top
  while v < 0x80000000U && s < 32 {
    v = v << 1
    s = s + 1
  }
  if s == 32 { s = 0 }  // already normalized
  // 2. Shift a and b left by s bits
  let norm_a : FixedArray[UInt] = FixedArray::make(a.len + 1, 0U)
  let norm_b : FixedArray[UInt] = FixedArray::make(b.len + 1, 0U)
  let s_inv = 32 - s
  let mut i = 0
  while i < a.len {
    let a_v = a.limbs[i]
    let next : UInt = if i + 1 < a.len { a.limbs[i + 1] } else { 0U }
    if s == 0 {
      norm_a[i] = a_v
    } else {
      norm_a[i] = ((a_v << s) | (next >> s_inv)) & 0xFFFFFFFFU
    }
    i = i + 1
  }
  if s > 0 && a.len > 0 {
    norm_a[a.len] = (a.limbs[a.len - 1] >> s_inv) & 0xFFFFFFFFU
  }
  let mut j = 0
  while j < b.len {
    let b_v = b.limbs[j]
    let next : UInt = if j + 1 < b.len { b.limbs[j + 1] } else { 0U }
    if s == 0 {
      norm_b[j] = b_v
    } else {
      norm_b[j] = ((b_v << s) | (next >> s_inv)) & 0xFFFFFFFFU
    }
    j = j + 1
  }
  if s > 0 && b.len > 0 {
    norm_b[b.len] = (b.limbs[b.len - 1] >> s_inv) & 0xFFFFFFFFU
  }
  // norm_a.len = a.len + 1 (always includes the top extra limb)
  // norm_b.len = b.len + 1
  let m = b.len  // effective m (ignoring top zero limb of norm_b)
  let n = (a.len + 1) - m  // n = (a.len + 1) - m; number of quotient limbs
  if n <= 0 {
    // a shifted by s is still < b shifted by s
    // This shouldn't happen if a >= b before shift
    return BigNat::mod_simple(a, b)
  }
  // 3. Knuth Algorithm D loop
  // We work with a mutable copy of norm_a as buffer (length a.len + 1)
  let buf : FixedArray[UInt] = FixedArray::make(a.len + 1, 0U)
  let mut bi = 0
  while bi <= a.len {
    buf[bi] = norm_a[bi]
    bi = bi + 1
  }
  let b_top_norm : UInt64 = norm_b[m - 1].to_uint64()
  let mut qi = n
  while qi > 0 {
    qi = qi - 1
    // q_hat estimate from buf[qi+m-1..qi+m+1]
    let a_high : UInt64 = if qi + m < buf.length() {
      (buf[qi + m].to_uint64() << 32) | buf[qi + m - 1].to_uint64()
    } else if qi + m - 1 < buf.length() {
      buf[qi + m - 1].to_uint64()
    } else {
      0UL
    }
    let a_next : UInt64 = if qi + m - 2 >= 0 && qi + m - 2 < buf.length() {
      buf[qi + m - 2].to_uint64()
    } else {
      0UL
    }
    // q_hat = a_high / b_top_norm, capped at 2^32 - 1
    let mut q_hat : UInt64 = if b_top_norm == 0UL { 0UL } else { a_high / b_top_norm }
    if q_hat > 0xFFFFFFFFUL { q_hat = 0xFFFFFFFFUL }
    // Refinement: if q_hat == 2^32 - 1 and b_top_norm == 2^32 - 1, OK; otherwise check
    let r_hat : UInt64 = a_high - q_hat * b_top_norm
    let b_second : UInt64 = if m >= 2 { norm_b[m - 2].to_uint64() } else { 0UL }
    // Check if q_hat * b_second > r_hat * 2^32 + a_next
    let lhs : UInt64 = q_hat * b_second
    let rhs : UInt64 = (r_hat << 32) | a_next
    if q_hat == b_top_norm || lhs > rhs {
      q_hat = q_hat - 1UL
    }
    // Subtract q_hat * norm_b from buf[qi..qi+m]
    let mut borrow : Int64 = 0L
    let mut jj = 0
    while jj < m {
      let prod : UInt64 = q_hat * norm_b[jj].to_uint64()
      let lo : UInt = (prod & 0xFFFFFFFFUL).to_uint()
      let hi : UInt = (prod >> 32).to_uint()
      // Subtract lo from buf[qi+jj] with borrow
      let cur_lo = buf[qi + jj].to_int64()
      let diff_lo : Int64 = cur_lo - lo.to_int64() - borrow
      if diff_lo < 0L {
        buf[qi + jj] = ((diff_lo + 0x100000000L).reinterpret_as_uint64() & 0xFFFFFFFFUL).to_uint()
        borrow = 1L
      } else {
        buf[qi + jj] = (diff_lo.reinterpret_as_uint64() & 0xFFFFFFFFUL).to_uint()
        borrow = 0L
      }
      // Subtract hi from buf[qi+jj+1] with carry from previous
      let cur_hi = buf[qi + jj + 1].to_int64()
      let diff_hi : Int64 = cur_hi - hi.to_int64() - borrow
      if diff_hi < 0L {
        buf[qi + jj + 1] = ((diff_hi + 0x100000000L).reinterpret_as_uint64() & 0xFFFFFFFFUL).to_uint()
        borrow = 1L
      } else {
        buf[qi + jj + 1] = (diff_hi.reinterpret_as_uint64() & 0xFFFFFFFFUL).to_uint()
        borrow = 0L
      }
      jj = jj + 1
    }
    // If buf[qi+m] underflowed (borrow propagated to it), add b back
    if borrow > 0L {
      // buf[qi..qi+m] -= norm_b[0..m-1] underflowed; add norm_b back to buf[qi..qi+m]
      let mut carry : UInt64 = 0UL
      let mut kk = 0
      while kk < m {
        let sum : UInt64 = buf[qi + kk].to_uint64() + norm_b[kk].to_uint64() + carry
        buf[qi + kk] = (sum & 0xFFFFFFFFUL).to_uint()
        carry = sum >> 32
        kk = kk + 1
      }
      // The top underflowed by 1, so we add back; buf[qi+m] should now be 0 (since b_top was subtracted)
      ignore(carry)
    }
  }
  // Remainder is in buf[0..m]; un-normalize by shifting right by s bits
  let remainder_arr : FixedArray[UInt] = FixedArray::make(m, 0U)
  let mut ri = 0
  while ri < m {
    let cur_v = buf[ri]
    let next_v : UInt = if ri + 1 < buf.length() { buf[ri + 1] } else { 0U }
    if s == 0 {
      remainder_arr[ri] = cur_v
    } else {
      remainder_arr[ri] = ((cur_v >> s) | (next_v << s_inv)) & 0xFFFFFFFFU
    }
    ri = ri + 1
  }
  // Normalize length
  let mut new_len = m
  while new_len > 0 && remainder_arr[new_len - 1] == 0U {
    new_len = new_len - 1
  }
  if new_len == 0 { new_len = 1 }
  { limbs: remainder_arr, len: new_len }
}

///| BigNat mod (simple fallback for small inputs)
fn BigNat::mod_simple(a : BigNat, b : BigNat) -> BigNat {
  if BigNat::cmp(a, b) < 0 {
    return { limbs: a.limbs, len: a.len }
  }
  let a_bits = a.bit_length()
  let b_bits = b.bit_length()
  let mut rem : BigNat = { limbs: a.limbs, len: a.len }
  let mut i = a_bits - b_bits
  while i >= 0 {
    let mut shifted_b : BigNat = b
    let mut k = 0
    while k < i {
      shifted_b = BigNat::shift_left_1(shifted_b)
      k = k + 1
    }
    if BigNat::cmp(rem, shifted_b) >= 0 {
      rem = BigNat::sub(rem, shifted_b)
    }
    i = i - 1
  }
  rem
}

///| BigNat left shift 1 bit
fn BigNat::shift_left_1(a : BigNat) -> BigNat {
  let out_len = a.len + 1
  let out : FixedArray[UInt] = FixedArray::make(out_len, 0U)
  let mut carry : UInt = 0U
  let mut i = 0
  while i < a.len {
    let v = a.limbs[i]
    out[i] = (v << 1) | carry
    carry = v >> 31
    i = i + 1
  }
  out[a.len] = carry
  let mut new_len = out_len
  while new_len > 0 && out[new_len - 1] == 0U {
    new_len = new_len - 1
  }
  { limbs: out, len: new_len }
}

// ============================================================================
// Debug helpers
// ============================================================================

///| BigNat -> hex string (uppercase, e.g. "1A2B3C")
pub fn BigNat::to_hex(self : BigNat) -> String {
  let bytes = self.to_bytes_be()
  let sb = StringBuilder()
  let hex : String = "0123456789ABCDEF"
  let mut i = 0
  while i < bytes.length() {
    let b = bytes[i].to_int()
    let hi = (b >> 4) & 0xF
    let lo = b & 0xF
    let hi_c = hex.unsafe_substring(start=hi, end=hi + 1)
    let lo_c = hex.unsafe_substring(start=lo, end=lo + 1)
    sb.write_string(hi_c)
    sb.write_string(lo_c)
    i = i + 1
  }
  sb.to_string()
}
