///| BigNat basic ops (Loop #26 G1)
///
/// 32-bit limbs (UInt), little-endian word order.
/// limbs[0] = LSB, limbs[len-1] = MSB.
///
/// Unsigned only (negative not supported for Loop #26/27 use cases).

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
  let mut bi = 0
  let mut ti = top_byte_idx
  while ti >= 0 {
    bytes[bi] = ((top_limb >> (ti * 8)) & 0xFFU).to_byte()
    bi = bi + 1
    ti = ti - 1
  }
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

///| SSH wire mpint encoding (RFC 4251 §5)
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
///   Standard algorithm: at each (i, j), multiply a[i] * b[j] (64-bit) and add to
///   r[i+j] with proper carry chain. r[] is UInt32 limbs (LE).
pub fn BigNat::mul(a : BigNat, b : BigNat) -> BigNat {
  if a.len == 0 || b.len == 0 {
    return BigNat::from_uint64(0UL)
  }
  let out_len = a.len + b.len
  let result : FixedArray[UInt] = FixedArray::make(out_len, 0U)
  let mut i = 0
  while i < a.len {
    let a_val : UInt64 = a.limbs[i].to_uint64()
    if a_val > 0UL {
      let mut carry : UInt64 = 0UL
      let mut j = 0
      while j < b.len {
        let b_val : UInt64 = b.limbs[j].to_uint64()
        let prod : UInt64 = a_val * b_val
        let prod_low : UInt = (prod & 0xFFFFFFFFUL).to_uint()
        let prod_high : UInt = ((prod >> 32) & 0xFFFFFFFFUL).to_uint()
        let pos = i + j
        let cur : UInt = result[pos]
        let cur64 : UInt64 = cur.to_uint64()
        let prod_low64 : UInt64 = prod_low.to_uint64()
        let total : UInt64 = cur64 + prod_low64 + carry
        result[pos] = (total & 0xFFFFFFFFUL).to_uint()
        carry = (total >> 32) + prod_high.to_uint64()
        j = j + 1
      }
      if carry > 0UL {
        let pos = i + b.len
        if pos < out_len {
          let cur : UInt = result[pos]
          let total : UInt64 = cur.to_uint64() + carry
          result[pos] = (total & 0xFFFFFFFFUL).to_uint()
          let mut new_carry : UInt64 = total >> 32
          let mut k = pos + 1
          while new_carry > 0UL && k < out_len {
            let cur_k : UInt = result[k]
            let total_k : UInt64 = cur_k.to_uint64() + new_carry
            result[k] = (total_k & 0xFFFFFFFFUL).to_uint()
            new_carry = total_k >> 32
            k = k + 1
          }
          ignore(new_carry)
        }
      }
    }
    i = i + 1
  }
  let mut new_len = result.length()
  while new_len > 0 && result[new_len - 1] == 0U {
    new_len = new_len - 1
  }
  if new_len == 0 { new_len = 1 }
  { limbs: result, len: new_len }
}

///| BigNat % BigNat (a mod b) -- binary long division with multi-bit shifts
pub fn BigNat::mod(a : BigNat, b : BigNat) -> BigNat {
  if b.len == 0 {
    abort("BigNat::mod: divide by zero")
  }
  if BigNat::cmp(a, b) < 0 {
    return { limbs: a.limbs, len: a.len }
  }
  let a_bits = a.bit_length()
  let b_bits = b.bit_length()
  if a_bits <= b_bits {
    return { limbs: a.limbs, len: a.len }
  }
  let mut shift = a_bits - b_bits
  let mut shifted_b = BigNat::shift_left_bits(b, (shift % 32).reinterpret_as_uint())
  let limb_shift = shift / 32
  if limb_shift > 0 {
    let new_limbs : FixedArray[UInt] = FixedArray::make(shifted_b.len + limb_shift, 0U)
    let mut i = 0
    while i < shifted_b.len {
      new_limbs[i + limb_shift] = shifted_b.limbs[i]
      i = i + 1
    }
    shifted_b = { limbs: new_limbs, len: new_limbs.length() }
  }
  let mut rem : BigNat = { limbs: a.limbs, len: a.len }
  while shift >= 0 {
    if BigNat::cmp(rem, shifted_b) >= 0 {
      rem = BigNat::sub(rem, shifted_b)
    }
    if shift > 0 {
      shifted_b = BigNat::shift_right_1(shifted_b)
    }
    shift = shift - 1
  }
  rem
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

// ============================================================================
// Multi-bit shifts for mod
// ============================================================================

///| BigNat left shift by s bits (s < 32, 0 <= s <= 32)
fn BigNat::shift_left_bits(a : BigNat, s : UInt) -> BigNat {
  if s == 0U { return { limbs: a.limbs, len: a.len } }
  let s_int : Int = s.reinterpret_as_int()
  let out_len = a.len + 1
  let out : FixedArray[UInt] = FixedArray::make(out_len, 0U)
  let mut carry : UInt = 0U
  let mut i = 0
  while i < a.len {
    let v = a.limbs[i]
    out[i] = ((v << s_int) | carry) & 0xFFFFFFFFU
    carry = v >> (32 - s_int)
    i = i + 1
  }
  out[a.len] = carry
  let mut new_len = out_len
  while new_len > 0 && out[new_len - 1] == 0U {
    new_len = new_len - 1
  }
  if new_len == 0 { new_len = 1 }
  { limbs: out, len: new_len }
}

///| BigNat right shift by 1 bit
fn BigNat::shift_right_1(a : BigNat) -> BigNat {
  if a.len == 0 { return a }
  let out_len = if a.len > 1 { a.len } else { 1 }
  let out : FixedArray[UInt] = FixedArray::make(out_len, 0U)
  let mut carry : UInt = 0U
  let mut i = a.len - 1
  while i >= 0 {
    let v = a.limbs[i]
    out[i] = (v >> 1) | carry
    carry = (v & 1U) << 31
    i = i - 1
  }
  let mut new_len = out_len
  while new_len > 0 && out[new_len - 1] == 0U {
    new_len = new_len - 1
  }
  if new_len == 0 { new_len = 1 }
  { limbs: out, len: new_len }
}