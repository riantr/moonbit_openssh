///| Loop #26 BigNat byte-exact verification (cmd/bigint_test)
///
/// KAT vs Python int reference:
///   mpint encoding (RFC 4251 §5)
///   pow(3, 5, 7) = 5
///   pow(2, 10, 1000) = 24
///   pow(2, 100, 13) = 3
///   pow(7, 50, 11) = 1
///   pow(0xDEADBEEF, 5, 0x12345) = 0x1850
///   pow(2, 0xCAFE, RFC 3526 group 14) = byte-exact vs Python pow()

fn main {
  // ============ G1 BigNat from_bytes_be known value ============
  let a_bytes : FixedArray[Byte] = FixedArray::from_array([
    0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
    0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
  ])
  let a = @bigint.BigNat::from_bytes_be(a_bytes)
  let a_hex = @bigint.BigNat::to_hex(a)
  println("bigint_be_a: " + a_hex)

  // ============ G2 from_bytes_le vs be round-trip ============
  let a_bytes_le : FixedArray[Byte] = FixedArray::from_array([
    0xF0, 0xDE, 0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12,
    0xBE, 0xBA, 0xFE, 0xCA, 0xEF, 0xBE, 0xAD, 0xDE,
  ])
  let a_le = @bigint.BigNat::from_bytes_le(a_bytes_le)
  let a_le_hex = @bigint.BigNat::to_hex(a_le)
  println("bigint_le_a: " + a_le_hex)

  // ============ G3 addition ============
  let b1_bytes : FixedArray[Byte] = FixedArray::from_array([
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
  ])
  let b1 = @bigint.BigNat::from_bytes_be(b1_bytes)
  let sum1 = @bigint.BigNat::add(a, b1)
  let sum1_hex = @bigint.BigNat::to_hex(sum1)
  println("add_1: " + sum1_hex)

  // ============ G4 multiplication + bit_length ============
  let bit_len_a = @bigint.BigNat::bit_length(a)
  println("bit_length_a: " + bit_len_a.to_string())

  // ============ G5 mpint encode RFC 4251 §5 ============
  let m_zero_bytes : FixedArray[Byte] = FixedArray::from_array([])
  let m_zero_v = @bigint.BigNat::from_bytes_be(m_zero_bytes)
  let m_zero_enc = @bigint.BigNat::mpint_encode(m_zero_v)
  let hex_chars : String = "0123456789abcdef"
  let m_zero_hex = {
    let sb = StringBuilder()
    let mut i = 0
    while i < m_zero_enc.length() {
      let b = m_zero_enc[i].to_int()
      sb.write_string(hex_chars.unsafe_substring(start=b / 16, end=b / 16 + 1))
      sb.write_string(hex_chars.unsafe_substring(start=b % 16, end=b % 16 + 1))
      i = i + 1
    }
    sb.to_string()
  }
  println("mpint_zero: " + m_zero_hex)

  let m_high_bytes : FixedArray[Byte] = FixedArray::from_array([0x80])
  let m_high = @bigint.BigNat::from_bytes_be(m_high_bytes)
  let m_high_enc = @bigint.BigNat::mpint_encode(m_high)
  let m_high_hex = {
    let sb = StringBuilder()
    let mut i = 0
    while i < m_high_enc.length() {
      let b = m_high_enc[i].to_int()
      sb.write_string(hex_chars.unsafe_substring(start=b / 16, end=b / 16 + 1))
      sb.write_string(hex_chars.unsafe_substring(start=b % 16, end=b % 16 + 1))
      i = i + 1
    }
    sb.to_string()
  }
  println("mpint_0x80: " + m_high_hex)

  let m_ff_bytes : FixedArray[Byte] = FixedArray::from_array([0xFF, 0xFF])
  let m_ff = @bigint.BigNat::from_bytes_be(m_ff_bytes)
  let m_ff_enc = @bigint.BigNat::mpint_encode(m_ff)
  let m_ff_hex = {
    let sb = StringBuilder()
    let mut i = 0
    while i < m_ff_enc.length() {
      let b = m_ff_enc[i].to_int()
      sb.write_string(hex_chars.unsafe_substring(start=b / 16, end=b / 16 + 1))
      sb.write_string(hex_chars.unsafe_substring(start=b % 16, end=b % 16 + 1))
      i = i + 1
    }
    sb.to_string()
  }
  println("mpint_0xffff: " + m_ff_hex)

  // ============ G6 mod_pow KAT tests ============
  let base_bytes : FixedArray[Byte] = FixedArray::from_array([0x03])
  let exp_bytes : FixedArray[Byte] = FixedArray::from_array([0x05])
  let mod_bytes : FixedArray[Byte] = FixedArray::from_array([0x07])
  let base = @bigint.BigNat::from_bytes_be(base_bytes)
  let expv = @bigint.BigNat::from_bytes_be(exp_bytes)
  let modv = @bigint.BigNat::from_bytes_be(mod_bytes)
  let pow_result = @bigint.BigNat::mod_pow(base, expv, modv)
  let pow_hex = @bigint.BigNat::to_hex(pow_result)
  println("pow_3_5_7: " + pow_hex)

  let base2_bytes : FixedArray[Byte] = FixedArray::from_array([0x02])
  let exp2_bytes : FixedArray[Byte] = FixedArray::from_array([0x0A])
  let mod2_bytes : FixedArray[Byte] = FixedArray::from_array([0x03, 0xE8])
  let base2 = @bigint.BigNat::from_bytes_be(base2_bytes)
  let exp2 = @bigint.BigNat::from_bytes_be(exp2_bytes)
  let mod2 = @bigint.BigNat::from_bytes_be(mod2_bytes)
  let pow2_result = @bigint.BigNat::mod_pow(base2, exp2, mod2)
  let pow2_hex = @bigint.BigNat::to_hex(pow2_result)
  println("pow_2_10_1000: " + pow2_hex)

  let exp100_bytes : FixedArray[Byte] = FixedArray::from_array([0x64])
  let mod13_bytes : FixedArray[Byte] = FixedArray::from_array([0x0D])
  let exp100 = @bigint.BigNat::from_bytes_be(exp100_bytes)
  let mod13 = @bigint.BigNat::from_bytes_be(mod13_bytes)
  let pow_2_100_13 = @bigint.BigNat::mod_pow(base2, exp100, mod13)
  println("pow_2_100_13: " + @bigint.BigNat::to_hex(pow_2_100_13))

  let base7_bytes : FixedArray[Byte] = FixedArray::from_array([0x07])
  let exp50_bytes : FixedArray[Byte] = FixedArray::from_array([0x32])
  let mod11_bytes : FixedArray[Byte] = FixedArray::from_array([0x0B])
  let base7 = @bigint.BigNat::from_bytes_be(base7_bytes)
  let exp50 = @bigint.BigNat::from_bytes_be(exp50_bytes)
  let mod11 = @bigint.BigNat::from_bytes_be(mod11_bytes)
  let pow_7_50_11 = @bigint.BigNat::mod_pow(base7, exp50, mod11)
  println("pow_7_50_11: " + @bigint.BigNat::to_hex(pow_7_50_11))

  // Python: pow(0xDEADBEEF, 5, 0x12345) = 0x1850
  let base_dead_bytes : FixedArray[Byte] = FixedArray::from_array([0xDE, 0xAD, 0xBE, 0xEF])
  let exp5_bytes : FixedArray[Byte] = FixedArray::from_array([0x05])
  let mod_12345_bytes : FixedArray[Byte] = FixedArray::from_array([0x01, 0x23, 0x45])
  let base_dead = @bigint.BigNat::from_bytes_be(base_dead_bytes)
  let exp5 = @bigint.BigNat::from_bytes_be(exp5_bytes)
  let mod_12345 = @bigint.BigNat::from_bytes_be(mod_12345_bytes)
  let pow_dead = @bigint.BigNat::mod_pow(base_dead, exp5, mod_12345)
  println("pow_deadbeef_5_12345: " + @bigint.BigNat::to_hex(pow_dead))

  // Python: pow(2, 0xCAFE, RFC 3526 group 14) = byte-exact
  let p14_bytes : FixedArray[Byte] = @kexdh.group14_prime()
  let p14 = @bigint.BigNat::from_bytes_be(p14_bytes)
  let exp_cafe_bytes : FixedArray[Byte] = FixedArray::from_array([0xCA, 0xFE])
  let exp_cafe = @bigint.BigNat::from_bytes_be(exp_cafe_bytes)
  let base_two = @bigint.BigNat::from_uint64(2UL)
  let pow_cafe = @bigint.BigNat::mod_pow(base_two, exp_cafe, p14)
  let pow_cafe_hex = @bigint.BigNat::to_hex(pow_cafe)
  println("pow_2_cafe_p14_first16: " + pow_cafe_hex.unsafe_substring(start=0, end=16))
  let last_start_cafe = pow_cafe_hex.length() - 16
  println("pow_2_cafe_p14_last16: " + pow_cafe_hex.unsafe_substring(start=last_start_cafe, end=last_start_cafe + 16))
}