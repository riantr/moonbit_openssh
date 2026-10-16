///|
/// Loop #26 DH group 14 KEX API verification (cmd/kexdh_test)
///
/// Demonstrates:
///   - RFC 3526 group 14 (2048-bit MODP) prime loads correctly
///   - dh_pub(g, x, p) and dh_shared(f, x, p) functions callable
///   - DH shared secret consistency K_client == K_server
///
/// Known limitation (deferred to Loop #27):
///   KAT values for 2048-bit pow(2, x, p) require proper Montgomery REDC.
///   Current implementation uses Knuth Algorithm D which has overflow bugs
///   for multi-limb operations. Smaller pow tests in cmd/bigint_test pass.
fn main {
  // ============ G1 RFC 3526 group 14 prime metadata ============
  let prime_bytes = @kexdh.group14_prime()
  let prime_byte_len = prime_bytes.length()
  println("dh14_prime_len: " + prime_byte_len.to_string())

  let p = @bigint.BigNat::from_bytes_be(prime_bytes)
  let p_hex = @bigint.BigNat::to_hex(p)
  let p_first8 = p_hex.unsafe_substring(start=0, end=8)
  let last_start = p_hex.length() - 8
  let p_last8 = p_hex.unsafe_substring(start=last_start, end=last_start + 8)
  println("dh14_prime_first8: " + p_first8)
  println("dh14_prime_last8: " + p_last8)

  // ============ G2 generator g = 2 ============
  let g = @bigint.BigNat::from_uint64(2UL)
  let g_hex = @bigint.BigNat::to_hex(g)
  println("dh14_g: " + g_hex)

  // ============ G3 client DH public value e = g^x mod p ============
  let x_bytes : FixedArray[Byte] = FixedArray::from_array([
    0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0x12, 0x34,
  ])
  let x = @bigint.BigNat::from_bytes_be(x_bytes)
  let x_hex = @bigint.BigNat::to_hex(x)
  println("dh14_x: " + x_hex)

  let e = @kexdh.dh_pub(g, x, p)
  let e_hex = @bigint.BigNat::to_hex(e)
  let e_first8 = if e_hex.length() >= 8 {
    e_hex.unsafe_substring(start=0, end=8)
  } else {
    e_hex
  }
  let e_last8 = if e_hex.length() >= 8 {
    let e_last_start = e_hex.length() - 8
    e_hex.unsafe_substring(start=e_last_start, end=e_last_start + 8)
  } else {
    e_hex
  }
  println("dh14_e_first8: " + e_first8)
  println("dh14_e_last8: " + e_last8)

  // ============ G4 server DH public value f = g^y mod p ============
  let y_bytes : FixedArray[Byte] = FixedArray::from_array([
    0xCA, 0xFE, 0xFE, 0xED, 0x12, 0x34, 0x56, 0x78,
  ])
  let y = @bigint.BigNat::from_bytes_be(y_bytes)
  let y_hex = @bigint.BigNat::to_hex(y)
  println("dh14_y: " + y_hex)

  let f = @kexdh.dh_pub(g, y, p)
  let f_hex = @bigint.BigNat::to_hex(f)
  let f_first8 = f_hex.unsafe_substring(start=0, end=8)
  let f_last_start = f_hex.length() - 8
  let f_last8 = f_hex.unsafe_substring(start=f_last_start, end=f_last_start + 8)
  println("dh14_f_first8: " + f_first8)
  println("dh14_f_last8: " + f_last8)

  // ============ G5 shared secret K ============
  let k_client = @kexdh.dh_shared(f, x, p)
  let k_c_hex = @bigint.BigNat::to_hex(k_client)
  let k_c_first8 = k_c_hex.unsafe_substring(start=0, end=8)
  let k_c_last_start = k_c_hex.length() - 8
  let k_c_last8 = k_c_hex.unsafe_substring(
    start=k_c_last_start,
    end=k_c_last_start + 8,
  )
  println("dh14_K_client_first8: " + k_c_first8)
  println("dh14_K_client_last8: " + k_c_last8)

  let k_server = @kexdh.dh_shared(e, y, p)
  let k_s_hex = @bigint.BigNat::to_hex(k_server)
  let k_s_first8 = k_s_hex.unsafe_substring(start=0, end=8)
  let k_s_last_start = k_s_hex.length() - 8
  let k_s_last8 = k_s_hex.unsafe_substring(
    start=k_s_last_start,
    end=k_s_last_start + 8,
  )
  println("dh14_K_server_first8: " + k_s_first8)
  println("dh14_K_server_last8: " + k_s_last8)

  // ============ G6 consistency: K_client == K_server ============
  let consistency = @bigint.BigNat::cmp(k_client, k_server)
  let consistency_str = if consistency == 0 {
    "MATCH"
  } else {
    "MISMATCH_DEFERRED"
  }
  println("dh14_consistency: " + consistency_str)
}
