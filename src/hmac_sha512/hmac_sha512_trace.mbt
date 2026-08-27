///| HMAC-SHA512 字符串接口 roundtrip 测试

///|
/// 验证 hmac_sha512 输出与 hex 字符串转换的正确性
let hex_chars : String = "0123456789abcdef"

///|
fn to_hex_str(arr : FixedArray[Byte]) -> String {
  let sb = StringBuilder()
  for i = 0; i < arr.length(); i = i + 1 {
    let h = arr[i].to_uint() / 16U
    let l = arr[i].to_uint() % 16U
    let h_c = hex_chars.unsafe_substring(
      start=h.reinterpret_as_int(),
      end=h.reinterpret_as_int() + 1,
    )
    let l_c = hex_chars.unsafe_substring(
      start=l.reinterpret_as_int(),
      end=l.reinterpret_as_int() + 1,
    )
    sb.write_string(h_c)
    sb.write_string(l_c)
  }
  sb.to_string()
}

///|
test "hex_roundtrip_rfc4231_test_1" {
  // 验证 hmac_sha512 输出可以无丢失地通过 hex 字符串表示
  let key : FixedArray[Byte] = FixedArray::make(20, 0x0b)
  let msg : FixedArray[Byte] = [0x48, 0x69, 0x20, 0x54, 0x68, 0x65, 0x72, 0x65]
  let tag = hmac_sha512(key, msg)
  let hex = to_hex_str(tag)
  // Python: 87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854
  assert_eq(hex.length(), 128)
  assert_eq(hex.unsafe_substring(start=0, end=8), "87aa7cde")
  assert_eq(hex.unsafe_substring(start=120, end=128), "3a126854")
}

///|
test "different_msg_changes_tag" {
  // 相同 key 不同 msg -> 不同 tag
  let key : FixedArray[Byte] = [0x01, 0x02, 0x03, 0x04]
  let msg1 : FixedArray[Byte] = [0xAA]
  let msg2 : FixedArray[Byte] = [0xBB]
  let t1 = hmac_sha512(key, msg1)
  let t2 = hmac_sha512(key, msg2)
  let mut differs = false
  for i = 0; i < 64; i = i + 1 {
    if t1[i] != t2[i] {
      differs = true
    }
  }
  assert_eq(differs, true)
}

///|
test "single_byte_msg" {
  // 1 字节 msg
  let key : FixedArray[Byte] = [0x0b]
  let msg : FixedArray[Byte] = [0x48]
  let tag = hmac_sha512(key, msg)
  assert_eq(tag.length(), 64)
}
