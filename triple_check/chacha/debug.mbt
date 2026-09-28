test "debug_kat2_state" {
  // Print the actual state after set_iv for KAT2
  let key : FixedArray[Byte] = FixedArray::make(32, 0x00)
  for i = 0; i < 32; i = i + 1 {
    key[i] = i.to_byte()
  }
  let iv : FixedArray[Byte] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]
  let state = ChaChaState::new256(key)
  let state_with_iv = state.set_iv(iv, counter=0x0100000000000000UL)
  // Print state[12..15] as hex u32
  let s = state_with_iv.input
  let mut msg = "state[12..15]: "
  for i = 12; i < 16; i = i + 1 {
    msg = msg + s[i].to_string(radix=16) + " "
  }
  println(msg)
}
