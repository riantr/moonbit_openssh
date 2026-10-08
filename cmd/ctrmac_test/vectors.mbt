///| GENERATED FILE -- do not edit by hand.

///| Regenerate with: python host/gen_ctrmac_vectors.py

///|

///| Every hex string below comes from host/ssh_ctrhmac_oracle.py, which

///| refuses to emit anything unless its own from-spec implementation and

///| paramiko's Packetizer agree byte for byte. Padding is zeroed on both

///| sides so the comparison is a true byte diff.

///|
/// AES-128 encryption key (letter 'C')
pub const KAT_KEY_HEX : String = "101112131415161718191a1b1c1d1e1f"

///|
/// client-to-server counter seed (letter 'A')
pub const KAT_IV_HEX : String = "202122232425262728292a2b2c2d2e2f"

///|
/// server-to-client counter seed (letter 'B')
pub const KAT_IV_STOC_HEX : String = "303132333435363738393a3b3c3d3e3f"

///|
/// hmac-sha2-256 key (letter 'E')
pub const KAT_MAC_KEY_HEX : String = "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"

///| One KAT case: `count` identical messages sent back to back on the

///| same connection.

///|

///| Sending several in a row is deliberate -- it exercises CTR counter

///| continuity across packets. An implementation that re-seeds the

///| counter from the IV for every packet still gets packet 0 right, so

///|
/// this is exactly the bug a single-packet test cannot see.
pub(all) struct KatCase {
  name : String
  msg_type : Byte
  payload_hex : String
  frames : Array[String]
  wires : Array[String]
}

///|
pub fn KatCase::new(
  name : String,
  msg_type : Byte,
  payload_hex : String,
  frames : Array[String],
  wires : Array[String],
) -> KatCase {
  { name, msg_type, payload_hex, frames, wires, }
}

///|
/// All KAT cases
pub fn kat_cases() -> Array[KatCase] {
  [
    KatCase::new(
      "svc_request",
      b'\x05',
      "030a11181f262d343b42495057",
      [
        "0000001c0d05030a11181f262d343b4249505700000000000000000000000000", "0000001c0d05030a11181f262d343b4249505700000000000000000000000000",
        "0000001c0d05030a11181f262d343b4249505700000000000000000000000000",
      ],
      [
        "d31dd5626f842fd7bac9d38c1173acd9d5010ffc47530c284355e15180c10bf3983530dfe257584fd8f360199b6b2d6f2c07c85da55e1c521f28e68c11cde25b",
        "22c990886a8cc1a9afed69560dd27e165023034ccfb934894b5711692d848eaf7dcd4c4cd6262188441d4230aa8ef6b18e14ec067d26cae89da4c8968fce7fa7",
        "243d778450e7771a0d8dc9f2602c800c04a10f4ddfb33e47521b28a261b70e7553a6c7c2cf4fa4ae4136671e84ad8382a7a57bb277a39a7d4b350a34d0b0146b",
      ],
    ),
    KatCase::new(
      "empty",
      b'\x21',
      "",
      ["0000000c0a2100000000000000000000", "0000000c0a2100000000000000000000"],
      [
        "d31dd57268a02cddabd1ccaa3c47979b09fa3076f5d7a1e3852250b62a692c758c5e1d4d0e3a5465424f2a3b38bed63a",
        "9c5158f04d720c284355e15180c10bf3d05243ad2e1ce988253764a97410e3e3d5a4fed7d7c4ceb0a3841850a756136b",
      ],
    ),
    KatCase::new(
      "long",
      b'\x94',
      "030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dce3eaf1f8ff060d141b222930373e454c535a61686f767d848b9299a0a7aeb5bcc3cad1d8dfe6edf4fb020910171e252c333a41484f565d646b727980878e959ca3aab1b8",
      [
        "0000006c0694030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dce3eaf1f8ff060d141b222930373e454c535a61686f767d848b9299a0a7aeb5bcc3cad1d8dfe6edf4fb020910171e252c333a41484f565d646b727980878e959ca3aab1b8000000000000",
        "0000006c0694030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dce3eaf1f8ff060d141b222930373e454c535a61686f767d848b9299a0a7aeb5bcc3cad1d8dfe6edf4fb020910171e252c333a41484f565d646b727980878e959ca3aab1b8000000000000",
      ],
      [
        "d31dd51264152fd7bac9d38c1173acd9d5010fa2223f7f52c2dd6ec71d65a0419b09575ab25521494f0d89762df25e76304363728af567d32a3f7e1f5000053dbd9dd036e85eb7dacd4d0932a0ec404c44e14f53fa9f0d7d135367f43cd365074d4447642c20fd0b535c0797f3c87b6bc02739a8de65daa95de987f24ba300578d9d94ad89aabbd70b3823fdaab55814",
        "a126b4e4cc08de3905c5d0318b260061ed34c87a85ce5c2908ca76e08f0d4b137dbc0a0f8944f8619e8c8fe272356b2bdbc33e7bb2f2cdb369e5cbb76d417840a97af639dc47fdd0b6041626f62cb4d730b577179945539e58ec90fa1560c700ec858cfee6a6d571ce7ba82d1b8abeffe6f92197dd2ee465e46f1bc46c8e89e9dabfe6c8e5c6a20ffe29e0db247537a9",
      ],
    ),
    KatCase::new(
      "boundary16",
      b'\x1e',
      "030a11181f262d343b424950575e656c",
      [
        "0000001c0a1e030a11181f262d343b424950575e656c00000000000000000000", "0000001c0a1e030a11181f262d343b424950575e656c00000000000000000000",
      ],
      [
        "d31dd562689f2fd7bac9d38c1173acd9d5010fa2223f0c284355e15180c10bf3fab5e8c64f5476e24c93f6eb02c61504c9373603606a712c052b44f619ff05b1",
        "22c990886d97c1a9afed69560dd27e1650230312aad534894b5711692d848eaf27d5f0c1fb36ffa6f6c96235f82763069a8888f080904e01588880a675360112",
      ],
    ),
  ]
}
