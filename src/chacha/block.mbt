///| ChaCha20 block function — 20 轮双轮计算

///| 对应 C `chacha_encrypt_bytes` 中的核心 20 轮计算部分

///|

///| 输入:16 个 UInt 的 4x4 状态矩阵(线性化)

///| 输出:16 个 UInt 的 keystream block(working state + 原始 state)

///|

///| 关键不变量:

///|   - 每轮 quarterround 保持 16 个 u32 的总和模 2^32

///|   - 20 轮后 working[i] = (mix(working[0..16], i)) + input[i]

///|   - 此函数不修改 input(只读)

///|
/// 对 4 个指定位置的 UInt 应用 quarterround 并写回
fn apply_qr(
  arr : FixedArray[UInt32],
  i : Int32,
  j : Int32,
  k : Int32,
  l : Int32,
) -> Unit {
  let (a, b, c, d) = quarterround(arr[i], arr[j], arr[k], arr[l])
  arr[i] = a
  arr[j] = b
  arr[k] = c
  arr[l] = d
}

///| ChaCha20 核心:对 4x4 状态做 20 轮(10 次双轮)计算,加上原始 state

///|

///| 输入:`state` 长度必须为 16

///|
/// 输出:新分配的 FixedArray[UInt] of length 16,keystream block
pub fn chacha_block(state : FixedArray[UInt32]) -> FixedArray[UInt32] {
  // 防御性检查
  if state.length() != 16 {
    abort("chacha_block: state length must be 16")
  }
  // 拷贝 state 到 working(我们不能直接修改原 state)
  let working : FixedArray[UInt32] = FixedArray::make(16, 0U)
  for i = 0; i < 16; i = i + 1 {
    working[i] = state[i]
  }
  // 10 次双轮(每次含 8 个 quarterround)
  for round = 0; round < 10; round = round + 1 {
    // 列轮(column rounds)
    apply_qr(working, 0, 4, 8, 12)
    apply_qr(working, 1, 5, 9, 13)
    apply_qr(working, 2, 6, 10, 14)
    apply_qr(working, 3, 7, 11, 15)
    // 对角轮(diagonal rounds)
    apply_qr(working, 0, 5, 10, 15)
    apply_qr(working, 1, 6, 11, 12)
    apply_qr(working, 2, 7, 8, 13)
    apply_qr(working, 3, 4, 9, 14)
  }
  // 加上原始 state(每字相加,模 2^32)
  for i = 0; i < 16; i = i + 1 {
    working[i] = working[i] + state[i]
  }
  working
}
