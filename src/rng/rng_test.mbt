///|
/// src/rng 黑盒测试
///
/// 跑法:`moon test src/rng --target native`（或 `--target js`）
///
/// 这些测试能检查的是**契约**,不是随机性本身。没有一个测试能证明一段输出
/// 是"不可预测的"——那不是可以用断言写的性质。能写下来的是包装层可能
/// 出错的几件事:
///
///   * 长度对不对(请求 n 字节就得到 n 字节);
///   * 两次调用是不是同一份数据(那说明返回的是常量,不是随机数);
///   * 输出是不是全零(全零会被当成密钥用,而零不是密钥);
///   * **整个缓冲区是不是都写了**——这一条是结构性的,不是统计性的。
///
/// 最后一条值得说清楚,而且它的**方向**一开始是反的。
///
/// 常见的一个错是「只填了一半缓冲区就返回」。第一版的断言比的是「两半
/// 是不是相等」,并且注释里说「只填了一半的实现,后一半是没被碰过的内存,
/// 和前一半相等的概率是 2^-16384」——**这句是错的**。一个只填了前半段的
/// 缓冲区,后半段是零,前一半是随机数,两半【不相等】;所以那条断言对一个
/// 只填一半的实现照样通过。变异 M2(「只填请求的一半缓冲」)就是这么漏过去
/// 的,是变异套件把它找出来的,不是门禁。
///
/// 抓它的断言是「**后半段不是全零**」:一个只填了前半段的实现,后半段就
/// 是没被碰过的内存,全零;而一份真的 CSPRNG 输出的后半段全零,概率是
/// 2^-16384。
///
/// 抓「整个缓冲区是一个常量」的断言是「两次调用不同」。两条一起,才是完整
///
/// 的契约:一条抓常量,一条抓半填充。
test "length_is_exact" {
  assert_eq(@rng.bytes(0).length(), 0)
  assert_eq(@rng.bytes(1).length(), 1)
  assert_eq(@rng.bytes(32).length(), 32)
  assert_eq(@rng.bytes(4096).length(), 4096)
}

///|
test "two_calls_are_not_the_same_bytes" {
  let a = @rng.bytes(32)
  let b = @rng.bytes(32)
  assert_eq(same_bytes(a, b), false)
}

///|
test "the_output_is_not_all_zero" {
  let a = @rng.bytes(64)
  let mut zeros = 0
  for i = 0; i < a.length(); i = i + 1 {
    if a[i] == b'\x00' {
      zeros = zeros + 1
    }
  }
  assert_eq(zeros < 64, true)
}

///|
/// The WHOLE buffer has to be written, and the way to see that is the SECOND
/// HALF: an implementation that filled only the first half leaves the second
/// half exactly as it found it -- all zeros.
test "the_whole_buffer_is_written" {
  let a = @rng.bytes(4096)
  let mut zeros = 0
  for i = 2048; i < 4096; i = i + 1 {
    if a[i] == b'\x00' {
      zeros = zeros + 1
    }
  }
  assert_eq(zeros < 2048, true)
}

///|
/// The two halves have to be DIFFERENT, which is what catches a buffer that
/// was filled with one constant value: its halves are equal.
test "the_two_halves_of_the_buffer_are_different" {
  let a = @rng.bytes(4096)
  let mut same = true
  for i = 0; i < 2048; i = i + 1 {
    if a[i] != a[i + 2048] {
      same = false
      break
    }
  }
  assert_eq(same, false)
}

///|
fn same_bytes(a : FixedArray[Byte], b : FixedArray[Byte]) -> Bool {
  if a.length() != b.length() {
    return false
  }
  for i = 0; i < a.length(); i = i + 1 {
    if a[i] != b[i] {
      return false
    }
  }
  true
}
