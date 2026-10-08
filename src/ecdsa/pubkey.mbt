///| ECDSA 公钥点导出(Loop #34)
///
/// Loop #30 实现了 ECDSA 的**验证**方向。RFC 4252 §7 的 publickey 认证需要
/// 相反方向的一步:从私钥导出公钥 Q = d·G。签名、wire 编码、blob 组装在
/// Loop #30 都已经有了(见 `src/ecdsa/wire.mbt` 的 `encode_pubkey_blob` /
/// `encode_sig_blob`),这里只补真正缺的那一块。
///
/// 刻意保持得很薄:第一版把这个文件写成了 `encode_pubkey_blob`、
/// `curve_name`、`str_bytes`、`bignat_to_fixed_be` 的完整副本,而那些在
/// `wire.mbt` / `params.mbt` 里**早就有了**。两份实现只要有一份漂移,
/// 客户端签名用的 blob 和服务端读到的 blob 就会对不上——而且这种不一致
/// 表现为一个笼统的 "invalid signature",极难定位。

///| 公钥点的 X 坐标
///
/// KAT 需要拿它和 RFC 6979 公布的 Ux 直接比对,所以这是一个真实的对外接口,
/// 不是为了绕过封装。
pub fn Point::x(self : Point) -> @bigint.BigNat {
  self.x
}

///| 公钥点的 Y 坐标
pub fn Point::y(self : Point) -> @bigint.BigNat {
  self.y
}

///| 曲线阶 n(私钥的取值上界)
///
/// 公开出来是因为调用方需要用它**校验**一把外来私钥。没有这个访问器,
/// 调用方只能拿私钥去试签,失败了也分不清是越界还是签名本身有问题。
pub fn Curve::order(c : Curve) -> @bigint.BigNat {
  c.n
}

///| 签名的 r 分量
pub fn Signature::r(self : Signature) -> @bigint.BigNat {
  self.r
}

///| 签名的 s 分量
pub fn Signature::s(self : Signature) -> @bigint.BigNat {
  self.s
}

///|
/// 由私钥 `d` 导出公钥点 Q = d·G。
///
/// 返回 None 表示 `d` 不在 [1, n-1]。这是一个应当被调用方拒绝的密钥,
/// 不能退化成用 d mod n 继续算——那样会生成一个能通过验签、却与私钥
/// 毫无关系的公钥,比直接失败危险得多。
pub fn Curve::public_key(c : Curve, d : @bigint.BigNat) -> Point? {
  let one = @bigint.BigNat::from_uint64(1UL)
  if @bigint.BigNat::cmp(d, one) < 0 || @bigint.BigNat::cmp(d, c.n) >= 0 {
    return None
  }
  Some(Curve::mul(c, d, c.generator()))
}
