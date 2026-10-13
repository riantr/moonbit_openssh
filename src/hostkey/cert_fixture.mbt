///| Loop #53 测试固定件 —— 由 `host/cert_gen_fixture.py` 生成，勿手改。
///
/// 来源：真实 `ssh-keygen -s <ca> [-h]` 签出的 ed25519 主机/用户证书，
/// 每一条都被 `ssh-keygen -L` 复核过。文件在 `.loop53/`。
///
/// **cert type 常量来自字节本身**（并与 `ssh-keygen -L` 交叉验证）：
///   -h 签出的证书，type 字段 == 2，`-L` 打印 `host certificate`
///   不带 -h 签出的证书，type 字段 == 1，`-L` 打印 `user certificate`
/// 所以 `USER == 1` / `HOST == 2`。写反的后果是把发给 alice 的
/// 用户证书当成主机身份证明。

/// principal 一律是 `127.0.0.1`，即门禁真正连的名字。principal 写成别的
/// 也能得到一个正确的拒绝，但测到的是另一条分支——一个没走到它要测的那一步
/// 的测试比没有测试更糟。好证书的窗口拉到十年，门禁过几周再跑也不会自己过期。

/// 常量 `SSH_CERT_TYPE_USER` / `SSH_CERT_TYPE_HOST` 不在这里重复定义：
/// 它们是生产代码（`cert.mbt`）的一部分，固定件只负责提供 blob。

///| `host-good-cert.pub`：type=2 (host) key id='host.example.com' principals='127.0.0.1'
///| valid 1476497589 .. 2107217589, signed_data = 240 bytes
pub const GOOD_CERT : String = "AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIAdXsI6qga/dfv2DgFdZhMyfuH4POSOuwciUiD9rbTXBAAAAIMbkxxyl9aoQgG+UxIQVbL2i73tHW2wMMhnT1ryJ0hOqAAAAAAAAAAAAAAACAAAAEGhvc3QuZXhhbXBsZS5jb20AAAANAAAACTEyNy4wLjAuMQAAAABYAZC1AAAAAH2ZlrUAAAAAAAAAAAAAAAAAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIPfAXCITZpnjH8qnict5ht7Nof2B/VP/xJKgnVFbsIQuAAAAUwAAAAtzc2gtZWQyNTUxOQAAAEC4bUI6inkPNttdmWnL1kerqaw4l3m49Es9xpZfzP3L6r5IN7xxwAjv3Z0+EtIsTNxbhywxGixyY/Gjg5gYVucG"

///| `host-other-cert.pub`：type=2 (host) key id='host.example.com' principals='other.example.com'
///| valid 1476497590 .. 2107217590, signed_data = 248 bytes
pub const OTHER_PRINCIPAL_CERT : String = "AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAICO4UBTkVYoIUF5pez/Dg1FkrxrT3Phm7ryScFVOVpzjAAAAIMbkxxyl9aoQgG+UxIQVbL2i73tHW2wMMhnT1ryJ0hOqAAAAAAAAAAAAAAACAAAAEGhvc3QuZXhhbXBsZS5jb20AAAAVAAAAEW90aGVyLmV4YW1wbGUuY29tAAAAAFgBkLYAAAAAfZmWtgAAAAAAAAAAAAAAAAAAADMAAAALc3NoLWVkMjU1MTkAAAAg98BcIhNmmeMfyqeJy3mG3s2h/YH9U//EkqCdUVuwhC4AAABTAAAAC3NzaC1lZDI1NTE5AAAAQJFr9gs/AzkhS84/vTf50UfikhwbWbhtwZI+uQfEO4TqzMv0N2OFQNOMcylAopdfYZus0mPmL6U82/x7xEkgiws="

///| `host-exp-cert.pub`：type=2 (host) key id='host.example.com' principals='127.0.0.1'
///| valid 1577808000 .. 1580486400, signed_data = 240 bytes
pub const EXPIRED_CERT : String = "AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIMnJVDZLlYrjk40SDS9ldng2aseiXjuxlE1odgIxxnvxAAAAIMbkxxyl9aoQgG+UxIQVbL2i73tHW2wMMhnT1ryJ0hOqAAAAAAAAAAAAAAACAAAAEGhvc3QuZXhhbXBsZS5jb20AAAANAAAACTEyNy4wLjAuMQAAAABeC3CAAAAAAF40TwAAAAAAAAAAAAAAAAAAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIPfAXCITZpnjH8qnict5ht7Nof2B/VP/xJKgnVFbsIQuAAAAUwAAAAtzc2gtZWQyNTUxOQAAAECAVUghxdgOAlwqo5KGvoPBcuwrYz9cefzAPnHz4k6V0bFRiBYWb+x25eMkyZ9JFozB3Wto9BR9GBFWGvZyQZsK"

///| `host-rogue-cert.pub`：type=2 (host) key id='host.example.com' principals='127.0.0.1'
///| valid 1476497590 .. 2107217590, signed_data = 240 bytes
pub const ROGUE_CA_CERT : String = "AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIKSD+svfAuIVdUisVONbHSmMJl++SGzYgZhNcBT2OG2aAAAAIMbkxxyl9aoQgG+UxIQVbL2i73tHW2wMMhnT1ryJ0hOqAAAAAAAAAAAAAAACAAAAEGhvc3QuZXhhbXBsZS5jb20AAAANAAAACTEyNy4wLjAuMQAAAABYAZC2AAAAAH2ZlrYAAAAAAAAAAAAAAAAAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIFmriclfIPb2axKKRT2Luxi1b3A67HSUbmCK3I+HKd3iAAAAUwAAAAtzc2gtZWQyNTUxOQAAAEAAER1h6EPwBKgCy0uahI2thlYvHD1VPmiBE91fNrZC46L0rTQi+8LhSViHzLl10rO88Lcf18JMNNFhWdU+OX8H"

///| `usercert-in-cert.pub`：type=1 (user) key id='loop53-user' principals='alice'
///| valid 1476497590 .. 2107217590, signed_data = 361 bytes
pub const USER_CERT : String = "AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIF5hCL3OkbSatJq60dgdcpeSKL66QtM1nL6Ibm2DI54vAAAAIFVjTujivBhinTftFErubX4Dwq1hWC7vEuzSaAUNnC6AAAAAAAAAAAAAAAABAAAAC2xvb3A1My11c2VyAAAACQAAAAVhbGljZQAAAABYAZC2AAAAAH2ZlrYAAAAAAAAAggAAABVwZXJtaXQtWDExLWZvcndhcmRpbmcAAAAAAAAAF3Blcm1pdC1hZ2VudC1mb3J3YXJkaW5nAAAAAAAAABZwZXJtaXQtcG9ydC1mb3J3YXJkaW5nAAAAAAAAAApwZXJtaXQtcHR5AAAAAAAAAA5wZXJtaXQtdXNlci1yYwAAAAAAAAAAAAAAMwAAAAtzc2gtZWQyNTUxOQAAACD3wFwiE2aZ4x/Kp4nLeYbezaH9gf1T/8SSoJ1RW7CELgAAAFMAAAALc3NoLWVkMjU1MTkAAABAQvnRoOfVpKCwEfupGSKVTGRK89B12KddNYmTMm96MbE3JHAg1I1dY8IyZD3YyFFbWW6Gq142bEOucOgcwqTTAQ=="

///| `user-cert-cert.pub`：type=2 (host) key id='loop53-user' principals='alice,bob'
///| valid 1476497590 .. 2107217590, signed_data = 238 bytes
pub const NON_HOST_PRINCIPAL_CERT : String = "AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAILD9wIRBiSswpCR0OG9U1rS5tFAlQ36AHyP9f66fWYUnAAAAIFVjTujivBhinTftFErubX4Dwq1hWC7vEuzSaAUNnC6AAAAAAAAAAAAAAAACAAAAC2xvb3A1My11c2VyAAAAEAAAAAVhbGljZQAAAANib2IAAAAAWAGQtgAAAAB9mZa2AAAAAAAAAAAAAAAAAAAAMwAAAAtzc2gtZWQyNTUxOQAAACD3wFwiE2aZ4x/Kp4nLeYbezaH9gf1T/8SSoJ1RW7CELgAAAFMAAAALc3NoLWVkMjU1MTkAAABAd9Qg+xZYpr8HggHzghWN+CLvt1oJjhe4397kSndfc3Ek3KQSPjAIzv+6cJNCEy4Q41ne7sX4erKNiEKMCqI0AA=="

///| `ca.pub`
pub const CA_PUB : String = "AAAAC3NzaC1lZDI1NTE5AAAAIPfAXCITZpnjH8qnict5ht7Nof2B/VP/xJKgnVFbsIQu"

///| `rogue.pub`
pub const ROGUE_CA_PUB : String = "AAAAC3NzaC1lZDI1NTE5AAAAIFmriclfIPb2axKKRT2Luxi1b3A67HSUbmCK3I+HKd3i"

///| `host.pub`
pub const HOST_PUB : String = "AAAAC3NzaC1lZDI1NTE5AAAAIMbkxxyl9aoQgG+UxIQVbL2i73tHW2wMMhnT1ryJ0hOq"

///| 每张证书的 signed_data 长度 = `len(blob) - 4 - len(signature)`，也就是
/// 证书 blob 去掉末尾那个 `string signature` 字段之后的全部内容——
/// **包含类型名，也包含 signature key 字段**。这不是照着源码抄的，是用
/// Node/OpenSSL 把所有连续切片都试了一遍、只有这一个过验签得来的
///（见 `host/cert_signed_data_oracle.mjs`）。
///
/// signed_data 切错不会报任何结构性错误，只会让验签失败；所以长度本身就是
/// 那个断言。
pub const GOOD_CERT_SIGNED_LEN : Int = 240
pub const OTHER_PRINCIPAL_CERT_SIGNED_LEN : Int = 248
pub const EXPIRED_CERT_SIGNED_LEN : Int = 240
pub const ROGUE_CA_CERT_SIGNED_LEN : Int = 240
pub const USER_CERT_SIGNED_LEN : Int = 361
pub const NON_HOST_PRINCIPAL_CERT_SIGNED_LEN : Int = 238

///| 有效期边界，同样由脚本给出——测试里不手写任何时间戳。
pub const GOOD_CERT_VALID_AFTER : UInt64 = 1476497589UL
pub const GOOD_CERT_VALID_BEFORE : UInt64 = 2107217589UL
pub const OTHER_PRINCIPAL_CERT_VALID_AFTER : UInt64 = 1476497590UL
pub const OTHER_PRINCIPAL_CERT_VALID_BEFORE : UInt64 = 2107217590UL
pub const EXPIRED_CERT_VALID_AFTER : UInt64 = 1577808000UL
pub const EXPIRED_CERT_VALID_BEFORE : UInt64 = 1580486400UL
pub const ROGUE_CA_CERT_VALID_AFTER : UInt64 = 1476497590UL
pub const ROGUE_CA_CERT_VALID_BEFORE : UInt64 = 2107217590UL
pub const USER_CERT_VALID_AFTER : UInt64 = 1476497590UL
pub const USER_CERT_VALID_BEFORE : UInt64 = 2107217590UL
pub const NON_HOST_PRINCIPAL_CERT_VALID_AFTER : UInt64 = 1476497590UL
pub const NON_HOST_PRINCIPAL_CERT_VALID_BEFORE : UInt64 = 2107217590UL
