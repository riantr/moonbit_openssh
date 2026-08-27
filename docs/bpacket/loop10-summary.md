# Loop #10 Summary — SSH Binary Packet Protocol

日期:2026-08-26
状态:**CLOSED — PASS_OVERALL**

## 交付物

| 产物 | 路径 |
|---|---|
| MoonBit 实现 | `src/bpacket/`(inline aead 积木 11 文件 + packet_ctx/send/recv + bpacket_test.mbt) |
| 测试 | 190/190 PASS(新增 17:T1-T18,含 Python KAT 锚点 T18) |
| Python 参考 | `verify_c/bpacket_python_ref.py`(27/27 自检)+ `_bpacket_ref_out.txt`(V1-V4 KAT) |
| C harness | `verify_c/bpacket_harness.c` + `build_bpacket.bat` → **33/33 PASS exit 0** |
| 报告 | `docs/bpacket/{navigator,architect,reviewer,reality-checker,loop10-summary}.md` |

## 实现内容

RFC 4253 §6 二进制包协议的完整收发状态机(对应 OpenSSH
`ssh_packet_send2_wrapped` / `ssh_packet_read_poll2` 的协议核心):

- **双模式**:Unencrypted(none cipher 等价,aadlen=0,padding 强制全零)+
  ChaCha20-Poly1305 AEAD(aadlen=4,tag=16)——直接对接 Loop #8 `ChachaPolyCtx`
- **对齐规则双分支**(本 loop 最核心发现):plain 对齐 `(4+packlen)%bs==0`,
  AEAD/EtM 对齐 `packlen%bs==0`(length 字段不加密导致目标不同);
  同一 padlen 公式天然区分(packet.c:1282 `len -= aadlen`)
- **seqnr 全生命周期**:每包 +1;initial-KEX 回绕双侧 fatal;strict-kex
  NEWKEYS 双侧归零;模式切换不重置
- **错误分类学**:BadLength/AlignError/AuthFailed/BadPadlen/PadOverflow/
  EmptyPayload/BadType/SeqnrWrapInitial 全部连接终止级;NeedMore 唯一非终止;
  攻击者输入无法触发 abort
- 随机源注入式设计(pad_src),生产接 CSPRNG 属集成层

## 三盲验证

```
Python(bpacket_python_ref.py) ──生成──> _bpacket_ref_out.txt (V1-V4)
   ↑ 自检 27/27                          │ 同一字面量
MoonBit(T18 双向) ←────逐字节比对────→ C harness(C1f/C3e/C3f/C5/C7-C8)
   190/190                                33/33 exit 0(真 chacha/poly1305/chachapoly)
```

- MoonBit emit == Python wire(seqnr 0/1/2);Python wire 被两侧解回
- 篡改矩阵四态(AuthFailed/BadLength/AlignError×2)三方一致
- 边界钉死:packlen=4 vs 5、262144 vs 262145

## 本 loop 新增教训

1. **转写分段算法时公式按结构重 derive**:OpenSSH 分两次解密(首块+余量),
   harness/MoonBit 单次解密——need 公式必须跟随结构变(`4+packlen-bs`
   vs 统一 `4+packlen-aadlen`),对齐判定模余等价。原行号注释保留供回溯。
2. **含状态接收机的负向测试必须显式重置**:错误路径不清 packlen 缓存是正确
   行为(连接即终止),但复用 state 对象会让后续用例吃到脏缓存。
3. **手抄 hex 必出事(再次)**:C harness V3 第三段误粘 V2_WIRE[2]——更危险的
   是它是**合法** seqnr=2 包(tag 验证通过),只有同时断言 type/payload 内容才
   能抓到。KAT 字面量机器生成/校验升级为铁律。
4. **AEAD 下篡改长度头的三态可达性**:置高位→BadLength;破坏低位→AlignError;
   整字节平移(+8)保持合法→需足够缓冲后 AuthFailed。测试构造要模拟流上
   已有的后续流量。

## 与传输层闭环的关系

Loop #9 `derive_keys(we_need=64)` 的 `enc_key_ctos/stoc` 恰为 chachapoly 所需
64 字节(K_main‖K_header,cipher 表 keylen=64 决定),`ChachaPolyCtx::new64(dk.enc_key_*)`
零适配直通;iv/mac_key 对 chachapoly 无效(nonce=BE(seqnr))。
至此 kex → 密钥 → 包加密解密的传输层主链在 MoonBit 侧全部贯通。

## 下一环候选

1. **sshkey 公钥解析(RSA/Ed25519 blob)** —— Loop #7 Ed25519 验证签名接线,
   REPLY 解析从"形态"升级为"可验证"
2. **服务端发现/主机密钥验证流程(read_passphrase/known_hosts 语义)** —— 轻量
3. **USERAUTH REQUEST 编码(password/publickey)** —— 打开用户认证层
4. **channel 层最小集(OPEN/DATA/WINDOW_ADJUST)** —— 直达交互数据面
