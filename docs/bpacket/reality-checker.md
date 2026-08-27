# Loop #10 Reality Checker — 诚实性审计

日期:2026-08-26
对象:Loop #10 SSH binary packet protocol 全部交付物与汇报口径。

## 结论

**PASS_OVERALL**。所有"通过"声明均有可复现证据;与 OpenSSH 的行为差异
全部显式记录且可论证为等价或更严格;无夸大、无未验证的断言混入结论。

## 1. 声明 vs 证据逐项核对

| 声明 | 证据 | 核实 |
|---|---|---|
| MoonBit 190/190 | `moon test` 尾行 Total tests: 190, passed: 190(本 loop 新增 17 个 test 块:173→190) | ✅ 复测于 fmt+info 之后 |
| Python 自检 27/27 | bpacket_python_ref.py 输出 SELF-CHECK: 27/27 passed,poly1305 与 cryptography 库交叉验证 OK(继承自 Loop #8 脚本头部自检) | ✅ |
| KAT 由 Python 生成 | _bpacket_ref_out.txt V1-V4;MoonBit T18 与 C harness 硬编码同一批字面量;无任何手抄 RFC 文本值 | ✅ 脚本化比对过 literal==ref(还抓出 C 侧一处手抄错) |
| C harness 33/33 exit 0 | build_bpacket.bat 构建输出 + EXIT: 0;链接真实 chacha.c/poly1305.c/cipher-chachapoly.c(仅 include 重写的 aead_chachapoly_ref.c) | ✅ |
| 三盲一致 | 同一 KEY64/输入下:MoonBit emit == Python wire(C3e 对应断言);Python wire 被 MoonBit/C 各自解回(T18 双向 / C3f);V1/V2/V3/V4 三方字面量同源 | ✅ |

## 2. 与 OpenSSH 的已知差异(全部有意为之)

1. **plain 模式判长门槛取 8 字节**(packet.c:1676 行为等价选择):明文其实
   4 字节即可读出 packlen,C 因首块解密需要 bs 字节。我们选择对齐 C 的
   可观测门槛而非最优化。文档已注明。
2. **SeqnrWrapFatal 时不出 wire 字节**:C 先入队再 ++seqnr 检查再断连;
   我们 fatal 分支不返回 wire。两端均立即终止连接,无可观测差别。已注明。
3. **不复刻 packet.c:1683 的 `p_send.seqnr` 怪味**:非 AEAD 部分块解密处
   C 用了发送序号(疑似历史笔误)。该路径属 plain CBC/CTR 场景且其密码学
   不依赖 seqnr(none cipher memcpy),本 loop plain=none 无影响。AEAD 主路径
   用 p_read.seqnr 正确。已注明。
4. **错误分类更细**:PadOverflow/EmptyPayload 在 C 里表现为 consume_end/
   get_u8 的内部错误码,我们提升为一等 PacketError 变体。终止级语义一致。
5. **范围外未做**:压缩、mux、HMAC-MAC(EtM/non-EtM)、CBC/CTR、rekey 容量
   限制、discard-after-MAC-error(CBC padding-oracle 缓解,AEAD 下无意义)、
   socket/网络层(recv 以喂缓冲为边界)。navigator §8 全部列名。
   ——这些不是"已完成",任何汇报不得暗示覆盖。

## 3. 测试有效性评估

- **负向用例真的会失败吗**:T7-T13 每条都先验证"正确数据通过"再验证
  "畸形数据被拒"(或错误变体互斥匹配),不存在恒真假断言
- **三态定点翻转的确定性**:byte0^0x80→packlen 置 bit31 必超界;
  byte3^0x01→奇数必不对齐;byte3^0x08(+32B 缓冲)→对齐合法但 tag 必炸。
  数学上唯一,非碰运气
- **边界精确性**:packlen=4(BadLength) vs 5(AlignError);
  262144(过长度门,卡对齐门) vs 262145(BadLength)——上下界两侧都钉死
- **strict-kex 对照组**:有非 strict 对照证明归零确由 strict 触发
- **wrap 四象限**:initial/rekey × tx/rx 全覆盖
- **属性扫描**:17 种尺寸(含 0、1、63、64、65 等 block 边界邻域)× 双模式

## 4. 开发过程如实记录

- 首轮 moon check 21 错(pub enum 外部构造限制 → Mode 改 pub(all);
  Byte 无 reinterpret_as_uint;Show trait 缺失),全部修复后归零
- 首轮测试 187/189(t16 断言笔误 + t8 缓冲不足),t8/t11 类问题在 C 侧
  以不同形态重现(状态污染/公式转写),说明这类坑跨语言共性——已写入
  reviewer §4 教训
- C harness 曾 25/33 → 修复 4 类问题 → 32/33 → 抓出手抄错 → 33/33。
  中间态全部保留在 stderr 诊断里,无掩盖
- 手抄 hex 出错一次(V3 第三段误粘 V2_WIRE[2]),由脚本化比对抓出。
  该风险真实发生,佐证了"KAT 字面量必须机器生成/校验"的项目铁律

## 5. 未验证事项(明示)

- 未在真机 ssh 握手中端到端使用(集成层未来 loop;本 loop 密钥材料为合成)
- 未做 fuzzing/property-framework 随机测试(手写参数扫描替代)
- Windows 下未测 wasm/js target(moon test 默认 target 与既往 loop 一致)
