# Loop #10 Architect — SSH Binary Packet Protocol 设计

日期：2026-08-26
前置：navigator.md（packet.c 证据链）

## 1. 包结构 `src/bpacket/`（自包含，无跨包 import）

```
src/bpacket/
  moon.pkg              # 空依赖
  chacha_api.mbt        # ┐
  chacha_block.mbt      # │ inline 自 src/aead（逐字节拷贝）
  chacha_primitives.mbt # │ 积木：ChaChaState + poly1305 + ChachaPolyCtx
  chacha_state.mbt      # │ （moon 0.1.20260608 不支持跨包 import）
  poly1305_{state,clamp,process,mul,final,api}.mbt # │
  ssh_wire.mbt          # ┘ ChachaPolyCtx::new64/crypt/get_length
  packet_ctx.mbt        # Mode/SendCtx/RecvCtx/常量/错误枚举/小工具
  send.mbt              # emit(): 组帧+加密+seqnr 推进
  recv.mbt              # recv(): 状态机解析
  bpacket_test.mbt      # blackbox 测试（含 Python 生成的 KAT hex）
```

**冲突审计**：inline 后跑顶层标识符正则扫描，重复集为空才继续（Loop #9 惯例）。
新代码命名避开 aead 集：`read_u32be/write_u32be/bump_seqnr` 等。

## 2. 类型设计

```moonbit
pub const MAX_PACKET_SIZE : Int = 262144   // PACKET_MAX_SIZE (256*1024)
// packlen 合法域 [5, MAX_PACKET_SIZE]（packet.c:1660/1687: <1+4 || >MAX）

pub enum Mode {
  Unencrypted                       // bs=8, aadlen=0, authlen=0, padding 强制全零
  Aead(ChachaPolyCtx)               // bs=8, aadlen=4, authlen=16, padding 取 pad_src
}                                   // 未来 HMAC 路径在此扩展

pub struct SendCtx { mode : Mode(私有); seqnr; strict_kex; initial_kex }
pub struct RecvCtx { mode; seqnr; packlen(0=等包头); strict_kex; initial_kex }
```

构造器 `SendCtx::make(mode, seqnr, strict, initial)` + `set_mode`（NEWKEYS 切换用）+
`seqnr()` 只读访问器；RecvCtx 同构。

## 3. 发送 API

```moonbit
pub struct SentPacket {
  frame : FixedArray[Byte]   // 明文帧 [packlen u32][padlen u8][type][payload][padding]
  wire  : FixedArray[Byte]   // 线上字节 = plain ? frame : ct头‖ct体‖tag16
}
pub enum EmitResult {
  Ok(SentPacket)
  SeqnrWrapFatal             // 发送后 ++seqnr 回绕且 initial_kex —— 连接必须终止
}
pub fn SendCtx::emit(self, msg_type : Byte, payload : FixedArray[Byte],
                     pad_src : FixedArray[Byte]) -> EmitResult
```

算法（对应 packet.c:1225-1389）：
1. `msg_type == 0` / `pad_src` 不足 / 总长超界 ⇒ abort（程序员错误，非协议错误）
2. `len = 6+n; len -= aadlen(mode)`
3. `padlen = bs - len%bs; padlen<4 ⇒ +=bs`；padding 内容：Aead→pad_src 前 padlen 字节，
   Unencrypted→全零（对齐 packet.c:1307-1315 行为）
4. 回填 packlen = len_total−4（BE），padlen@[4]，type@[5]
5. Aead → `crypt(seqnr, frame, 4, frame.length()−4, true)`
6. `++seqnr`；回绕且 initial_kex ⇒ SeqnrWrapFatal；strict && type==NEWKEYS ⇒ seqnr=0

与 C 的可观测差异（记录）：C 先入队再检 wrap 再断连；我们 fatal 时不出 wire 字节——
两端都立即断连，无可观测差别。

## 4. 接收 API

```moonbit
pub enum PacketError {
  BadLength(UInt)     // packlen ∉ [5,262144]         (packet.c:1660/1687)
  AlignError(UInt)    // need % bs != 0               (1716)
  AuthFailed          // Poly1305 tag 不匹配           (crypt→None)
  BadPadlen(UInt)     // padlen < 4                   (1793)
  PadOverflow(UInt)   // padlen > packlen−1           (consume_end 失败等价)
  EmptyPayload        // payload_len == 0（get_u8 失败等价）
  BadType(UInt)       // type == 0                    (1828)
  SeqnrWrapInitial    // 收方向回绕且 initial_kex      (1778)
}
pub enum RecvEvent {
  NeedMore                            // consumed=0，保留 packlen 状态
  Packet(UInt, Byte, FixedArray[Byte]) // seqnr_used, msg_type, payload(不含 type)
  Failed(PacketError)                  // 连接终止级
}
pub struct RecvResult { consumed : Int, event : RecvEvent }
pub fn RecvCtx::recv(self, input : FixedArray[Byte]) -> RecvResult
```

状态机（对应 packet.c:1624-1858）：
1. `packlen==0`：AEAD 需 ≥4B（get_length）；plain 需 ≥8B（对齐 C 的首块解密门槛，
   虽然明文其实 4B 即可判长——行为等价优先）。越界 ⇒ BadLength
2. `need = aead ? packlen : 4+packlen−bs`；`need%bs≠0` ⇒ AlignError
3. 输入 < `aadlen+need+authlen` ⇒ NeedMore
4. 解密：Aead→crypt(...,false)，None ⇒ AuthFailed；plain→memcpy 透传
   统一缓冲布局 `[len u32][padlen][payload][padding]` ⇒ padlen 恒在 @[4]
5. **先推进 seqnr**（C 行序 1778 在解析前）：回绕且 initial ⇒ SeqnrWrapInitial；
   strict && type==NEWKEYS ⇒ seqnr=0（type 提取后）
6. padlen<4 ⇒ BadPadlen；padlen>packlen−1 ⇒ PadOverflow；
   payload_len = packlen−1−padlen；==0 ⇒ EmptyPayload；pt[5]==0 ⇒ BadType
7. 返回 Packet(seqnr_used, type, pt[6..5+payload_len])；consumed=aadlen+need+authlen；
   packlen 复位 0

契约：input 必须从当前包起点开始连续；consumed 之后调用方切片重喂。

## 5. 密钥接线（集成层约定）

- `ChachaPolyCtx::new64(dk.enc_key_ctos)` 直接成立：kex 的 cipher keylen 字段就是 64，
  chachapoly_new 前 32=K_main 后 32=K_header（navigator §1/§5）
- iv_ctos/stoc、mac_key_* 对 chachapoly 无效（nonce=BE(seqnr)，poly_key 派生自 K_main）
- 测试用合成 64B key；真实 KEX 材料由未来集成 loop 接线

## 6. 测试矩阵（MoonBit blackbox 为主，plain 模式可自由构造畸形帧故无需 wbtest）

| # | 用例 | 锁定 |
|---|---|---|
| T1 | plain round-trip（type=20 + payload） | 基线语义 |
| T2 | plain 帧字段数学：`(4+packlen)%8==0`、padlen∈[4,255]、padding 全零 | 对齐规则 aadlen=0 分支 |
| T3 | aead round-trip；wire 长 = 4+packlen+16 | AEAD 封装 |
| T4 | `packlen%8==0`（aead） | 对齐规则 aadlen=4 分支 |
| T5 | 三包流水线：consumed 累计、seqnr 0,1,2 | 流式消费 |
| T6 | 逐字节碎片投喂 → NeedMore → 最终 Packet | 状态机保持 |
| T7 | 篡改密文体 1 字节 → AuthFailed | tag 完整性 |
| T8 | 篡改长度头三处定点翻转 → 分别命中 BadLength/AlignError/AuthFailed | 三态可达性 |
| T9 | 手工 plain 帧 padlen=3 → BadPadlen | 下界 |
| T10 | padlen=packlen−0? → PadOverflow | 上界 |
| T11 | packlen=4 / 262145 → BadLength | 长度域 |
| T12 | n=0 帧（packlen=12,padlen=11）→ EmptyPayload | C get_u8 失败等价 |
| T13 | type=0 → BadType | 消息号下界 |
| T14 | plain→AEAD 中途切模式，seqnr 连续不归零 | set_newkeys 语义 |
| T15 | strict-kex NEWKEYS 双侧归零 vs 非 strict 不归零 | kex_strict |
| T16 | seqnr=0xFFFFFFFF：initial⇒fatal / 非initial⇒回绕到 0 继续 | wrap 两态 |
| T17 | n ∈ {0..70 奇数} 全 round-trip 属性扫描 | 参数化 |
| T18 | Python KAT hex 断言（V1/V2/V3 向量硬编码进测试） | 三盲锚点 |

## 7. Python 参考（verify_c/bpacket_python_ref.py）

- `from aead_python_ref import ssh_wrap_encrypt, ssh_wrap_decrypt`（复用 Loop #8 已验证原语）
- 独立实现 build_frame/parse_stream/错误分类；先跑 SELF-CHECK 全绿再产出 KAT 到
  `_bpacket_ref_out.txt`：
  - V1 plain 帧 hex + 字段分解（type=20, n=10 固定 payload）
  - V2 key64 固定、seqnr=0/1/2 的 aead wire hex
  - V3 三包拼接流 hex
  - V4 篡改样本 + 期望错误名
- MoonBit T18 与 C harness 共同引用该输出文件中的字面量

## 8. C harness（verify_c/bpacket_harness.c + build_bpacket.bat）

- 链接 openssh-C 真实 `chacha.c/poly1305.c/cipher-chachapoly.c`（非 libcrypto 变体）
  + compat stubs（复用 aead_ssh_compat.h 经验）
- framing 按 packet.c 行号转写（send2_wrapped/read_poll2 的纯计算部分）
- 用例与 MoonBit T1-T17 一一对应 + 与 _bpacket_ref_out.txt 字面量比对
- 单 TU，exit 0 = PASS

## 9. 已知风险

- inline 体量大（aead 约 700 行），靠审计脚本兜底冲突
- T8 三态定点的确定性：开发期先用 MoonBit 暴力搜索找到定点，再固化断言
  （Python/C 同点验证）
- plain 模式 8B 门槛是行为等价选择（C 因首块解密所需），文档已注明
