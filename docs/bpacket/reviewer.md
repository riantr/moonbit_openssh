# Loop #10 Code Reviewer — src/bpacket

日期:2026-08-26
审查范围:`src/bpacket/`(inline aead 积木 11 文件 + packet_ctx/send/recv + 测试)、
`verify_c/bpacket_python_ref.py`、`verify_c/bpacket_harness.c`。

## 1. 总评

**PASS**。实现忠实转写 OpenSSH send2_wrapped/read_poll2 的协议核心,
三盲(MoonBit 190/190 ⊕ Python 27/27 ⊕ C harness 33/33 exit 0)在共享 KAT
上逐字节一致。发现并修复的问题见 §4;遗留建议见 §5,均不阻塞。

## 2. 正确性要点核对

| 项 | 结论 |
|---|---|
| padding 数学 | plain `(4+packlen)%8==0`;aead `packlen%8==0`;padlen∈[4,11] 构造性满足 RFC [4,255]。T17 扫描 17 种尺寸 × 双模式全过 |
| padlen 公式分支 | `aadlen=0` 与 `aadlen=4` 两个对齐目标天然由同一公式区分(packet.c:1282 `len -= aadlen`),T2/T3 分别锁定 packlen=20/padlen=8 与 packlen=16/padlen=4(恰好下界) |
| 接收统一布局 | 解密缓冲 `[len u32][padlen][payload][padding]`,padlen 恒在 @[4](plain 下 length 字段透传),解析逻辑两模式共用——与 C 一致且更简洁 |
| 错误顺序 | BadLength → Align → (等待) → AuthFailed(tag 先验) → seqnr 推进(wrap fatal 先于解析,C 行序 1778<1793) → BadPadlen → PadOverflow → EmptyPayload → BadType。T8 三态定点翻转逐一锁定 |
| tag 先验 | decrypt 路径先 poly1305 后解密(Loop #8 已锁),bpacket 只消费其 None→AuthFailed 映射 |
| seqnr 生命周期 | tx/rx 各 +1;initial-KEX 回绕双侧 fatal(T16 四象限);strict-kex NEWKEYS 双侧归零(T15);set_mode 切换不重置(T14,对齐 ssh_set_newkeys 注释) |
| 随机源注入 | emit(pad_src) 注入式;plain 强制全零对齐 packet.c explicit_bzero 分支;生产接 CSPRNG 属集成层 |

## 3. 安全性审查

- **无常量时间问题引入**:tag 比较沿用 Loop #8 实现(逐字节比较+提前返回 None;
  与 OpenSSH timingsafe_bcmp 有微差,但 Loop #8 reality-check 已评估为可接受——
  poly1305 tag 比较非旁路热点,且本层不做新的密码学决策)
- **无未初始化内存流出**:所有 FixedArray::make 后即填充;recv 输出 out 长度
  = payload_len-1 精确
- **abort 仅用于程序员错误**(msg_type==0 / pad_src 不足 / 超界 / crypt 加密向
  None),协议级错误全部走 Failed(PacketError) 值路径——攻击者无法触发 abort
- **无 panic 路径于 attacker-controlled 输入**:recv 对任意字节输入只会返回
  NeedMore/Packet/Failed 三者之一(fuzz 友好)
- 整数域:packlen 用 UInt(32 位)承载,与线上 u32 同宽;Int 运算处值均
  ≤ 262144+常数,无溢出

## 4. 本 loop 开发中发现并修复的问题(证据链)

1. **C harness need 公式转写错**(首版):照抄 OpenSSH 分段解密式
   `4+packlen-bs`,但 harness 是单次整帧解密,应为统一式 `4+packlen-aadlen`。
   表征:C1e consumed≠wire 长、C17 plain sweep 失败。
   **教训:转写分段处理算法时,harness 结构若不同,公式必须按结构重derive,
   注释保留原行号供回溯。**
2. **C harness 负向子测试状态污染**:复用 bp_recv_state 导致前一用例缓存的
   packlen 影响后续判定(C9 缓存 12 → C11 全歪)。MoonBit 侧每用例新建
   RecvCtx 天然免疫。
   **教训:含跨调用状态的接收机,负向测试必须显式重置状态。**
3. **V3_STREAM 手抄错**:C harness 第三段误粘 V2_WIRE[2](同为合法 seqnr=2 包,
   tag 竟验证通过,ty=20/plen=10)。诊断靠 stderr 打印 e=0 但 ty 不符锁定;
   Python 交叉脚本确认字面量 MISMATCH@153。
   **教训:手抄 hex 必有风险,KAT 字面量应脚本化生成/校验(已留 _check_v3.py
   方法论于 summary);"合法但错误"的数据比解析失败更危险——它证明测试断言
   (ty/plen/内容)必须同时锚定,单看'没报错'不够。**
4. MoonBit 侧两处:T16 断言笔误(type 0x88 vs 0x08)、T8 篡改后包长变大需补足
   缓冲才达 AuthFailed(追加 32 零字节模拟流上后续流量,语义真实)。

## 5. 遗留建议(非阻塞)

- `RecvCtx` 可加 `pending_packlen()` 观测器,便于上层遥测(现仅 seqnr)
- `bp_manual_frame` 与 `bp_build_frame` 语义差异(body 含 type vs 不含)在
  harness 内并存,已加注释;未来若加用例优先走 build_frame
- Mode 未来扩展 HMAC-MAC 时,aadlen/authlen 分派函数已是唯一改动点,无需动
  状态机主体
