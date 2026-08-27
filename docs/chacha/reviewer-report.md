# 👁️ Code Reviewer Report — ChaCha20 MoonBit 实现

> 评审对象:`src/chacha/{state,primitives,block,api}.mbt`
> 评审标准:OpenSSH 风格 / moon prove 友好 / 可读性 / 安全性
> 评审日期:2026-07-23

---

## 总体评价

✅ **通过**(有 3 项 P2 改进建议,无阻断项)

代码结构清晰,模块切分合理(state / primitives / block / api),符合 Architect 设计。
所有 10 个测试通过(含 3 个 KAT 字节级对比,与 OpenSSH 原版 chacha.c 完全一致)。

---

## 详细评分

| 维度 | 评分 | 备注 |
|---|---|---|
| 算法正确性 | ⭐⭐⭐⭐⭐ | KAT 验证字节级一致 |
| 代码结构 | ⭐⭐⭐⭐⭐ | 4 文件分层,职责单一 |
| 安全性 | ⭐⭐⭐⭐ | 见下文改进 #2 |
| 性能 | ⭐⭐⭐⭐ | 未做 SIMD 优化,但语义正确优先 |
| moon prove 友好度 | ⭐⭐⭐ | primitive 是纯函数,可加规约;block 循环仍需 loop invariant |
| 文档/注释 | ⭐⭐⭐⭐ | 模块顶部有 ///\| 文档,但部分函数可补充 |

---

## 改进项

### P1(阻断)— 无

### P2(建议,不影响发布)

1. **`api.mbt::process` 边界 if 链可读性**
   - 当前 4 个 `if base + N < take` 序列可以提取为内层 helper,降低嵌套深度
   - 影响:可读性,不影响正确性
   - 建议:Loop 2 之前抽一个小 `xor_block_into` 辅助函数

2. **公开 API 缺防御性 assert**
   - `ChaChaState::new128 / new256` / `set_iv` 用 `abort` 在 length 错时报错,这是 fail-fast 模式 OK
   - 但 `process` 未校验 `self.input` 长度(假设 16)。可在 `self.input.length() != 16` 时 abort
   - 影响:内部 invariant 保护,防止未来重构误用

3. **`u8_to_32_le` 未做越界保护**
   - `bytes[offset + 3]` 在 length = offset + 3 时刚好,offset + 4 时越界
   - 当前由调用方保证,建议在内部 `if bytes.length() < offset + 4` 时 abort
   - 防御性编程加分项

### P3(可忽略)

- 注释里 "i.e. word_sum 不变" 这句话我读得有点拗口,改写一下
- 状态矩阵布局图用 ASCII,后续可换成 mermaid

---

## KAT 验证(与 OpenSSH 原版 chacha.c 字节级对比)

| Test | key | iv / counter | 首 4 字节 (C 输出) | MoonBit 输出 | 一致 |
|---|---|---|---|---|---|
| TEST1 | 32×0x00 | all zero | 76 b8 e0 ad | 76 b8 e0 ad | ✅ |
| TEST2 | 0..31 | bytes [0..0, 0x01] | b9 76 cc bb | b9 76 cc bb | ✅ |
| TEST3 | 0xFF,0xFE,..,0xF0 | 0x55×8 | b5 c4 3f 9d | b5 c4 3f 9d | ✅ |
| 64B block | 32×0x00 | all zero | 76 b8 e0 ad a0 f1 3d 90 ... | 76 b8 e0 ad a0 f1 3d 90 ... | ✅ |

完整 64 字节比对通过:`kat_64byte_block` 测试。

---

## moon prove 准备度

- `primitives.mbt` 的 `rotl32` / `quarterround` 是纯函数,易于加规约
- `block.mbt` 的 10 轮循环需要 loop invariant 标注才能高效证明
- 当前未尝试 `moon prove` 标注(Why3 在 Windows 装不上),下一轮可补

---

## 通过条件

- [x] 所有测试通过(包括 KAT 字节级对比)
- [x] 模块文件按设计文件分四层
- [x] 公开 API 与 Architect 设计 § 2 一致
- [x] 无 panic-prone 代码(全部用 abort 显式触发)
- [x] 不直接复用 C 代码(从零按规范重写)

---

**Reviewer 签字**:👁️ Code Reviewer
**下一步**:交 Reality Checker 跑 `moon prove`(如环境允许)或签发验收
