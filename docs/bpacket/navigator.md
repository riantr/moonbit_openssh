# Loop #10 Navigator — SSH Binary Packet Protocol

日期：2026-08-26
目标：SSH2 binary packet protocol（RFC 4253 §6 + OpenSSH packet.c 特化），
对接 Loop #8 ChachaPolyCtx（AEAD）与 Loop #9 kexc25519 派生密钥，形成传输层闭环。

## 1. 信源

| 文件 | 关键位置 | 内容 |
|---|---|---|
| `openssh-C/packet.h` v1.107 | 全文 | sshpkt_* API 表面 |
| `openssh-C/packet.c` | L99 | `PACKET_MAX_SIZE = 256*1024` |
| 同上 | L101-106 | `struct packet_state { seqnr, packets, blocks, bytes }` |
| 同上 | L1225-1389 | `ssh_packet_send2_wrapped` 发送封装全流程 |
| 同上 | L1624-1858 | `ssh_packet_read_poll2` 接收状态机 |
| 同上 | L2858-2867 | `sshpkt_start`: outgoing 缓冲区预置 6 字节 `[0,0,0,0,0,type]` |
| 同上 | L416-436 | `ssh_packet_start_discard`（CBC 专属路径，本 loop 范围外） |
| 同上 | L976-1029+ | `ssh_set_newkeys`: seqnr **不**重置；packets/blocks 清零 |
| `openssh-C/cipher.c` | L332-353 | `cipher_crypt`：CFLAG_NONE → 纯 memcpy 透传（"未加密"=none cipher） |
| 同上 | L404-416 | `cipher_get_length` 分派到 chachapoly_get_length |
| `openssh-C/cipher-chachapoly.c` | L68-119 | `chachapoly_crypt` 布局与顺序（tag 先验） |
| 同上 | L124-136 | `chachapoly_get_length`：K_header counter=0 解密前 4 字节 |
| `openssh-C/chachapoly key` | chachapoly_new | 64 字节 key = K_main(前32) ‖ K_header(后32)；cipher 表中 chachapoly 的 keylen 字段就是 64 → kex 的 enc_key 直接是这 64 字节 |
| `openssh-C/ssh2.h` v1.22 | 全文 | 消息号表（DISCONNECT=1 … NEWKEYS=21 … CHANNEL_*=90-100） |

## 2. 线格式（RFC 4253 §6，OpenSSH 视角）

```
wire = packet_length(4, BE) ‖ padding_length(1) ‖ payload(n) ‖ padding(p) [‖ tag]
packlen := packet_length 的值 = 1 + n + p        (RFC: "payload+padding_length+padding")
```

- 未加密模式：无 tag；AEAD(chachapoly)：末尾追加 Poly1305 tag(16)。
- **对齐规则（两种不同目标！发送方 padlen 计算天然区分）**：
  - aadlen=0（未加密）：`(4 + packlen) % block_size == 0`
    （即整个明文帧 6+n+p 是 bs 的倍数）
  - aadlen=4（AEAD/EtM，length 字段不加密）：`packlen % block_size == 0`
    （只有加密体对齐；接收端 `need % block_size != 0` 检查与此一致，packet.c:1716）
  - block_size：none cipher = 8；chachapoly = 8（cipher 表第二列）。本 loop 两模式都是 8。
- RFC 约束 `4 ≤ p ≤ 255`：bs=8 时 p ∈ {4..11}，构造性满足。
- 发送侧 padlen 公式（packet.c:1282-1285）：
  ```
  len   = 缓冲区长度(6+n)，若 aadlen 则 len -= 4
  padlen = bs - (len % bs); if padlen < 4 { padlen += bs }
  ```
- padding 内容（packet.c:1307-1315）：**加密时随机**（arc4random_buf），未加密时全零
  （explicit_bzero）。→ MoonBit 侧用注入式 pad_src，plain 模式强制清零以保持行为等价。
- `packet_length` 写入值 = 总缓冲长 − 4（packet.c:1324），padlen 字节在 offset[4]。

## 3. 发送算法（send2_wrapped，去压缩/mux/extra_pad）

1. 取 mode：newkeys[OUT] 有则 enc/mac；authlen≠0 ⇒ mac=NULL（AEAD 吞掉 MAC 位）
2. aadlen = ((mac&&etm) || authlen) ? 4 : 0 —— 本 loop：plain⇒0，chachapoly⇒4
3. type = outgoing[5]（sshpkt_start 预置的第 6 字节）
4. 按 §2 公式算 padlen，追加 padding，回填 packet_length(offset 0..4) 与 padlen(offset 4)
5. 非 EtM HMAC 才有 pre-encrypt MAC——范围外
6. `cipher_crypt(send_ctx, seqnr, out, frame, len-aadlen, aadlen, authlen)`：
   - plain(none)：memcpy 整帧
   - chachapoly：见 §5 crypt 布局，输出 = ct头4 ‖ ct体 packlen ‖ tag16
7. `++seqnr`；wrap 到 0 且 KEX_INITIAL ⇒ 断连错误；kex_strict 且 type==NEWKEYS ⇒ seqnr=0
   （packet.c:1363-1379）

## 4. 接收状态机（read_poll2，去压缩/mux/discard）

状态：`packlen`（0=等包头）、seqnr、mode。

1. packlen==0 && aadlen：需 ≥4 字节输入，`get_length(seqnr, input)` 解密出 packlen；
   越界（<5 或 >262144）⇒ "Bad packet length" 硬错（packet.c:1655-1669）
2. packlen==0 && !aadlen：需 ≥block_size 字节，解密首块后 PEEK_U32；
   同样越界检查（1671-1698）。**注意 C 在这里用了 `state->p_send.seqnr`**
   （packet.c:1683，应为 p_read——上游怪味；plain 模式密码学与 seqnr 无关所以无实际影响，
   我们不复刻，直接用读方向 seqnr）
3. need = aadlen ? packlen : (4 + packlen − block_size)
4. `need % block_size != 0` ⇒ padding error 硬错（1716-1721）
5. 输入不足 `aadlen+need+authlen(+maclen)` ⇒ 返回"未完成"，保留状态（1730）
6. EtM 先验 MAC——范围外；AEAD 由 crypt 内部先验 tag
7. 解密整段：输出缓冲统一为 `[4字节长度字段][padlen][payload][padding]`（plain 模式下
   前 4 字节同样透传在缓冲头部）⇒ padlen 一律在 offset[4]，解析逻辑两模式共用
8. `++seqnr`（wrap 处理同发送）；`packlen=0`；type==NEWKEYS && strict ⇒ seqnr=0
   （1778-1852）
9. padlen < 4 ⇒ "Corrupted padlen" 硬错（1793）
10. 弃 5 字节头 + 尾部 padlen 字节；type = 下一个 u8；`type < 1` ⇒ 协议错（1828）
11. C 里 `sshbuf_consume_end(padlen)` 若 padlen > 剩余会失败返回错误——MoonBit 显式
    检查 `padlen ≤ packlen−1`（等价语义，错误分类 PadOverflow）

## 5. 对接面（已有积木）

### Loop #8 `src/aead`

```moonbit
ChachaPolyCtx::new64(key64)            // 前32=K_main 后32=K_header
ChachaPolyCtx::crypt(self, seqnr: UInt, src: FixedArray[Byte],
                     aadlen: Int, datalen: Int, do_encrypt: Bool)
  // 加密: src = pt头(aadlen) ‖ pt体(datalen) → 返回 ct头 ‖ ct体 ‖ tag16
  // 解密: src = ct头 ‖ ct体 ‖ tag16 → 先验 tag(None=失败) → 返回 pt头 ‖ pt体
ChachaPolyCtx::get_length(self, seqnr: UInt, hdr_ct) -> UInt   // ≥4B, K_header ctr=0
```

### Loop #9 `src/kexc25519`

```moonbit
derive_keys(hash, ss_mpint, we_need) -> DerivedKeys
// we_need=64 时 enc_key_ctos/stoc 为 64 字节 = 直接喂给 ChachaPolyCtx::new64
// iv_ctos/stoc 与 mac_key_* 对 chachapoly 无效（nonce=大端 seqnr，poly_key 派生自 K_main）
```

## 6. seqnr 生命周期

- 每 tx/rx 一个包 +1；uint32 回绕正常允许（仅日志）
- **初始 KEX 期间回绕 = 硬错**（KEX_INITIAL 标志，两端对称，packet.c:1363/1778）
- kex_strict（strict-kex 扩展）：NEWKEYS 包本身发完/收完后 seqnr 归零（两侧）
- ssh_set_newkeys 切换钥匙时 seqnr 不重置（注释明示 packet.c:1014）

## 7. 错误分类学（接收端，attacker-controlled）

| 错误 | 触发 | C 对应行为 |
|---|---|---|
| BadLength | packlen ∉ [5, 262144] | disconnect "Packet corrupt"/start_discard |
| AlignError | need % bs ≠ 0 | start_discard（CBC 场景）/断连 |
| AuthFailed | Poly1305 tag 不匹配 | SSH_ERR_MAC_INVALID → 断连 |
| BadPadlen | padlen < 4 | disconnect "Corrupted padlen" |
| PadOverflow | padlen > packlen−1 | consume_end 失败 → 内部错误 |
| BadType | type == 0 | disconnect "Invalid ssh2 packet type" |
| SeqnrWrapInitial | 回绕且 initial_kex | disconnect |

以上全部为连接终止级错误；唯一非终止结果是 NeedMore（数据不全）。

## 8. 范围裁定

**做**：Unencrypted + ChaCha20-Poly1305 两种模式；完整收发状态机；seqnr 全生命周期
（含 strict-kex NEWKEYS 归零、initial-KEX 回绕硬错）；可注入随机源。

**不做（记录理由）**：
- CBC/CTR/HMAC-MAC(EtM 与 non-EtM) 路径 —— 现代 OpenSSH 默认 chachapoly；
  HMAC 路径需要协商层集成，留待未来 loop（Mode 枚举预留扩展位）
- 压缩（zlib/delayed-compression）、mux、rekey 容量限制、discard-after-MAC-error
  （那是 CBC padding-oracle 缓解，AEAD 下无意义）
- 网络/socket 层 —— 我们的 recv 以"喂缓冲区"为边界，消费字节数显式返回

## 9. 三盲验证计划

- **MoonBit**：src/bpacket（独立实现）
- **Python**：复用 verify_c/aead_python_ref.py 的 ssh_wrap_encrypt/decrypt +
  独立写包格式 build/parse（含全部错误分支期望值），先自检再生成 KAT
- **C harness**：链接 openssh-C 真实 chacha.c/poly1305.c/cipher-chachapoly.c +
  按 packet.c 行号转写 framing（标注行号），覆盖：round-trip、padding 数学性质、
  多包流、篡改三态（BadLength/AlignError/AuthFail）、碎片投喂、NEWKEYS 切换、
  seqnr wrap、bad-padlen/type 拒绝
