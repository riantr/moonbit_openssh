# Loop #12 Navigator — KEX 全流程组装(kexgen 客户端)

日期:2026-08-27
目标:把 kexc25519(交换哈希/派生/REPLY 解析)+ hostkey(解析/验签)+
bpacket(帧收发/AEAD)接成 **curve25519-sha256 + ssh-ed25519 +
chacha20-poly1305@openssh.com 的完整客户端握手**,产出 session_id 与可用
的双向加密通道。

## 0. 工程前提变更(本 loop 最重要的发现)

**跨包 import 在 moon v0.1.20260819 下可用**(旧约束"moon 不支持跨包
import"失效,推测为旧版 moon 限制)。实验证据:src/_imp_test 探针包以

```
import {
  "openssh/openssh_moonbit/src/hostkey",
}
```

(moon.pkg 为 MoonBit DSL 语法,**不是 JSON**;`{` 开头或裸 `import "..."`
均报 UnexpectedToken;`import { "a", }` 才对)成功调用
@hostkey.HostKey::from_blob / @kexc25519.parse_reply /
@bpacket.SendCtx::make,test 通过。**结论:kexflow 无需第三次 inline
335KB 积木,直接 import 三包。**

## 1. 源码地图(E:\src\moon\openssh-C)

| 文件 | 位置 | 内容 |
|---|---|---|
| kexgen.c | :48-96 | `kex_gen_hash`:V_C‖V_S‖I_C‖I_S‖K_S‖e‖f‖K → SHA-256。**I_C/I_S 加 fake header:u32(len+1)+u8(20)**——即 kex->my/peer 存的是类型字节之后的 payload |
| kexgen.c | :99-127 | `kex_gen_client`:keypair 后发 MSG_KEX_ECDH_INIT(30)=type+string(e) |
| kexgen.c | :131-233 | `input_kex_gen_reply`:getb_froms(K_S blob)→**sshkey_fromb 解析**→kex_verify_host_key(信任回调)→getb_froms(f)+get_string(sig)+**sshpkt_get_end(尾随拒绝)**→c25519_dec→hash→**sshkey_verify**→derive_keys→send_newkeys |
| kexgen.c | :236-330 | 服务端镜像(server 角色范围外,仅作向量生成参照) |
| kex.c | :146-170 | `kex_prop2buf`:cookie(16B 零,发送时 arc4random 覆盖)‖10×cstring(PROPOSAL 序)‖u8 follows=0‖u32 reserved=0。无 type 字节 |
| kex.h | PROPOSAL_* | 类目序:KEX_ALGS, SERVER_HOST_KEY_ALGS, ENC_CTOS, ENC_STOC, MAC_CTOS, MAC_STOC, COMP_CTOS, COMP_STOC, LANG_CTOS, LANG_STOC(KEX_COOKIE_LEN=16) |
| kex.c | :574-608 | `kex_send_kexinit`:cookie 填随机后 sshpkt_start(20)+putb(my)。**my 不含 type 字节** |
| kex.c | :612-680 | `kex_input_kexinit`:整段存 kex->peer(同样不含 type);重复 KEXINIT → disconnect |
| kex.c | :391-404 | `kex_send_newkeys`:发 NEWKEYS(21,type 后空体)后激活输出侧 |
| kex.c | :528-545 | `kex_input_newkeys`:收到 NEWKEYS 激活输入侧 |
| kex.c | :1132-1177 | `kex_derive_keys`:initial 时 session_id=H;6 密钥字母 A-F,K1=HASH(K‖H‖letter‖session_id),扩展 Kn=HASH(K‖H‖K1..Kn-1)(**无 session_id**);client 的 MODE_OUT 取 A/C/E |
| kexc25519.c | :59-77 | `kexc25519_shared_key_ext`:x25519 后**全零共享密钥拒**(SSH_ERR_KEY_INVALID_EC_VALUE);raw=0 时 bignum2 编码 |
| kexc25519.c | :160-194 | `kex_c25519_dec`:f 长度恰 32 否则 SSH_ERR_SIGNATURE_INVALID |
| kex-names/match.c | match.c:313 | `match_list`:**客户端列表第一个也出现在服务端列表的项**(逗号分隔精确 strcmp);各类目独立错误 NO_*_ALG_MATCH |
| kex.c | choose_hostkeyalg | 协商出的 hostkey alg 必须 type_from_name≠UNSPEC |

## 2. Loop #9 已验证可复用件(src/kexc25519 pkg.generated.mbti)

- `ExchangeInputs::make(V_C,V_S,I_C,I_S)` + `build_exchange_input`(fake
  header 已实现,exchange_hash.mbt:49-72 注释与 kexgen.c 一致)
- `kex_gen_hash` → H(SHA-256)
- `derive_keys(K_mpint,H,need=64)` / `derive_keys_with_session(...,sid)`
  (rekey 语义备用)
- `parse_reply(msg31_payload)` → KexReply{hostkey_blob,server_pub,sig_blob},
  已含尾随拒绝 + f==32 校验(client.mbt:80-102)
- `c25519_shared_key_mpint(sk,f)` → mpint 或 None(**全零已拒**,t139 锁定)
- `parse_sig` / `sig_is_ed25519`(sig blob 拆解,Loop #9 形态层)
- KxBuf(put_string/u32/u8/mpint)、sha256、x25519、c25519_keygen(seed→pk)

## 3. Loop #11 可复用件(src/hostkey)

`HostKey::from_blob(blob)`(错误分类学 11 变体)、`HostKey::verify(H,
sig_blob)`(内含 alg==ssh-ed25519 精确匹配 → TypeMismatch,trailing,
len>64,<64 等价捷径,ed25519 密码学验证)——正是 sshkey_verify 的转写,
直接对接 input_kex_gen_reply 的验签点。

## 4. Loop #10 对接件(src/bpacket)

- `SendCtx/RecvCtx::make(mode, seqnr, strict_kex, initial_kex)`;初始握手期
  Unencrypted,NEWKEYS 后 `set_mode(Aead(ChachaPolyCtx::new64(key64)))`
- chachapoly 方向 key64 = enc.key(64B = chacha32+poly头32),iv 在 AEAD 下
  由 seqnr 构造(cipher_ivlen=0),故 we_need=64,密钥 C/D 即 key64;
  A/B(iv)/E/F(mac) 派生但 AEAD 不用——仍按 C 全量派生保持位对齐
- strict-kex:NEWKEYS 双侧 seqnr 归零(make 第 3 参)

## 5. 本 loop 新增面(kexflow 包职责)

1. **提案构造**:`kexinit_payload(cookie16, proposal10)` 按 kex_prop2buf
   布局;默认子集表(curve25519-sha256[+strict 标记]、ssh-ed25519、
   chacha20-poly1305@openssh.com×2、mac 空/占位、none×2、lang 空×2)
2. **提案解析** `parse_kexinit(payload)`:cookie+10 串+follows+reserved+
   尾随拒;重复 KEXINIT 检测交由调用方状态机
3. **协商** `negotiate(my, peer)`:match_list 语义逐类目 first-match,
   任一必需类目(kex/hostkey/cipher ctos/stoc)无交集 → NegotiationFailed
4. **客户端流程**:start(产 I_C+e)→ on_kexinit(I_S)→ on_reply(msg31):
   parse_reply → from_blob(K_S) → x25519+全零检查 → build_exchange_input
   → H → hostkey.verify(H, sig) → derive_keys(session_id=H)
5. **NEWKEYS 帧**:type 21 空体,经 bpacket emit;发送后切输出 Aead,收到
   对端 NEWKEYS 切输入 Aead(strict 标志透传)

## 6. 范围裁定

- **范围内**:上述 1-5;非严格与 strict-kex 双模式;篡改矩阵(sig/H/f/K_S/
  尾随/重复 KEXINIT)
- **范围外**:版本横幅交换与 CRLF 处理(V_C/V_S 作为入参,不含换行);
  ext-info(EXT_INFO 消息);rekey(initial only,session_id 管道留接口);
  known_hosts 信任回调(接受任何可解析的 ed25519 主机钥——Loop #13 补);
  服务端角色;DH/GEX/其他 KEX 族;first_kex_packet_follows 猜测路径
  (恒 0,对端为 1 时忽略——C 注释 XXX 同款处理)

## 7. 三盲设计草案

Python 以 cryptography 库扮**确定性服务端**(固定 seed:x25519 服务端钥、
ed25519 主机钥、cookie 固定):输出 V 向量组——期望 I_C(服务端视角收到的
客户端 KEXINIT payload!)、I_S、msg31、session_id、六密钥 hex、首帧 AEAD
wire。MoonBit/C 扮客户端跑同一向量:I_C 必须逐字节等于期望 I_C(锁定提案
构造),派生密钥逐字节一致,首帧解出已知明文;篡改 sig/f/K_S 各得对应
错误类。
