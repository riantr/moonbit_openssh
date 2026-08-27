# Loop #12 Architect — src/kexflow

日期:2026-08-27
前置:navigator.md(源码地图 + 跨包 import 可用性实验)。

## 1. 包结构(零 inline,import 三积木)

```
src/kexflow/
├── moon.pkg          # import { hostkey, kexc25519, bpacket }(DSL 语法!)
├── proposal.mbt      # 提案构造/解析/协商(kex_prop2buf + kex_buf2prop + match_list)
├── flow.mbt          # 客户端状态机(input_kex_gen_reply 精确序转写)
└── kexflow_test.mbt  # T 系列(脚本生成 KAT 字面量)
verify_c/
├── kexflow_python_ref.py   # 确定性服务端 + V 向量组
├── gen_kexflow_test.py     # _kexflow_ref_out.txt → 测试字面量/C 头
├── _kexflow_ref_out.txt
├── _kexflow_kat.h
└── kexflow_harness.c + build_kexflow.bat
```

## 2. API 设计

```moonbit
// ---------- proposal.mbt ----------
pub const KEX_COOKIE_LEN : Int = 16

pub(all) struct Proposal {           // 10 类目,kex.h PROPOSAL 序
  kex_algs : String                  // 逗号分隔;strict 模式自动追加 strict 标记
  hostkey_algs : String
  enc_ctos : String
  enc_stoc : String
  mac_ctos : String
  mac_stoc : String
  comp_ctos : String
  comp_stoc : String
  lang_ctos : String
  lang_stoc : String
}

pub fn Proposal::default_client(strict_kex : Bool) -> Proposal
  // kex: "curve25519-sha256" (+ ",kex-strict-c-v00@openssh.com" if strict)
  // hostkey: "ssh-ed25519";enc×2: "chacha20-poly1305@openssh.com"
  // mac×2: "" (AEAD 不用;C 对 chachapoly 发 ""?——不,C 发完整 mac 表但
  //   choose_mac 仍跑。为对齐 C 行为本实现发 "hmac-sha2-256-etm@openssh.com";
  //   协商结果仅记录不使用)※见 §5 决策 D3
  // comp×2: "none";lang×2: ""

pub fn kexinit_payload(cookie : FixedArray[Byte], p : Proposal) -> FixedArray[Byte]
  // kex_prop2buf 布局:cookie‖10×cstring‖u8(0)‖u32(0);不含 type 字节

pub(all) struct PeerKexInit { cookie, 十串, follows : Bool }
pub fn parse_kexinit(payload : FixedArray[Byte]) -> PeerKexInit?
  // 尾随拒;cookie 原样保留(进哈希的 I_S 是整个 payload)

pub(all) enum NegotiationError { NoKexAlg, NoHostkeyAlg, NoCipherAlg, NoCompAlg }
pub(all) struct Negotiated {
  kex_alg : String; hostkey_alg : String; cipher : String; comp : String
}
pub fn negotiate(my : Proposal, peer : PeerKexInit) -> Negotiated? // Result 风格用 enum?
  // match_list:first-match;必需类目 kex/hostkey/enc_ctos/enc_stoc 失败给
  // 分类错误;comp 无交集 NoCompAlg(C choose_comp 同罪);mac 不协商(AEAD)

// ---------- flow.mbt ----------
pub(all) struct FlowConfig {
  version_client : FixedArray[Byte]    // V_C 不含换行
  version_server : FixedArray[Byte]
  cookie : FixedArray[Byte]            // 16B,注入式确定性
  client_seed : FixedArray[Byte]       // x25519 seed(32B)
  strict_kex : Bool
}

pub(all) enum FlowState {
  AwaitingServerKexinit(I_C : FixedArray[Byte], e : FixedArray[Byte])  // start() 产物
  ...
}
```

状态机取舍:**一次性驱动函数**而非 dispatch 回调模拟(消息层纯函数,
帧层归 bpacket/调用方):

```moonbit
pub(all) enum FlowError {
  ProtocolError          // 解析失败/尾随/长度不符(含 parse_reply None)
  HostkeyInvalid         // from_blob 拒绝(细分错误经 debug 文本,不再嵌套)
  SignatureInvalid       // verify 拒绝(含 TypeMismatch)
  SharedSecretInvalid    // x25519 全零(c25519_shared_key_mpint None)
  Negotiated(NegotiationError 内嵌?)→ 单独:
  NoAgreement            // 协商失败(类目诊断入 abort 文本?不——值语义,加字段)
}

pub struct StartedFlow {
  ic_payload : FixedArray[Byte]   // 我方 KEXINIT payload(type 后),即 I_C
  e_pub : FixedArray[Byte]        // string(e) 内容 32B
  init_msg : FixedArray[Byte]     // 待发 INIT 消息体 = type30+string(e)(无帧头)
}
pub fn flow_start(cfg : FlowConfig, my : Proposal) -> StartedFlow
  // c25519_keygen(seed) → e;I_C=kexinit_payload(cookie,p);INIT=0x1E‖string(e)

pub(all) enum ReplyOutcome {
  Established(Established)
  Failed(FlowError)
}
pub(all) struct Established {
  session_id : FixedArray[Byte]        // = H(initial)
  keys : @kexc25519.DerivedKeys        // 六密钥
  newkeys_msg : FixedArray[Byte]       // type21 空体(待经 bpacket emit)
}
pub fn flow_on_reply(
  started : StartedFlow, my : Proposal,
  peer_ic_payload : FixedArray[Byte],   // I_S(type 后)
  reply_msg : FixedArray[Byte],         // msg31 整体:type31+三 string(get_end 已由 parse 保证)
) -> ReplyOutcome
```

流程(flow_on_reply 内部,input_kex_gen_reply:131-233 一一对应):
1. `@kexc25519.parse_reply(reply_msg[1:])`(None→ProtocolError)
2. `@hostkey.HostKey::from_blob(K_S)`(Rejected→HostkeyInvalid)
3. negotiate(my, parse_kexinit(peer_ic))(None→NoAgreement);
   negotiated.hostkey_alg 必须=="ssh-ed25519"(子集单算法;不等→ProtocolError)
4. `@kexc25519.c25519_shared_key_mpint(sk, f)`(None→SharedSecretInvalid)
   —— sk 从 seed 现算(x25519 标量 = clamp(seed),c25519_keygen 的逆用:
   直接暴露 sk?kexc25519 只有 keygen(seed)->pk!需 wbtest 或重derive:
   **x25519(clamp(seed), f)** —— c25519_shared_key_* 接受 (sk,f),sk=seed
   本身?Loop #9 契约:c25519_keygen(seed) 返回 pk,x25519(scalar,point)。
   scalar 是否就是 seed?RFC 7748:scalar=clamped seed。查 kexc25519 实现
   后定;若 keygen 内部 clamp,则 shared= c25519_shared_key_mpint(seed,f))
5. H = kex_gen_hash(ExchangeInputs(V_C,V_S,I_C,I_S), K_S, e, f, K_mpint)
6. hostkey.verify(H, sig_blob)(非 Accepted→SignatureInvalid)
7. derive_keys(K_mpint, H, 64) → keys;session_id=H
8. newkeys_msg=[0x15]

**顺序注意**:C 先验 hostkey 解析再算 K/H 再验签;协商在更早的
kex_choose_conf(KEXINIT 收到时)。本 API 把协商放进 on_reply 是**偏差**
——修正:on_reply 第一步先协商(对应 C 时序:choose_conf 在 input_kexinit
内,REPLY 前完成)。调用形态不变。

## 3. 与 bpacket 的对接(集成测试层,不在 kexflow 内)

```
send = SendCtx::make(Unencrypted, 0U, strict, true)
recv = RecvCtx::make(Unencrypted, 0U, strict, true)
emit KEXINIT 帧: send.emit(20, I_C, pad_src)      ← plain
emit INIT 帧:    send.emit(30, e_string, ...)
emit NEWKEYS:    send.emit(21, [], ...) → send.set_mode(Aead(new64(keys.enc_key_ctos)))
recv 对端 NEWKEYS → recv.set_mode(Aead(new64(keys.enc_key_stoc)))
此后双向 AEAD;首帧加密数据用已知明文互证
```

## 4. 测试矩阵(T 编号)

| # | 用例 | 锚点 |
|---|---|---|
| T1 | default_client 提案字符串表 + kexinit_payload 布局(cookie/序/follows/reserved)| Python V 组 |
| T2 | parse_kexinit 往返 + 尾随拒 + 短 buffer 拒 | Python |
| T3 | 协商 first-match:服务端乱序表选我方第一项;四类目各自空交集拒 | Python |
| T4 | 全流程 happy path:I_C==期望、H/session_id/六密钥逐字节 | Python cryptography 服务端 |
| T5 | 首帧 AEAD 双向:NEWKEYS 后 emit/recv 已知明文 == python 加密帧 | Python |
| T6 | 篡改 sig → SignatureInvalid;篡改 f → SharedSecretInvalid 或 ProtocolError(f 长度变)/签名不一致(SignatureInvalid);全零 f 点 → SharedSecretInvalid | Python |
| T7 | K_S 篡改一字节 → from_blob 多半仍过(ed25519 pk 合法域)但验签挂 → SignatureInvalid;K_S 换成畸形 blob → HostkeyInvalid | Python |
| T8 | msg31 尾随 2 字节 → ProtocolError(parse_reply 尾随拒) | Python |
| T9 | strict_kex=true:提案含 strict 标记;bpacket seqnr 归零行为(借 Loop#10 T15 语义) | Python |
| T10 | 重复 on_reply / 错误 msg type 首字节 → ProtocolError | — |

## 5. 关键决策

- **D1**:kexflow 纯消息层,不含 bpacket ctx(§3 归集成测试)——包间依赖
  仅 hostkey+kexc25519,bpacket 只在测试里用(import 但不构成运行时耦合)?
  否——moon.pkg import 即编译依赖;测试文件同包。接受:bpacket 进 import。
- **D2**:FlowError 扁平五值,不嵌套 KeyError/NegotiationError(跨包枚举
  嵌套徒增映射;诊断文本够用)
- **D3**:MAC 提案串发 "hmac-sha2-256-etm@openssh.com,hmac-sha2-256"
  (OpenSSH 默认表前两项;AEAD 下协商结果弃用)——比发空串更贴近真实
  客户端指纹;negotiate 不产出 mac 字段
- **D4**:strict-kex 标记追加在 kex 列表尾部(C kex_proposal_populate_entries
  语义);flow 不自动置 follows
- **D5**:cookie 注入式(测试确定性);生产随机属集成层(与 bpacket pad_src
  同哲学)
- **D6**:sk 复用问题(§2 流程 4):若 c25519_shared_key_mpint 第一参即
  raw seed(内部 clamp),直接传 client_seed;实现时核对 Loop #9 代码后定,
  必要时补一个 wbtest 断言 clamp 幂等

## 6. Python 参考脚本设计(verify_c/kexflow_python_ref.py)

- SEED_C/SEED_S(x25519)、HOST_SEED(ed25519)、COOKIE=16×i、V_C/V_S 固定串
- 服务端:f = x25519(SEED_S, basepoint);K = x25519(SEED_S, e);
  H = sha256(按 kex_gen_hash 布局自组包,独立实现 wire 原语);
  sig = HOST_SK.sign(H);msg31 组包;六密钥按 KDF 展开(sha256 自实现)
- 输出 V1-V5:V1 期望 I_C(hex)+proposal 文本;V2 I_S/msg31;
  V3 session_id+keys;V4 首帧 AEAD wire(两端方向各一);
  V5 篡改组(sig flip/f flip/K_S swap/trailing)
- 自检:python 端独立复算 KDF 展开公式 + chachapoly 加密(cryptography
  ChaCha20Poly1305?注意 OpenSSH poly key 用法不同——header key 异或构造
  poly1305 key,不能直接用 cryptography 的 AEAD;改为 python 手写
  chacha20-poly1305@openssh.com 组合:chacha20(rfc7539, 32B main)+
  poly1305(key=encrypt(block0 counter=0)[32:64])——工作量可控,且这正是
  Loop #8 aead_python_ref 已有逻辑,**直接复用其函数**)
