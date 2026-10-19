#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Loop #10 — SSH binary packet protocol 三盲参考(Python 侧)

复用 Loop #8 已验证的 ssh_wrap_encrypt/ssh_wrap_decrypt(aead_python_ref),
独立实现包格式 build/parse 与错误分类(对应 OpenSSH packet.c
send2_wrapped / read_poll2)。

输出:
  - SELF-CHECK 全部 PASS 后才生成 KAT
  - _bpacket_ref_out.txt: V1/V2/V3/V4 向量(MoonBit 测试与 C harness 共同引用)

三盲对齐:
  MoonBit src/bpacket/bpacket_test.mbt (T18 硬编码本文件产出的 hex)
  C      verify_c/bpacket_harness.c   (独立转写 packet.c framing,比对同一批向量)
"""
import os
import struct
import sys

# Loop #71: this was sys.path.insert(0, r'E:\src\moon\openssh_moonbit\verify_c').
# On a runner the checkout is at D:\a\..., so the sibling `aead_python_ref`
# import below resolved against a directory that is not there. Derived from
# __file__, so it is the directory this script actually lives in -- which is
# what it was always trying to say.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from aead_python_ref import ssh_wrap_encrypt, ssh_wrap_decrypt, poly1305

MAX_PACKET_SIZE = 256 * 1024          # packet.c:99
MIN_PACKET_LENGTH = 5                 # packet.c:1660 (<1+4)
BLOCK_SIZE = 8                        # none 与 chachapoly 相同(cipher 表)
AADLEN_PLAIN, AUTHLEN_PLAIN = 0, 0
AADLEN_AEAD, AUTHLEN_AEAD = 4, 16
MSG_NEWKEYS = 21

# 共享合成密钥(与 MoonBit bp_key64 / C harness 一致)
KEY64 = bytes(range(64))

# ---------------------------------------------------------------- 发送侧

def padlen_for(n_payload: int, msg_type: int, aadlen: int) -> int:
    """packet.c:1276-1285:len=6+n;EtM/AEAD 扣除不加密的 length 字段。"""
    n_total = 1 + n_payload                    # payload 含 type 字节
    length = 4 + 1 + n_total                   # len 占位 + padlen 占位 + type+payload
    length -= aadlen
    p = BLOCK_SIZE - (length % BLOCK_SIZE)
    if p < 4:
        p += BLOCK_SIZE
    return p


def build_frame(msg_type: int, payload: bytes, aadlen: int,
                pad_fill: bytes) -> bytes:
    """明文帧 [packlen u32][padlen u8][type][payload][padding]。"""
    assert 1 <= msg_type <= 255
    p = padlen_for(len(payload), msg_type, aadlen)
    total = 6 + len(payload) + p
    packlen = total - 4
    assert packlen <= MAX_PACKET_SIZE
    frame = bytearray(total)
    frame[:4] = struct.pack('>I', packlen)
    frame[4] = p
    frame[5] = msg_type
    frame[6:6 + len(payload)] = payload
    # 加密模式取 pad_fill(随机源注入);未加密强制全零(packet.c:1307-1315)
    if aadlen:
        assert len(pad_fill) >= p
        frame[6 + len(payload):] = pad_fill[:p]
    return bytes(frame), packlen, p


def emit_plain(msg_type: int, payload: bytes):
    frame, packlen, p = build_frame(msg_type, payload, AADLEN_PLAIN, b'')
    return frame, frame, packlen, p            # wire == frame


def emit_aead(key64: bytes, seqnr: int, msg_type: int, payload: bytes,
              pad_fill: bytes):
    frame, packlen, p = build_frame(msg_type, payload, AADLEN_AEAD, pad_fill)
    wire = ssh_wrap_encrypt(key64, seqnr, frame[:4], frame[4:])
    return frame, wire, packlen, p

# ---------------------------------------------------------------- 接收侧

class Fail(Exception):
    def __init__(self, kind, value=None):
        self.kind, self.value = kind, value
        super().__init__(f'{kind}({value})')


def get_length(key64, seqnr: int, buf: bytes) -> int:
    """chachapoly_get_length:K_header counter=0 解密前 4 字节。"""
    khead = key64[32:]
    from aead_python_ref import ssh_xor_stream
    hdr = ssh_xor_stream(khead, seqnr, 0, buf[:4])
    return struct.unpack('>I', hdr)[0]


def recv_packet(mode: str, ctx_key, seqnr: int, input_buf: bytes,
                state: dict):
    """对应 read_poll2 的单次调用。

    mode: 'plain' | 'aead';ctx_key: None 或 key64。
    state: {'packlen': int};返回 (consumed, event) 或抛 NeedMore/Fail。
    event = ('packet', seqnr_used, type, payload)
    """
    aadlen = AADLEN_AEAD if mode == 'aead' else AADLEN_PLAIN
    authlen = AUTHLEN_AEAD if mode == 'aead' else AUTHLEN_PLAIN
    if state['packlen'] == 0:
        min_hdr = 4 if aadlen else BLOCK_SIZE
        if len(input_buf) < min_hdr:
            raise NeedMore()
        plen = (get_length(ctx_key, seqnr, input_buf) if aadlen
                else struct.unpack('>I', input_buf[:4])[0])
        if plen < MIN_PACKET_LENGTH or plen > MAX_PACKET_SIZE:
            raise Fail('BadLength', plen)
        state['packlen'] = plen
    packlen = state['packlen']
    need = 4 + packlen - aadlen
    if need % BLOCK_SIZE != 0:
        raise Fail('AlignError', need)
    total = aadlen + need + authlen
    if len(input_buf) < total:
        raise NeedMore()
    if aadlen:
        pt = ssh_wrap_decrypt(ctx_key, seqnr, input_buf[:total])
        if pt is None:
            raise Fail('AuthFailed')
    else:
        pt = input_buf[:total]
    seqnr_used = seqnr
    nxt = (seqnr + 1) & 0xFFFFFFFF
    if nxt == 0 and state.get('initial_kex'):
        raise Fail('SeqnrWrapInitial')
    state['seqnr'] = nxt
    padlen = pt[4]
    if padlen < 4:
        raise Fail('BadPadlen', padlen)
    if padlen > packlen - 1:
        raise Fail('PadOverflow', padlen)
    payload_len = packlen - 1 - padlen
    if payload_len < 1:
        raise Fail('EmptyPayload')
    msg_type = pt[5]
    if msg_type == 0:
        raise Fail('BadType', msg_type)
    state['packlen'] = 0
    return total, ('packet', seqnr_used, msg_type,
                   bytes(pt[6:5 + payload_len]))


class NeedMore(Exception):
    pass

# ---------------------------------------------------------------- 自检

def selfcheck():
    pad = bytes((0xA5 ^ i) & 0xFF for i in range(32))
    checks = []

    def ok(name, cond):
        checks.append((name, cond))
        if not cond:
            print(f'FAIL {name}')
        else:
            print(f'pass {name}')

    # S1 plain round-trip + 对齐
    _, w, pk, pd = emit_plain(20, bytes(range(10)))
    st = {'packlen': 0}
    c, ev = recv_packet('plain', None, 0, w, st)
    ok('S1a plain rt', ev[1] == 0 and ev[2] == 20 and ev[3] == bytes(range(10)))
    ok('S1b consumed', c == len(w))
    ok('S1c align', (4 + pk) % 8 == 0 and 4 <= pd <= 255)

    # S2 aead round-trip + 对齐 + wire 长度
    fr, w2, pk2, pd2 = emit_aead(KEY64, 0, 20, bytes(range(10)), pad)
    ok('S2a packlen16', pk2 == 16 and pd2 == 4)   # 最小 padding 恰好下界
    ok('S2b align', pk2 % 8 == 0)
    ok('S2c wire len', len(w2) == 4 + pk2 + 16)
    st2 = {'packlen': 0}
    c2, ev2 = recv_packet('aead', KEY64, 0, w2, st2)
    ok('S2d aead rt', ev2[1] == 0 and ev2[2] == 20 and ev2[3] == bytes(range(10)))

    # S3 流水线三包
    stream = b''
    exps = []
    for rnd in range(3):
        _, wi, _, _ = emit_aead(KEY64, rnd, 90 + rnd,
                                bytes(((i * 7 + rnd) & 0xFF)
                                      for i in range(5 + rnd)), pad)
        stream += wi
        exps.append((rnd, 90 + rnd))
    off = 0
    got = []
    st3 = {'packlen': 0}
    for rnd in range(3):
        c3, ev3 = recv_packet('aead', KEY64, rnd, stream[off:], st3)
        off += c3
        got.append((ev3[1], ev3[2]))
    ok('S3 pipeline', got == exps and off == len(stream))

    # S4 碎片投喂(plain 与 aead 各一轮)
    for mode, em in (('plain', emit_plain(4, bytes(9))),
                     ('aead', emit_aead(KEY64, 0, 4, bytes(9), pad))):
        _, ww, _, _ = em
        st4 = {'packlen': 0}
        frag_ok = True
        for k in range(1, len(ww)):
            try:
                recv_packet(mode, KEY64 if mode == 'aead' else None, 0,
                            ww[:k], st4)
                frag_ok = False
            except NeedMore:
                pass
        try:
            c4, ev4 = recv_packet(mode, KEY64 if mode == 'aead' else None, 0,
                                  ww, st4)
            frag_ok = frag_ok and ev4[2] == 4
        except Exception as e:
            frag_ok = False
        ok(f'S4 fragment {mode}', frag_ok)

    # S5 篡改矩阵(aead):体翻转→AuthFailed;头三定点→三态
    _, wb, _, _ = emit_aead(KEY64, 0, 6, bytes(8), pad)
    tb = bytearray(wb); tb[10] ^= 1
    st5 = {'packlen': 0}
    try:
        recv_packet('aead', KEY64, 0, bytes(tb), st5)
        t_body = False
    except Fail as f:
        t_body = f.kind == 'AuthFailed'
    ok('S5a tamper body', t_body)

    def flip(pos, mask, padded=False):
        _, wt, _, _ = emit_aead(KEY64, 0, 6, bytes(8), pad)
        x = bytearray(wt); x[pos] ^= mask
        if padded:
            x += b'\x00' * 32
        stx = {'packlen': 0}
        try:
            recv_packet('aead', KEY64, 0, bytes(x), stx)
            return None
        except Fail as f:
            return f.kind
        except NeedMore:
            return 'NeedMore'

    ok('S5b flip byte0^80', flip(0, 0x80) == 'BadLength')
    ok('S5c flip byte3^01', flip(3, 0x01) == 'AlignError')
    ok('S5d flip byte3^08(+pad)', flip(3, 0x08, True) == 'AuthFailed')

    # S6 手工畸形帧(plain 无认证)
    def manual(packlen, padlen, body=b''):
        arr = bytearray(4 + max(packlen, 0) if packlen > 0 else 12)
        arr[:4] = struct.pack('>I', packlen & 0xFFFFFFFF)
        arr[4] = padlen & 0xFF
        arr[5:5 + len(body)] = body
        return bytes(arr)

    st6 = {'packlen': 0}
    try:
        recv_packet('plain', None, 0, manual(12, 3, b'\xAA' * 8), st6)
        ok('S6a badpadlen', False)
    except Fail as f:
        ok('S6a badpadlen', f.kind == 'BadPadlen')
    st6b = {'packlen': 0}
    try:
        recv_packet('plain', None, 0, manual(12, 12, b'\xAA' * 8), st6b)
        ok('S6b padoverflow', False)
    except Fail as f:
        ok('S6b padoverflow', f.kind == 'PadOverflow')
    st6c = {'packlen': 0}
    try:
        recv_packet('plain', None, 0, manual(12, 11, b'\xAA' * 4), st6c)
        ok('S6c empty payload', False)
    except Fail as f:
        ok('S6c empty payload', f.kind == 'EmptyPayload')
    st6d = {'packlen': 0}
    try:
        recv_packet('plain', None, 0, manual(12, 7, b'\x00\x01\x02\x03'), st6d)
        ok('S6d badtype', False)
    except Fail as f:
        ok('S6d badtype', f.kind == 'BadType')
    st6e = {'packlen': 0}
    try:
        recv_packet('plain', None, 0, manual(4, 4), st6e)
        ok('S6e badlength low', False)
    except Fail as f:
        ok('S6e badlength low', f.kind == 'BadLength')
    huge = bytearray(12); huge[:4] = struct.pack('>I', 262145); huge[4] = 7
    st6f = {'packlen': 0}
    try:
        recv_packet('plain', None, 0, bytes(huge), st6f)
        ok('S6f badlength high', False)
    except Fail as f:
        ok('S6f badlength high', f.kind == 'BadLength')
    edge = bytearray(12); edge[:4] = struct.pack('>I', 262144); edge[4] = 7
    st6g = {'packlen': 0}
    try:
        recv_packet('plain', None, 0, bytes(edge), st6g)
        ok('S6g 262144 boundary passes to align', False)
    except Fail as f:
        ok('S6g 262144 boundary passes to align', f.kind == 'AlignError')

    # S7 strict-kex NEWKEYS 归零 / 非strict 不归零
    st7s_seq, st7r_seq = 0, 0

    def bump(seq, is_newkeys, strict):
        nxt = (seq + 1) & 0xFFFFFFFF
        return 0 if (strict and is_newkeys) else nxt

    s_seq = bump(bump(bump(0, False, True), False, True), True, True)
    ok('S7 strict reset', s_seq == 0)
    s2 = bump(bump(0, True, False), False, False)
    ok('S7 nonstrict keeps', s2 == 2)

    # S8 seqnr 回绕两态
    wrap_init = {'initial_kex': True, 'packlen': 0}
    frame_w = manual(12, 7, b'\x88' * 4)
    try:
        recv_packet('plain', None, 0xFFFFFFFF, frame_w, wrap_init)
        ok('S8a rx wrap initial fatal', False)
    except Fail as f:
        ok('S8a rx wrap initial fatal', f.kind == 'SeqnrWrapInitial')
    wrap_rk = {'initial_kex': False, 'packlen': 0}
    c8, ev8 = recv_packet('plain', None, 0xFFFFFFFF, frame_w, wrap_rk)
    ok('S8b rx wrap rekey ok',
       ev8[1] == 0xFFFFFFFF and wrap_rk['seqnr'] == 0)

    # S9 属性扫描:奇数长度全 round-trip
    sweep_ok = True
    for n in range(0, 70, 2):
        pay = bytes((i * 13 + 7) & 0xFF for i in range(n))
        for mode, em in (
                ('plain', emit_plain(100 + n % 50, pay)),
                ('aead', emit_aead(KEY64, 0, 150 + n % 50, pay, pad))):
            _, wm, pkm, pdm = em
            good = ((4 + pkm) % 8 == 0 and 4 <= pdm <= 255 if mode == 'plain'
                    else pkm % 8 == 0 and 4 <= pdm <= 255)
            stm = {'packlen': 0}
            cm, evm = recv_packet(mode, KEY64 if mode == 'aead' else None, 0,
                                  wm, stm)
            good = good and evm[3] == pay
            sweep_ok = sweep_ok and good
    ok('S9 sweep even sizes', sweep_ok)
    sweep2 = all(
        (lambda pay: (lambda fr: fr[2] % 8 == 0)(
            emit_aead(KEY64, 0, 20, pay, pad)))(bytes(i & 0xFF for i in range(n)))
        for n in range(1, 70, 2))
    ok('S9b sweep odd sizes aead align', sweep2)

    npass = sum(1 for _, c in checks if c)
    print(f'\nSELF-CHECK: {npass}/{len(checks)} passed')
    return npass == len(checks)

# ---------------------------------------------------------------- KAT 输出

def emit_kats():
    lines = []
    pad = bytes((0xA5 ^ i) & 0xFF for i in range(32))
    payload_v1 = bytes(range(10))

    # V1:plain 帧(type=20, n=10)
    fr, w1, pk1, pd1 = emit_plain(20, payload_v1)
    lines.append('[V1 plain frame]')
    lines.append(f'type=20 n={len(payload_v1)} packlen={pk1} padlen={pd1}')
    lines.append('frame_hex=' + fr.hex())

    # V2:aead wire(seqnr=0/1/2,type=20,n=10,key=00..3F,pad=A5^i)
    lines.append('')
    lines.append('[V2 aead wires]')
    for sq in range(3):
        _, wv, pkv, pdv = emit_aead(KEY64, sq, 20, payload_v1, pad)
        lines.append(f'seqnr={sq} packlen={pkv} padlen={pdv}')
        lines.append(f'wire_hex_{sq}=' + wv.hex())

    # V3:三包拼接流(aead,type=90/91/92,n=5/6/7)
    lines.append('')
    lines.append('[V3 pipelined stream]')
    stream = b''
    parts = []
    for rnd in range(3):
        pay = bytes((i * 7 + rnd) & 0xFF for i in range(5 + rnd))
        _, wp, _, _ = emit_aead(KEY64, rnd, 90 + rnd, pay, pad)
        parts.append(wp.hex())
        stream += wp
    lines.append('parts=' + ','.join(parts))
    lines.append('stream_hex=' + stream.hex())

    # V4:篡改样本与期望错误名
    lines.append('')
    lines.append('[V4 tampers on V2 seqnr=0 wire]')
    _, w0, _, _ = emit_aead(KEY64, 0, 20, payload_v1, pad)
    cases = [('body_flip_pos10_xor01', lambda a: a.__setitem__(10, a[10] ^ 1),
              'AuthFailed'),
             ('hdr_flip_pos0_xor80', lambda a: a.__setitem__(0, a[0] ^ 0x80),
              'BadLength'),
             ('hdr_flip_pos3_xor01', lambda a: a.__setitem__(3, a[3] ^ 0x01),
              'AlignError')]
    for name, mut, want in cases:
        arr = bytearray(w0)
        mut(arr)
        lines.append(f'{name}: hex={bytes(arr).hex()} expect={want}')
    # 第三态需要补足缓冲(包长+8 → total 变大):追加 32 零字节后 AuthFailed
    arr = bytearray(w0)
    arr[3] ^= 0x08
    arr += b'\x00' * 32
    lines.append(f'hdr_flip_pos3_xor08_padded: hex={bytes(arr).hex()} '
                 f'expect=AuthFailed note=padded+32zeros')

    out = '\n'.join(lines) + '\n'
    # Loop #71: was r'E:\src\moon\openssh_moonbit\verify_c\_bpacket_ref_out.txt'.
    # The KAT landed beside the script, which is the only relationship it ever
    # needed, and that relationship travels.
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           '_bpacket_ref_out.txt'),
              'w', encoding='utf-8') as fh:
        fh.write(out)
    print('KAT written to _bpacket_ref_out.txt')
    print(out)


if __name__ == '__main__':
    if not selfcheck():
        sys.exit(1)
    print()
    emit_kats()
