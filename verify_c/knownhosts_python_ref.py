#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Loop #13 -- known_hosts 解析 + host_key_check Python 三盲参考。

实现要点 (全部 100% 独立手写,不用 OpenSSH 库):
- SHA-1 (RFC 3174 / FIPS PUB 180-4) -- 独立 Python 实现 + hashlib.sha1 交叉自检
- HMAC-SHA1 (RFC 2104) -- 独立 Python 实现 + hmac.new(..., hashlib.sha1) 交叉自检
- base64 (nopad + padded, OpenSSH b64_pton 兼容)
- 通配符 NFA (match.c:82-152, '*'/'?' 转写)
- last-match-wins (hostfile.c:408-428 check_key_in_hostkeys)
- HMAC-SHA1 哈希 host `|1|<b64-salt>|<b64-hash>` (hostfile.c:116-150 host_hash)

输出: verify_c/_knownhosts_ref_out.txt (KAT 格式 key=value 段标)
       + 双产 verify_c/_knownhosts_kat.h + src/knownhosts/knownhosts_test.mbt
       (通过 gen_knownhosts_test.py)

用法:
    python verify_c/knownhosts_python_ref.py
    -> 自检 SHA-1/HMAC/NFA/parse/check,落盘 _knownhosts_ref_out.txt
"""
from __future__ import annotations

import base64 as _b64
import hashlib
import hmac as _hmac
import os
import re
import sys
from typing import List, Optional, Tuple

# ============================================================================
# SHA-1 (RFC 3174) -- 独立 Python 实现,与 hashlib.sha1 字节级一致
# ============================================================================

def _rotl32(x, n):
    x &= 0xFFFFFFFF
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def sha1(data: bytes) -> bytes:
    """SHA-1 独立实现,RFC 3174 严格遵循,big-endian。"""
    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0
    # 累计的字节流
    buf = bytearray(data)
    bit_len = len(buf) * 8
    # pad
    buf.append(0x80)
    while len(buf) % 64 != 56:
        buf.append(0x00)
    buf += bit_len.to_bytes(8, 'big')
    # 处理每个 64 字节块
    for off in range(0, len(buf), 64):
        w = [0] * 80
        for i in range(16):
            w[i] = int.from_bytes(buf[off + i * 4:off + (i + 1) * 4], 'big')
        for i in range(16, 80):
            w[i] = _rotl32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1)
        a, b, c, d, e = h0, h1, h2, h3, h4
        for i in range(80):
            if i < 20:
                f = (b & c) | ((b ^ 0xFFFFFFFF) & d)
                k = 0x5A827999
            elif i < 40:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif i < 60:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            else:
                f = b ^ c ^ d
                k = 0xCA62C1D6
            t = (_rotl32(a, 5) + f + e + k + w[i]) & 0xFFFFFFFF
            e = d
            d = c
            c = _rotl32(b, 30)
            b = a
            a = t
        h0 = (h0 + a) & 0xFFFFFFFF
        h1 = (h1 + b) & 0xFFFFFFFF
        h2 = (h2 + c) & 0xFFFFFFFF
        h3 = (h3 + d) & 0xFFFFFFFF
        h4 = (h4 + e) & 0xFFFFFFFF
    return (h0.to_bytes(4, 'big') + h1.to_bytes(4, 'big') +
            h2.to_bytes(4, 'big') + h3.to_bytes(4, 'big') +
            h4.to_bytes(4, 'big'))


# ============================================================================
# HMAC-SHA1 (RFC 2104)
# ============================================================================

def hmac_sha1(key: bytes, msg: bytes) -> bytes:
    block_key = bytearray(64)
    if len(key) > 64:
        h = sha1(key)
        block_key[:len(h)] = h
    else:
        block_key[:len(key)] = key
    ipad = bytes(b ^ 0x36 for b in block_key)
    opad = bytes(b ^ 0x5C for b in block_key)
    inner = sha1(ipad + msg)
    return sha1(opad + inner)


# ============================================================================
# base64 (nopad 兼容,OpenSSH b64_pton 行为:写入时无 padding,读取时也接受)
# ============================================================================

def b64_decode(s: str) -> bytes:
    """与 OpenSSH b64_pton 兼容:接受 base64 标准,可无 padding。"""
    return _b64.b64decode(s + '=' * (-len(s) % 4), validate=False)


# ============================================================================
# 通配符 NFA (OpenSSH match.c:82-152)
# '*' 匹配零或多字符;'?' 匹配单字符;'\\' 转义后续字符 (本子集不实现转义)
# ============================================================================

def match_pattern_nfa(s: str, pattern: str) -> bool:
    m = len(pattern)
    if m == 0:
        return len(s) == 0
    # states[i] 表示"已匹配到第 i 个 pattern 字符"为活跃
    states = [False] * (m + 1)
    states[0] = True
    _epsilon_closure(states, pattern, m)
    for sc in s:
        nxt = [False] * (m + 1)
        for i in range(m):
            if not states[i]:
                continue
            pc = pattern[i]
            if pc == '*':
                nxt[i] = True
            elif pc == '?' or pc == sc:
                nxt[i + 1] = True
        _epsilon_closure(nxt, pattern, m)
        if not any(nxt):
            return False
        states = nxt
    return states[m]


def _epsilon_closure(states: List[bool], pattern: str, m: int) -> None:
    changed = True
    while changed:
        changed = False
        for i in range(m):
            if states[i] and pattern[i] == '*':
                if not states[i + 1]:
                    states[i + 1] = True
                    changed = True


# ============================================================================
# known_hosts 解析 (OpenSSH hostfile.c:790-963 + hostfile.c:180-213 markers)
# ============================================================================

# 行格式:
#   [marker] <hosts> <keytype> <base64key> [comment]
# 标记:@cert-authority / @revoked(各允许一次,hostfile.c:188-189)


def _split_host_patterns(host_raw: str) -> List[str]:
    """逗号分隔,trim ASCII 空白,跳过 `!` 否定前缀(语义跳过)。"""
    out: List[str] = []
    for piece in host_raw.split(','):
        piece = piece.strip()
        if not piece:
            continue
        # 跳过 `!` 否定(本子集不强制语义;保留 pattern 用于显示)
        out.append(piece)
    return out


def _check_marker(s: str, start: int) -> Optional[Tuple[str, int]]:
    """返回 (marker_str, after_pos) 或 None。"""
    if start >= len(s) or s[start] != '@':
        return None
    end = start + 1
    while end < len(s) and s[end] not in ' \t':
        end += 1
    if end == start + 1 or end >= len(s):
        return None
    marker = s[start:end]
    after = end
    while after < len(s) and s[after] in ' \t':
        after += 1
    # 只允许一个 marker(hostfile.c:188-189)
    if after < len(s) and s[after] == '@':
        return None
    if marker not in ('@cert-authority', '@revoked'):
        return None
    return (marker, after)


def parse_line(line: str, linenum: int = 0) -> Optional[dict]:
    """解析单行 known_hosts 条目;返回 dict(marker, host_raw, key_type, key_blob) 或 None。"""
    line = line.rstrip('\r\n')
    pos = 0
    while pos < len(line) and line[pos] in ' \t':
        pos += 1
    if pos >= len(line) or line[pos] == '#':
        return None
    # marker
    marker = None
    if line[pos] == '@':
        m = _check_marker(line, pos)
        if m is None:
            return None
        marker, pos = m
    # host field
    host_end = pos
    while host_end < len(line) and line[host_end] not in ' \t':
        host_end += 1
    if host_end >= len(line) or host_end == pos:
        return None
    host_raw = line[pos:host_end]
    pos = host_end
    while pos < len(line) and line[pos] in ' \t':
        pos += 1
    # key type
    kt_end = pos
    while kt_end < len(line) and line[kt_end] not in ' \t':
        kt_end += 1
    if kt_end >= len(line) or kt_end == pos:
        return None
    key_type = line[pos:kt_end]
    pos = kt_end
    while pos < len(line) and line[pos] in ' \t':
        pos += 1
    # base64 blob
    blob_end = pos
    while blob_end < len(line) and line[blob_end] not in ' \t':
        blob_end += 1
    if blob_end == pos:
        return None
    blob_str = line[pos:blob_end]
    try:
        key_blob = b64_decode(blob_str)
    except Exception:
        return None
    return {
        'marker': marker,
        'host_raw': host_raw,
        'host_patterns': [split_host_pattern_spec(p)
                          for p in _split_host_patterns(host_raw)],
        'key_type': key_type,
        'key_blob': key_blob,
        'raw_line': line,
        'linenum': linenum,
    }


def parse_file(content: str) -> List[dict]:
    """解析完整 known_hosts 内容;跳过注释/空行/无效行。"""
    out: List[dict] = []
    for i, line in enumerate(content.splitlines(), start=1):
        e = parse_line(line, linenum=i)
        if e is not None:
            out.append(e)
    return out


# ============================================================================
# match (last-match-wins + 哈希 host + 通配符 NFA)
# ============================================================================

HOST_OK = 0
HOST_MISMATCH = 1
HOST_UNKNOWN = 2
HOST_INVALID = 3


def is_hashed_host(s: str) -> bool:
    return s.startswith('|1|')


def parse_int_str(s: str):
    """十进制整数解析,失败返回 None"""
    if not s:
        return None
    try:
        return int(s)
    except ValueError:
        return None


def split_host_str(s: str):
    """解包 `[host]:port` 与 `[host]` 形式.
    返回 (host_only, port?)。非 `[...]` 形式整段作为 host_only、port=None。
    """
    if s.startswith('['):
        close = s.find(']')
        if close > 0:
            host_inner = s[1:close]
            if close + 1 < len(s) and s[close + 1] == ':':
                port = parse_int_str(s[close + 2:])
                return (host_inner, port)
            return (host_inner, None)
        return (s, None)
    return (s, None)


def split_host_pattern_spec(p: str):
    """Loop #14: 解析单个 pattern 为 (host_only, port?)
    例: 'foo.example.com' -> ('foo.example.com', None)
        '[foo.example.com]:2200' -> ('foo.example.com', 2200)
        '!bar.example.com' -> ('bar.example.com', None)  # 剥离否定
    """
    s = p[1:] if p.startswith('!') else p
    return split_host_str(s)


def match_hashed_host(expected_host: str, hashed_pattern: str) -> bool:
    """验证 `|1|<b64-salt>|<b64-hash>` 条目。HMAC-SHA1(salt, host) vs decoded hash。"""
    rest = hashed_pattern[3:]  # 跳过 |1|
    sep = rest.find('|')
    if sep < 0:
        return False
    salt_b64 = rest[:sep]
    hash_b64 = rest[sep + 1:]
    try:
        salt = b64_decode(salt_b64)
        exp = b64_decode(hash_b64)
    except Exception:
        return False
    actual = hmac_sha1(salt, expected_host.encode('utf-8'))
    return actual == exp


def match_host_pattern(host: str, pattern_list: str) -> bool:
    """逗号分隔模式列表;支持 `!` 否定 / `|1|...` 哈希 / `*`/`?` 通配符。
    假设 host 已经是 host_only(不含 `[host]:port`),caller 应先 split_host_str。
    """
    for pat in pattern_list.split(','):
        pat = pat.strip()
        if not pat:
            continue
        # `!` 否定跳过(本子集不强制语义)
        real = pat[1:] if pat.startswith('!') else pat
        # split pattern (可能含 [host]:port)
        host_only, _ = split_host_pattern_spec(real)
        if is_hashed_host(host_only):
            if match_hashed_host(host, host_only):
                return True
        else:
            if match_pattern_nfa(host, host_only):
                return True
    return False


def find_last_match_v2(entries: List[dict], host_only: str, port: int):
    """Loop #14: 端口感知的 last-match-wins。
    跳过 marker=Revoked 的条目(全局扫在 caller 中做)。
    """
    found = None
    for e in entries:
        if e['marker'] == '@revoked':
            continue  # Revoked 全局后置,这里不参与 host match
        # e['host_patterns'] 含每个 pattern 的 host_only
        for hp in e.get('host_patterns', []):
            if isinstance(hp, tuple):
                pat_host_only, pat_port = hp
            else:
                # backward compat: str 类型(旧 payload)
                pat_host_only, pat_port = hp, None
            if pat_port is not None and pat_port != port:
                continue
            if is_hashed_host(pat_host_only):
                if match_hashed_host(host_only, pat_host_only):
                    found = e
                    break
                continue
            if match_pattern_nfa(host_only, pat_host_only):
                found = e
                break
    return found


def check_host_key(entries: List[dict], host_str: str, port: int,
                   presented_blob: bytes) -> int:
    """Loop #14: host_key_check 主体(支持 `[host]:port]` 与 Revoked 后置)。

    输入:
        entries: KnownHostEntry 字典列表
        host_str: 可以是 "example.com" 或 "[example.com]:2200"
        port: 0 = SSH default 22;否则覆盖 host_str 中的 port
        presented_blob: server 提供的 hostkey blob
    """
    if not entries:
        return HOST_UNKNOWN
    # Normalize caller
    host_only_caller, port_from_str = split_host_str(host_str)
    if port == 0:
        port_caller = port_from_str if port_from_str is not None else 22
    else:
        port_caller = port
    # 后置:全 entries @revoked 检查(OpenSSH hostfile.c:399)
    for e in entries:
        if e['marker'] == '@revoked' and e['key_blob'] == presented_blob:
            return HOST_MISMATCH  # 不管 host 匹不匹配,revoked key 一律拒
    # last-match-wins 找 host+port 命中
    found = find_last_match_v2(entries, host_only_caller, port_caller)
    if found is None:
        return HOST_UNKNOWN
    return HOST_OK if found['key_blob'] == presented_blob else HOST_MISMATCH


def check_host_key_strict(entries: List[dict], host_str: str, port: int,
                          presented_blob: bytes, strict_kex: bool) -> int:
    r = check_host_key(entries, host_str, port, presented_blob)
    if r == HOST_UNKNOWN and strict_kex:
        return HOST_INVALID
    return r


# ============================================================================
# ed25519 keypair (跟 Loop #11 同样的种子,确保密钥字节级可复现)
# ============================================================================

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey, Ed25519PublicKey,
    )
    _HAS_CRYPTO = True
except Exception:
    _HAS_CRYPTO = False


SEED_A = bytes(range(1, 33))                    # 与 hostkey_python_ref 一致
SEED_B = bytes([255 - i for i in range(32)])    # 全 1~0 镜像


def ed25519_keypair(seed: bytes):
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    pk = sk.public_key().public_bytes_raw()
    return pk, sk


def _w_string(s: bytes) -> bytes:
    return len(s).to_bytes(4, 'big') + s


def blob_ed25519(pk: bytes) -> bytes:
    return _w_string(b'ssh-ed25519') + _w_string(pk)


if _HAS_CRYPTO:
    PK_A, SK_A = ed25519_keypair(SEED_A)
    PK_B, SK_B = ed25519_keypair(SEED_B)
    BLOB_A = blob_ed25519(PK_A)
    BLOB_B = blob_ed25519(PK_B)


# ============================================================================
# 自检 + KAT 落盘
# ============================================================================

CHECKS: List[Tuple[str, bool]] = []


def _ok(name: str, cond: bool) -> None:
    CHECKS.append((name, cond))
    print(('pass ' if cond else 'FAIL ') + name)


def selfcheck() -> bool:
    # ===== S1: SHA-1 自检 (hashlib.sha1 交叉)
    for msg in (b'', b'a', b'abc', b'The quick brown fox jumps over the lazy dog',
                b'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'):
        got = sha1(msg).hex()
        exp = hashlib.sha1(msg).hexdigest()
        _ok(f'S1 SHA-1({msg[:8]!r}...) == hashlib', got == exp)
    # RFC 3174 三个标准测试向量直接比 hex
    _ok('S1a SHA1("") = da39a3ee...',
        sha1(b'').hex() == 'da39a3ee5e6b4b0d3255bfef95601890afd80709')
    _ok('S1b SHA1("abc") = a9993e36...',
        sha1(b'abc').hex() == 'a9993e364706816aba3e25717850c26c9cd0d89d')

    # ===== S2: HMAC-SHA1 自检 (hmac.new 交叉) + RFC 2202 vector
    for k, m, exp in (
        (b'\x0b' * 20, b'Hi There',
         'b617318655057264e28bc0b6fb378c8ef146be00'),
        (b'Jefe', b'what do ya want for nothing?',
         'effcdf6ae5eb2fa2d27416d5f184df9c259a7c79'),
    ):
        got = hmac_sha1(k, m).hex()
        _ok(f'S2 HMAC-SHA1({k[:4]!r}) == hmac',
            got == exp)
        # 交叉库级
        _ok(f'S2a HMAC({k[:4]!r}, {m[:6]!r}) == hmac.new',
            got == _hmac.new(k, m, hashlib.sha1).hexdigest())

    # ===== S3: NFA 通配符
    _ok('S3a *.example.com match foo.example.com',
        match_pattern_nfa('foo.example.com', '*.example.com'))
    _ok('S3b *.example.com match bar.example.com',
        match_pattern_nfa('bar.example.com', '*.example.com'))
    _ok('S3c *.example.com no-match foo.example.org',
        not match_pattern_nfa('foo.example.org', '*.example.com'))
    _ok('S3d ?hello match ahello',
        match_pattern_nfa('ahello', '?hello'))
    _ok('S3e * match anything',
        match_pattern_nfa('abcdef', '*'))
    _ok('S3f * match empty',
        match_pattern_nfa('', '*'))
    _ok('S3g exact match',
        match_pattern_nfa('exact', 'exact'))
    _ok('S3h mismatch',
        not match_pattern_nfa('exact', 'exac'))
    # 全匹配边界:. 不会 '跳过',剩余字符必须被消解。
    # `*.example.com` vs `foo.example.com.evil`:搜完 pattern 后还剩 `.evil`,
    # NFA 严格全程消费 input,应返回 False。
    _ok('S3i *.example.com does NOT match foo.example.com.evil',
        not match_pattern_nfa('foo.example.com.evil', '*.example.com'))
    _ok('S3j *.example.com matches foo.example.com (positive baseline)',
        match_pattern_nfa('foo.example.com', '*.example.com'))

    # ===== S4: parse_line round-trip
    if _HAS_CRYPTO:
        line = (f'example.com,*.example.com ssh-ed25519 '
                f'{_b64.b64encode(BLOB_A).decode()}')
        e = parse_line(line)
        _ok('S4a parse_line returns dict', e is not None)
        if e:
            _ok('S4b host_patterns count = 2', len(e['host_patterns']) == 2)
            _ok('S4c key_blob == BLOB_A', e['key_blob'] == BLOB_A)
            _ok('S4d key_type == ssh-ed25519', e['key_type'] == 'ssh-ed25519')

        # ===== S5: parse_file with multiple lines
        kh_lines = '\n'.join([
            line,
            f'foo.example.com ssh-ed25519 {_b64.b64encode(BLOB_B).decode()}',
            '# a comment',
            '',
            f'bar.example.com ssh-ed25519 {_b64.b64encode(BLOB_A).decode()}',
        ])
        es = parse_file(kh_lines)
        _ok('S5a parse_file yields 3 entries (skip # and empty)',
            len(es) == 3 and es[0]['host_raw'] == 'example.com,*.example.com'
            and es[1]['host_raw'] == 'foo.example.com'
            and es[2]['host_raw'] == 'bar.example.com')

        # ===== S6: HMAC-SHA1 hash entry |1|...
        salt = os.urandom(20)
        host_for_hash = 'hashed.example.com'
        h = hmac_sha1(salt, host_for_hash.encode('utf-8'))
        hash_entry = (f'|1|{_b64.b64encode(salt).decode().rstrip("=")}'
                      f'|{_b64.b64encode(h).decode().rstrip("=")}')
        _ok('S6a match_hashed_host exact',
            match_hashed_host(host_for_hash, hash_entry))
        _ok('S6b match_hashed_host wrong host',
            not match_hashed_host('other.example.com', hash_entry))

        # ===== S7: check_host_key (last-match-wins)
        # entry1: example.com → A  ; entry2: *.example.com → B
        # host = "foo.example.com" presented = A → entry2 wins (B) → Mismatch
        es7 = parse_file('\n'.join([
            f'example.com ssh-ed25519 {_b64.b64encode(BLOB_A).decode()}',
            f'*.example.com ssh-ed25519 {_b64.b64encode(BLOB_B).decode()}',
        ]))
        r = check_host_key(es7, 'foo.example.com', 0, BLOB_A)
        _ok('S7a last-match-wins mismatch (entry2 B ≠ A)',
            r == HOST_MISMATCH)
        r = check_host_key(es7, 'example.com', 0, BLOB_B)
        _ok('S7b last-match-wins also mismatch (entry2 B vs B? No - B != A)',
            r == HOST_MISMATCH)  # entry2 (B) 不匹配 B 被覆盖前还在,last-match 是 B
        r = check_host_key(es7, 'example.com', 0, BLOB_A)
        _ok('S7c example.com 匹配 entry1 → Ok (A)',
            r == HOST_OK)
        r = check_host_key(es7, '*.foo', 0, BLOB_A)
        _ok('S7d foo.foo 不匹配任何 → Unknown',
            r == HOST_UNKNOWN)
        # strict
        r = check_host_key_strict(es7, 'unknown.host', 0, BLOB_A, True)
        _ok('S7e strict Unknown → Invalid',
            r == HOST_INVALID)
        r = check_host_key_strict(es7, 'unknown.host', 0, BLOB_A, False)
        _ok('S7f non-strict Unknown → Unknown',
            r == HOST_UNKNOWN)

        # ===== S8: Loop #14 [host]:port 拆分 + Revoked 后置 =====
        # V9: plain host + default port → Ok
        es9 = parse_file(
            f'foo.example.com ssh-ed25519 {_b64.b64encode(BLOB_A).decode()}')
        r = check_host_key(es9, 'foo.example.com', 0, BLOB_A)
        _ok('S8a V9 plain host + default port → Ok',
            r == HOST_OK)
        # V10: [host]:port explicit → Ok (split then match)
        es10 = parse_file(
            f'[foo.example.com]:2200 ssh-ed25519 '
            f'{_b64.b64encode(BLOB_A).decode()}')
        r = check_host_key(es10, '[foo.example.com]:2200', 0, BLOB_A)
        _ok('S8b V10 [host]:2200 explicit (caller full) → Ok',
            r == HOST_OK)
        r = check_host_key(es10, 'foo.example.com', 2200, BLOB_A)
        _ok('S8c V10 plain host + port=2200 → Ok',
            r == HOST_OK)
        # V11: caller port differs from entry port → Unknown
        r = check_host_key(es10, 'foo.example.com', 0, BLOB_A)
        _ok('S8d V11 port 0 vs entry 2200 → Unknown',
            r == HOST_UNKNOWN)
        r = check_host_key(es10, '[foo.example.com]:9999', 0, BLOB_A)
        _ok('S8e V11 caller port 9999 vs entry 2200 → Unknown',
            r == HOST_UNKNOWN)
        # V12: Revoked 后置全局扫,presented key 与 @revoked 命中 → Mismatch
        es12 = parse_file(
            '@revoked foo.example.com ssh-ed25519 '
            f'{_b64.b64encode(BLOB_A).decode()}')
        r = check_host_key(es12, 'foo.example.com', 0, BLOB_A)
        _ok('S8f V12 @revoked + A presented → Mismatch',
            r == HOST_MISMATCH)
        # V12b: same Revoked list but unrelated host → 同样 Mismatch (Revoked 是全局)
        r = check_host_key(es12, 'other.example.com', 0, BLOB_A)
        _ok('S8g V12 Revoked scan covers any host',
            r == HOST_MISMATCH)
        # V12c: present a different key (B) → Not in @revoked, host not match → Unknown
        r = check_host_key(es12, 'foo.example.com', 0, BLOB_B)
        _ok('S8h V12 present B + Revoked A list → Unknown',
            r == HOST_UNKNOWN)

    npass = sum(1 for _, c in CHECKS if c)
    print(f'\nSELF-CHECK: {npass}/{len(CHECKS)} passed')
    return npass == len(CHECKS)


def emit_kats() -> None:
    """KAT 落盘到 _knownhosts_ref_out.txt,key=value 格式供 gen_knownhosts_test.py 双产。"""
    L: List[str] = []
    L.append('[V0 SHA-1 standard vectors (RFC 3174 / FIPS 180-4)]')
    L.append('V0_sha1_empty_hex = ' + sha1(b'').hex())
    L.append('V0_sha1_abc_hex = ' + sha1(b'abc').hex())
    L.append('V0_sha1_long_hex = ' +
             sha1(b'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq').hex())
    L.append('')

    L.append('[V0b HMAC-SHA1 standard vectors (RFC 2202)]')
    L.append('V0b_hmac_case1_hex = ' +
             hmac_sha1(b'\x0b' * 20, b'Hi There').hex())
    L.append('V0b_hmac_case2_hex = ' +
             hmac_sha1(b'Jefe', b'what do ya want for nothing?').hex())
    L.append('')

    L.append('[V1 single plaintext host match]')
    if _HAS_CRYPTO:
        salt1 = bytes(range(20))  # 确定性 salt
        host1 = 'foo.example.com'
        h1 = hmac_sha1(salt1, host1.encode('utf-8'))
        L.append('V1_host = ' + host1)
        L.append('V1_blob_hex = ' + BLOB_A.hex())
        L.append('V1_salt_hex = ' + salt1.hex())
        L.append('V1_hash_hex = ' + h1.hex())
        L.append('V1_expected_status = ' + str(HOST_OK))
        # 单条目 known_hosts 内容(给 C harness 测试用)
        L.append('V1_knownhosts_line = '
                 f'example.com,*.example.com ssh-ed25519 '
                 f'{_b64.b64encode(BLOB_A).decode().rstrip("=")}')
    L.append('')

    L.append('[V2 wildcard host match]')
    if _HAS_CRYPTO:
        L.append('V2_host = bar.example.com')
        L.append('V2_blob_hex = ' + BLOB_A.hex())
        L.append('V2_expected_status = ' + str(HOST_OK))
    L.append('')

    L.append('[V3 negation prefix `!` does not affect other matches]')
    if _HAS_CRYPTO:
        L.append('V3_host = good.example.com')
        L.append('V3_blob_hex = ' + BLOB_A.hex())
        L.append('V3_knownhosts_line = '
                 f'!bad.example.com,good.example.com,*.example.com ssh-ed25519 '
                 f'{_b64.b64encode(BLOB_A).decode().rstrip("=")}')
        L.append('V3_expected_status = ' + str(HOST_OK))
    L.append('')

    L.append('[V4 |1| HMAC-SHA1 hash host match]')
    if _HAS_CRYPTO:
        salt4 = b'hashed_salt_01234567'[:16] + b'\x00\x00\x00\x00'
        host4 = 'hashed.example.com'
        h4 = hmac_sha1(salt4, host4.encode('utf-8'))
        L.append('V4_host = ' + host4)
        L.append('V4_salt_hex = ' + salt4.hex())
        L.append('V4_hash_hex = ' + h4.hex())
        L.append('V4_blob_hex = ' + BLOB_B.hex())
        L.append('V4_knownhosts_line = '
                 f'|1|{_b64.b64encode(salt4).decode().rstrip("=")}'
                 f'|{_b64.b64encode(h4).decode().rstrip("=")} '
                 f'ssh-ed25519 {_b64.b64encode(BLOB_B).decode().rstrip("=")}')
        L.append('V4_expected_status = ' + str(HOST_OK))
    L.append('')

    L.append('[V5 mismatch: hit host but presented key differs]')
    if _HAS_CRYPTO:
        L.append('V5_host = foo.example.com')
        L.append('V5_presented_blob_hex = ' + BLOB_B.hex())
        L.append('V5_knownhosts_line = '
                 f'foo.example.com ssh-ed25519 '
                 f'{_b64.b64encode(BLOB_A).decode().rstrip("=")}')
        L.append('V5_expected_status = ' + str(HOST_MISMATCH))
    L.append('')

    L.append('[V6 unknown host returns Unknown (non-strict)]')
    if _HAS_CRYPTO:
        L.append('V6_host = unknown.example.org')
        L.append('V6_presented_blob_hex = ' + BLOB_A.hex())
        L.append('V6_knownhosts_line = '
                 f'known.example.com ssh-ed25519 '
                 f'{_b64.b64encode(BLOB_A).decode().rstrip("=")}')
        L.append('V6_expected_status = ' + str(HOST_UNKNOWN))
    L.append('')

    L.append('[V7 strict + Unknown → Invalid]')
    if _HAS_CRYPTO:
        L.append('V7_host = unknown.example.org')
        L.append('V7_presented_blob_hex = ' + BLOB_A.hex())
        L.append('V7_knownhosts_line = '
                 f'known.example.com ssh-ed25519 '
                 f'{_b64.b64encode(BLOB_A).decode().rstrip("=")}')
        L.append('V7_expected_status = ' + str(HOST_INVALID))
    L.append('')

    L.append('[V8 keypair A & B for byte-exact cross-validation]')
    if _HAS_CRYPTO:
        L.append('V8_PK_A_hex = ' + PK_A.hex())
        L.append('V8_PK_B_hex = ' + PK_B.hex())
        L.append('V8_BLOB_A_hex = ' + BLOB_A.hex())
        L.append('V8_BLOB_B_hex = ' + BLOB_B.hex())
    L.append('')

    # ===== Loop #14 Vectors: [host]:port + Revoked =====
    L.append('[V9 plain host + default port → Ok]')
    if _HAS_CRYPTO:
        L.append('V9_host = foo.example.com')
        L.append('V9_port = 0')
        L.append('V9_presented_blob_hex = ' + BLOB_A.hex())
        L.append('V9_knownhosts_line = '
                 f'foo.example.com ssh-ed25519 '
                 f'{_b64.b64encode(BLOB_A).decode().rstrip("=")}')
        L.append('V9_expected_status = ' + str(HOST_OK))
    L.append('')

    L.append('[V10 [host]:port explicit → Ok]')
    if _HAS_CRYPTO:
        L.append('V10_host = [foo.example.com]:2200')  # caller 给完整 [host]:port 字面
        L.append('V10_port = 2200')
        L.append('V10_presented_blob_hex = ' + BLOB_A.hex())
        L.append('V10_knownhosts_line = '
                 f'[foo.example.com]:2200 ssh-ed25519 '
                 f'{_b64.b64encode(BLOB_A).decode().rstrip("=")}')
        L.append('V10_expected_status = ' + str(HOST_OK))
    L.append('')

    L.append('[V11 port mismatch → Unknown]')
    if _HAS_CRYPTO:
        L.append('V11_host = foo.example.com')
        L.append('V11_port = 0')  # caller 默认 22,但 entry 是 2200
        L.append('V11_presented_blob_hex = ' + BLOB_A.hex())
        L.append('V11_knownhosts_line = '
                 f'[foo.example.com]:2200 ssh-ed25519 '
                 f'{_b64.b64encode(BLOB_A).decode().rstrip("=")}')
        L.append('V11_expected_status = ' + str(HOST_UNKNOWN))
    L.append('')

    L.append('[V12 @revoked wins → Mismatch]')
    if _HAS_CRYPTO:
        L.append('V12_host = foo.example.com')
        L.append('V12_port = 0')
        L.append('V12_presented_blob_hex = ' + BLOB_A.hex())
        L.append('V12_knownhosts_line = '
                 f'@revoked foo.example.com ssh-ed25519 '
                 f'{_b64.b64encode(BLOB_A).decode().rstrip("=")}')
        L.append('V12_expected_status = ' + str(HOST_MISMATCH))
    L.append('')

    out = '\n'.join(L) + '\n'
    out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            '_knownhosts_ref_out.txt')
    with open(out_path, 'w', encoding='utf-8', newline='\n') as f:
        f.write(out)
    print(f'wrote {out_path} ({len(out)} bytes, {len(L)} lines)')


def main() -> int:
    if not selfcheck():
        print('SELF-CHECK FAILED; aborting before KAT emit')
        return 1
    emit_kats()
    return 0


if __name__ == '__main__':
    sys.exit(main())
