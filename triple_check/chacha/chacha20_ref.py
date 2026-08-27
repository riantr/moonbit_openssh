"""Pure-Python ChaCha20 (Bernstein + OpenSSH convention).

Layout (32-bit words):
  state[0..3]   = constants ("expand 32-byte k" or "expand 16-byte k")
  state[4..11]  = key (256-bit or 128-bit)
  state[12..13] = counter (8 bytes, treated as 2 little-endian u32)
  state[14..15] = iv (8 bytes, treated as 2 little-endian u32)

Each block is 64 bytes of keystream. The counter increments by 1
between blocks (low u32 of state[12] only, low-level wrap handled in
the C reference; for sub-2^32 byte inputs we just increment that one).

RFC: https://www.rfc-editor.org/rfc/rfc7539 (IETF form differs:
IETF uses 12-byte combined counter+nonce with different byte order).
This module is the **Bernstein/OpenSSH** form, matching the OpenSSH
chacha.c reference used in triple_check/chacha/chacha.c.
"""
import struct


def _rotl32(v, n):
    v &= 0xFFFFFFFF
    return ((v << n) | (v >> (32 - n))) & 0xFFFFFFFF


def _qr(a, b, c, d):
    a = (a + b) & 0xFFFFFFFF; d = _rotl32(d ^ a, 16)
    c = (c + d) & 0xFFFFFFFF; b = _rotl32(b ^ c, 12)
    a = (a + b) & 0xFFFFFFFF; d = _rotl32(d ^ a, 8)
    c = (c + d) & 0xFFFFFFFF; b = _rotl32(b ^ c, 7)
    return a, b, c, d


def chacha20_block(state):
    """Run 20 rounds (10 double-rounds = 80 quarter-rounds) and return
    64 bytes of keystream."""
    x = list(state)
    for _ in range(10):
        # column rounds
        x[0], x[4], x[8],  x[12] = _qr(x[0], x[4], x[8],  x[12])
        x[1], x[5], x[9],  x[13] = _qr(x[1], x[5], x[9],  x[13])
        x[2], x[6], x[10], x[14] = _qr(x[2], x[6], x[10], x[14])
        x[3], x[7], x[11], x[15] = _qr(x[3], x[7], x[11], x[15])
        # diagonal rounds
        x[0], x[5], x[10], x[15] = _qr(x[0], x[5], x[10], x[15])
        x[1], x[6], x[11], x[12] = _qr(x[1], x[6], x[11], x[12])
        x[2], x[7], x[8],  x[13] = _qr(x[2], x[7], x[8],  x[13])
        x[3], x[4], x[9],  x[14] = _qr(x[3], x[4], x[9],  x[14])
    out = b""
    for i in range(16):
        out += struct.pack("<I", (x[i] + state[i]) & 0xFFFFFFFF)
    return out


def chacha20_keystream(key, iv, counter, n_bytes):
    """Return n_bytes of ChaCha20 keystream (Bernstein/OpenSSH form)."""
    assert len(key) in (16, 32)
    assert len(iv) == 8
    assert len(counter) == 8
    if len(key) == 32:
        constants = b"expand 32-byte k"
    else:
        constants = b"expand 16-byte k"
    state = [0] * 16
    state[0:4] = struct.unpack("<4I", constants)
    state[4:12] = struct.unpack("<8I", key + (b"\x00" * (32 - len(key))))
    # Wait - this is wrong, key here is 32 bytes max so we don't need padding
    # Let me fix: state[4..11] = 8 words from 32-byte key, or 4 words from 16-byte key
    # Reset and redo
    state = [0] * 16
    state[0:4] = list(struct.unpack("<4I", constants))
    # 256-bit key: state[4..11] = 8 u32 LE; 128-bit: state[4..7] = 4 u32 LE, state[8..11] = 0
    # In OpenSSH chacha_keysetup:
    #   state[4..7] = key[0..15]  (always)
    #   state[8..11] = key[16..31] OR key[0..15] for 128-bit (k += 16 not done)
    # Actually for 128-bit, k points to start of key, state[8..11] = key[0..15]
    # Wait, looking at OpenSSH chacha_keysetup more carefully:
    #   x->input[4] = U8TO32_LITTLE(k + 0);  // first 4 bytes of k
    #   x->input[5] = U8TO32_LITTLE(k + 4);
    #   x->input[6] = U8TO32_LITTLE(k + 8);
    #   x->input[7] = U8TO32_LITTLE(k + 12);
    #   if (kbits == 256) { k += 16; constants = sigma; }
    #   else { constants = tau; }
    #   x->input[8] = U8TO32_LITTLE(k + 0);  // k is now either original (128) or k+16 (256)
    #   ...
    # So for 128-bit: state[4..7] = key[0..15], state[8..11] = key[0..15] (re-read same data)
    # For 256-bit: state[4..7] = key[0..15], state[8..11] = key[16..31]
    key_padded = key + key[:16] if len(key) == 16 else key[:32]
    state[4:12] = list(struct.unpack("<8I", key_padded[:32]))
    state[12:14] = list(struct.unpack("<2I", counter))
    state[14:16] = list(struct.unpack("<2I", iv))

    out = b""
    while len(out) < n_bytes:
        block = chacha20_block(state)
        # increment counter (low u32 of state[12])
        state[12] = (state[12] + 1) & 0xFFFFFFFF
        if state[12] == 0:
            state[13] = (state[13] + 1) & 0xFFFFFFFF
        take = min(64, n_bytes - len(out))
        out += block[:take]
    return out


if __name__ == "__main__":
    # Self-test: TEST1 from MoonBit wbtest
    key = bytes(32)
    iv = bytes(8)
    counter = bytes(8)
    expected = bytes.fromhex("76b8e0ada0f13d90405d6ae55386bd28")
    got = chacha20_keystream(key, iv, counter, 16)
    print("TEST1 (key=zeros, iv=zeros, ctr=0):")
    print("  expected:", expected.hex())
    print("  got     :", got.hex())
    print("  match   :", got == expected)
