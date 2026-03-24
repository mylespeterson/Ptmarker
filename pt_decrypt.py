"""
pt_decrypt.py

Decrypt Cisco Packet Tracer encrypted `.pka` / `.pkt` files.

Newer versions of Packet Tracer (7.x +) encrypt activity files using a
two-stage obfuscation layer around **Twofish-EAX** authenticated encryption,
followed by Qt-style zlib compression.  This module implements the full
decryption pipeline using only the Python standard library (no third-party
crypto packages required).

Algorithm references
--------------------
* **Twofish** — Bruce Schneier, John Kelsey, Doug Whiting, David Wagner,
  Chris Hall, Niels Ferguson.  Public-domain block cipher.
* **EAX** — M. Bellare, P. Rogaway, D. Wagner.  Authenticated-encryption
  mode built on CMAC + CTR.
* **CMAC** — NIST SP 800-38B.
* **CTR** — Standard counter-mode encryption.
"""

import struct
import zlib

# ---------------------------------------------------------------------------
# Twofish block cipher (128-bit block, 128/192/256-bit key)
# ---------------------------------------------------------------------------
# Implemented from the public Twofish specification.

_BLOCK = 16

_TAB_5B = (0, 90, 180, 238)
_TAB_EF = (0, 238, 180, 90)
_ROR4 = (0, 8, 1, 9, 2, 10, 3, 11, 4, 12, 5, 13, 6, 14, 7, 15)
_ASHX = (0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 5, 14, 7)
_QT0 = ((8,1,7,13,6,15,3,2,0,11,5,9,14,12,10,4),
        (2,8,11,13,15,7,6,14,3,1,9,4,0,10,12,5))
_QT1 = ((14,12,11,8,1,2,3,5,15,4,10,6,7,0,9,13),
        (1,14,2,11,4,12,3,7,6,13,10,5,15,9,0,8))
_QT2 = ((11,10,5,14,6,13,9,0,12,8,15,3,2,4,7,1),
        (4,12,7,5,1,6,9,10,0,14,13,8,2,11,3,15))
_QT3 = ((13,7,15,4,1,2,6,14,9,11,3,0,8,5,12,10),
        (11,9,5,1,12,3,13,14,6,4,7,15,2,0,8,10))


def _qp(n, x):
    a0 = x >> 4
    b0 = x & 15
    a1 = a0 ^ b0
    b1 = _ROR4[b0] ^ _ASHX[a0]
    a2 = _QT0[n][a1]
    b2 = _QT1[n][b1]
    a3 = a2 ^ b2
    b3 = _ROR4[b2] ^ _ASHX[a2]
    return (_QT3[n][b3] << 4) | _QT2[n][a3]


def _rotr32(x, n):
    return (x >> n) | ((x << (32 - n)) & 0xFFFFFFFF)


def _rotl32(x, n):
    return ((x << n) & 0xFFFFFFFF) | (x >> (32 - n))


def _byte(x, n):
    return (x >> (8 * n)) & 0xFF


class _TwofishCtx:
    __slots__ = ("k_len", "l_key", "s_key", "q_tab", "m_tab", "mk_tab")

    def __init__(self):
        self.k_len = 0
        self.l_key = [0] * 40
        self.s_key = [0] * 4
        self.q_tab = [[0] * 256, [0] * 256]
        self.m_tab = [[0] * 256 for _ in range(4)]
        self.mk_tab = [[0] * 256 for _ in range(4)]


def _gen_qtab(ctx):
    for i in range(256):
        ctx.q_tab[0][i] = _qp(0, i)
        ctx.q_tab[1][i] = _qp(1, i)


def _gen_mtab(ctx):
    for i in range(256):
        f01 = ctx.q_tab[1][i]
        f5b = f01 ^ (f01 >> 2) ^ _TAB_5B[f01 & 3]
        fef = f01 ^ (f01 >> 1) ^ (f01 >> 2) ^ _TAB_EF[f01 & 3]
        ctx.m_tab[0][i] = f01 + (f5b << 8) + (fef << 16) + (fef << 24)
        ctx.m_tab[2][i] = f5b + (fef << 8) + (f01 << 16) + (fef << 24)

        f01 = ctx.q_tab[0][i]
        f5b = f01 ^ (f01 >> 2) ^ _TAB_5B[f01 & 3]
        fef = f01 ^ (f01 >> 1) ^ (f01 >> 2) ^ _TAB_EF[f01 & 3]
        ctx.m_tab[1][i] = fef + (fef << 8) + (f5b << 16) + (f01 << 24)
        ctx.m_tab[3][i] = f5b + (f01 << 8) + (fef << 16) + (f5b << 24)


def _gen_mk_tab(ctx, key):
    if ctx.k_len == 2:
        for i in range(256):
            by = i & 0xFF
            ctx.mk_tab[0][i] = ctx.m_tab[0][
                ctx.q_tab[0][ctx.q_tab[0][by] ^ _byte(key[1], 0)] ^ _byte(key[0], 0)]
            ctx.mk_tab[1][i] = ctx.m_tab[1][
                ctx.q_tab[0][ctx.q_tab[1][by] ^ _byte(key[1], 1)] ^ _byte(key[0], 1)]
            ctx.mk_tab[2][i] = ctx.m_tab[2][
                ctx.q_tab[1][ctx.q_tab[0][by] ^ _byte(key[1], 2)] ^ _byte(key[0], 2)]
            ctx.mk_tab[3][i] = ctx.m_tab[3][
                ctx.q_tab[1][ctx.q_tab[1][by] ^ _byte(key[1], 3)] ^ _byte(key[0], 3)]
    elif ctx.k_len == 3:
        for i in range(256):
            by = i & 0xFF
            ctx.mk_tab[0][i] = ctx.m_tab[0][
                ctx.q_tab[0][ctx.q_tab[0][ctx.q_tab[1][by] ^ _byte(key[2], 0)]
                             ^ _byte(key[1], 0)] ^ _byte(key[0], 0)]
            ctx.mk_tab[1][i] = ctx.m_tab[1][
                ctx.q_tab[0][ctx.q_tab[1][ctx.q_tab[1][by] ^ _byte(key[2], 1)]
                             ^ _byte(key[1], 1)] ^ _byte(key[0], 1)]
            ctx.mk_tab[2][i] = ctx.m_tab[2][
                ctx.q_tab[1][ctx.q_tab[0][ctx.q_tab[0][by] ^ _byte(key[2], 2)]
                             ^ _byte(key[1], 2)] ^ _byte(key[0], 2)]
            ctx.mk_tab[3][i] = ctx.m_tab[3][
                ctx.q_tab[1][ctx.q_tab[1][ctx.q_tab[0][by] ^ _byte(key[2], 3)]
                             ^ _byte(key[1], 3)] ^ _byte(key[0], 3)]
    elif ctx.k_len == 4:
        for i in range(256):
            by = i & 0xFF
            ctx.mk_tab[0][i] = ctx.m_tab[0][
                ctx.q_tab[0][ctx.q_tab[0][ctx.q_tab[1][ctx.q_tab[1][by]
                             ^ _byte(key[3], 0)] ^ _byte(key[2], 0)]
                             ^ _byte(key[1], 0)] ^ _byte(key[0], 0)]
            ctx.mk_tab[1][i] = ctx.m_tab[1][
                ctx.q_tab[0][ctx.q_tab[1][ctx.q_tab[1][ctx.q_tab[0][by]
                             ^ _byte(key[3], 1)] ^ _byte(key[2], 1)]
                             ^ _byte(key[1], 1)] ^ _byte(key[0], 1)]
            ctx.mk_tab[2][i] = ctx.m_tab[2][
                ctx.q_tab[1][ctx.q_tab[0][ctx.q_tab[0][ctx.q_tab[0][by]
                             ^ _byte(key[3], 2)] ^ _byte(key[2], 2)]
                             ^ _byte(key[1], 2)] ^ _byte(key[0], 2)]
            ctx.mk_tab[3][i] = ctx.m_tab[3][
                ctx.q_tab[1][ctx.q_tab[1][ctx.q_tab[0][ctx.q_tab[1][by]
                             ^ _byte(key[3], 3)] ^ _byte(key[2], 3)]
                             ^ _byte(key[1], 3)] ^ _byte(key[0], 3)]


def _h_fun(ctx, x, key):
    b0 = _byte(x, 0)
    b1 = _byte(x, 1)
    b2 = _byte(x, 2)
    b3 = _byte(x, 3)
    if ctx.k_len >= 4:
        b0 = ctx.q_tab[1][b0] ^ _byte(key[3], 0)
        b1 = ctx.q_tab[0][b1] ^ _byte(key[3], 1)
        b2 = ctx.q_tab[0][b2] ^ _byte(key[3], 2)
        b3 = ctx.q_tab[1][b3] ^ _byte(key[3], 3)
    if ctx.k_len >= 3:
        b0 = ctx.q_tab[1][b0] ^ _byte(key[2], 0)
        b1 = ctx.q_tab[1][b1] ^ _byte(key[2], 1)
        b2 = ctx.q_tab[0][b2] ^ _byte(key[2], 2)
        b3 = ctx.q_tab[0][b3] ^ _byte(key[2], 3)
    if ctx.k_len >= 2:
        b0 = ctx.q_tab[0][ctx.q_tab[0][b0] ^ _byte(key[1], 0)] ^ _byte(key[0], 0)
        b1 = ctx.q_tab[0][ctx.q_tab[1][b1] ^ _byte(key[1], 1)] ^ _byte(key[0], 1)
        b2 = ctx.q_tab[1][ctx.q_tab[0][b2] ^ _byte(key[1], 2)] ^ _byte(key[0], 2)
        b3 = ctx.q_tab[1][ctx.q_tab[1][b3] ^ _byte(key[1], 3)] ^ _byte(key[0], 3)
    return ctx.m_tab[0][b0] ^ ctx.m_tab[1][b1] ^ ctx.m_tab[2][b2] ^ ctx.m_tab[3][b3]


def _mds_rem(p0, p1):
    for _ in range(8):
        t = p1 >> 24
        p1 = ((p1 << 8) & 0xFFFFFFFF) | (p0 >> 24)
        p0 = (p0 << 8) & 0xFFFFFFFF
        u = (t << 1) & 0xFFFFFFFF
        if t & 0x80:
            u ^= 0x0000014D
        p1 ^= t ^ ((u << 16) & 0xFFFFFFFF)
        u ^= t >> 1
        if t & 0x01:
            u ^= 0x0000014D >> 1
        p1 ^= ((u << 24) & 0xFFFFFFFF) | ((u << 8) & 0xFFFFFFFF)
    return p1


def _set_key(ctx, in_key, key_len):
    _gen_qtab(ctx)
    _gen_mtab(ctx)
    ctx.k_len = (key_len * 8) // 64

    me_key = [0] * 4
    mo_key = [0] * 4
    for i in range(ctx.k_len):
        me_key[i] = in_key[i * 2]
        mo_key[i] = in_key[i * 2 + 1]
        ctx.s_key[ctx.k_len - i - 1] = _mds_rem(in_key[i * 2], in_key[i * 2 + 1])

    for i in range(0, 40, 2):
        a = (0x01010101 * i) % 0x100000000
        b = (a + 0x01010101) % 0x100000000
        a = _h_fun(ctx, a, me_key)
        b = _rotl32(_h_fun(ctx, b, mo_key), 8)
        ctx.l_key[i] = (a + b) % 0x100000000
        ctx.l_key[i + 1] = _rotl32((a + 2 * b) % 0x100000000, 9)

    _gen_mk_tab(ctx, ctx.s_key)


def _tf_encrypt_block(ctx, in_blk):
    blk = [
        in_blk[0] ^ ctx.l_key[0], in_blk[1] ^ ctx.l_key[1],
        in_blk[2] ^ ctx.l_key[2], in_blk[3] ^ ctx.l_key[3],
    ]
    for i in range(8):
        t1 = (ctx.mk_tab[0][_byte(blk[1], 3)] ^ ctx.mk_tab[1][_byte(blk[1], 0)]
              ^ ctx.mk_tab[2][_byte(blk[1], 1)] ^ ctx.mk_tab[3][_byte(blk[1], 2)])
        t0 = (ctx.mk_tab[0][_byte(blk[0], 0)] ^ ctx.mk_tab[1][_byte(blk[0], 1)]
              ^ ctx.mk_tab[2][_byte(blk[0], 2)] ^ ctx.mk_tab[3][_byte(blk[0], 3)])
        blk[2] = _rotr32(blk[2] ^ ((t0 + t1 + ctx.l_key[4 * i + 8]) % 0x100000000), 1)
        blk[3] = _rotl32(blk[3], 1) ^ ((t0 + 2 * t1 + ctx.l_key[4 * i + 9]) % 0x100000000)
        t1 = (ctx.mk_tab[0][_byte(blk[3], 3)] ^ ctx.mk_tab[1][_byte(blk[3], 0)]
              ^ ctx.mk_tab[2][_byte(blk[3], 1)] ^ ctx.mk_tab[3][_byte(blk[3], 2)])
        t0 = (ctx.mk_tab[0][_byte(blk[2], 0)] ^ ctx.mk_tab[1][_byte(blk[2], 1)]
              ^ ctx.mk_tab[2][_byte(blk[2], 2)] ^ ctx.mk_tab[3][_byte(blk[2], 3)])
        blk[0] = _rotr32(blk[0] ^ ((t0 + t1 + ctx.l_key[4 * i + 10]) % 0x100000000), 1)
        blk[1] = _rotl32(blk[1], 1) ^ ((t0 + 2 * t1 + ctx.l_key[4 * i + 11]) % 0x100000000)
    return [
        blk[2] ^ ctx.l_key[4], blk[3] ^ ctx.l_key[5],
        blk[0] ^ ctx.l_key[6], blk[1] ^ ctx.l_key[7],
    ]


class _Twofish:
    """Twofish block cipher — encrypt-only (sufficient for EAX/CTR)."""

    def __init__(self, key: bytes):
        if len(key) not in (16, 24, 32):
            raise ValueError("Twofish key must be 16, 24, or 32 bytes")
        self._ctx = _TwofishCtx()
        key_words = [0] * 32
        for i in range(len(key) // 4):
            key_words[i] = struct.unpack("<L", key[i * 4:i * 4 + 4])[0]
        _set_key(self._ctx, key_words, len(key))

    def encrypt_block(self, block: bytes) -> bytes:
        """Encrypt a single 16-byte block."""
        a, b, c, d = struct.unpack("<4L", block[:16])
        r = _tf_encrypt_block(self._ctx, [a, b, c, d])
        return struct.pack("<4L", *r)


# ---------------------------------------------------------------------------
# CMAC  (NIST SP 800-38B)
# ---------------------------------------------------------------------------

def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _left_shift_one(data: bytes) -> bytes:
    out = bytearray(len(data))
    carry = 0
    for i in reversed(range(len(data))):
        out[i] = ((data[i] << 1) & 0xFF) | carry
        carry = (data[i] & 0x80) >> 7
    return bytes(out)


def _cmac_subkeys(encrypt_fn):
    L = encrypt_fn(bytes(_BLOCK))
    K1 = _left_shift_one(L)
    if L[0] & 0x80:
        K1 = _xor_bytes(K1, b"\x00" * 15 + b"\x87")
    K2 = _left_shift_one(K1)
    if K1[0] & 0x80:
        K2 = _xor_bytes(K2, b"\x00" * 15 + b"\x87")
    return K1, K2


def _cmac_digest(encrypt_fn, K1, K2, data: bytes) -> bytes:
    if len(data) == 0:
        last = _xor_bytes(b"\x80" + b"\x00" * 15, K2)
        blocks = []
    else:
        blocks = [data[i:i + _BLOCK] for i in range(0, len(data), _BLOCK)]
        if len(blocks[-1]) == _BLOCK:
            last = _xor_bytes(blocks[-1], K1)
            blocks = blocks[:-1]
        else:
            padded = blocks[-1] + b"\x80" + b"\x00" * (_BLOCK - len(blocks[-1]) - 1)
            last = _xor_bytes(padded, K2)
            blocks = blocks[:-1]

    X = bytes(_BLOCK)
    for blk in blocks:
        X = encrypt_fn(_xor_bytes(X, blk))
    return encrypt_fn(_xor_bytes(X, last))


# ---------------------------------------------------------------------------
# CTR mode
# ---------------------------------------------------------------------------

def _inc_counter_be(counter: bytearray):
    for i in range(_BLOCK - 1, -1, -1):
        counter[i] = (counter[i] + 1) & 0xFF
        if counter[i] != 0:
            break


def _ctr_process(encrypt_fn, initial_counter: bytes, data: bytes) -> bytes:
    counter = bytearray(initial_counter)
    out = bytearray()
    offset = 0
    while offset < len(data):
        keystream = encrypt_fn(bytes(counter))
        _inc_counter_be(counter)
        blk = data[offset:offset + _BLOCK]
        out.extend(b ^ k for b, k in zip(blk, keystream[:len(blk)]))
        offset += _BLOCK
    return bytes(out)


# ---------------------------------------------------------------------------
# EAX authenticated encryption (Bellare–Rogaway–Wagner)
# ---------------------------------------------------------------------------

def _omac_with_prefix(encrypt_fn, K1, K2, prefix: int, data: bytes) -> bytes:
    P = b"\x00" * (_BLOCK - 1) + bytes([prefix])
    return _cmac_digest(encrypt_fn, K1, K2, P + data)


def _eax_decrypt(encrypt_fn, nonce: bytes, ciphertext: bytes, tag: bytes,
                 aad: bytes = b"") -> bytes:
    K1, K2 = _cmac_subkeys(encrypt_fn)

    n_tag = _omac_with_prefix(encrypt_fn, K1, K2, 0x00, nonce)

    plaintext = _ctr_process(encrypt_fn, n_tag, ciphertext)

    h_tag = _omac_with_prefix(encrypt_fn, K1, K2, 0x01, aad)
    c_tag = _omac_with_prefix(encrypt_fn, K1, K2, 0x02, ciphertext)

    expected_tag = _xor_bytes(_xor_bytes(n_tag, h_tag), c_tag)
    if expected_tag != tag:
        raise ValueError("EAX authentication failed — file may be corrupted "
                         "or use an unsupported encryption variant")
    return plaintext


# ---------------------------------------------------------------------------
# Packet Tracer obfuscation / compression layers
# ---------------------------------------------------------------------------

def _deobfuscate_stage1(data: bytes) -> bytes:
    """Reverse the first obfuscation layer (byte-reversal with XOR)."""
    L = len(data)
    return bytes(data[L - 1 - i] ^ (L - i * L & 0xFF) for i in range(L))


def _deobfuscate_stage2(data: bytes) -> bytes:
    """Reverse the second obfuscation layer (sequential XOR)."""
    L = len(data)
    return bytes(b ^ (L - i & 0xFF) for i, b in enumerate(data))


def _decompress_qt(blob: bytes) -> bytes:
    """Decompress Qt-style zlib data (4-byte big-endian size prefix)."""
    if len(blob) < 5:
        raise ValueError("Compressed data too short")
    size = struct.unpack(">I", blob[:4])[0]
    return zlib.decompress(blob[4:])[:size]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

# Packet Tracer uses a fixed Twofish-128 key and IV for .pka/.pkt files.
_PT_KEY = bytes([137]) * 16
_PT_IV = bytes([16]) * 16


def decrypt_pka(raw: bytes) -> bytes:
    """Decrypt an encrypted Packet Tracer `.pka` file to its XML content.

    Args:
        raw: The entire file contents as bytes.

    Returns:
        The decrypted XML document as bytes.

    Raises:
        ValueError: If decryption or decompression fails (wrong format,
            corrupted data, unsupported encryption variant, etc.).
    """
    if len(raw) < _BLOCK + 1:
        raise ValueError("File too small to be an encrypted PKA archive")

    try:
        stage1 = _deobfuscate_stage1(raw)

        tf = _Twofish(_PT_KEY)
        ciphertext = stage1[:-_BLOCK]
        tag = stage1[-_BLOCK:]

        decrypted = _eax_decrypt(tf.encrypt_block, _PT_IV, ciphertext, tag)

        stage2 = _deobfuscate_stage2(decrypted)

        return _decompress_qt(stage2)
    except (ValueError, zlib.error, struct.error) as exc:
        raise ValueError(f"Failed to decrypt PKA file: {exc}") from exc
