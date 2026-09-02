#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AES 加解密 (纯 Python, 零依赖) —— 银行现代系统国际算法主力
==========================================================
AES-128/256, 模式 ECB / CBC / CTR / GCM (GCM 输出认证标签)。
GCM 为现代标准 (TLS/API/字段加密), CBC 为兼容旧系统。

用法:
    # CBC 解密
    python aes.py -m cbc -d --hex -k 000102030405060708090A0B0C0D0E0F --iv 00000000000000000000000000000000 <密文>
    # GCM 解密 (需要认证标签)
    python aes.py -m gcm -d --hex -k <32hex> --iv <12hex> --tag <32hex> <密文>
    # GCM 加密 (输出密文 + 标签)
    python aes.py -m gcm -e -k <32hex> --iv <12hex> "明文"
    # CTR / ECB
    python aes.py -m ctr -d --hex -k <key> --iv <16hex> <密文>

    # 自检 (FIPS 197 + NIST GCM 向量)
    python aes.py --selftest
"""
import argparse
import base64
import re
import sys

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

# ---------------- GF(2^8) 与 S-box ----------------
def _gmul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a <<= 1
        if a & 0x100:
            a ^= 0x11B
        b >>= 1
    return r & 0xFF


def _gen_sbox():
    exp, log = [0] * 256, [0] * 256
    x = 1
    for i in range(255):
        exp[i] = x
        log[x] = i
        x = _gmul(x, 3)
    sbox = [0] * 256
    inv_sbox = [0] * 256
    for i in range(256):
        inv = 0 if i == 0 else exp[(255 - log[i]) % 255]
        b = inv
        b ^= ((inv << 1) | (inv >> 7)) & 0xFF
        b ^= ((inv << 2) | (inv >> 6)) & 0xFF
        b ^= ((inv << 3) | (inv >> 5)) & 0xFF
        b ^= ((inv << 4) | (inv >> 4)) & 0xFF
        b ^= 0x63
        sbox[i] = b
        inv_sbox[b] = i
    return sbox, inv_sbox


SBOX, INV_SBOX = _gen_sbox()


def _xtime(a):
    return (a << 1) ^ (0x11B if a & 0x80 else 0)


def _sub_word(w, sbox):
    return ((sbox[(w >> 24) & 0xFF] << 24) | (sbox[(w >> 16) & 0xFF] << 16)
            | (sbox[(w >> 8) & 0xFF] << 8) | sbox[w & 0xFF])


def _rot_word(w):
    return ((w << 8) | (w >> 24)) & 0xFFFFFFFF


def _expand_key(key, nk, nr):
    w = [int.from_bytes(key[4 * i:4 * i + 4], 'big') for i in range(nk)]
    rcon = 1
    for i in range(nk, 4 * (nr + 1)):
        temp = w[i - 1]
        if i % nk == 0:
            temp = _sub_word(_rot_word(temp), SBOX) ^ (rcon << 24)
            rcon = _xtime(rcon) & 0xFF
        elif nk > 6 and i % nk == 4:
            temp = _sub_word(temp, SBOX)
        w.append(w[i - nk] ^ temp)
    return w


def _add_round_key(state, rk):
    for i in range(16):
        state[i] ^= (rk[i // 4] >> (24 - 8 * (i % 4))) & 0xFF


def _sub_bytes(state, sbox):
    for i in range(16):
        state[i] = sbox[state[i]]


def _shift_rows(state, inv=False):
    # 索引 = row + 4*col; 加密左移: s'[r][c] = s[r][(c+r)%4]
    out = [0] * 16
    for row in range(4):
        for col in range(4):
            src_col = (col - row) % 4 if inv else (col + row) % 4
            out[row + 4 * col] = state[row + 4 * src_col]
    return out


def _mix_columns(state, inv=False):
    out = [0] * 16
    for c in range(4):
        v = state[4 * c:4 * c + 4]
        if not inv:
            out[4 * c] = _gmul(v[0], 2) ^ _gmul(v[1], 3) ^ v[2] ^ v[3]
            out[4 * c + 1] = v[0] ^ _gmul(v[1], 2) ^ _gmul(v[2], 3) ^ v[3]
            out[4 * c + 2] = v[0] ^ v[1] ^ _gmul(v[2], 2) ^ _gmul(v[3], 3)
            out[4 * c + 3] = _gmul(v[0], 3) ^ v[1] ^ v[2] ^ _gmul(v[3], 2)
        else:
            out[4 * c] = _gmul(v[0], 14) ^ _gmul(v[1], 11) ^ _gmul(v[2], 13) ^ _gmul(v[3], 9)
            out[4 * c + 1] = _gmul(v[0], 9) ^ _gmul(v[1], 14) ^ _gmul(v[2], 11) ^ _gmul(v[3], 13)
            out[4 * c + 2] = _gmul(v[0], 13) ^ _gmul(v[1], 9) ^ _gmul(v[2], 14) ^ _gmul(v[3], 11)
            out[4 * c + 3] = _gmul(v[0], 11) ^ _gmul(v[1], 13) ^ _gmul(v[2], 9) ^ _gmul(v[3], 14)
    return out


class AES:
    def __init__(self, key: bytes):
        self.nk = len(key) // 4
        if self.nk not in (4, 6, 8):
            raise ValueError("AES key 须为 16/24/32 字节")
        self.nr = {4: 10, 6: 12, 8: 14}[self.nk]
        self._rk = _expand_key(key, self.nk, self.nr)

    def encrypt_block(self, b: bytes) -> bytes:
        st = list(b)
        _add_round_key(st, self._rk[0:4])
        for r in range(1, self.nr):
            _sub_bytes(st, SBOX)
            st = _shift_rows(st)
            st = _mix_columns(st)
            _add_round_key(st, self._rk[r * 4:(r + 1) * 4])
        _sub_bytes(st, SBOX)
        st = _shift_rows(st)
        _add_round_key(st, self._rk[self.nr * 4:self.nr * 4 + 4])
        return bytes(st)

    def decrypt_block(self, b: bytes) -> bytes:
        st = list(b)
        _add_round_key(st, self._rk[self.nr * 4:self.nr * 4 + 4])
        for r in range(self.nr - 1, 0, -1):
            st = _shift_rows(st, inv=True)
            _sub_bytes(st, INV_SBOX)
            _add_round_key(st, self._rk[r * 4:(r + 1) * 4])
            st = _mix_columns(st, inv=True)
        st = _shift_rows(st, inv=True)
        _sub_bytes(st, INV_SBOX)
        _add_round_key(st, self._rk[0:4])
        return bytes(st)


# ---------------- 填充 ----------------
def _pkcs7_pad(data, bs=16):
    n = bs - len(data) % bs
    return data + bytes([n]) * n


def _pkcs7_unpad(data, bs=16):
    if not data:
        return data
    n = data[-1]
    if not 1 <= n <= bs or data[-n:] != bytes([n]) * n:
        raise ValueError("PKCS7 填充校验失败")
    return data[:-n]


# ---------------- 模式 ----------------
def _ecb(data, key, decrypt, padding):
    c = AES(key)
    fn = c.decrypt_block if decrypt else c.encrypt_block
    if not decrypt and padding == 'pkcs7':
        data = _pkcs7_pad(data)
    assert len(data) % 16 == 0
    out = b''.join(fn(data[i:i + 16]) for i in range(0, len(data), 16))
    return _pkcs7_unpad(out) if (decrypt and padding == 'pkcs7') else out


def _cbc(data, key, iv, decrypt, padding):
    c = AES(key)
    if not decrypt and padding == 'pkcs7':
        data = _pkcs7_pad(data)
    assert len(data) % 16 == 0
    out = b''
    prev = iv
    for i in range(0, len(data), 16):
        blk = data[i:i + 16]
        if decrypt:
            dec = c.decrypt_block(blk)
            out += bytes(a ^ b for a, b in zip(dec, prev))
            prev = blk
        else:
            out += c.encrypt_block(bytes(a ^ b for a, b in zip(blk, prev)))
            prev = out[-16:]
    return _pkcs7_unpad(out) if (decrypt and padding == 'pkcs7') else out


def _ctr(data, key, iv):
    c = AES(key)
    ctr = int.from_bytes(iv, 'big')
    out = b''
    for i in range(0, len(data), 16):
        ks = c.encrypt_block(ctr.to_bytes(16, 'big'))
        blk = data[i:i + 16]
        out += bytes(a ^ b for a, b in zip(blk, ks))
        ctr = (ctr + 1) & ((1 << 128) - 1)
    return out


# ---------------- GCM (NIST SP 800-38D) ----------------
def _gf128_mul(x, y):
    """GF(2^128) 乘法 (GCM 规范): Y 从最高位处理, V 右移, 约简 0xE1<<120。"""
    r = 0
    v = x
    for i in range(127, -1, -1):
        if (y >> i) & 1:
            r ^= v
        if v & 1:
            v = (v >> 1) ^ 0xE1000000000000000000000000000000
        else:
            v >>= 1
    return r


def _ghash(h, blocks: bytes) -> int:
    y = 0
    for i in range(0, len(blocks), 16):
        y = _gf128_mul(y ^ int.from_bytes(blocks[i:i + 16], 'big'), h)
    return y


def _inc32(x: int) -> int:
    return ((x >> 32) << 32) | ((x + 1) & 0xFFFFFFFF)


def aes_gcm(key: bytes, iv: bytes, data: bytes, tag: bytes = None,
            aad: bytes = b'', decrypt: bool = False, taglen: int = 16):
    """GCM 加解密。decrypt=False → (密文, 标签); decrypt=True → 明文 (校验标签)。"""
    c = AES(key)
    h = int.from_bytes(c.encrypt_block(bytes(16)), 'big')  # H = E(K, 0^128)
    if len(iv) == 12:
        j0 = int.from_bytes(iv + b'\x00\x00\x00\x01', 'big')
    else:
        padded_iv = iv + b'\x00' * ((16 - len(iv) % 16) % 16) + (len(iv) * 8).to_bytes(8, 'big')
        j0 = _ghash(h, padded_iv)

    def gctr(start, blocks):
        out = b''
        ctr = start
        for i in range(0, len(blocks), 16):
            ks = c.encrypt_block(ctr.to_bytes(16, 'big'))
            out += bytes(a ^ b for a, b in zip(blocks[i:i + 16], ks))
            ctr = _inc32(ctr)
        return out

    if not decrypt:
        ct = gctr(_inc32(j0), data)
    else:
        if tag is None:
            raise ValueError("GCM 解密需要 --tag")
        ct = data
        data = gctr(_inc32(j0), ct)

    # S = GHASH_H(AAD‖pad‖CT‖pad‖[len(A)]64‖[len(C)]64)
    aad_pad = aad + b'\x00' * ((16 - len(aad) % 16) % 16)
    ct_pad = ct + b'\x00' * ((16 - len(ct) % 16) % 16)
    lens = ((len(aad) * 8) << 64 | (len(ct) * 8)).to_bytes(16, 'big')
    s = _ghash(h, aad_pad + ct_pad + lens)
    t = gctr(j0, s.to_bytes(16, 'big'))[:taglen]

    if decrypt:
        if not _const_eq(t, tag):
            raise ValueError("GCM 认证标签校验失败: 密钥/IV/密文/标签不对")
        return data
    return ct, t


def _const_eq(a: bytes, b: bytes) -> bool:
    if len(a) != len(b):
        return False
    r = 0
    for x, y in zip(a, b):
        r |= x ^ y
    return r == 0


def _looks_utf8(b):
    try:
        b.decode('utf-8')
        return True
    except UnicodeDecodeError:
        return False


def selftest():
    ok = True
    # FIPS 197 向量
    k = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
    pt = bytes.fromhex('00112233445566778899aabbccddeeff')
    ct = bytes.fromhex('69c4e0d86a7b0430d8cdb78070b4c55a')
    got = AES(k).encrypt_block(pt)
    ok = ok and got == ct
    print(f"  [{'OK' if got == ct else 'FAIL'}] AES-128 FIPS197: {got.hex()}")
    ok = ok and AES(k).decrypt_block(ct) == pt
    print(f"  [{'OK' if AES(k).decrypt_block(ct) == pt else 'FAIL'}] AES-128 解密还原")

    # GCM NIST 向量 (cryptography 库校验): key=0, iv=0(12B), pt=16个0, aad=""
    gk = bytes(16)
    giv = bytes(12)
    gpt = bytes(16)
    c, tag = aes_gcm(gk, giv, gpt)
    ok = ok and c.hex() == '0388dace60b6a392f328c2b971b2fe78' \
        and tag.hex() == 'ab6e47d42cec13bdf53a67b21257bddf'
    print(f"  [{'OK' if c.hex() == '0388dace60b6a392f328c2b971b2fe78' else 'FAIL'}] "
          f"GCM 加密向量: CT={c.hex()}")
    ok = ok and tag.hex() == 'ab6e47d42cec13bdf53a67b21257bddf'
    print(f"  [{'OK' if tag.hex() == 'ab6e47d42cec13bdf53a67b21257bddf' else 'FAIL'}] GCM 标签向量: T={tag.hex()}")
    # GCM 解密还原 + 标签校验
    back = aes_gcm(gk, giv, c, tag, decrypt=True)
    ok = ok and back == gpt
    print(f"  [{'OK' if back == gpt else 'FAIL'}] GCM 解密还原")
    # 篡改标签应失败
    try:
        aes_gcm(gk, giv, c, bytes([tag[0] ^ 1]) + tag[1:], decrypt=True)
        ok = False
        print("  [FAIL] 篡改标签应拒绝")
    except ValueError:
        print("  [OK] 篡改标签被拒绝")

    # CBC 往返
    for m in (b'hello aes', '银行 AES 报文 中文测试'.encode(), b'A' * 40):
        enc = _cbc(m, k, bytes(16), False, 'pkcs7')
        ok = ok and _cbc(enc, k, bytes(16), True, 'pkcs7') == m
    print(f"  [{'OK' if ok else 'FAIL'}] CBC/中文明文往返")
    print(f"\n[{'全部通过' if ok else '存在失败'}] AES/GCM 自检 (FIPS197 + NIST GCM)")
    sys.exit(0 if ok else 1)


def main():
    ap = argparse.ArgumentParser(description='AES 加解密 (ECB/CBC/CTR/GCM)')
    ap.add_argument('--selftest', action='store_true')
    ap.add_argument('-m', '--mode', choices=['ecb', 'cbc', 'ctr', 'gcm'], default='cbc')
    ap.add_argument('-e', '--encrypt', action='store_true')
    ap.add_argument('-d', '--decrypt', action='store_true')
    ap.add_argument('-k', '--key', required=False, help='密钥 hex (16/24/32字节)')
    ap.add_argument('--iv', help='IV (hex 16 或 GCM 12)')
    ap.add_argument('--tag', help='GCM 认证标签 (hex)')
    ap.add_argument('--aad', help='GCM 附加认证数据 (hex)')
    ap.add_argument('--hex', action='store_true')
    ap.add_argument('--b64', action='store_true')
    ap.add_argument('--padding', choices=['pkcs7', 'none'], default='pkcs7')
    ap.add_argument('-i', '--in', dest='infile')
    ap.add_argument('data', nargs='?')
    args = ap.parse_args()

    if args.selftest:
        selftest(); return
    if not args.key:
        sys.exit("[-] 需要 --key (hex)")
    key = bytes.fromhex(args.key)
    if len(key) not in (16, 24, 32):
        sys.exit("[-] AES key 须为 16/24/32 字节")

    if args.infile:
        raw = open(args.infile, 'r', encoding='utf-8', errors='replace').read()
        raw = re.sub(r'\s+', '', raw)
    elif args.data:
        raw = args.data
    else:
        sys.exit("[-] 需要数据")
    data = bytes.fromhex(raw) if args.hex else \
        (base64.b64decode(raw) if args.b64 else raw.encode('utf-8'))
    decrypt = not args.encrypt

    try:
        if args.mode == 'gcm':
            if len(args.iv or '') != 24:
                sys.exit("[-] GCM 需 12 字节 IV (hex 24 字符)")
            iv = bytes.fromhex(args.iv)
            aad = bytes.fromhex(args.aad) if args.aad else b''
            tag = bytes.fromhex(args.tag) if args.tag else None
            if not decrypt:
                ct, tg = aes_gcm(key, iv, data, aad=aad)
                print(f"[*] GCM 加密, 密文 ({len(ct)}B):")
                print(f"    hex: {ct.hex()}")
                print(f"    标签: {tg.hex()}")
            else:
                pt = aes_gcm(key, iv, data, tag, aad, decrypt=True)
                print(f"[+] GCM 解密 (标签校验通过):")
                print("    " + (pt.decode('utf-8', 'replace') if _looks_utf8(pt) else 'hex: ' + pt.hex()))
            return
        iv = bytes.fromhex(args.iv) if args.iv else bytes(16)
        if args.mode in ('cbc', 'ctr') and not args.iv:
            sys.exit(f"[-] {args.mode.upper()} 需要 --iv")
        if args.mode == 'ecb':
            out = _ecb(data, key, decrypt, args.padding)
        elif args.mode == 'cbc':
            out = _cbc(data, key, iv, decrypt, args.padding)
        else:
            out = _ctr(data, key, iv)
    except (ValueError, AssertionError) as e:
        sys.exit(f"[-] {e}")

    print(f"[*] {'解密' if decrypt else '加密'} AES-{len(key)*8} {args.mode.upper()}")
    if _looks_utf8(out):
        print("[+] " + out.decode('utf-8', 'replace'))
    else:
        print("[?] hex: " + out.hex())


if __name__ == '__main__':
    main()
