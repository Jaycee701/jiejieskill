#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DES / 3DES 加解密 (纯 Python, 零依赖)
=====================================
遗留银行系统 / POS / 支付报文常用 3DES。与 sm4.py 同接口。

DES:   8字节key, 64bit块, 16轮 Feistel (FIPS 46-3)
3DES:  EDE 结构; 2-key(16B) / 3-key(24B)
模式:  ECB / CBC; 填充 PKCS7 / NoPadding

用法:
    # 解密 (CBC, hex)
    python des3.py -m cbc -d --hex -k 133457799BBCDFF1 --iv 0000000000000000 <密文>
    # 加密 (ECB)
    python des3.py -m ecb -e -k 133457799BBCDFF1 "hello"
    # 3DES (16/24字节key自动识别)
    python des3.py -m cbc -d --hex -k <32hex> --iv <16hex> <密文>

    # 自检 (DES 标准向量)
    python des3.py --selftest
"""
import argparse
import base64
import re
import sys

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

# ---------------- DES 查表 (FIPS 46-3) ----------------
IP = [
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
]
FP = [
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
]
E = [
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
]
P = [
    16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25,
]
PC1 = [
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4,
]
PC2 = [
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
]
SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

SBOXES = [
    [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
     0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
     4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
     15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
    [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
     3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
     0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
     13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
    [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
     13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
     13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
     1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
    [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
     13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
     10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
     3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
    [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
     14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
     4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
     11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
    [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
     10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
     9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
     4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
    [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
     13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
     1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
     6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
    [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
     1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
     7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
     2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
]


def _permute(src, table, in_bits=64):
    out = 0
    for i, pos in enumerate(table):
        bit = (src >> (in_bits - pos)) & 1
        out |= bit << (len(table) - 1 - i)
    return out


def _key_schedule(key8):
    key = int.from_bytes(key8, 'big')
    k56 = _permute(key, PC1, 64)
    c = (k56 >> 28) & 0x0fffffff
    d = k56 & 0x0fffffff
    rk = []
    for shift in SHIFTS:
        c = ((c << shift) | (c >> (28 - shift))) & 0x0fffffff
        d = ((d << shift) | (d >> (28 - shift))) & 0x0fffffff
        rk.append(_permute((c << 28) | d, PC2, 56))
    return rk


def _f(r, subkey):
    x = _permute(r, E, 32) ^ subkey
    s = 0
    for i in range(8):
        chunk = (x >> (42 - i * 6)) & 0x3f
        row = ((chunk & 0x20) >> 4) | (chunk & 1)
        col = (chunk >> 1) & 0x0f
        s = (s << 4) | SBOXES[i][row * 16 + col]
    return _permute(s, P, 32)


def _des_block(block8, rk, decrypt=False):
    b = _permute(int.from_bytes(block8, 'big'), IP, 64)
    l = (b >> 32) & 0xffffffff
    r = b & 0xffffffff
    keys = list(reversed(rk)) if decrypt else rk
    for k in keys:
        l, r = r, l ^ _f(r, k)
    pre = (r << 32) | l
    return _permute(pre, FP, 64).to_bytes(8, 'big')


class DES:
    def __init__(self, key: bytes):
        assert len(key) == 8, "DES key 须为 8 字节"
        self._rk = _key_schedule(key)

    def encrypt_block(self, b):
        return _des_block(b, self._rk, False)

    def decrypt_block(self, b):
        return _des_block(b, self._rk, True)


class TripleDES:
    """3DES-EDE: 2-key(16B) 或 3-key(24B)。
    加密: C = E_K1( D_K2( E_K3(M) ))
    解密: M = D_K1( E_K2( D_K3(C) ))
    """

    def __init__(self, key: bytes):
        if len(key) == 16:
            self._keys = [DES(key[:8]), DES(key[8:16]), DES(key[:8])]  # K3=K1
        elif len(key) == 24:
            self._keys = [DES(key[:8]), DES(key[8:16]), DES(key[16:24])]
        else:
            raise ValueError("3DES key 须为 16 或 24 字节")

    def encrypt_block(self, b):
        return self._keys[0].encrypt_block(
            self._keys[1].decrypt_block(self._keys[2].encrypt_block(b)))

    def decrypt_block(self, b):
        # M = D_K3( E_K2( D_K1(C) ))
        return self._keys[2].decrypt_block(
            self._keys[1].encrypt_block(self._keys[0].decrypt_block(b)))


# ---------------- 填充 ----------------
def pkcs7_pad(data, bs=8):
    n = bs - len(data) % bs
    return data + bytes([n]) * n


def pkcs7_unpad(data, bs=8):
    if not data:
        return data
    n = data[-1]
    if not 1 <= n <= bs or data[-n:] != bytes([n]) * n:
        raise ValueError("PKCS7 填充校验失败")
    return data[:-n]


def _cipher(key: bytes):
    return TripleDES(key) if len(key) in (16, 24) else DES(key)


def des3_cbc(data: bytes, key: bytes, iv: bytes, decrypt: bool,
             padding: str = 'pkcs7', bs: int = 8) -> bytes:
    c = _cipher(key)
    if not decrypt and padding == 'pkcs7':
        data = pkcs7_pad(data, bs)
    assert len(data) % bs == 0, "数据长度不是块大小倍数"
    out = b''
    prev = iv
    for i in range(0, len(data), bs):
        blk = data[i:i + bs]
        if decrypt:
            dec = c.decrypt_block(blk)
            out += bytes(a ^ b for a, b in zip(dec, prev))
            prev = blk
        else:
            x = bytes(a ^ b for a, b in zip(blk, prev))
            out += c.encrypt_block(x)
            prev = out[-bs:]
    if decrypt and padding == 'pkcs7':
        out = pkcs7_unpad(out, bs)
    return out


def des3_ecb(data: bytes, key: bytes, decrypt: bool, padding: str = 'pkcs7',
             bs: int = 8) -> bytes:
    c = _cipher(key)
    fn = c.decrypt_block if decrypt else c.encrypt_block
    if not decrypt and padding == 'pkcs7':
        data = pkcs7_pad(data, bs)
    assert len(data) % bs == 0
    out = b''.join(fn(data[i:i + bs]) for i in range(0, len(data), bs))
    if decrypt and padding == 'pkcs7':
        out = pkcs7_unpad(out, bs)
    return out


def looks_utf8(b):
    try:
        b.decode('utf-8')
        return True
    except UnicodeDecodeError:
        return False


def selftest():
    ok = True
    # FIPS 46-3 标准向量
    k = bytes.fromhex('133457799BBCDFF1')
    pt = bytes.fromhex('0123456789ABCDEF')
    ct = bytes.fromhex('85E813540F0AB405')
    got = DES(k).encrypt_block(pt)
    ok = ok and got == ct
    print(f"  [{'OK' if got == ct else 'FAIL'}] DES 标准向量: {got.hex().upper()}")
    # 解密还原
    back = DES(k).decrypt_block(ct)
    ok = ok and back == pt
    print(f"  [{'OK' if back == pt else 'FAIL'}] DES 解密还原")
    # 3DES 2-key 往返
    k3 = bytes.fromhex('0123456789ABCDEFFEDCBA9876543210')
    c = TripleDES(k3)
    enc = c.encrypt_block(pt)
    ok = ok and c.decrypt_block(enc) == pt
    print(f"  [{'OK' if c.decrypt_block(enc) == pt else 'FAIL'}] 3DES-2KEY 往返")
    # 3DES 3-key 往返
    k3k = bytes.fromhex('0123456789ABCDEFFEDCBA987654321089ABCDEF01234567')
    c = TripleDES(k3k)
    enc = c.encrypt_block(pt)
    ok = ok and c.decrypt_block(enc) == pt
    print(f"  [{'OK' if c.decrypt_block(enc) == pt else 'FAIL'}] 3DES-3KEY 往返")
    # CBC 中文明文往返
    key = bytes.fromhex('0123456789ABCDEFFEDCBA9876543210')
    iv = bytes(8)
    msg = '3DES 支付报文 中文测试'.encode()
    ct = des3_cbc(msg, key, iv, False)
    rt = des3_cbc(ct, key, iv, True)
    ok = ok and rt == msg
    print(f"  [{'OK' if rt == msg else 'FAIL'}] 3DES-CBC 中文明文往返")
    print(f"\n[{'全部通过' if ok else '存在失败'}] DES/3DES 自检")
    sys.exit(0 if ok else 1)


def main():
    ap = argparse.ArgumentParser(description='DES/3DES 加解密 (零依赖)')
    ap.add_argument('data', nargs='?')
    ap.add_argument('-m', '--mode', choices=['ecb', 'cbc'], default='ecb')
    ap.add_argument('-e', '--encrypt', action='store_true')
    ap.add_argument('-d', '--decrypt', action='store_true')
    ap.add_argument('-k', '--key', help='密钥: DES=8B, 3DES=16B/24B (hex)')
    ap.add_argument('--iv', help='IV (hex 16)')
    ap.add_argument('--hex', action='store_true')
    ap.add_argument('--b64', action='store_true')
    ap.add_argument('--padding', choices=['pkcs7', 'none'], default='pkcs7')
    ap.add_argument('-i', '--in', dest='infile')
    ap.add_argument('-o', '--out', dest='outfile')
    ap.add_argument('--selftest', action='store_true')
    args = ap.parse_args()

    if args.selftest:
        selftest(); return

    if not args.key:
        sys.exit("[-] 需要 --key (hex)")
    key = bytes.fromhex(args.key)
    if len(key) not in (8, 16, 24):
        sys.exit("[-] key 须为 8(DES)/16/24(3DES) 字节")
    if args.encrypt and args.decrypt:
        sys.exit("[-] -e/-d 互斥")
    decrypt = not args.encrypt

    if args.infile:
        raw = open(args.infile, 'r', encoding='utf-8', errors='replace').read()
        raw = re.sub(r'\s+', '', raw)
    elif args.data:
        raw = args.data
    else:
        sys.exit("[-] 需要数据")

    data = bytes.fromhex(raw) if args.hex else \
        (base64.b64decode(raw) if args.b64 else raw.encode('utf-8'))

    iv = bytes.fromhex(args.iv) if args.iv else bytes(8)
    try:
        out = des3_cbc(data, key, iv, decrypt, args.padding) if args.mode == 'cbc' \
            else des3_ecb(data, key, decrypt, args.padding)
    except (ValueError, AssertionError) as e:
        sys.exit(f"[-] {e}")

    if args.outfile:
        open(args.outfile, 'wb').write(out)
        print(f"[*] 已写出: {args.outfile}")
        return
    print(f"[*] {'解密' if decrypt else '加密'} {'3DES' if len(key) > 8 else 'DES'} {args.mode.upper()}")
    if looks_utf8(out):
        print("[+] " + out.decode('utf-8', 'replace'))
    else:
        print("[?] hex: " + out.hex())


if __name__ == '__main__':
    main()
