#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RSA 加解密 / 签名 / 弱密钥检测 (纯 Python, 零依赖)
==================================================
银行数字证书 / 密钥交换 / U盾体系的基础。支持:
  - 密钥生成 (p,q,e,d,n, 含 CRT 参数)
  - 公钥加密 / 私钥解密 (PKCS#1 v1.5 与 NoPadding)
  - 私钥签名 / 公钥验签 (PKCS#1 v1.5)
  - 弱密钥检测: 小公钥因子分解 (Pollard's rho), 探测低指数/共享模数

用法:
    # 生成密钥对
    python rsa.py --genkey 2048
    # 公钥加密 (PKCS#1 v1.5)
    python rsa.py --encrypt --n <hex> --e 65537 "明文"
    # 私钥解密
    python rsa.py --decrypt --d <hex> --n <hex> <密文hex>
    # 签名 / 验签
    python rsa.py --sign --d <hex> --n <hex> "消息"
    python rsa.py --verify --e 65537 --n <hex> --sig <hex> "消息"
    # 弱密钥检测 (小 n 分解)
    python rsa.py --factorize <n_hex>

    # 自检
    python rsa.py --selftest
"""
import argparse
import base64
import secrets
import sys

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')


# ---------------- 大数基础 ----------------
def _is_prime(n, rounds=20):
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _gen_prime(bits):
    while True:
        p = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if _is_prime(p):
            return p


def _egcd(a, b):
    if b == 0:
        return a, 1, 0
    g, x, y = _egcd(b, a % b)
    return g, y, x - (a // b) * y


def _modinv(a, m):
    g, x, _ = _egcd(a % m, m)
    if g != 1:
        raise ValueError("无逆元")
    return x % m


# ---------------- 密钥生成 ----------------
def gen_keypair(bits=2048, e=65537):
    p = q = 1
    while p == q:
        p = _gen_prime(bits // 2)
        q = _gen_prime(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    d = _modinv(e, phi)
    return {'p': p, 'q': q, 'e': e, 'd': d, 'n': n,
            'dp': d % (p - 1), 'dq': d % (q - 1), 'qinv': _modinv(q, p)}


# ---------------- PKCS#1 v1.5 填充 ----------------
def _pkcs1_pad(data: bytes, k: int) -> bytes:
    """k = 模数字节数。EM = 0x00||0x02||PS(≥8非0随机)||0x00||M"""
    if len(data) > k - 11:
        raise ValueError("消息过长")
    ps = bytearray()
    while len(ps) < k - 3 - len(data):
        b = secrets.randbelow(256)
        if b != 0:
            ps.append(b)
    return b'\x00\x02' + bytes(ps) + b'\x00' + data


def _pkcs1_unpad(em: bytes) -> bytes:
    if len(em) < 11 or em[0] != 0 or em[1] != 2:
        raise ValueError("PKCS#1 填充无效")
    i = em.index(0, 2)
    return em[i + 1:]


def _pkcs1_sign_pad(data: bytes, k: int) -> bytes:
    """签名: 0x00||0x01||0xFF...||0x00||M"""
    if len(data) > k - 11:
        raise ValueError("消息过长")
    return b'\x00\x01' + b'\xff' * (k - 3 - len(data)) + b'\x00' + data


def _pkcs1_sign_unpad(em: bytes) -> bytes:
    if len(em) < 11 or em[0] != 0 or em[1] != 1:
        raise ValueError("签名填充无效")
    i = em.index(0, 2)
    return em[i + 1:]


# ---------------- 加解密 / 签名 ----------------
def encrypt(data: bytes, n: int, e: int, padding='pkcs1') -> bytes:
    k = (n.bit_length() + 7) // 8
    em = _pkcs1_pad(data, k) if padding == 'pkcs1' else \
        (data if len(data) == k else data.ljust(k, b'\x00'))
    m = int.from_bytes(em, 'big')
    return pow(m, e, n).to_bytes(k, 'big')


def decrypt(ct: bytes, d: int, n: int, padding='pkcs1',
            p=None, q=None, dp=None, dq=None, qinv=None) -> bytes:
    k = (n.bit_length() + 7) // 8
    c = int.from_bytes(ct[:k], 'big')
    if p and q and dp and dq and qinv:
        # CRT 加速
        m1 = pow(c, dp, p)
        m2 = pow(c, dq, q)
        h = (qinv * (m1 - m2)) % p
        m = m2 + h * q
    else:
        m = pow(c, d, n)
    em = m.to_bytes(k, 'big')
    return _pkcs1_unpad(em) if padding == 'pkcs1' else em


def sign(msg: bytes, d: int, n: int, padding='pkcs1') -> bytes:
    k = (n.bit_length() + 7) // 8
    em = _pkcs1_sign_pad(msg, k)
    m = int.from_bytes(em, 'big')
    return pow(m, d, n).to_bytes(k, 'big')


def verify(msg: bytes, sig: bytes, e: int, n: int, padding='pkcs1') -> bool:
    k = (n.bit_length() + 7) // 8
    s = int.from_bytes(sig[:k], 'big')
    em = pow(s, e, n).to_bytes(k, 'big')
    try:
        return _pkcs1_sign_unpad(em) == msg
    except ValueError:
        return False


# ---------------- 弱密钥检测 (因子分解) ----------------
def _pollard_rho(n):
    if n % 2 == 0:
        return 2
    x = secrets.randbelow(n - 2) + 2
    y = x
    c = secrets.randbelow(n - 1) + 1
    d = 1
    while d == 1:
        x = (x * x + c) % n
        y = (y * y + c) % n
        y = (y * y + c) % n
        d = _egcd(abs(x - y), n)[0]
        if d == n:
            x = secrets.randbelow(n - 2) + 2
            y = x
            c = secrets.randbelow(n - 1) + 1
            d = 1
    return d


def factorize(n, limit=100000):
    """尝试分解 n: 先试小素数, 再用 Pollard's rho。返回 (p, q) 或 None。"""
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47):
        if n % p == 0:
            return p, n // p
    d = _pollard_rho(n)
    if d not in (1, n):
        return d, n // d
    return None


# ---------------- 自检 ----------------
def selftest():
    ok = True
    # 1024 位生成 + 往返
    kp = gen_keypair(1024)
    msg = 'RSA 银行报文 中文测试 12345'.encode()
    ct = encrypt(msg, kp['n'], kp['e'])
    pt = decrypt(ct, kp['d'], kp['n'], p=kp['p'], q=kp['q'],
                 dp=kp['dp'], dq=kp['dq'], qinv=kp['qinv'])
    ok = ok and pt == msg
    print(f"  [{'OK' if pt == msg else 'FAIL'}] 1024bit 生成 + 加解密往返 (CRT)")
    # 非 CRT 解密
    pt2 = decrypt(ct, kp['d'], kp['n'])
    ok = ok and pt2 == msg
    print(f"  [{'OK' if pt2 == msg else 'FAIL'}] 非 CRT 解密")
    # 签名验签
    sig = sign(msg, kp['d'], kp['n'])
    ok = ok and verify(msg, sig, kp['e'], kp['n'])
    ok = ok and not verify(msg + b'x', sig, kp['e'], kp['n'])
    print(f"  [{'OK' if verify(msg, sig, kp['e'], kp['n']) else 'FAIL'}] 签名验签 + 篡改拒绝")
    # 弱密钥分解
    small = 1000000000000000003  # 素数
    n_small = small * 1000000000000000077
    f = factorize(n_small)
    ok = ok and f is not None and f[0] * f[1] == n_small
    print(f"  [{'OK' if f and f[0]*f[1]==n_small else 'FAIL'}] 弱密钥分解: {f[0] if f else None}")
    print(f"\n[{'全部通过' if ok else '存在失败'}] RSA 自检")
    sys.exit(0 if ok else 1)


def main():
    ap = argparse.ArgumentParser(description='RSA 加解密/签名/弱密钥检测')
    ap.add_argument('--selftest', action='store_true')
    ap.add_argument('--genkey', type=int, metavar='BITS', help='生成密钥对 (bits)')
    ap.add_argument('--encrypt', action='store_true', help='公钥加密')
    ap.add_argument('--decrypt', action='store_true', help='私钥解密')
    ap.add_argument('--sign', action='store_true', help='私钥签名')
    ap.add_argument('--verify', action='store_true', help='公钥验签')
    ap.add_argument('--n', help='模数 n (hex)')
    ap.add_argument('--e', type=int, default=65537, help='公钥指数 e')
    ap.add_argument('--d', help='私钥 d (hex)')
    ap.add_argument('--sig', help='签名 (hex)')
    ap.add_argument('--nopad', action='store_true', help='NoPadding (默认 PKCS#1 v1.5)')
    ap.add_argument('--hex', action='store_true', help='输入为 hex')
    ap.add_argument('--b64', action='store_true', help='输入为 base64')
    ap.add_argument('--factorize', help='分解模数 n (hex)')
    ap.add_argument('data', nargs='?')
    args = ap.parse_args()

    if args.selftest:
        selftest(); return

    if args.genkey:
        kp = gen_keypair(args.genkey)
        print(f"[*] {args.genkey}bit RSA 密钥对:")
        print(f"  p    = {kp['p']:x}")
        print(f"  q    = {kp['q']:x}")
        print(f"  n    = {kp['n']:x}")
        print(f"  e    = {kp['e']}")
        print(f"  d    = {kp['d']:x}")
        print(f"  dp   = {kp['dp']:x}")
        print(f"  dq   = {kp['dq']:x}")
        print(f"  qinv = {kp['qinv']:x}")
        return

    if args.factorize:
        n = int(args.factorize, 16)
        print(f"[*] 尝试分解 n = {args.factorize}")
        f = factorize(n)
        if f:
            print(f"[+] 分解成功: p = {f[0]:x}")
            print(f"             q = {f[1]:x}")
            print(f"[!] 私钥可恢复: d = e^-1 mod (p-1)(q-1)")
        else:
            print("[-] 分解失败 (n 过大, 尝试 Pollard's rho 未命中)")
        return

    if not args.n:
        sys.exit("[-] 需要 --n (模数 hex)")
    n = int(args.n, 16)
    k = (n.bit_length() + 7) // 8

    data = None
    if args.data:
        data = bytes.fromhex(args.data) if args.hex else \
            (base64.b64decode(args.data) if args.b64 else args.data.encode('utf-8'))

    padding = 'none' if args.nopad else 'pkcs1'

    if args.encrypt:
        if data is None:
            sys.exit("[-] 需要明文")
        ct = encrypt(data, n, args.e, padding)
        print(f"[*] RSA 加密 ({len(ct)}B):")
        print(f"    hex: {ct.hex()}")
        print(f"    b64: {base64.b64encode(ct).decode()}")
    elif args.decrypt:
        if not args.d or data is None:
            sys.exit("[-] 解密需要 --d 和密文")
        try:
            pt = decrypt(data, int(args.d, 16), n, padding)
        except ValueError as e:
            sys.exit(f"[-] {e}")
        print(f"[+] 明文:")
        try:
            print("    " + pt.decode('utf-8'))
        except UnicodeDecodeError:
            print("    hex: " + pt.hex())
    elif args.sign:
        if not args.d or data is None:
            sys.exit("[-] 签名需要 --d 和消息")
        sig = sign(data, int(args.d, 16), n, padding)
        print(f"[*] RSA 签名 ({len(sig)}B):")
        print(f"    hex: {sig.hex()}")
    elif args.verify:
        if not args.sig or data is None:
            sys.exit("[-] 验签需要 --sig 和消息")
        ok = verify(data, bytes.fromhex(args.sig), args.e, n, padding)
        print(f"[{'OK' if ok else 'FAIL'}] 验签结果: {'通过' if ok else '不通过'}")
    else:
        sys.exit("[-] 需要 --genkey / --encrypt / --decrypt / --sign / --verify / --factorize")


if __name__ == '__main__':
    main()
