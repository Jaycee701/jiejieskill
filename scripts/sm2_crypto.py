#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SM2 加密/解密 (GB/T 32918.4-2016, 零依赖)
==========================================
非对称加密: 公钥加密, 私钥解密。密文格式 C1‖C3‖C2。
    C1 = k·G (点, 65/33 字节)
    C2 = M ⊕ KDF(x2‖y2)        (x2,y2) = k·PB
    C3 = SM3(x2‖M‖y2)          校验值

用法:
    # 生成密钥对 (输出 d / px / py)
    python sm2_crypto.py --genkey

    # 加密 (公钥)
    python sm2_crypto.py --encrypt --px <hex> --py <hex> "转账 100 元"
    # 加密 (hex 输入 / 压缩点 / 旧版 C1C2C3 顺序)
    python sm2_crypto.py --encrypt --px <hex> --py <hex> --hex <data_hex> --compress --order c1c2c3
    # 加密 (从文件)
    python sm2_crypto.py --encrypt --px <hex> --py <hex> -i file.bin

    # 解密 (私钥)
    python sm2_crypto.py --decrypt --priv <d_hex> <C_hex>
    # 解密 (base64 密文)
    python sm2_crypto.py --decrypt --priv <d_hex> --b64 <C_b64>

    # 自检
    python sm2_crypto.py --selftest
"""
import argparse
import base64
import secrets
import sys

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

from sm2_k_reuse import N, P, A, B, GX, GY, sm3_hash, scalar_mul


def _inv(x):
    return pow(x % N, -1, N)


# ============ KDF (GB/T 32918.3) ============
def kdf(z: bytes, klen: int) -> bytes:
    """基于 SM3 的密钥派生, 输出 klen 字节。"""
    out = b''
    ct = 1
    while len(out) < klen:
        out += sm3_hash(z + ct.to_bytes(4, 'big'))
        ct += 1
    return out[:klen]


# ============ 点序列化 ============
def point_to_bytes(pt, compress: bool = False) -> bytes:
    if pt is None:
        raise ValueError('无穷远点')
    x, y = pt
    xb, yb = x.to_bytes(32, 'big'), y.to_bytes(32, 'big')
    if compress:
        return bytes([2 | (y & 1)]) + xb
    return b'\x04' + xb + yb


def bytes_to_point(b: bytes):
    if not b:
        raise ValueError('空点')
    prefix = b[0]
    if prefix == 4:
        if len(b) != 65:
            raise ValueError(f'非压缩点应为65字节, 实为{len(b)}')
        return (int.from_bytes(b[1:33], 'big'), int.from_bytes(b[33:65], 'big'))
    if prefix in (2, 3):
        if len(b) != 33:
            raise ValueError(f'压缩点应为33字节, 实为{len(b)}')
        x = int.from_bytes(b[1:33], 'big')
        y = pow((x * x * x + A * x + B) % P, (P + 1) // 4, P)  # p ≡ 3 mod 4
        if (y & 1) != (prefix & 1):
            y = P - y
        return (x, y)
    raise ValueError(f'未知点前缀 0x{prefix:02x}')


# ============ SM2 加密 (GB/T 32918.4) ============
def sm2_encrypt(m: bytes, pb: tuple, compress: bool = False) -> bytes:
    """公钥加密。返回 C = C1‖C3‖C2。"""
    klen = len(m)
    while True:
        k = secrets.randbelow(N - 1) + 1
        c1 = scalar_mul(k, (GX, GY))
        s = scalar_mul(k, pb)                 # (x2,y2) = k·PB
        if s is None:
            continue
        x2, y2 = s[0].to_bytes(32, 'big'), s[1].to_bytes(32, 'big')
        t = kdf(x2 + y2, klen)
        if klen > 0 and t == bytes(klen):     # 全零需重试 (空消息跳过)
            continue
        c2 = bytes(a ^ b for a, b in zip(m, t))
        c3 = sm3_hash(x2 + m + y2)
        return point_to_bytes(c1, compress) + c3 + c2


def sm2_decrypt(c: bytes, d: int, order: str = 'c1c3c2') -> bytes:
    """私钥解密。order: c1c3c2(现行标准) 或 c1c2c3(旧版兼容)。"""
    prefix = c[0]
    c1_len = 33 if prefix in (2, 3) else 65
    c1 = bytes_to_point(c[:c1_len])
    if order == 'c1c3c2':
        c3, c2 = c[c1_len:c1_len + 32], c[c1_len + 32:]
    else:  # c1c2c3: C2 长度未知, 从末尾取 C3
        c2, c3 = c[c1_len:-32], c[-32:]
    s = scalar_mul(d, c1)                     # S = d·C1
    if s is None:
        raise ValueError('S 为无穷远点')
    x2, y2 = s[0].to_bytes(32, 'big'), s[1].to_bytes(32, 'big')
    t = kdf(x2 + y2, len(c2))
    m = bytes(a ^ b for a, b in zip(c2, t))
    if sm3_hash(x2 + m + y2) != c3:
        raise ValueError('C3 校验失败: 私钥不匹配或密文被篡改')
    return m


def gen_keypair():
    d = secrets.randbelow(N - 1) + 1
    return d, scalar_mul(d, (GX, GY))


# ============ 自检 ============
def selftest():
    import random
    random.seed(11)
    ok = True
    for i in range(5):
        d, pb = gen_keypair()
        for m in (b'hello sm2', b'', b'A' * 100, '银行转账 100 元 测试'.encode()):
            for compress in (False, True):
                for order in ('c1c3c2', 'c1c2c3'):
                    try:
                        ct = sm2_encrypt(m, pb, compress)
                        # 为测试 c1c2c3 解密, 手动重排
                        if order == 'c1c2c3':
                            cl = 33 if compress else 65
                            ct = ct[:cl] + ct[cl + 32:] + ct[cl:cl + 32]
                        pt = sm2_decrypt(ct, d, order)
                        good = pt == m
                    except Exception as e:
                        good, pt = False, f'异常 {e}'
                    ok = ok and good
                    if not good:
                        print(f'  [FAIL] 迭代{i} len={len(m)} comp={compress} order={order}: {pt}')
    # 错钥应解密失败
    d1, pb = gen_keypair()
    d2, _ = gen_keypair()
    ct = sm2_encrypt(b'secret', pb)
    try:
        sm2_decrypt(ct, d2)
        wrong = False
    except ValueError:
        wrong = True
    ok = ok and wrong

    print(f"[{'全部通过' if ok else '存在失败'}] SM2 加解密自检 (含空消息/多块/压缩点/两种顺序/错钥拒绝)")
    sys.exit(0 if ok else 1)


def main():
    ap = argparse.ArgumentParser(description='SM2 加解密 (GB/T 32918.4)')
    ap.add_argument('--selftest', action='store_true')
    ap.add_argument('--genkey', action='store_true', help='生成密钥对')
    ap.add_argument('--encrypt', action='store_true', help='加密')
    ap.add_argument('--decrypt', action='store_true', help='解密')
    ap.add_argument('--px', help='公钥 x (hex)')
    ap.add_argument('--py', help='公钥 y (hex)')
    ap.add_argument('--priv', help='私钥 d (hex)')
    ap.add_argument('--compress', action='store_true', help='C1 用压缩点 (33字节)')
    ap.add_argument('--order', choices=['c1c3c2', 'c1c2c3'], default='c1c3c2',
                    help='密文顺序 (默认现行标准 c1c3c2)')
    ap.add_argument('--hex', action='store_true', help='输入为 hex')
    ap.add_argument('--b64', action='store_true', help='输入为 base64')
    ap.add_argument('-i', '--in', dest='infile', help='从文件读明文/密文')
    ap.add_argument('data', nargs='?', help='明文或密文')
    args = ap.parse_args()

    if args.selftest:
        selftest(); return
    if args.genkey:
        d, pb = gen_keypair()
        print(f"私钥 d  = {d:064x}")
        print(f"公钥 px = {pb[0]:064x}")
        print(f"公钥 py = {pb[1]:064x}")
        return

    # 读数据
    if args.infile:
        raw = open(args.infile, 'rb').read()
        if args.hex:
            data = bytes.fromhex(raw.decode().strip())
        elif args.b64:
            data = base64.b64decode(raw.strip())
        else:
            data = raw
    elif args.data:
        if args.hex:
            data = bytes.fromhex(args.data)
        elif args.b64:
            data = base64.b64decode(args.data)
        else:
            data = args.data.encode('utf-8')
    else:
        sys.exit("[-] 需要数据或 --genkey")

    if args.encrypt:
        if not (args.px and args.py):
            sys.exit("[-] 加密需要 --px --py (公钥)")
        pb = (int(args.px, 16), int(args.py, 16))
        ct = sm2_encrypt(data, pb, args.compress)
        # 按请求的密文顺序输出
        if args.order == 'c1c2c3':
            cl = 33 if args.compress else 65
            ct = ct[:cl] + ct[cl + 32:] + ct[cl:cl + 32]
        if args.compress:
            print(f"[*] C1 压缩点 (33B), 顺序 {args.order}, 密文 hex ({len(ct)}B):")
        else:
            print(f"[*] C1 非压缩点 (65B), 顺序 {args.order}, 密文 hex ({len(ct)}B):")
        print(ct.hex())
        print(f"[*] base64: {base64.b64encode(ct).decode()}")

    elif args.decrypt:
        if not args.priv:
            sys.exit("[-] 解密需要 --priv (私钥)")
        ct = data
        try:
            pt = sm2_decrypt(ct, int(args.priv, 16), args.order)
        except ValueError as e:
            sys.exit(f"[-] {e}")
        print(f"[+] 明文 ({len(pt)}B):")
        try:
            print("    " + pt.decode('utf-8'))
        except UnicodeDecodeError:
            print("    hex: " + pt.hex())

    else:
        sys.exit("[-] 需要 --encrypt / --decrypt / --genkey")


if __name__ == '__main__':
    main()
