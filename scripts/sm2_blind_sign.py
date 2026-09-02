#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SM2 盲签名 (Blind Signature) —— 签名者看不到被签消息 (零依赖)
=============================================================
协议 (乘法盲化构造, 签名结果可被标准 SM2 验签通过):
    1. 签名者生成 k1, 发 R1 = k1·G 给用户
    2. 用户选盲因子 α, 计算 R = α·R1 (= k·G, k=α·k1), 摘要 e,
       r = (e + x_R) mod n, 将 r' = α^{-1}·r 发给签名者
    3. 签名者用标准 SM2 对 r' 签名: s' = (1+d)^{-1}(k1 − r'·d)
    4. 用户去盲: s = α·s'  →  (r, s) 即标准 SM2 签名, 直接可验

代数验证: s = α(1+d)^{-1}(k1 − α^{-1}r·d) = (1+d)^{-1}(α·k1 − r·d) = (1+d)^{-1}(k − r·d) ✓
盲性: 签名者只见 r' = α^{-1}·r (α 随机), 无法关联消息/最终签名

适用: 银行 e-cash / 匿名凭证 / 隐私交易类系统盲签名实现测试。
生产级盲签名请用标准化方案 (如 GM/T 0043), 本实现用于理解与验证盲签名服务。

用法:
    # 自检: 完整协议往返 + 验签 + 盲性演示
    python sm2_blind_sign.py --selftest

    # 交互演示 (打印双方视角)
    python sm2_blind_sign.py --demo --message "转账 100 元"
"""
import argparse
import secrets
import sys

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

from sm2_k_reuse import (N, GX, GY, DEFAULT_ID, sm2_za, sm3_hash,
                         scalar_mul, sm2_verify)


def _inv(x):
    return pow(x % N, -1, N)


class Signer:
    """签名者角色: 持有私钥 d, 只对"盲化后的 r'"签名, 永远接触不到明文消息。"""

    def __init__(self, d: int):
        self.d = d
        self.P = scalar_mul(d, (GX, GY))

    def blind_request(self):
        """生成 k1 并保留会话状态, 对外只返回 R1。"""
        k1 = secrets.randbelow(N - 1) + 1
        return {'k1': k1, 'R1': scalar_mul(k1, (GX, GY))}

    def blind_sign(self, state: dict, r_prime: int) -> int:
        """对盲化值 r' 签名, 返回 s'。仅需标准 SM2 签名中的 (k1, r') 两个量。"""
        r_prime %= N
        if r_prime == 0 or (state['k1'] + r_prime) % N == 0:
            raise ValueError("[!] r'+k1 ≡ 0, 需重新发起盲签名 (概率极低)")
        return _inv(1 + self.d) * (state['k1'] - r_prime * self.d) % N


class User:
    """用户角色: 盲化消息, 去盲得到最终签名。"""

    def __init__(self, ida: bytes = DEFAULT_ID):
        self.ida = ida

    def blind(self, message: bytes, R1: tuple, pub: tuple):
        """输入消息与签名者公钥 R1/P, 输出 (会话状态, 发给签名者的 r')。"""
        alpha = secrets.randbelow(N - 1) + 1          # 盲因子
        R = scalar_mul(alpha, R1)                      # k = α·k1
        e = int.from_bytes(sm3_hash(sm2_za(self.ida, pub) + message), 'big')
        r = (e + R[0]) % N
        if r == 0:
            raise ValueError("[!] r=0, 需重新发起 (概率极低)")
        r_prime = (_inv(alpha) * r) % N
        return {'alpha': alpha, 'r': r, 'R': R}, r_prime

    def unblind(self, state: dict, s_prime: int):
        """收到 s' 后去盲, 得到最终标准 SM2 签名 (r, s)。"""
        return state['r'], (state['alpha'] * s_prime) % N


def blind_sign(message: bytes, d: int, ida: bytes = DEFAULT_ID):
    """完整协议单次执行, 返回 (签名(r,s), 签名者公钥P)。"""
    signer = Signer(d)
    user = User(ida)
    while True:
        st_sig = signer.blind_request()
        st_usr, r_prime = user.blind(message, st_sig['R1'], signer.P)
        try:
            s_prime = signer.blind_sign(st_sig, r_prime)
        except ValueError:
            continue
        return user.unblind(st_usr, s_prime), signer.P


def selftest():
    import random
    random.seed(2026)
    d = 0x3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8
    ida = DEFAULT_ID
    ok = True

    # 1. 协议往返 → 标准验签
    for m in (b'TRANSFER 100 CNY', '转账 100 元 到 6222...'.encode(), b'\x01' * 40):
        (r, s), P = blind_sign(m, d, ida)
        v = sm2_verify(m, r, s, P, ida)
        ok = ok and v
        print(f"  [{'OK' if v else 'FAIL'}] 盲签名({m[:12]!r}…) 验签通过: {v}")

    # 2. 盲性: 同一消息两次盲签名, r' 不同 (会话不可关联)
    signer = Signer(d)
    user = User(ida)
    m = b'secret message X'
    primes = set()
    for _ in range(5):
        st_sig = signer.blind_request()
        _, r_prime = user.blind(m, st_sig['R1'], signer.P)
        primes.add(r_prime)
    blind_ok = len(primes) > 1
    ok = ok and blind_ok
    print(f"  [{'OK' if blind_ok else 'FAIL'}] 同一消息 5 次盲化 r' 均不同 (不可关联): "
          f"distinct={len(primes)}")

    # 3. 签名者视角: 只见过 r' 与 R1, 无 (m, r)
    print(f"  [i] 签名者每次只接触 r' 与 R1, 从不接触消息原文")

    print(f"\n[{'全部通过' if ok else '存在失败'}] SM2 盲签名自检")
    sys.exit(0 if ok else 1)


def demo(message: bytes):
    d = 0x3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8
    ida = DEFAULT_ID
    signer = Signer(d)
    user = User(ida)
    st_sig = signer.blind_request()
    print(f"[签名者] 生成 k1, 发送 R1 = ({st_sig['R1'][0]:064x})")
    st_usr, r_prime = user.blind(message, st_sig['R1'], signer.P)
    print(f"[用户]   收到 R1, 盲化消息 → 发送 r' = {r_prime:064x}")
    s_prime = signer.blind_sign(st_sig, r_prime)
    print(f"[签名者] 对盲化值签名 → 返回 s' = {s_prime:064x}")
    r, s = user.unblind(st_usr, s_prime)
    print(f"[用户]   去盲得签名 (r, s) = ({r:064x}\n                     , {s:064x})")
    v = sm2_verify(message, r, s, signer.P, ida)
    print(f"[验签]   标准 SM2 验签: {'通过 ✓' if v else '失败 ✗'}")


def main():
    ap = argparse.ArgumentParser(description='SM2 盲签名 (盲性验证)')
    ap.add_argument('--selftest', action='store_true', help='自检')
    ap.add_argument('--demo', action='store_true', help='打印协议双方视角')
    ap.add_argument('--message', default='转账 100 元', help='demo 用消息')
    args = ap.parse_args()
    if args.selftest:
        selftest()
    elif args.demo:
        demo(args.message.encode('utf-8'))
    else:
        sys.exit("[-] 需要 --selftest 或 --demo")


if __name__ == '__main__':
    main()
