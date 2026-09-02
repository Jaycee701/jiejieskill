#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SM2 恶意签名 / 验证健壮性测试工具 (零依赖)
==========================================
用途:
    1. 生成"畸形签名"批量提交给目标验签接口, 探测其是否做了完整的
       r,s ∈ [1,n-1] / t≠0 范围校验 (缺校验 = 签名验证可被绕过, 高危)
    2. 延展性检测: 有效签名是否可被改造成另一有效签名 (可延展性)
    3. 用攻击者指定 k 签名 (可预测 nonce 接受度测试)
    4. 通用 SM2 签名/验签工具

用法:
    # 生成畸形签名批次 (目标只校验"是否通过"时, 任何一条被接受即漏洞)
    python sm2_sign_tools.py --malformed --message "amount=100&to=6222"

    # 延展性检测: 对已有有效签名尝试 r/s 变换
    python sm2_sign_tools.py --malleability --message "转账" --r <hex> --s <hex> \
        --px <hex> --py <hex>

    # 指定 k 签名 (验证目标是否接受可预测 nonce; k=1 最弱)
    python sm2_sign_tools.py --sign --message "amount=100" --k 1

    # 通用签名/验签
    python sm2_sign_tools.py --sign --message "amount=100"
    python sm2_sign_tools.py --verify --message "amount=100" --r <hex> --s <hex> --px <hex> --py <hex>

    # 自检
    python sm2_sign_tools.py --selftest
"""
import argparse
import secrets
import sys

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

from sm2_k_reuse import (N, GX, GY, DEFAULT_ID, sm2_za, sm3_hash,
                         scalar_mul, sm2_sign, sm2_verify)

# 测试用私钥 (公开测试值, 仅演示)
TEST_D = 0x3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8
TEST_P = scalar_mul(TEST_D, (GX, GY))


def pubkey_of(d: int):
    return scalar_mul(d, (GX, GY))


def craft_malformed(message: bytes, d: int, ida: bytes = DEFAULT_ID):
    """
    生成畸形签名批次。标准验签全部应为 False;
    若目标验签接口接受了其中任何一条, 说明其缺失对应校验。
    """
    pub = pubkey_of(d)
    k = secrets.randbelow(N - 1) + 1
    r0, s0 = sm2_sign(message, d, k, ida, pub)
    cases = [
        ('r=0 (未校验 r∈[1,n-1])',         0, s0),
        ('s=0 (未校验 s∈[1,n-1])',         r0, 0),
        ('r=n (越界上界)',                  N, s0),
        ('s=n (越界上界)',                  r0, N),
        ('r=1 (极值下界)',                  1, s0),
        ('s=1 (极值下界)',                  r0, 1),
        ('r=n-1 (越界前一位)',              N - 1, s0),
        ('r+s=n → t=0 (未校验拒绝路径)',    (N - s0) % N, s0),
        ('r=0,s=0 (全零)',                  0, 0),
        ('r=n,s=n (双越界)',                N, N),
    ]
    results = []
    for name, r, s in cases:
        try:
            valid = sm2_verify(message, r, s, pub, ida)
        except Exception:
            valid = False
        results.append((name, r, s, valid))
    return results


def malleability_test(message: bytes, r: int, s: int, pub: tuple,
                      ida: bytes = DEFAULT_ID):
    """对已有有效签名尝试 r/s 代数变换, 检测目标是否接受可延展版本。"""
    variants = [
        ('s → n-s (取负)',      r, (N - s) % N),
        ('s → s+n (越界加n)',   r, s + N),
        ('r → n-r (取负)',      (N - r) % N, s),
        ('r → r+n (越界加n)',   r + N, s),
        ('r,s 互换',            s, r),
        ('r,s 同乘2',           (r * 2) % N, (s * 2) % N),
    ]
    out = []
    for name, rr, ss in variants:
        try:
            valid = sm2_verify(message, rr, ss, pub, ida)
        except Exception:
            valid = False
        out.append((name, rr, ss, valid))
    return out


def selftest():
    ok = True
    ida = DEFAULT_ID
    m = b'amount=100&to=6222'

    # 1. 畸形签名: 标准验签必须全部拒绝
    print("--- 畸形签名 (标准验签应全部 False) ---")
    for name, r, s, valid in craft_malformed(m, TEST_D, ida):
        ok = ok and not valid
        print(f"  [{'OK' if not valid else 'FAIL!'}] {name:<24} valid={valid}")

    # 2. 延展性: 标准验签应全部拒绝
    print("--- 延展性 (标准验签应全部 False) ---")
    k = secrets.randbelow(N - 1) + 1
    r0, s0 = sm2_sign(m, TEST_D, k, ida, TEST_P)
    for name, rr, ss, valid in malleability_test(m, r0, s0, TEST_P, ida):
        ok = ok and not valid
        print(f"  [{'OK' if not valid else 'FAIL!'}] {name:<20} valid={valid}")

    # 3. 指定 k 签名 → 验签必须通过 (k=1 也可验, 只是对签名方危险)
    r1, s1 = sm2_sign(m, TEST_D, 1, ida, TEST_P)
    v = sm2_verify(m, r1, s1, TEST_P, ida)
    ok = ok and v
    print(f"--- 指定 k=1 签名 → 验签通过: {v} (可预测 nonce 对签名方致命) ---")

    print(f"\n[{'全部通过' if ok else '存在失败'}] SM2 签名工具自检")
    sys.exit(0 if ok else 1)


def main():
    ap = argparse.ArgumentParser(description='SM2 恶意签名/验证健壮性测试')
    ap.add_argument('--selftest', action='store_true')
    ap.add_argument('--malformed', action='store_true', help='生成畸形签名批次')
    ap.add_argument('--malleability', action='store_true', help='延展性检测')
    ap.add_argument('--sign', action='store_true', help='签名')
    ap.add_argument('--verify', action='store_true', help='验签')
    ap.add_argument('--message', default='amount=100&to=6222', help='消息 (文本)')
    ap.add_argument('--message-hex', help='消息 (hex)')
    ap.add_argument('--r', help='签名 r (hex)')
    ap.add_argument('--s', help='签名 s (hex)')
    ap.add_argument('--px', help='公钥 x (hex)')
    ap.add_argument('--py', help='公钥 y (hex)')
    ap.add_argument('--k', type=int, help='指定签名 nonce k (默认随机)')
    ap.add_argument('--d', dest='priv', help='用指定私钥 (hex, 默认测试私钥)')
    args = ap.parse_args()

    if args.selftest:
        selftest()
        return

    message = bytes.fromhex(args.message_hex) if args.message_hex else args.message.encode()
    d = int(args.priv, 16) if args.priv else TEST_D
    pub = pubkey_of(d)
    ida = DEFAULT_ID

    if args.malformed:
        print(f"[*] 畸形签名批次 (消息: {message.decode('utf-8','replace')!r})")
        print("    标准验签应全部 False。提交给目标验签接口, 任何一条返回「通过」即漏洞:\n")
        for name, r, s, valid in craft_malformed(message, d, ida):
            flag = '← 标准验签失败,提交目标观察' if not valid else '← 异常(标准验签竟通过)'
            print(f"  {name}")
            print(f"    r = {r:064x}")
            print(f"    s = {s:064x}   {flag}")

    elif args.malleability:
        if not (args.r and args.s and args.px and args.py):
            sys.exit("[-] --malleability 需要 --r --s --px --py")
        r, s = int(args.r, 16), int(args.s, 16)
        pub = (int(args.px, 16), int(args.py, 16))
        base = sm2_verify(message, r, s, pub, ida)
        print(f"[*] 原始签名验签: {'通过' if base else '不通过'}")
        for name, rr, ss, valid in malleability_test(message, r, s, pub, ida):
            flag = '⚠ 目标若接受此变体=签名可延展' if valid else ''
            print(f"  {name:<22} 标准验签={valid} {flag}")
            if not valid:
                print(f"    r={rr:064x}\n    s={ss:064x}")

    elif args.sign:
        k = args.k if args.k is not None else secrets.randbelow(N - 1) + 1
        r, s = sm2_sign(message, d, k, ida, pub)
        print(f"[*] SM2 签名 (k={'指定:' + str(k) if args.k else '随机'}):")
        print(f"    r = {r:064x}")
        print(f"    s = {s:064x}")
        print(f"    公钥: px={pub[0]:064x}")
        print(f"          py={pub[1]:064x}")

    elif args.verify:
        if not (args.r and args.s and args.px and args.py):
            sys.exit("[-] --verify 需要 --r --s --px --py")
        r, s = int(args.r, 16), int(args.s, 16)
        pub = (int(args.px, 16), int(args.py, 16))
        print(f"[*] 验签结果: {'通过 ✓' if sm2_verify(message, r, s, pub, ida) else '不通过 ✗'}")

    else:
        sys.exit("[-] 需要 --selftest / --malformed / --malleability / --sign / --verify")


if __name__ == '__main__':
    main()
