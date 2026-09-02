#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TOTP / HOTP 动态口令工具 (RFC 4226 / RFC 6238, 零依赖)
======================================================
银行手机银行 / 动态令牌 / 短信验证码常用 TOTP/HOTP。
测试点: 时间窗口是否过大、验证码是否可重放、同步算法。

HOTP (RFC 4226):  HOTP = Truncate(HMAC-SHA1(K, C))   C=计数器
TOTP (RFC 6238):  TOTP = HOTP(K, T)                  T=floor(time/period)

用法:
    # 当前验证码 (base32 secret, 8位, 30秒)
    python totp.py --secret JBSWY3DPEHPK3PXP

    # 指定时间 (epoch 秒)
    python totp.py --secret JBSWY3DPEHPK3PXP --time 1700000000

    # 指定步长/位数/算法 (SHA256/SHA512 也支持)
    python totp.py --secret ... --period 60 --digits 6 --algo sha256

    # HOTP 模式 (计数器)
    python totp.py --secret ... --counter 100

    # 重放窗口扫描: 当前时间前后 5 步的验证码 (测试窗口过大/重放)
    python totp.py --secret ... --window 5

    # 验证某验证码是否有效 (含前后窗口)
    python totp.py --secret ... --verify 123456

    # 自检 (RFC 6238 标准向量)
    python totp.py --selftest
"""
import argparse
import base64
import hashlib
import hmac
import sys
import time

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')


def parse_secret(secret: str) -> bytes:
    """secret 支持 base32 (RFC4648, 去空格) / hex / ascii。"""
    s = secret.strip().replace(' ', '').replace('-', '')
    # base32 特征: 仅 A-Z 2-7
    if s and all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=' for c in s.upper()) and len(s) >= 8:
        return base64.b32decode(s.upper() + '=' * ((8 - len(s) % 8) % 8))
    if s and all(c in '0123456789abcdefABCDEF' for c in s) and len(s) % 2 == 0:
        try:
            return bytes.fromhex(s)
        except ValueError:
            pass
    return s.encode('utf-8')


def hotp(secret: bytes, counter: int, digits: int = 6, algo: str = 'sha1') -> str:
    """RFC 4226 HOTP。"""
    h = hmac.new(secret, counter.to_bytes(8, 'big'), algo).digest()
    off = h[-1] & 0x0f
    code = int.from_bytes(h[off:off + 4], 'big') & 0x7fffffff
    return str(code % (10 ** digits)).zfill(digits)


def totp(secret: bytes, t: int, period: int = 30, digits: int = 6,
         algo: str = 'sha1') -> str:
    """RFC 6238 TOTP。t = Unix 时间戳 (秒)。"""
    return hotp(secret, t // period, digits, algo)


def selftest():
    # RFC 6238 附录 B: secret = "12345678901234567890" (ASCII), SHA1, 8位, 30秒
    secret = b'12345678901234567890'
    vectors = [
        (59, '94287082'),
        (1111111109, '07081804'),
        (1111111111, '14050471'),
        (1234567890, '89005924'),
        (2000000000, '69279037'),
        (20000000000, '65353130'),
    ]
    ok = True
    for t, expect in vectors:
        got = totp(secret, t, 30, 8, 'sha1')
        good = got == expect
        ok = ok and good
        print(f"  [{'OK' if good else 'FAIL'}] t={t:<12} got={got} expect={expect}")
    # HOTP RFC 4226 向量
    h_secret = b'12345678901234567890'
    h_vecs = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
    h_vals = ['755224', '287082', '359152', '969429', '338314',
              '254676', '287922', '162583', '399871', '520489']
    for c, expect in zip(h_vecs, h_vals):
        got = hotp(h_secret, c, 6, 'sha1')
        good = got == expect
        ok = ok and good
        if not good:
            print(f"  [FAIL] HOTP c={c} got={got} expect={expect}")
    print(f"  [{'OK' if ok else 'FAIL'}] TOTP/HOTP 标准向量全部匹配")
    print(f"\n[{'全部通过' if ok else '存在失败'}] TOTP/HOTP 自检 (RFC 4226/6238)")
    sys.exit(0 if ok else 1)


def main():
    ap = argparse.ArgumentParser(description='TOTP/HOTP 动态口令 (RFC 4226/6238)')
    ap.add_argument('--selftest', action='store_true')
    ap.add_argument('--secret', required=False, help='密钥: base32 / hex / ascii')
    ap.add_argument('--time', type=int, help='指定时间戳 (秒), 默认当前时间')
    ap.add_argument('--counter', type=int, help='HOTP 模式: 计数器值')
    ap.add_argument('--period', type=int, default=30, help='TOTP 时间步长 (默认30)')
    ap.add_argument('--digits', type=int, default=6, choices=[6, 8], help='验证码位数')
    ap.add_argument('--algo', default='sha1', choices=['sha1', 'sha256', 'sha512'])
    ap.add_argument('--window', type=int, default=0, help='前后 N 步扫描 (重放窗口测试)')
    ap.add_argument('--verify', help='验证某验证码是否有效')
    args = ap.parse_args()

    if args.selftest:
        selftest(); return
    if not args.secret:
        sys.exit("[-] 需要 --secret 密钥")

    secret = parse_secret(args.secret)
    now = args.time if args.time is not None else int(time.time())

    if args.verify:
        target = args.verify
        hits = []
        for off in range(-args.window, args.window + 1):
            c = (now // args.period) + off
            code = hotp(secret, c, args.digits, args.algo)
            if code == target:
                hits.append((off, c))
        if hits:
            off, c = hits[0]
            print(f"[+] 验证通过: 偏移 {off:+d} 步 (计数器 {c})")
            if len(hits) > 1:
                print(f"    [!] 多个时间片匹配 → 目标可能存在重放/窗口过大风险")
        else:
            print(f"[-] 验证失败: 前后 {args.window} 步内无匹配")
        return

    if args.counter is not None:
        code = hotp(secret, args.counter, args.digits, args.algo)
        print(f"[*] HOTP 计数器={args.counter} ({args.algo}, {args.digits}位): {code}")
        return

    if args.window > 0:
        print(f"[*] TOTP 重放窗口扫描 (当前 ±{args.window} 步, {args.period}s/步, {args.digits}位):")
        for off in range(-args.window, args.window + 1):
            c = (now // args.period) + off
            code = hotp(secret, c, args.digits, args.algo)
            when = '◀◀ 当前' if off == 0 else f'{off:+d}'
            print(f"    偏移 {when:>6} → {code}")
        return

    code = totp(secret, now, args.period, args.digits, args.algo)
    t_remain = args.period - (now % args.period)
    print(f"[*] TOTP ({args.algo}, {args.digits}位, {args.period}s步长): {code}")
    print(f"    时间片剩余 {t_remain}s")


if __name__ == '__main__':
    main()
