#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
银行卡号 / 磁道数据工具 (零依赖)
================================
Luhn 校验/生成 + 磁道 1/2/3 解析。配合 PIN Block / DUKPT 做 POS/收单测试。

用法:
    # Luhn
    python card.py luhn 6222020200012345678       # 校验卡号
    python card.py gen --bin 622202 --len 19      # 生成合法卡号
    python card.py checkdigit 622202020001234567  # 计算校验位

    # 磁道解析
    python card.py track1 "%B622202...^张^三^2504^...?"
    python card.py track2 ";622202...=2512..."
    python card.py track3 ";622202...=...?"

    # 自检
    python card.py --selftest
"""
import argparse
import random
import re
import sys

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')


# ---------------- Luhn ----------------
def luhn_check_digit(number: str) -> str:
    """计算 Luhn 校验位。"""
    digits = [int(c) for c in number]
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 0:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return str((10 - total % 10) % 10)


def luhn_ok(number: str) -> bool:
    if not number.isdigit():
        return False
    return luhn_check_digit(number[:-1]) == number[-1]


def gen_card(bin_prefix: str, length: int = 16, count: int = 1) -> list:
    """按 BIN 生成合法卡号。"""
    out = []
    for _ in range(count):
        mid_len = length - 1 - len(bin_prefix)
        mid = ''.join(str(random.randrange(10)) for _ in range(max(0, mid_len)))
        base = bin_prefix + mid
        out.append(base + luhn_check_digit(base))
    return out


# ---------------- 磁道解析 ----------------
def parse_track1(data: str) -> dict:
    """磁道1: %B PAN^NAME^EXPIRY^SERVICE^DISCRETIONARY?...?"""
    d = data.strip()
    if d.startswith('%'):
        d = d[1:]
    if d[:1].isalpha():      # 格式码 %B / %A / %F 等
        d = d[1:]
    if d.endswith('?'):
        d = d[:-1]
    parts = d.split('^')
    return {
        'format': '磁道1',
        'pan': parts[0] if len(parts) > 0 else '',
        'name': parts[1] if len(parts) > 1 else '',
        'expiry': parts[2][:4] if len(parts) > 2 else '',
        'service': parts[2][4:7] if len(parts) > 2 and len(parts[2]) >= 7 else '',
        'discretionary': parts[3] if len(parts) > 3 else '',
    }


def parse_track2(data: str) -> dict:
    """磁道2: ;PAN=EXPIRY_SERVICE_DISCRETIONARY?"""
    d = data.strip()
    if d.startswith(';'):
        d = d[1:]
    if d.endswith('?'):
        d = d[:-1]
    if '=' not in d:
        return {'format': '磁道2', 'pan': d, 'expiry': '', 'service': ''}
    pan, rest = d.split('=', 1)
    expiry = rest[:4] if rest else ''
    service = rest[4:7] if len(rest) >= 7 else ''
    return {'format': '磁道2', 'pan': pan, 'expiry': expiry,
            'service': service, 'discretionary': rest[7:] if len(rest) > 7 else ''}


def parse_track3(data: str) -> dict:
    """磁道3: ;PAN=DISCRETIONARY? (较少见)"""
    d = data.strip()
    if d.startswith(';'):
        d = d[1:]
    if d.endswith('?'):
        d = d[:-1]
    if '=' in d:
        pan, rest = d.split('=', 1)
        return {'format': '磁道3', 'pan': pan, 'discretionary': rest}
    return {'format': '磁道3', 'pan': d}


def parse_track(data: str) -> dict:
    """自动识别磁道类型解析。"""
    d = data.strip()
    if d.startswith('%'):
        return parse_track1(d)
    if d.startswith(';'):
        # 磁道2 通常 PAN=EXPIRY; 磁道3 是 PAN=DDDDDDDDDDDDDDD
        return parse_track2(d) if '=' in d and len(d.split('=')[1]) >= 4 else parse_track3(d)
    raise ValueError("磁道数据需以 % (磁道1) 或 ; (磁道2/3) 开头")


def selftest():
    ok = True
    # Luhn 已知有效卡号 (Visa/UnionPay/Mastercard 测试号)
    for num in ('4111111111111111', '6222026672057077547', '5555555555554444'):
        good = luhn_ok(num)
        ok = ok and good
        print(f"  [{'OK' if good else 'FAIL'}] Luhn 校验 {num} = {'有效' if good else '无效'}")
    # 生成→校验
    for _ in range(3):
        card = gen_card('622202', 19)[0]
        ok = ok and luhn_ok(card) and card.startswith('622202')
    print(f"  [{'OK' if ok else 'FAIL'}] 按 BIN 生成卡号 → Luhn 校验通过")
    # 磁道解析
    t2 = parse_track2(';6222020200012345678=251210100000123?')
    ok = ok and t2['pan'] == '6222020200012345678' and t2['expiry'] == '2512'
    print(f"  [{'OK' if t2['pan'] == '6222020200012345678' else 'FAIL'}] 磁道2解析: "
          f"PAN={t2['pan']} 有效期={t2['expiry']}")
    t1 = parse_track1('%B6222020200012345678^ZHANG/SAN^2512101^000000000000?')
    ok = ok and t1['name'] == 'ZHANG/SAN' and t1['expiry'] == '2512'
    print(f"  [{'OK' if t1['name'] == 'ZHANG/SAN' else 'FAIL'}] 磁道1解析: "
          f"姓名={t1['name']} 有效期={t1['expiry']} 服务码={t1['service']}")
    print(f"\n[{'全部通过' if ok else '存在失败'}] 卡号/磁道自检")
    sys.exit(0 if ok else 1)


def main():
    ap = argparse.ArgumentParser(description='银行卡号/磁道工具')
    ap.add_argument('--selftest', action='store_true')
    ap.add_argument('op', nargs='?', choices=['luhn', 'gen', 'checkdigit',
                                              'track1', 'track2', 'track3', 'track'])
    ap.add_argument('data', nargs='?', help='卡号或磁道数据')
    ap.add_argument('--bin', help='gen: BIN 前缀')
    ap.add_argument('--len', type=int, default=16, help='gen: 卡号长度')
    ap.add_argument('--count', type=int, default=1, help='gen: 生成数量')
    args = ap.parse_args()

    if args.selftest:
        selftest(); return
    if not args.op:
        sys.exit("[-] 需要操作: luhn / gen / checkdigit / track1 / track2 / track3 / track")

    if args.op == 'luhn':
        if not args.data:
            sys.exit("[-] 需要卡号")
        ok = luhn_ok(args.data)
        print(f"[{'OK' if ok else 'FAIL'}] 卡号 {args.data}: {'有效 (Luhn)' if ok else '无效'}")
        return

    if args.op == 'checkdigit':
        if not args.data:
            sys.exit("[-] 需要卡号前缀")
        cd = luhn_check_digit(args.data)
        print(f"[*] 校验位: {cd}  完整卡号: {args.data}{cd}")
        return

    if args.op == 'gen':
        if not args.bin:
            sys.exit("[-] gen 需要 --bin (如 622202)")
        if len(args.bin) >= args.len:
            sys.exit("[-] BIN 长度需小于卡号长度")
        cards = gen_card(args.bin, args.len, args.count)
        for c in cards:
            print(f"    {c}  (Luhn {'✓' if luhn_ok(c) else '✗'})")
        return

    if args.op in ('track1', 'track2', 'track3', 'track'):
        if not args.data:
            sys.exit("[-] 需要磁道数据")
        fn = {'track1': parse_track1, 'track2': parse_track2,
              'track3': parse_track3, 'track': parse_track}[args.op]
        try:
            info = fn(args.data)
        except ValueError as e:
            sys.exit(f"[-] {e}")
        print(f"[*] {info.get('format', '')} 解析:")
        for k, v in info.items():
            if k != 'format' and v:
                print(f"    {k:<14}: {v}")
        return


if __name__ == '__main__':
    main()
