#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
自定义 XOR / Base64 加密破解工具 (零依赖)
=========================================
App/Web 前端最常见的"伪加密": 硬编码 key 的 XOR + Base64。本工具:

    1. 自动识别 Base64 / hex 输入
    2. 单字节 XOR 全量爆破 (256 种 key, 按文本可读性打分)
    3. 多字节 XOR: --known 已知明文推导 key / --keys 字典尝试 / --key 直接解
    4. 输出候选明文与命中的 key

用法:
    python xor_decrypt.py -b64 <base64密文>
    python xor_decrypt.py --hex <hex密文>
    python xor_decrypt.py -i cipher.txt                 # 从文件读
    python xor_decrypt.py --hex <hex> --known '{"amt":'  # 已知明文推导多字节key
    python xor_decrypt.py --hex <hex> --key mysecret     # 直接给定key
    python xor_decrypt.py --hex <hex> --keys keys.txt    # 字典尝试

    # 爆破单字节后自动尝试常见多字节 key
    python xor_decrypt.py --hex <hex> --auto
"""
import argparse
import base64
import re
import string
import sys
from collections import Counter

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

PRINTABLE = set(bytes(string.printable, 'ascii'))
# 文本型字符: 字母数字 + 常见标点
TEXT_CHARS = set(string.ascii_letters + string.digits
                 + ' \t\n\r"\047{}[]():,./\\-_=+@#$%*&?!<>|')
# JSON/文本高频结构字符: 引号/括号/冒号/逗号/空格
STRUCT_BYTES = (0x22, 0x7B, 0x7D, 0x3A, 0x2C, 0x20)
COMMON_KEYS = [
    b'secret', b'key', b'password', b'sm4key', b'SecKey', b'!@#$%',
    b'12345678', b'0123456789', b'1q2w3e4r', b'abcdefgh', b'sm4sm4sm4sm4',
]


def read_input(args):
    if args.infile:
        raw = open(args.infile, 'rb').read()
    else:
        raw = args.data.encode() if args.data else sys.exit("[-] 需要输入或 --in 文件")
    # 去掉空白
    s = raw.decode('ascii', 'ignore').strip()
    if args.b64:
        try:
            return base64.b64decode(s)
        except Exception:
            sys.exit("[-] base64 解码失败")
    if args.hex or re.fullmatch(r'[0-9a-fA-F]{2,}', s):
        try:
            return bytes.fromhex(s)
        except ValueError:
            pass
    # 纯文本 ASCII (如自定义 base64 变种), 原样返回
    return raw


def score(data: bytes):
    """
    文本可读性评分 (越高越像明文)。
    XOR 密文常全是可打印字符, 纯可打印占比无法区分, 需结合:
      1. 文本型字符占比 (字母数字+标点)
      2. JSON/文本结构字符密度 (引号/括号/冒号/逗号/空格)
      3. 单字符过度集中惩罚 (XOR 噪声常有一个主导字符)
      4. UTF-8 有效性
    """
    if not data:
        return 0
    n = len(data)
    cnt = Counter(data)
    text_like = sum(1 for b in data if chr(b) in TEXT_CHARS) / n
    struct = sum(cnt.get(b, 0) for b in STRUCT_BYTES) / n
    # JSON 特征: 引号密度 (JSON 明文引号极多, XOR 噪声几乎没有)
    quotes = cnt.get(0x22, 0) / n
    top = cnt.most_common(1)[0][1] / n
    penalty = max(0.0, top - 0.25) * 2.0
    try:
        data.decode('utf-8')
        utf8_ok = 1.0
    except UnicodeDecodeError:
        utf8_ok = 0.0
    return text_like + struct + quotes + utf8_ok - penalty


def xor_decrypt(data: bytes, key: bytes) -> bytes:
    return bytes(c ^ key[i % len(key)] for i, c in enumerate(data))


def brute_single(data: bytes, top=3):
    """单字节 XOR 全量爆破。"""
    best = []
    for k in range(256):
        out = xor_decrypt(data, bytes([k]))
        sc = score(out)
        if sc > 1.5 and out.count(b'\x00') < len(out) // 10:
            best.append((sc, k, out))
    best.sort(key=lambda x: -x[0])
    return best[:top]


def derive_multi(data: bytes, known: bytes) -> bytes | None:
    """用已知明文推导多字节 key (需 known 长度 ≥ key 长度 且 key 长度 ≤ len(known))。"""
    key = bytes(c ^ known[i % len(known)] for i, c in enumerate(data[:len(known)]))
    return key


def main():
    ap = argparse.ArgumentParser(description='自定义 XOR/Base64 破解工具')
    ap.add_argument('data', nargs='?', help='输入数据')
    ap.add_argument('-b64', '--b64', action='store_true', help='按 base64 解析')
    ap.add_argument('--hex', action='store_true', help='按 hex 解析')
    ap.add_argument('-i', '--in', dest='infile', help='从文件读输入')
    ap.add_argument('-k', '--key', help='直接给定 key (ascii/hex 自动识别)')
    ap.add_argument('--keys', help='字典文件, 每行一个 key')
    ap.add_argument('--known', help='已知明文前缀 (推导多字节 key)')
    ap.add_argument('--auto', action='store_true', help='单字节爆破后自动尝试常见多字节 key')
    ap.add_argument('--top', type=int, default=3, help='单字节爆破输出条数')
    args = ap.parse_args()

    data = read_input(args)
    print(f"[*] 输入: {len(data)} bytes")

    # 1. 直接 key 解密
    if args.key:
        k = bytes.fromhex(args.key) if re.fullmatch(r'[0-9A-Fa-f]+', args.key) and len(args.key) % 2 == 0 \
            else args.key.encode()
        out = xor_decrypt(data, k)
        print(f"[+] key={k!r}: {out.decode('utf-8', 'replace')!r}")
        return

    # 2. 已知明文推导 key
    if args.known:
        kb = args.known.encode()
        k = derive_multi(data, kb)
        out = xor_decrypt(data, k)
        print(f"[+] 推导 key(前{len(k)}字节) = {k!r} (hex: {k.hex()})")
        print(f"    明文: {out.decode('utf-8', 'replace')!r}")
        # 提示: 已知明文推导的 key 只覆盖前 len(known) 字节, 之后按周期重复
        print(f"    [!] key 仅恢复到已知明文长度 ({len(k)} 字节); 若密文后段仍乱码, "
              f"说明 key 更长, 需更长 --known (≥ key 长度) 或结合 --keys 字典补全")
        return

    # 3. 字典尝试
    if args.keys:
        for line in open(args.keys, encoding='utf-8', errors='ignore'):
            k = line.rstrip('\n').encode()
            if not k:
                continue
            out = xor_decrypt(data, k)
            if score(out) > 1.2:
                print(f"[+] 字典命中 key={k!r}: {out.decode('utf-8', 'replace')!r}")
                return
        print("[-] 字典未命中")
        return

    # 4. 单字节爆破
    hits = brute_single(data, args.top)
    if hits:
        print(f"[+] 单字节 XOR 候选 ({len(hits)}):")
        for sc, k, out in hits:
            print(f"    key=0x{k:02x} ({chr(k) if 32 <= k < 127 else '?'}) 分数={sc:.2f}")
            print(f"      → {out.decode('utf-8', 'replace')[:200]!r}")
    else:
        print("[-] 单字节 XOR 无高置信候选, 尝试多字节/已知明文 (--known / --keys)")

    # 5. auto: 常见多字节 key
    if args.auto:
        for k in COMMON_KEYS:
            out = xor_decrypt(data, k)
            if score(out) > 1.2:
                print(f"[+] 常见 key 命中 {k!r}: {out.decode('utf-8', 'replace')[:200]!r}")
                return
        print("[-] 常见多字节 key 未命中")


if __name__ == '__main__':
    main()
