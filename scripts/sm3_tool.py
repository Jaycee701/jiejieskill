#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SM3 哈希 / HMAC-SM3 工具 (GB/T 32905, 零依赖)
==============================================
SM3 为国密哈希 (256bit 输出), 单向不可逆; "加解密"侧实际做的是摘要/HMAC。

用法:
    # 字符串 SM3
    python sm3_tool.py "转账 100 元"
    # hex 输入
    python sm3_tool.py --hex <data_hex>
    # 文件 SM3 (也可校验下载文件完整性)
    python sm3_tool.py -i file.bin
    # HMAC-SM3 (带密钥的消息认证码, 银行签名报文常用)
    python sm3_tool.py --hmac "s3cr3t_key" "amount=100&to=6222"
    # 校验: 对比预期摘要
    python sm3_tool.py "abc" --expect 66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0

    # 自检 (国标向量)
    python sm3_tool.py --selftest
"""
import argparse
import sys

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

from sm2_k_reuse import sm3_hash


def hmac_sm3(key: bytes, data: bytes) -> bytes:
    """HMAC 构造 (RFC 2104) + SM3。密钥>64字节先哈希, 再填充到64字节块。"""
    if len(key) > 64:
        key = sm3_hash(key)
    key += b'\x00' * (64 - len(key))
    ipad = bytes(b ^ 0x36 for b in key)
    opad = bytes(b ^ 0x5c for b in key)
    return sm3_hash(opad + sm3_hash(ipad + data))


def selftest():
    # GB/T 32905 标准向量
    cases = [
        (b'abc', '66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0'),
        (b'abcd' * 16, 'debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732'),
        (b'', '1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b'),
    ]
    ok = True
    for data, expect in cases:
        got = sm3_hash(data).hex()
        good = got == expect
        ok = ok and good
        print(f"  [{'OK' if good else 'FAIL'}] SM3({data[:8]!r}…) = {got[:24]}…")
    # HMAC-SM3 往返一致性 (无国标公开向量, 用性质验证: 不同key不同结果)
    h1 = hmac_sm3(b'key1', b'msg')
    h2 = hmac_sm3(b'key2', b'msg')
    h3 = hmac_sm3(b'key1', b'msg')
    hmac_ok = h1 != h2 and h1 == h3
    ok = ok and hmac_ok
    print(f"  [{'OK' if hmac_ok else 'FAIL'}] HMAC-SM3: 不同key结果不同, 同key稳定")
    print(f"\n[{'全部通过' if ok else '存在失败'}] SM3 工具自检")
    sys.exit(0 if ok else 1)


def main():
    ap = argparse.ArgumentParser(description='SM3 哈希 / HMAC 工具')
    ap.add_argument('--selftest', action='store_true')
    ap.add_argument('--hex', action='store_true', help='输入按 hex 解析')
    ap.add_argument('-i', '--in', dest='infile', help='对文件做 SM3')
    ap.add_argument('--hmac', metavar='KEY', help='计算 HMAC-SM3 (带密钥)')
    ap.add_argument('--expect', help='与预期摘要比对, 一致输出 ✓')
    ap.add_argument('data', nargs='?', help='输入数据')
    args = ap.parse_args()

    if args.selftest:
        selftest(); return

    if args.infile:
        with open(args.infile, 'rb') as f:
            data = f.read()
        label = f"文件 {args.infile} ({len(data)}B)"
    elif args.data:
        if args.hex:
            data = bytes.fromhex(args.data)
        else:
            data = args.data.encode('utf-8')
        label = f"数据 ({len(data)}B)"
    else:
        sys.exit("[-] 需要输入数据或 -i 文件")

    if args.hmac:
        digest = hmac_sm3(args.hmac.encode('utf-8'), data).hex()
        kind = 'HMAC-SM3'
    else:
        digest = sm3_hash(data).hex()
        kind = 'SM3'

    print(f"[*] {kind} ({label}):")
    print(f"    {digest}")
    if args.expect:
        match = digest == args.expect.lower()
        print(f"[{'✓' if match else '✗'}] 与预期比对: {'一致' if match else '不一致'}")
        sys.exit(0 if match else 1)


if __name__ == '__main__':
    main()
