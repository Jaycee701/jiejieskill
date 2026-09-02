#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
哈希 + 编码转换工具 (零依赖, 标准库)
====================================
哈希:  SHA-1/224/256/384/512, MD5, HMAC-SHA (银行报文摘要比对)
编码:  hex / base64 / URL / ASCII 互转 (抓包报文处理刚需)

用法:
    # 哈希
    python hashencode.py hash "报文数据" --algo sha256
    python hashencode.py hash --hex <数据hex>
    python hashencode.py hash -i file.bin --algo sha1
    python hashencode.py hmac --key s3cr3t "amount=100" --algo sha256

    # 编码转换 (通用)
    python hashencode.py conv --from hex --to base64 "aabbcc"
    python hashencode.py conv --from base64 --to hex "<b64>"
    python hashencode.py conv --from utf8 --to url "转账 100&to=6222"
    # 快捷: b64e / b64d / hexd
    python hashencode.py b64d "dGFyZ2V0..."     # base64 → 文本
    python hashencode.py hexd "68656c6c6f"      # hex → 文本

    # 自检
    python hashencode.py --selftest
"""
import argparse
import base64
import hashlib
import hmac as hmac_mod
import sys
import urllib.parse

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

HASHES = {
    'md5': hashlib.md5, 'sha1': hashlib.sha1, 'sha224': hashlib.sha224,
    'sha256': hashlib.sha256, 'sha384': hashlib.sha384, 'sha512': hashlib.sha512,
}


def read_input(args):
    if args.infile:
        data = open(args.infile, 'rb').read()
    elif args.data:
        data = bytes.fromhex(args.data) if args.hex else args.data.encode('utf-8')
    else:
        sys.exit("[-] 需要输入数据或 -i 文件")
    return data


def do_hash(data, algo):
    return HASHES[algo](data).hexdigest()


def do_hmac(data, key, algo):
    a = algo if algo in ('sha1', 'sha224', 'sha256', 'sha384', 'sha512') else 'sha256'
    return hmac_mod.new(key.encode(), data, getattr(hashlib, a)).hexdigest()


def conv(from_enc, to_enc, data: bytes) -> bytes:
    if from_enc == 'utf8':
        pass
    elif from_enc == 'hex':
        data = bytes.fromhex(data.decode('ascii'))
    elif from_enc == 'base64':
        data = base64.b64decode(data)
    elif from_enc == 'url':
        data = urllib.parse.unquote_to_bytes(data.decode('utf-8'))
    else:
        raise ValueError(f"未知输入编码 {from_enc}")

    if to_enc == 'utf8':
        return data
    if to_enc == 'hex':
        return data.hex().encode('ascii')
    if to_enc == 'base64':
        return base64.b64encode(data)
    if to_enc == 'url':
        return urllib.parse.quote_from_bytes(data).encode('ascii')
    raise ValueError(f"未知输出编码 {to_enc}")


def selftest():
    ok = True
    # SHA-256 标准向量
    cases = [
        ('sha256', 'abc', 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'),
        ('sha1', 'abc', 'a9993e364706816aba3e25717850c26c9cd0d89d'),
        ('md5', 'abc', '900150983cd24fb0d6963f7d28e17f72'),
    ]
    for algo, data, expect in cases:
        got = do_hash(data.encode(), algo)
        good = got == expect
        ok = ok and good
        print(f"  [{'OK' if good else 'FAIL'}] {algo}('abc') = {got}")
    # HMAC-SHA256 与标准库对照
    import hmac as hm, hashlib as hl
    ref = hm.new(b'key', b'The quick brown fox', hl.sha256).hexdigest()
    mine = do_hmac(b'The quick brown fox', 'key', 'sha256')
    ok = ok and mine == ref
    print(f"  [{'OK' if mine == ref else 'FAIL'}] HMAC-SHA256 一致")
    # 编码转换往返
    rt = conv('hex', 'base64', b'aabbcc')
    back = conv('base64', 'hex', rt)
    ok = ok and back == b'aabbcc'
    print(f"  [{'OK' if back == b'aabbcc' else 'FAIL'}] hex→b64→hex 往返")
    rt2 = conv('utf8', 'url', '转账 100&to=6222'.encode())
    back2 = conv('url', 'utf8', rt2)
    ok = ok and back2 == '转账 100&to=6222'.encode()
    print(f"  [{'OK' if back2 == '转账 100&to=6222'.encode() else 'FAIL'}] utf8→url→utf8 往返")
    print(f"\n[{'全部通过' if ok else '存在失败'}] 哈希/编码自检")
    sys.exit(0 if ok else 1)


def main():
    ap = argparse.ArgumentParser(description='哈希 + 编码转换工具')
    ap.add_argument('--selftest', action='store_true')
    ap.add_argument('op', nargs='?', choices=['hash', 'hmac', 'conv', 'b64e', 'b64d', 'hexd'],
                    help='操作: hash/hmac/conv/b64e/b64d/hexd')
    ap.add_argument('data', nargs='?', help='数据')
    ap.add_argument('--algo', default='sha256', choices=list(HASHES), help='哈希算法')
    ap.add_argument('--key', help='HMAC 密钥')
    ap.add_argument('--from', dest='from_enc', default='hex',
                    choices=['hex', 'base64', 'utf8', 'url'], help='conv 输入编码')
    ap.add_argument('--to', dest='to_enc', default='utf8',
                    choices=['hex', 'base64', 'utf8', 'url'], help='conv 输出编码')
    ap.add_argument('--hex', action='store_true', help='数据按 hex 解析')
    ap.add_argument('-i', '--in', dest='infile', help='从文件读')
    args = ap.parse_args()

    if args.selftest:
        selftest(); return
    if not args.op:
        sys.exit("[-] 需要操作: hash / hmac / conv / b64e / b64d / hexd")

    # 快捷: b64e/b64d/hexd
    if args.op in ('b64e', 'b64d', 'hexd'):
        data = read_input(args)
        if args.op == 'b64e':
            print(base64.b64encode(data).decode())
        elif args.op == 'b64d':
            try:
                out = base64.b64decode(args.data if args.data else data)
                print(out.decode('utf-8', 'replace') if out else '')
            except Exception as e:
                sys.exit(f"[-] base64 解码失败: {e}")
        else:  # hexd
            print(data.decode('utf-8', 'replace'))
        return

    data = read_input(args)
    if args.op == 'hash':
        print(do_hash(data, args.algo))
    elif args.op == 'hmac':
        if not args.key:
            sys.exit("[-] hmac 需要 --key")
        print(do_hmac(data, args.key, args.algo))
    elif args.op == 'conv':
        try:
            out = conv(args.from_enc, args.to_enc, data)
        except (ValueError, Exception) as e:
            sys.exit(f"[-] {e}")
        print(out.decode('utf-8', 'replace'))


if __name__ == '__main__':
    main()
