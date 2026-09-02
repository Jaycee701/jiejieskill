#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
硬编码密钥/IV 扫描器 (零依赖)
=============================
扫描 JS / APK 反编译目录 / 配置文件中疑似硬编码的 SM4/AES key、IV、盐值。
配合 sm4.py 解密使用: 先扫出 key, 再解密流量。

用法:
    python crypto_scan.py app.js
    python crypto_scan.py /path/to/jadx_out -r            # 递归
    python crypto_scan.py app.js -r --json                # 输出 JSON
    python crypto_scan.py --ctx 60 -e .js,.html,.java app
"""
import argparse
import json
import os
import re
import sys

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

# 加密上下文关键词: 命中则重点标注 (下划线视为边界, 兼容 SM4_KEY / AES_IV)
C_KEYWORDS = re.compile(r'(?<![A-Za-z0-9])(sm4|sm2|sm3|aes|des|rsa|encrypt|decrypt|secret|密钥|密匙|加密)(?![A-Za-z0-9])', re.I)

# 模式1: key/iv 变量 = 字符串常量 (含 SM4_KEY / aesKey / SECRET 等带前缀命名)
PAT_KEY_ASSIGN = re.compile(
    r"""\b[\w]*(?:key|iv|secret|salt|sm4key|aeskey|passphrase)\b\s*[=:]\s*['\"]([^'\"]{6,96})['\"]""",
    re.I)

# 模式2: 16/32 字节 hex key (crypto 上下文附近)
PAT_HEX_KEY = re.compile(r"""['\"]\s*([0-9a-fA-F]{32}|[0-9a-fA-F]{64})\s*['\"]""")

# 模式3: base64 key 字符串
PAT_B64_KEY = re.compile(r"""['\"]([A-Za-z0-9+/]{16,44}={0,2})['\"]""")

# 模式4: Java/C byte[] 数组 {0x..,0x..}
PAT_BYTEARRAY = re.compile(
    r"""(?:byte\[\]|new byte\[\]|byte\[)\s*(\w*)\s*[=:]\s*\{([^}]{8,})\}""", re.I)

# 模式5: CryptoJS / sm2 / new SM4( 等构造调用
PAT_CALL = re.compile(
    r"""\b(SM4|Sm4|sm4|AES|aes|CryptoJS|DESede|SM2|sm2)\.?\s*(?:\(|\[|\.)""")

DEFAULT_EXTS = {'.js', '.html', '.htm', '.php', '.java', '.kt', '.xml', '.json',
                '.properties', '.conf', '.ini', '.py', '.go', '.c', '.cpp', '.h',
                '.ts', '.tsx', '.jsx', '.txt', '.cfg', '.yml', '.yaml'}


def scan_text(text: str, path: str, ctx: int) -> list:
    findings = []
    lines = text.splitlines()

    def ctx_str(match):
        start = max(0, match.start() - ctx)
        end = min(len(text), match.end() + ctx)
        return text[start:end].replace('\n', '␤')

    for pat, name in ((PAT_KEY_ASSIGN, 'key/iv 赋值'),
                      (PAT_BYTEARRAY, 'byte[] 密钥数组'),
                      (PAT_CALL, '加密函数调用')):
        for m in pat.finditer(text):
            has_crypto = bool(C_KEYWORDS.search(m.group(0)))
            findings.append({
                'type': name,
                'match': m.group(0)[:120],
                'context': ctx_str(m),
                'crypto_ctx': has_crypto,
            })

    for m in PAT_HEX_KEY.finditer(text):
        val = m.group(1)
        # hex key 需要 crypto 上下文, 且不是普通 32 位整数/时间戳
        if C_KEYWORDS.search(ctx_str(m)):
            findings.append({'type': 'hex 密钥', 'match': val,
                             'context': ctx_str(m), 'crypto_ctx': True})
    return findings


def main():
    ap = argparse.ArgumentParser(description='硬编码密钥/IV 扫描器')
    ap.add_argument('target', help='文件或目录')
    ap.add_argument('-r', '--recursive', action='store_true', help='递归扫描目录')
    ap.add_argument('-e', '--ext', default='', help='仅扫描指定扩展名, 逗号分隔 (默认全常用)')
    ap.add_argument('--ctx', type=int, default=80, help='上下文窗口字符数')
    ap.add_argument('--json', action='store_true', help='JSON 输出')
    ap.add_argument('--max-len', type=int, default=1000000, help='跳过超过该大小的文本文件')
    args = ap.parse_args()

    exts = {e.strip().lower() if e.strip().startswith('.') else '.' + e.strip().lower()
            for e in args.ext.split(',') if e.strip()} or DEFAULT_EXTS

    if os.path.isdir(args.target):
        files = []
        for root, dirs, names in os.walk(args.target):
            if not args.recursive:
                dirs[:] = []
            for n in names:
                p = os.path.join(root, n)
                if os.path.splitext(p)[1].lower() in exts:
                    files.append(p)
    else:
        files = [args.target]

    all_findings = {}
    total = 0
    for p in files:
        try:
            size = os.path.getsize(p)
            if size > args.max_len:
                continue
            text = open(p, 'r', encoding='utf-8', errors='replace').read()
        except Exception:
            continue
        finds = scan_text(text, p, args.ctx)
        if finds:
            all_findings[p] = finds
            total += len(finds)

    if args.json:
        print(json.dumps(all_findings, ensure_ascii=False, indent=1))
        return

    if not all_findings:
        print("[-] 未发现疑似硬编码密钥")
        return
    print(f"[+] 发现 {total} 处疑似密钥 ({len(all_findings)} 个文件):\n")
    for p, finds in all_findings.items():
        for f in finds:
            tag = '★crypto' if f['crypto_ctx'] else '  '
            print(f"[{tag}] {p}")
            print(f"    类型  : {f['type']}")
            print(f"    匹配  : {f['match']!r}")
            print(f"    上下文: {f['context']!r}")
            print()


if __name__ == '__main__':
    main()
