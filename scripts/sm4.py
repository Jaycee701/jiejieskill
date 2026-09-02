#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SM4 纯 Python 实现 + 命令行加解密工具（零依赖）
===============================================
GB/T 32907-2016 国密分组密码 SM4 (128bit block / 128bit key / 32轮)

用法:
    # 解密 (CBC, hex 密文, hex key + iv)
    python sm4.py -m cbc -d --hex -k 0123456789abcdeffedcba9876543210 \
        --iv 00000000000000000000000000000000 \
        681edf34d206965e86b3e94f536e4246

    # 解密 (ECB, base64 密文)
    python sm4.py -m ecb -d --b64 -k 00112233445566778899aabbccddeeff \
        aIzoGOMUY4mdku9M/MTd8Q==

    # 加密 (CBC)
    python sm4.py -m cbc -e --hex -k 0123456789abcdeffedcba9876543210 \
        --iv 00000000000000000000000000000000 \
        0123456789abcdeffedcba9876543210

    # 从文件读密文
    python sm4.py -m ecb -d --hex -k <key> -i cipher.hex

    # 自动尝试 key 列表文件 (已知明文头如 {" 开头时自动判定)
    python sm4.py -m cbc -d --hex --keylist keys.txt --iv <iv> cipher.txt

    # 自定义 key 编码: --key-enc hex|ascii|b64  (iv 同理 --iv-enc)
参数:
    mode:  ecb | cbc | ctr
    key:   16 字节 (hex 32 / ascii 16 / b64 24)
    iv:    16 字节, cbc/ctr 必填
    padding: pkcs7 | none (默认 pkcs7; none 要求密文为 16 倍数)
"""
import argparse
import sys
import re

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

# ---- SM4 S-box (GB/T 32907) ----
SBOX = [
    0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05,
    0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99,
    0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62,
    0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6,
    0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8,
    0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35,
    0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87,
    0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e,
    0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1,
    0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3,
    0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f,
    0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51,
    0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8,
    0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0,
    0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84,
    0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48,
]

FK = (0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc)

CK = (
    0x00070e15,0x1c232a31,0x383f464d,0x545b6269,
    0x70777e85,0x8c939aa1,0xa8afb6bd,0xc4cbd2d9,
    0xe0e7eef5,0xfc030a11,0x181f262d,0x343b4249,
    0x50575e65,0x6c737a81,0x888f969d,0xa4abb2b9,
    0xc0c7ced5,0xdce3eaf1,0xf8ff060d,0x141b2229,
    0x30373e45,0x4c535a61,0x686f767d,0x848b9299,
    0xa0a7aeb5,0xbcc3cad1,0xd8dfe6ed,0xf4fb0209,
    0x10171e25,0x2c333a41,0x484f565d,0x646b7279,
)

MASK = 0xffffffff


def _rotl(x, n):
    return ((x << n) & MASK) | (x >> (32 - n))


def _tau(a):
    """S-box substitution on 4 bytes."""
    return (SBOX[a >> 24 & 0xff] << 24) | (SBOX[a >> 16 & 0xff] << 16) \
        | (SBOX[a >> 8 & 0xff] << 8) | SBOX[a & 0xff]


def _T(a):
    b = _tau(a)
    return b ^ _rotl(b, 2) ^ _rotl(b, 10) ^ _rotl(b, 18) ^ _rotl(b, 24)


def _Tp(a):  # key schedule T'
    b = _tau(a)
    return b ^ _rotl(b, 13) ^ _rotl(b, 23)


def _expand_key(key):
    k = [int.from_bytes(key[4 * i:4 * i + 4], 'big') for i in range(4)]
    k = [k[i] ^ FK[i] for i in range(4)]
    rk = [0] * 32
    for i in range(32):
        k.append(k[i] ^ _Tp(k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ CK[i]))
        rk[i] = k[i + 4]
    return rk


def _block_crypt(block, rk):
    x = [int.from_bytes(block[4 * i:4 * i + 4], 'big') for i in range(4)]
    for i in range(32):
        x.append(x[i] ^ _T(x[i + 1] ^ x[i + 2] ^ x[i + 3] ^ rk[i]))
    out = b''.join(x[35 - i].to_bytes(4, 'big') for i in range(4))
    return out


class SM4:
    """SM4 cipher. key: 16 bytes."""

    def __init__(self, key: bytes):
        assert len(key) == 16, "SM4 key must be 16 bytes"
        self._rk_e = _expand_key(key)
        self._rk_d = list(reversed(self._rk_e))

    def encrypt_block(self, block: bytes) -> bytes:
        return _block_crypt(block, self._rk_e)

    def decrypt_block(self, block: bytes) -> bytes:
        return _block_crypt(block, self._rk_d)


# ---- PKCS7 padding ----
def pkcs7_pad(data: bytes, bs: int = 16) -> bytes:
    n = bs - len(data) % bs
    return data + bytes([n]) * n


def pkcs7_unpad(data: bytes, bs: int = 16) -> bytes:
    if not data:
        return data
    n = data[-1]
    if not 1 <= n <= bs or data[-n:] != bytes([n]) * n:
        raise ValueError("PKCS7 填充校验失败 (可能密钥/模式/IV 不对)")
    return data[:-n]


# ---- 各模式 (统一签名: data, key, iv, decrypt, padding; ecb 忽略 iv) ----
def sm4_ecb(data: bytes, key: bytes, iv: bytes = None, decrypt: bool = True, padding: str = 'pkcs7') -> bytes:
    c = SM4(key)
    fn = c.decrypt_block if decrypt else c.encrypt_block
    if not decrypt and padding == 'pkcs7':
        data = pkcs7_pad(data)
    assert len(data) % 16 == 0, "数据长度不是 16 的倍数"
    out = b''.join(fn(data[i:i + 16]) for i in range(0, len(data), 16))
    if decrypt and padding == 'pkcs7':
        out = pkcs7_unpad(out)
    return out


def sm4_cbc(data: bytes, key: bytes, iv: bytes, decrypt: bool, padding: str = 'pkcs7') -> bytes:
    c = SM4(key)
    if not decrypt and padding == 'pkcs7':
        data = pkcs7_pad(data)
    assert len(data) % 16 == 0, "数据长度不是 16 的倍数"
    out = b''
    prev = iv
    for i in range(0, len(data), 16):
        blk = data[i:i + 16]
        if decrypt:
            # P_i = D(C_i) ^ C_{i-1}
            dec = c.decrypt_block(blk)
            out += bytes(a ^ b for a, b in zip(dec, prev))
            prev = blk
        else:
            # C_i = E(P_i ^ C_{i-1})
            x = bytes(a ^ b for a, b in zip(blk, prev))
            out += c.encrypt_block(x)
            prev = out[-16:]
    if decrypt and padding == 'pkcs7':
        out = pkcs7_unpad(out)
    return out


def sm4_ctr(data: bytes, key: bytes, iv: bytes = None, decrypt: bool = True, padding: str = 'pkcs7') -> bytes:
    """CTR 模式加解密同构, 不受 padding 影响 (iv 视为计数器起始, 大端自增)。"""
    c = SM4(key)
    counter = int.from_bytes(iv, 'big')
    out = b''
    for i in range(0, len(data), 16):
        ks = c.encrypt_block(counter.to_bytes(16, 'big'))
        blk = data[i:i + 16]
        out += bytes(a ^ b for a, b in zip(blk, ks))
        counter = (counter + 1) & ((1 << 128) - 1)
    return out


# ---- 编码辅助 ----
def decode_key(s: str, enc: str) -> bytes:
    if enc == 'hex':
        return bytes.fromhex(s)
    if enc == 'b64':
        import base64
        return base64.b64decode(s)
    return s.encode('utf-8')


def looks_utf8(b: bytes) -> bool:
    try:
        b.decode('utf-8')
        return True
    except UnicodeDecodeError:
        return False


def main():
    ap = argparse.ArgumentParser(description='SM4 国密加解密工具 (零依赖)')
    ap.add_argument('data', nargs='?', help='密文/明文 (hex/base64/utf8) 或通过 --in 文件')
    ap.add_argument('-m', '--mode', choices=['ecb', 'cbc', 'ctr'], default='ecb')
    ap.add_argument('-e', '--encrypt', action='store_true', help='加密 (默认解密)')
    ap.add_argument('-d', '--decrypt', action='store_true', help='解密 (默认)')
    ap.add_argument('-k', '--key', help='密钥, 默认 hex 32 字符')
    ap.add_argument('--key-enc', choices=['hex', 'ascii', 'b64'], default='hex')
    ap.add_argument('--iv', help='IV, 默认 hex 32 字符')
    ap.add_argument('--iv-enc', choices=['hex', 'ascii', 'b64'], default='hex')
    ap.add_argument('--hex', action='store_true', help='输入按 hex 解析')
    ap.add_argument('--b64', action='store_true', help='输入按 base64 解析')
    ap.add_argument('--padding', choices=['pkcs7', 'none'], default='pkcs7')
    ap.add_argument('-i', '--in', dest='infile', help='从文件读输入 (去除空白)')
    ap.add_argument('-o', '--out', dest='outfile', help='输出到文件')
    ap.add_argument('--keylist', help='从文件尝试多个密钥 (每行一个, hex/ascii 自适应)')
    ap.add_argument('--auto', action='store_true',
                    help='keylist 模式下自动判定: 明文以 {" [ 等字符开头视为成功')
    args = ap.parse_args()

    if args.decrypt and args.encrypt:
        sys.exit("[-] -e/-d 互斥")
    decrypt = not args.encrypt

    # 读输入
    if args.infile:
        raw = open(args.infile, 'r', encoding='utf-8', errors='replace').read()
        raw = re.sub(r'\s+', '', raw)
    elif args.data:
        raw = args.data
    else:
        sys.exit("[-] 需要输入数据或 --in 文件")

    mode = args.mode

    # keylist 模式
    if args.keylist:
        keys = [l.strip() for l in open(args.keylist, encoding='utf-8', errors='ignore') if l.strip()]
        iv = decode_key(args.iv, args.iv_enc) if args.iv else None
        for kk in keys:
            for enc, kb in (('hex', bytes.fromhex(kk)) if re.fullmatch(r'[0-9A-Fa-f]{32}', kk)
                            else ('ascii', kk.encode())):
                try:
                    data = bytes.fromhex(raw) if args.hex else \
                        (__import__('base64').b64decode(raw) if args.b64 else raw.encode())
                    pt = globals()[f'sm4_{mode}'](data, kb, iv, True, args.padding)
                    ok = looks_utf8(pt)
                    if args.auto and ok:
                        print(f"[+] 命中密钥 [{enc}] {kk}")
                        print(f"    {pt.decode('utf-8', 'replace')}")
                        return
                except Exception:
                    continue
        print("[-] keylist 未命中")
        return

    key = decode_key(args.key, args.key_enc)
    iv = decode_key(args.iv, args.iv_enc) if args.iv else None
    if mode in ('cbc', 'ctr') and iv is None:
        sys.exit(f"[-] {mode.upper()} 模式需要 --iv (16 字节)")

    data = bytes.fromhex(raw) if args.hex else \
        (__import__('base64').b64decode(raw) if args.b64 else raw.encode())

    try:
        out = globals()[f'sm4_{mode}'](data, key, iv, decrypt, args.padding)
    except (ValueError, AssertionError) as e:
        sys.exit(f"[-] {e}")

    if args.outfile:
        open(args.outfile, 'wb').write(out)
        print(f"[*] 已写出: {args.outfile} ({len(out)} bytes)")
        return

    print("[*] 操作: " + ("解密" if decrypt else "加密") + f" {mode.upper()}"
          + (f" / key(hex)={key.hex()}" if args.key_enc == 'hex' else ""))
    if looks_utf8(out):
        print("[+] 明文: " + out.decode('utf-8', 'replace'))
    else:
        print("[?] 明文非纯文本, 输出 hex:")
        print("    " + out.hex())


if __name__ == '__main__':
    main()
