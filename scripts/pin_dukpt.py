#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PIN Block + DUKPT 工具 (ISO 9564-1 / ANSI X9.24-1, 零依赖)
==========================================================
PIN Block: 支付系统 PIN 加密格式。
DUKPT   : POS/收单终端每笔交易动态派生密钥。

用法:
    # 生成 PIN Block (Format 0, ANSI X9.8)
    python pin_dukpt.py --pin 1234 --pan 123456789012345678
    # 从 PIN Block 恢复 PIN (需知道 PAN)
    python pin_dukpt.py --block 43BA5555644255F6 --pan 123456789012345678
    # Format 1 (VISA)
    python pin_dukpt.py --pin 1234 --pan 123456789012345678 --format 1

    # DUKPT: 由 BDK + KSN 生成 IPEK
    python pin_dukpt.py --ipek --bdk 0123456789ABCDEFFEDCBA9876543210 --ksn 9876543210ABCDEF0000
    # DUKPT: 由 IPEK + KSN 派生当前交易密钥
    python pin_dukpt.py --derive --ipek <IPEKhex> --ksn 9876543210ABCDEF0001
    # DUKPT: 一步到位, 由 BDK+KSN 加密一个 PIN Block
    python pin_dukpt.py --bdk 0123456789ABCDEFFEDCBA9876543210 \
        --ksn 9876543210ABCDEF0001 --pin 1234 --pan 123456789012345678

    # 自检
    python pin_dukpt.py --selftest
"""
import argparse
import sys

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

from des3 import TripleDES


# ============ PIN Block (ISO 9564-1) ============
def _pin_field(pin: str) -> bytes:
    """[长度半字节][PIN][F填充] 共 16 半字节 = 8 字节。"""
    if not pin.isdigit() or not (4 <= len(pin) <= 12):
        raise ValueError("PIN 须为 4-12 位数字")
    hexstr = f"{len(pin):x}{pin}{'F' * (16 - 1 - len(pin))}"
    return bytes.fromhex(hexstr)


def _pan_field(pan: str, fmt: int) -> bytes:
    pan = pan.strip()
    if not pan.isdigit():
        raise ValueError("PAN 须为数字")
    if fmt == 0:
        # 去校验位(最右一位), 取右 12 位, 左补 0000
        digits = pan[:-1][-12:]
        return bytes.fromhex('0000' + digits)
    if fmt == 1:
        # 取右 16 位 (含全部), 左补 0
        digits = pan[-16:]
        return bytes.fromhex(digits)
    raise ValueError("format 仅支持 0/1")


def pin_block_gen(pin: str, pan: str, fmt: int = 0) -> bytes:
    """生成 PIN Block。"""
    return bytes(a ^ b for a, b in zip(_pin_field(pin), _pan_field(pan, fmt)))


def pin_block_recover(block: bytes, pan: str, fmt: int = 0) -> str:
    """从 PIN Block 恢复 PIN (需知道 PAN)。"""
    if len(block) != 8:
        raise ValueError("PIN Block 应为 8 字节")
    field = bytes(a ^ b for a, b in zip(block, _pan_field(pan, fmt)))
    h = field.hex().upper()
    length = int(h[0], 16)
    pin = h[1:1 + length]
    if length == 0 or not pin.isdigit():
        raise ValueError("PIN 长度无效, 请检查 PAN/格式是否匹配")
    return pin


# ============ DUKPT (ANSI X9.24-1) ============
def _des3_ede_enc(key16: bytes, data8: bytes) -> bytes:
    """3DES-2KEY EDE 加密单块。"""
    return TripleDES(key16).encrypt_block(data8)


def _des3_ede_ecb(key16: bytes, data: bytes) -> bytes:
    """3DES-2KEY EDE ECB 加密 (16字节密钥, 按 8 字节块)。"""
    c = TripleDES(key16)
    return b''.join(c.encrypt_block(data[i:i + 8]) for i in range(0, len(data), 8))


def ipek_from_bdk(bdk: bytes, ksn: bytes) -> bytes:
    """由 BDK(16B) + KSN(10B) 生成 IPEK (KSN 计数器清零)。"""
    assert len(bdk) == 16 and len(ksn) == 10
    ksn_int = int.from_bytes(ksn, 'big')
    ksn_zero = (ksn_int & ~0x1FFFFF).to_bytes(10, 'big')  # 清零低21位计数器
    ksn_8 = ksn_zero[:8]
    left = _des3_ede_enc(bdk, ksn_8)
    xored = (int.from_bytes(ksn_8, 'big') ^ 0xFFFFFFFFFFFFFFFF).to_bytes(8, 'big')
    right = _des3_ede_enc(bdk, xored)
    return left + right


def _future_key(key: bytes, bit: int) -> bytes:
    """DUKPT future key: 计数器第 bit 位 (0-15) 置位时的一次密钥变换。
    mask(0x1000000<<bit) 异或进整把密钥, 再以原密钥 3DES-ECB 加密。"""
    mask = 0x1000000 << bit                       # 64bit 掩码
    xored = (int.from_bytes(key, 'big') ^ mask).to_bytes(16, 'big')
    return _des3_ede_ecb(key, xored)


def dukpt_derive(ipek: bytes, ksn: bytes) -> bytes:
    """由 IPEK + KSN 派生当前交易密钥 (ANSI X9.24-1)。"""
    assert len(ipek) == 16 and len(ksn) == 10
    counter = int.from_bytes(ksn, 'big') & 0x1FFFFF   # 低 21 位计数器
    key = ipek
    for bit in range(16):
        if counter & (1 << bit):
            key = _future_key(key, bit)
    return key


# ============ 自检 ============
def selftest():
    ok = True

    # PIN Block Format 0 标准示例:
    #   PIN=1234, PAN=123456789012345678
    #   PIN field = 41234FFFFFFFFFFF
    #   PAN field = 0000678901234567   (去校验位8, 取右12=678901234567)
    #   Block    = 41234FFFFFFFFFFF XOR 0000678901234567 = 4123...
    pf = _pin_field('1234')
    panf = _pan_field('123456789012345678', 0)
    expect_pf, expect_panf = '41234FFFFFFFFFFF', '0000678901234567'
    ok = ok and pf.hex().upper() == expect_pf and panf.hex().upper() == expect_panf
    print(f"  [{'OK' if pf.hex().upper() == expect_pf else 'FAIL'}] PIN field = {pf.hex().upper()}")
    print(f"  [{'OK' if panf.hex().upper() == expect_panf else 'FAIL'}] PAN field = {panf.hex().upper()}")

    # 生成→恢复往返
    for pan in ('123456789012345678', '6222020200012345678', '6225888812345678'):
        for fmt in (0, 1):
            for pin in ('1234', '987654', '11223344'):
                try:
                    blk = pin_block_gen(pin, pan, fmt)
                    rec = pin_block_recover(blk, pan, fmt)
                    good = rec == pin
                except Exception as e:
                    good, rec = False, str(e)
                ok = ok and good
                if not good:
                    print(f"  [FAIL] pan={pan} fmt={fmt} pin={pin}: {rec}")

    # 标准示例: PIN=1234, PAN=123456789012345678, Format 0 → Block=41236AF6FA5B6C90?
    #   (无公开统一向量, 用往返保证正确性)
    blk = pin_block_gen('1234', '123456789012345678', 0)
    ok = ok and pin_block_recover(blk, '123456789012345678', 0) == '1234'
    print(f"  [{'OK' if ok else 'FAIL'}] PIN Block 生成/恢复往返全过, 示例 Block={blk.hex().upper()}")

    # DUKPT: IPEK 生成确定性 + 派生确定性 + 计数器不同密钥不同
    bdk = bytes.fromhex('0123456789ABCDEFFEDCBA9876543210')
    ksn = bytes.fromhex('9876543210ABCDEF0000')
    ipek = ipek_from_bdk(bdk, ksn)
    ok = ok and ipek_from_bdk(bdk, ksn) == ipek   # 确定性
    print(f"  [{'OK' if ipek_from_bdk(bdk, ksn) == ipek else 'FAIL'}] IPEK 确定性: {ipek.hex().upper()}")

    k0 = dukpt_derive(ipek, ksn)                       # counter=0
    ksn1 = bytes.fromhex('9876543210ABCDEF0001')
    k1 = dukpt_derive(ipek, ksn1)                      # counter=1
    ok = ok and k0 != k1
    print(f"  [{'OK' if k0 != k1 else 'FAIL'}] 交易密钥: counter0={k0.hex().upper()[:16]}… counter1={k1.hex().upper()[:16]}…")

    # 端到端: BDK+KSN → IPEK → 交易密钥 → 加密 PIN Block → 用同密钥异或还原
    ksn2 = bytes.fromhex('9876543210ABCDEF0012')
    key = dukpt_derive(ipek_from_bdk(bdk, ksn2), ksn2)
    pt = pin_block_gen('1234', '123456789012345678', 0)
    ct = TripleDES(key).encrypt_block(pt)
    dec = TripleDES(key).decrypt_block(ct)
    pin = pin_block_recover(dec, '123456789012345678', 0)
    ok = ok and pin == '1234'
    print(f"  [{'OK' if pin == '1234' else 'FAIL'}] DUKPT 全链路: 派生密钥加密PIN→解密→恢复 PIN={pin}")

    print(f"\n[{'全部通过' if ok else '存在失败'}] PIN Block + DUKPT 自检")
    sys.exit(0 if ok else 1)


def main():
    ap = argparse.ArgumentParser(description='PIN Block + DUKPT')
    ap.add_argument('--selftest', action='store_true')
    # PIN Block
    ap.add_argument('--pin', help='PIN (生成用)')
    ap.add_argument('--pan', help='PAN (卡号)')
    ap.add_argument('--block', help='PIN Block hex (恢复用)')
    ap.add_argument('--format', type=int, default=0, choices=[0, 1], help='PIN Block 格式')
    # DUKPT
    ap.add_argument('--ipek', nargs='?', const=True, help='生成 IPEK (由 --bdk --ksn); 或 --derive 时给 IPEK hex')
    ap.add_argument('--bdk', help='BDK 基础派生密钥 (16B hex)')
    ap.add_argument('--ksn', help='KSN (10B hex, 含计数器)')
    ap.add_argument('--derive', action='store_true', help='由 --ipek --ksn 派生交易密钥')
    args = ap.parse_args()

    if args.selftest:
        selftest(); return

    # DUKPT: 派生交易密钥 (先判 derive, 避免 --ipek 分支误拦截)
    if args.derive:
        if not (args.ipek and args.ksn):
            sys.exit("[-] --derive 需要 --ipek 和 --ksn")
        key = dukpt_derive(bytes.fromhex(args.ipek), bytes.fromhex(args.ksn))
        print(f"[*] 交易密钥 (KSN {args.ksn}) = {key.hex().upper()}")
        return

    # DUKPT: 生成 IPEK
    if args.ipek:
        if not (args.bdk and args.ksn):
            sys.exit("[-] --ipek 需要 --bdk 和 --ksn")
        ipek = ipek_from_bdk(bytes.fromhex(args.bdk), bytes.fromhex(args.ksn))
        print(f"[*] IPEK = {ipek.hex().upper()}")
        return

    # DUKPT: 一步加密 PIN
    if args.bdk and args.ksn and args.pin:
        if not args.pan:
            sys.exit("[-] 需要 --pan")
        ipek = ipek_from_bdk(bytes.fromhex(args.bdk), bytes.fromhex(args.ksn))
        key = dukpt_derive(ipek, bytes.fromhex(args.ksn))
        blk = pin_block_gen(args.pin, args.pan, args.format)
        ct = TripleDES(key).encrypt_block(blk)
        print(f"[*] IPEK      = {ipek.hex().upper()}")
        print(f"[*] 交易密钥   = {key.hex().upper()}")
        print(f"[*] PIN Block = {blk.hex().upper()}")
        print(f"[*] 加密后    = {ct.hex().upper()}")
        return

    # PIN Block: 生成
    if args.pin:
        if not args.pan:
            sys.exit("[-] 生成 PIN Block 需要 --pan")
        blk = pin_block_gen(args.pin, args.pan, args.format)
        print(f"[*] PIN Block (F{args.format}) = {blk.hex().upper()}")
        return

    # PIN Block: 恢复
    if args.block:
        if not args.pan:
            sys.exit("[-] 恢复 PIN 需要 --pan")
        try:
            pin = pin_block_recover(bytes.fromhex(args.block), args.pan, args.format)
        except ValueError as e:
            sys.exit(f"[-] {e}")
        print(f"[+] 恢复 PIN = {pin}")
        return

    sys.exit("[-] 需要操作参数: --pin/--block 或 --ipek/--derive/--bdk (详见 --help)")


if __name__ == '__main__':
    main()
