#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
JieJie加解密 —— 国密/加密攻击工具集一键入口 (桌面独立包, 自包含)
=============================================================
本目录为完整独立包: scripts/ 下已包含全部工具, 拷贝到任何机器可直接用。

用法:
    # 直接派发 (等价于调用对应工具 CLI)
    python crypto_cli.py sm4 --help
    python crypto_cli.py sm2-kreuse --selftest
    python crypto_cli.py sm4 -m cbc -d --hex -k <key> --iv <iv> <密文>
    python crypto_cli.py scan /path/to/jadx_out -r --json

    # 交互菜单 (一键选择)
    python crypto_cli.py

    # 列出工具 / 全部自检
    python crypto_cli.py --list
    python crypto_cli.py --selftest-all

Windows 快捷: crypto-cli.bat (同目录)
"""
import os
import shlex
import subprocess
import sys

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

# ---- 工具注册表: (命令名, 模块文件名, 描述, 分类) ----
TOOLS = [
    ('sm2-kreuse',    'sm2_k_reuse',        'SM2 k 复用恢复私钥',       '签名'),
    ('sm2-blind',     'sm2_blind_sign',     'SM2 盲签名协议',           '签名'),
    ('sm2-sign',      'sm2_sign_tools',     'SM2 畸形签名/验签测试',    '签名'),
    ('sm2-crypto',    'sm2_crypto',         'SM2 加解密 (C1C3C2)',      '对称'),
    ('sm4',           'sm4',                'SM4 加解密 (ECB/CBC/CTR)', '对称'),
    ('aes',           'aes',                'AES 加解密 (含 GCM)',      '对称'),
    ('des3',          'des3',               'DES/3DES 加解密',          '对称'),
    ('rsa',           'rsa',                'RSA 加解密/签名',          '对称'),
    ('fin-mac',       'fin_mac',            '金融报文 MAC 计算',        '对称'),
    ('padding-oracle','sm4_padding_oracle', 'SM4-CBC padding oracle',   '对称'),
    ('pin-dukpt',     'pin_dukpt',          'PIN Block + DUKPT',        '对称'),
    ('jwt',           'jwt',                'JWT 解析/伪造/攻击',       '签名'),
    ('sm3',           'sm3_tool',           'SM3 哈希 / HMAC-SM3',      '哈希'),
    ('sm3-le',        'sm3_length_ext',     'SM3 长度扩展攻击',         '哈希'),
    ('hash-le',       'hash_le',            'SHA 长度扩展攻击',         '哈希'),
    ('totp',          'totp',               'TOTP/HOTP 动态口令',       '哈希'),
    ('hashencode',    'hashencode',         '哈希+编码转换',            '哈希'),
    ('xor',           'xor_decrypt',        '自定义 XOR/Base64 破解',   '提取'),
    ('scan',          'crypto_scan',        '硬编码密钥扫描',           '提取'),
    ('cert8583',      'cert8583',           '证书解析+8583报文',        '提取'),
    ('tls',           'tls',                'TLS 弱配置检测',           '提取'),
    ('card',          'card',               '卡号/磁道工具',            '提取'),
    ('frida',         'frida_run',          'Frida 运行时抓 key/iv',    '动态'),
    ('http-brute',    'http_brute',         'HTTP 表单并发爆破',        '爆破'),
]

CATEGORIES = ['签名', '对称', '哈希', '提取', '动态', '爆破']

# 本包自带脚本目录 (优先使用, 保证便携; 不存在才回退到 skill)
LOCAL_SCRIPTS = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'scripts')


def find_tools_dir():
    """定位工具脚本目录: 优先本包 scripts/, 其次环境变量/skill。"""
    candidates = [
        LOCAL_SCRIPTS,
        os.environ.get('CRYPTO_TOOLS_DIR'),
    ]
    for c in candidates:
        if c and os.path.isdir(c) and os.path.isfile(os.path.join(c, 'sm4.py')):
            return os.path.abspath(c)
    sys.exit("[-] 未找到 scripts 目录 (本包缺失或已损坏), 可设置 CRYPTO_TOOLS_DIR 指向工具目录。")


def tool_by_name(name):
    for n, mod, desc, cat in TOOLS:
        if n == name:
            return n, mod, desc, cat
    sys.exit(f"[-] 未知工具: {name}  (crypto_cli.py --list 查看)")


def dispatch(tool_name, args):
    """在当前进程内调用目标工具的 main()。"""
    import importlib
    n, mod, desc, cat = tool_by_name(tool_name)
    sys.argv = [f'crypto-cli {n}'] + args
    importlib.import_module(mod).main()


def print_usage(n, mod, desc):
    """打印单个工具的 --help。"""
    print(f"\n{'=' * 62}\n[{n}] {desc}\n{'=' * 62}")
    path = os.path.join(TOOLS_DIR, mod + '.py')
    try:
        subprocess.run([sys.executable, path, '--help'])
    except Exception as e:
        print(f"  (无法显示帮助: {e})")


def interactive():
    while True:
        print('\n' + '═' * 62)
        print('  JieJie加解密 · 国密/加密攻击工具集')
        print('═' * 62)
        idx = 1
        mapping = {}
        for cat in CATEGORIES:
            print(f'\n  ── {cat} ──')
            for n, mod, desc, c in TOOLS:
                if c == cat:
                    print(f'  [{idx:>2}] {desc} ({n})')
                    mapping[idx] = n
                    idx += 1
        print(f'  [ 0] 退出')
        print('  [--] 输入 `工具名 参数` 直接派发, 如: scan /path -r')
        try:
            choice = input('\n  选择编号或命令: ').strip()
        except (KeyboardInterrupt, EOFError):
            print()
            return
        if choice == '0':
            return
        if not choice:
            continue
        parts = shlex.split(choice)
        if parts[0] in [n for n, *_ in TOOLS]:
            try:
                dispatch(parts[0], parts[1:])
            except SystemExit:
                pass
            continue
        if choice.isdigit() and int(choice) in mapping:
            n = mapping[int(choice)]
            _, mod, desc, _ = tool_by_name(n)
            print_usage(n, mod, desc)
            try:
                line = input(f'\n  [{n}] 输入参数 (直接回车=自检): ').strip()
            except (KeyboardInterrupt, EOFError):
                continue
            args = shlex.split(line) if line else ['--selftest']
            try:
                dispatch(n, args)
            except SystemExit:
                pass
            input('\n  按回车返回菜单...')


def _run(cmd, cwd=None):
    return subprocess.run(cmd, capture_output=True, text=True,
                          encoding='utf-8', errors='replace', cwd=cwd)


NATIVE_SELFTEST = {'sm2_k_reuse', 'sm2_blind_sign', 'sm2_sign_tools',
                   'sm2_crypto', 'sm4_padding_oracle', 'sm3_tool',
                   'sm3_length_ext', 'des3', 'fin_mac', 'totp', 'pin_dukpt',
                   'aes', 'rsa', 'hashencode', 'cert8583',
                   'jwt', 'hash_le', 'tls', 'card', 'http_brute'}


def _selftest_sm4():
    code = ("from sm4 import sm4_ecb; k=bytes.fromhex('0123456789abcdeffedcba9876543210');"
            "assert sm4_ecb(bytes.fromhex('0123456789abcdeffedcba9876543210'),k,None,False,'none')"
            ".hex()=='681edf34d206965e86b3e94f536e4246'")
    return _run([sys.executable, '-c', code], cwd=TOOLS_DIR).returncode == 0


def _selftest_xor():
    code = ("import xor_decrypt as x;"
            "pt=b'{\"amt\":\"100.00\",\"to\":\"6222\",\"acct\":\"6217\"}';"
            "ct=bytes(c^0x5a for c in pt);"
            "assert x.xor_decrypt(ct, b'\\x5a')==pt;"
            "hits=x.brute_single(ct, 3);"
            "assert hits and any(k==0x5a for _,k,_ in hits)")
    return _run([sys.executable, '-c', code], cwd=TOOLS_DIR).returncode == 0


def _selftest_scan():
    import tempfile
    sample = ('const SM4_KEY = "0123456789ABCDEFFEDCBA9876543210";\n'
              'var iv = "000102030405060708090A0B0C0D0E0F";\n')
    fd, path = tempfile.mkstemp(suffix='.js')
    try:
        with os.fdopen(fd, 'w') as f:
            f.write(sample)
        r = _run([sys.executable, os.path.join(TOOLS_DIR, 'crypto_scan.py'), path, '--json'])
        return r.returncode == 0 and '0123456789ABCDEFFEDCBA9876543210' in r.stdout
    finally:
        os.unlink(path)


def _selftest_frida():
    r = _run([sys.executable, os.path.join(TOOLS_DIR, 'frida_run.py'), '--help'])
    return r.returncode == 0


def selftest_all():
    print('═' * 62)
    print('  全部工具自检')
    print('═' * 62)
    results = []
    for n, mod, desc, cat in TOOLS:
        path = os.path.join(TOOLS_DIR, mod + '.py')
        if mod in NATIVE_SELFTEST:
            r = _run([sys.executable, path, '--selftest'])
            ok = r.returncode == 0
            tail = (r.stdout + r.stderr).strip().splitlines()
            note = tail[-1] if tail else ''
        elif mod == 'sm4':
            ok, note = _selftest_sm4(), '国标向量'
        elif mod == 'xor_decrypt':
            ok, note = _selftest_xor(), '单字节爆破'
        elif mod == 'crypto_scan':
            ok, note = _selftest_scan(), '硬编码key命中'
        elif mod == 'frida_run':
            ok, note = _selftest_frida(), '加载'
        else:
            ok, note = False, '无自检方式'
        results.append((n, ok, note))
        print(f"  [{'PASS' if ok else 'FAIL'}] {n:<16} {desc}  ({note})")
    print('\n' + '═' * 62)
    print('  汇总: ' + ' | '.join(f'{n}={"✓" if ok else "✗"}' for n, ok, _ in results))
    failed = [n for n, ok, _ in results if not ok]
    sys.exit(1 if failed else 0)


def main():
    if len(sys.argv) < 2:
        interactive()
        return
    cmd = sys.argv[1]
    if cmd in ('--list', '-l'):
        for cat in CATEGORIES:
            print(f'\n── {cat} ──')
            for n, mod, desc, c in TOOLS:
                if c == cat:
                    print(f'  {n:<16} {desc}')
        return
    if cmd == '--selftest-all':
        selftest_all()
        return
    if cmd.startswith('-'):
        sys.exit(f"[-] 未知选项 {cmd}  (用 --list 看工具, 或直接 crypto_cli.py <工具名>)")
    dispatch(cmd, sys.argv[2:])


if __name__ == '__main__':
    TOOLS_DIR = find_tools_dir()
    sys.path.insert(0, TOOLS_DIR)
    main()
