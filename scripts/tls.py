#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TLS 弱配置检测 (纯 Python ssl, 零依赖)
======================================
银行 TLS 合规检查: 协议版本 / 弱套件 / 证书信息 / 国密套件支持。

用法:
    python tls.py --host bank.com --port 443
    python tls.py --host bank.com --port 443 --timeout 8
    python tls.py --host bank.com --port 8443 --quick   # 仅版本扫描

输出: 支持的协议版本、弱套件检测、证书主体/有效期、国密支持。

注意: 需目标可达网络; 部分云/CDN 会拦截非浏览器 TLS ClientHello。
"""
import argparse
import ssl
import socket
import sys
import datetime
import warnings

warnings.filterwarnings('ignore', category=DeprecationWarning)

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

# 弱套件关键词 (OpenSSL 名称片段)
WEAK_CIPHERS = ['RC4', 'DES', 'EXPORT', 'NULL', 'PSK', 'aNULL', 'MD5']
GCM_TLS_CIPHERS = ['SM4', 'SM3', 'SM2', 'ECDHE-SM2']


def _cipher_name(ss):
    """安全取 cipher 名 (TLS1.3 下可能为 None)。"""
    try:
        c = ss.cipher()
        return c[0] if c else '未知'
    except Exception:
        return '未知'


def _connect(host, port, timeout, min_version, max_version, ciphers=None,
             server_hostname=None):
    """建立 TLS 连接, 返回 (存活 ss, error)。调用方负责关闭。"""
    sock = None
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        if min_version:
            ctx.minimum_version = min_version
        if max_version:
            ctx.maximum_version = max_version
        if ciphers:
            ctx.set_ciphers(ciphers)
        sock = socket.create_connection((host, port), timeout=timeout)
        ss = ctx.wrap_socket(sock, server_hostname=server_hostname or host)
        return ss, None
    except Exception as e:
        if sock:
            try:
                sock.close()
            except Exception:
                pass
        return None, str(e)


def scan_versions(host, port, timeout, server_hostname=None):
    """扫描各 TLS 版本支持情况。"""
    versions = [
        ('TLS 1.0', ssl.TLSVersion.TLSv1),
        ('TLS 1.1', ssl.TLSVersion.TLSv1_1),
        ('TLS 1.2', ssl.TLSVersion.TLSv1_2),
        ('TLS 1.3', ssl.TLSVersion.TLSv1_3),
    ]
    results = []
    for name, ver in versions:
        try:
            ss, err = _connect(host, port, timeout, ver, ver,
                               server_hostname=server_hostname)
        except Exception:
            ss, err = None, 'error'
        if ss:
            v = ss.version()
            results.append((name, True, v if v else '未知', _cipher_name(ss)))
            ss.close()
        else:
            results.append((name, False, '', ''))
    return results


def scan_weak_ciphers(host, port, timeout, server_hostname=None):
    """只提供弱套件连接, 能协商成功才算目标支持该弱套件。"""
    weak_found = []
    for name in WEAK_CIPHERS:
        ss, err = _connect(host, port, timeout,
                           ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_2,
                           ciphers=name, server_hostname=server_hostname)
        if ss:
            weak_found.append((name, _cipher_name(ss)))
            ss.close()
    return weak_found


def scan_sm_ciphers(host, port, timeout, server_hostname=None):
    """检测目标是否支持国密 (SM2/SM3/SM4) 套件。"""
    try:
        ss, err = _connect(host, port, timeout,
                           ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2,
                           ciphers='SM4:SM3:ECDHE-SM2', server_hostname=server_hostname)
        if ss:
            return _cipher_name(ss)
    except Exception:
        pass
    return None


def cert_info(ss):
    """提取证书信息。"""
    try:
        cert = ss.getpeercert()
    except Exception:
        return {}
    info = {}
    if not cert:
        return {}
    info['subject'] = dict(x[0] for x in cert.get('subject', []))
    info['issuer'] = dict(x[0] for x in cert.get('issuer', []))
    info['not_after'] = cert.get('notAfter')
    info['not_before'] = cert.get('notBefore')
    try:
        exp = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
        days = (exp - datetime.datetime.now()).days
        info['days_left'] = days
    except Exception:
        info['days_left'] = None
    return info


def selftest():
    ok = True
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ciphers = ctx.get_ciphers()
        ok = ok and len(ciphers) > 0
        print(f"  [{'OK' if ok else 'FAIL'}] 本地 OpenSSL 支持 {len(ciphers)} 个套件")
        sm = [c['name'] for c in ciphers if 'SM' in c['name'].upper()]
        print(f"  [i] 本地国密套件: {sm if sm else '无'}")
    except Exception as e:
        ok = False
        print(f"  [FAIL] ssl 能力: {e}")
    print("\n[全部通过] TLS 工具自检 (本地能力; 实际检测需对目标 --host)")
    sys.exit(0 if ok else 1)


def main():
    ap = argparse.ArgumentParser(description='TLS 弱配置检测')
    ap.add_argument('--selftest', action='store_true', help='本地自检')
    ap.add_argument('--host', required=False, help='目标主机')
    ap.add_argument('--port', type=int, default=443, help='端口 (默认 443)')
    ap.add_argument('--timeout', type=int, default=5, help='超时秒数')
    ap.add_argument('--quick', action='store_true', help='仅协议版本扫描')
    ap.add_argument('--sni', help='SNI (默认同 host)')
    args = ap.parse_args()

    if args.selftest:
        selftest(); return
    if not args.host:
        sys.exit("[-] 需要 --host 目标 (或 --selftest)")

    sni = args.sni or args.host
    print(f"[*] 目标: {args.host}:{args.port}  (SNI={sni}, 超时 {args.timeout}s)\n")

    # 1. 协议版本
    print("─" * 50)
    print("协议版本扫描:")
    results = scan_versions(args.host, args.port, args.timeout, sni)
    for name, ok, ver, cipher in results:
        if ok:
            safe = (ver or '').lower()
            mark = '✓' if ('tlsv1.2' in safe or 'tlsv1.3' in safe) else '⚠'
            print(f"  [{mark}] {name}: 支持  (协商 {ver}, {cipher})")
        else:
            print(f"  [✗] {name}: 不支持")

    # 2. 弱套件
    print("\n弱套件检测 (RC4/DES/EXPORT/NULL/PSK):")
    weak = scan_weak_ciphers(args.host, args.port, args.timeout, sni)
    if weak:
        for name, cipher in weak:
            print(f"  [⚠] 允许 {name} 类 → 协商 {cipher}")
    else:
        print("  [✓] 未发现弱套件")

    # 3. 国密支持
    sm = scan_sm_ciphers(args.host, args.port, args.timeout, sni)
    if sm:
        print(f"\n国密套件: [✓] 支持 ({sm})")
    else:
        print("\n国密套件: [✗] 未检测到支持")

    # 4. 证书信息 (取默认 TLS1.2/1.3 连接)
    if not args.quick:
        print("\n证书信息:")
        ss, err = _connect(args.host, args.port, args.timeout,
                           ssl.TLSVersion.TLSv1_2, None, server_hostname=sni)
        if not ss:
            ss, err = _connect(args.host, args.port, args.timeout,
                               ssl.TLSVersion.TLSv1, None, server_hostname=sni)
        if ss:
            info = cert_info(ss)
            if info:
                print(f"  主体   : {info.get('subject')}")
                print(f"  签发者 : {info.get('issuer')}")
                print(f"  有效期 : {info.get('not_before')} ~ {info.get('not_after')}")
                dl = info.get('days_left')
                if dl is not None:
                    flag = '⚠ 即将过期' if dl < 30 else '✓'
                    print(f"  剩余   : {dl} 天 {flag}")
            print(f"  协商   : {ss.version()}, {_cipher_name(ss)}")
            ss.close()
        elif err:
            print(f"  [!] 连接失败: {err[:100]}")


if __name__ == '__main__':
    main()
