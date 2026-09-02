#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
X.509 证书解析 + ISO 8583 金融报文解析/组包 (纯 Python, 零依赖)
================================================================
证书: 从 DER 证书提取 RSA/EC/SM2 公钥 (验签目标身份)
8583: 银联/POS 金融报文, 域/位图解析与组包

用法:
    # 证书解析
    python cert8583.py --cert server.der                     # DER 证书
    python cert8583.py --cert server.pem                     # PEM 证书
    python cert8583.py --cert server.cer --extract-pubkey    # 输出公钥参数

    # ISO 8583 解析
    python cert8583.py --8583-parse 0200B23A000000100000000000000000...
    # ISO 8583 组包
    python cert8583.py --8583-build --mti 0200 --fields 3:123456 4:000000010000 11:000001 41:TERM0001

    # 自检 (会用 cryptography 生成测试证书, 缺失则跳过证书部分)
    python cert8583.py --selftest
"""
import argparse
import base64
import sys

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

# ================= X.509 / DER =================
OID_RSA = '1.2.840.113549.1.1.1'
OID_EC = '1.2.840.10045.2.1'
OID_SM2 = '1.2.156.10197.1.301'
OID_CN = '2.5.4.3'
OID_OU = '2.5.4.11'
OID_O = '2.5.4.10'


def _der_len(data, off):
    """DER 长度编码解析, 返回 (长度, 新偏移)。"""
    b = data[off]
    if b < 0x80:
        return b, off + 1
    n = b & 0x7f
    return int.from_bytes(data[off + 1:off + 1 + n], 'big'), off + 1 + n


def _der_tlv(data, off):
    """返回 (tag, value, value_off, value_end)。"""
    tag = data[off]
    ln, lstart = _der_len(data, off + 1)
    return tag, data[lstart:lstart + ln], lstart, lstart + ln


def _der_children(seq):
    """SEQUENCE 的子元素列表 [(tag, value_bytes), ...]。"""
    children = []
    off = 0
    while off < len(seq):
        tag, val, _, end = _der_tlv(seq, off)
        children.append((tag, val))
        off = end
    return children


def _der_oid(oid_bytes):
    """OID 字节 → 点分字符串。"""
    first = oid_bytes[0]
    parts = [str(first // 40), str(first % 40)]
    n = 0
    for b in oid_bytes[1:]:
        n = (n << 7) | (b & 0x7f)
        if not b & 0x80:
            parts.append(str(n))
            n = 0
    return '.'.join(parts)


def _collect_oids(blob, depth=0):
    """递归收集 DER 块内所有 OID (点分字符串), 兼容任意嵌套深度。"""
    out = []
    if depth > 6 or not blob:
        return out
    off = 0
    while off < len(blob):
        try:
            tag, val, _, end = _der_tlv(blob, off)
        except Exception:
            break
        if tag == 0x06:
            try:
                out.append(_der_oid(val))
            except Exception:
                pass
        elif tag in (0x30, 0x31):
            out.extend(_collect_oids(val, depth + 1))
        off = end
    return out


def _der_int(der_int):
    return int.from_bytes(der_int, 'big')


def parse_cert(der):
    """解析 X.509 证书, 返回公钥与元信息。"""
    # 外层 Certificate SEQUENCE → tbsCertificate
    _, cert_val, _, _ = _der_tlv(der, 0)
    children = _der_children(cert_val)
    tbs = children[0][1]
    tbs_children = _der_children(tbs)

    info = {'serial': None, 'subject': {}, 'issuer': {}, 'algorithm': None}
    # tbs: [0]version, serial(2), sigAlg(3), issuer(4), validity(5), subject(6), spki(7)...
    for tag, val in tbs_children:
        if tag == 0x02:  # INTEGER = serial
            if info['serial'] is None:
                info['serial'] = _der_int(val)
        elif tag == 0x30:
            sub = _der_children(val)
            oids = _collect_oids(val)
            if not oids:
                continue
            if OID_CN in oids or OID_O in oids or OID_OU in oids:
                # Name: 直接在该 SEQUENCE 内搜 OID+字符串
                name = {
                    'CN': _find_oid_string(val, OID_CN),
                    'O': _find_oid_string(val, OID_O),
                    'OU': _find_oid_string(val, OID_OU),
                }
                # 归属 issuer 还是 subject (按出现顺序, issuer 在 validity 前)
                if info['issuer'] == {} and info['algorithm'] is None and info['serial'] is not None:
                    info['issuer'] = name
                elif not info['subject']:
                    info['subject'] = name
            elif any(o in (OID_RSA, OID_EC, OID_SM2) for o in oids):
                # SubjectPublicKeyInfo
                info['algorithm'] = next(o for o in oids if o in (OID_RSA, OID_EC, OID_SM2))
                # 下一元素应为 BIT STRING 公钥
                for c2 in sub:
                    if c2[0] == 0x03:
                        info['key_bits'] = c2[1]
    return info


def _find_oid_string(blob, oid_str):
    """在 DER 块中定位 OID 及其后的字符串值。"""
    oid_bytes = _encode_oid(oid_str)
    idx = blob.find(oid_bytes)
    if idx < 0:
        return None
    off = idx + len(oid_bytes)
    while off < len(blob):
        tag, val, _, end = _der_tlv(blob, off)
        if tag in (0x13, 0x0c, 0x16):  # PrintableString/UTF8String/IA5String
            try:
                return val.decode('utf-8')
            except UnicodeDecodeError:
                return val.hex()
        off = end
    return None


def _encode_oid(oid_str):
    parts = [int(x) for x in oid_str.split('.')]
    out = bytes([parts[0] * 40 + parts[1]])
    for n in parts[2:]:
        enc = []
        while True:
            enc.insert(0, n & 0x7f)
            n >>= 7
            if n == 0:
                break
        for i, e in enumerate(enc):
            if i < len(enc) - 1:
                e |= 0x80
            out += bytes([e])
    return out


def extract_pubkey(info):
    """从解析结果提取公钥。RSA → (n, e); EC/SM2 → (x, y)。"""
    key = info.get('key_bits')
    if not key:
        return None
    bits = key[1:]  # 去掉 unused-bits 字节
    if info['algorithm'] == OID_RSA:
        _, spki, _, _ = _der_tlv(bits, 0)
        ints = _der_children(spki)
        n = _der_int(ints[0][1])
        e = _der_int(ints[1][1])
        return ('RSA', n, e)
    if info['algorithm'] in (OID_EC, OID_SM2):
        if bits[0] == 4:  # 非压缩 04||X||Y
            x = int.from_bytes(bits[1:33], 'big')
            y = int.from_bytes(bits[33:65], 'big')
            name = 'SM2' if info['algorithm'] == OID_SM2 else 'EC'
            return (name, x, y)
    return None


def load_cert(path):
    data = open(path, 'rb').read()
    if b'-----BEGIN' in data:  # PEM
        b64 = b''.join(l for l in data.split(b'\n') if not l.startswith(b'-----'))
        data = base64.b64decode(b64)
    return data


# ================= ISO 8583 =================
# 字段规格: 类型 (N固定数字/AN定长/LLVAR/LLLVAR/B二进制), 长度
FIELDS = {
    1: ('B', 8, '次级位图'), 2: ('LLVAR', 19, '主账号 PAN'),
    3: ('N', 6, '处理码'), 4: ('N', 12, '交易金额'),
    7: ('N', 10, '传输日期时间'), 11: ('N', 6, '流水号 STAN'),
    12: ('N', 6, '本地时间'), 13: ('N', 4, '本地日期'),
    14: ('N', 4, '有效期'), 22: ('N', 3, 'POS输入方式'),
    24: ('N', 3, '功能码'), 25: ('N', 2, 'POS条件'),
    32: ('LLVAR', 11, '收单机构'), 35: ('LLVAR', 37, '二磁道'),
    37: ('AN', 12, '检索参考号'), 39: ('AN', 2, '响应码'),
    41: ('AN', 8, '终端号'), 42: ('AN', 15, '商户号'),
    48: ('LLLVAR', 999, '附加数据'), 49: ('N', 3, '币种'),
    52: ('B', 8, 'PIN数据'), 60: ('LLLVAR', 999, '自定义'),
    61: ('LLLVAR', 999, '自定义'), 62: ('LLLVAR', 999, '自定义'),
    63: ('LLLVAR', 999, '自定义'), 64: ('B', 8, 'MAC'),
    70: ('N', 3, '网络管理码'), 90: ('N', 42, '原始数据元素'),
    95: ('LLVAR', 99, '替代金额'),
}
SECONDARY_BITMAP_BIT = 1


def parse_8583(hexmsg):
    """
    解析 ISO 8583 报文 (hex)。格式: MTI(2字节) + 主位图(8字节) [+次级位图(8字节)] + 域数据。
    数值域为 ASCII; 二进制域 (52/64) 为原始字节。
    """
    raw = bytes.fromhex(hexmsg)
    mti = raw[0:2].hex()
    bitmap = int.from_bytes(raw[2:10], 'big')
    has_secondary = (bitmap >> 63) & 1
    nbits = 128 if has_secondary else 64
    pos = 10
    if has_secondary:
        sec = int.from_bytes(raw[10:18], 'big')
        bitmap = (bitmap << 64) | sec
        pos = 18
    fields = {}
    for bit in range(2, nbits + 1):
        if not (bitmap >> (nbits - bit)) & 1:
            continue
        spec = FIELDS.get(bit)
        if not spec:
            fields[bit] = ('<未定义>', b'')
            continue
        ftype, flen, desc = spec
        if ftype == 'LLVAR':
            ln = int(raw[pos:pos + 2])
            val = raw[pos + 2:pos + 2 + ln]
            pos += 2 + ln
        elif ftype == 'LLLVAR':
            ln = int(raw[pos:pos + 3])
            val = raw[pos + 3:pos + 3 + ln]
            pos += 3 + ln
        else:  # N/AN 定长 或 B 二进制
            val = raw[pos:pos + flen]
            pos += flen
        fields[bit] = (desc, val)
    return {'mti': mti, 'fields': fields}


def build_8583(mti, fields):
    """组包。fields = {int位: 值字符串}; 输出 hex (MTI 2字节 + 位图 + 域)。"""
    bits = sorted(k for k in fields if k != 1)
    has_secondary = max(bits) > 64
    nbits = 128 if has_secondary else 64
    bitmap_bits = set(bits)
    if has_secondary:
        bitmap_bits.add(1)
    bitmap = 0
    for b in bitmap_bits:
        bitmap |= 1 << (nbits - b)
    raw = bytes.fromhex(mti)                       # MTI → 2 字节
    raw += bitmap.to_bytes(nbits // 8, 'big')      # 位图
    for k in bits:
        v = fields[k]
        spec = FIELDS.get(k)
        if not spec:
            continue
        ftype, flen, desc = spec
        vb = v.encode('ascii', 'replace')
        if ftype == 'LLVAR':
            raw += f'{len(vb):02d}'.encode() + vb
        elif ftype == 'LLLVAR':
            raw += f'{len(vb):03d}'.encode() + vb
        else:
            raw += vb
    return raw.hex()


# ================= 自检 =================
def selftest():
    ok = True
    # 8583 组包→解析 往返
    msg = build_8583('0200', {3: '123456', 4: '000000010000', 11: '000001',
                              41: 'TERM0001', 49: '156'})
    parsed = parse_8583(msg)
    ok = ok and parsed['mti'] == '0200'
    ok = ok and parsed['fields'].get(3, ('', ''))[1] == b'123456'
    ok = ok and parsed['fields'].get(4, ('', ''))[1] == b'000000010000'
    ok = ok and parsed['fields'].get(49, ('', ''))[1] == b'156'
    print(f"  [{'OK' if ok else 'FAIL'}] 8583 组包→解析往返 MTI={parsed['mti']}")
    print(f"    {msg[:60]}...")

    # 证书解析: 用 cryptography 生成测试证书 (可用则验证)
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives.asymmetric import rsa, ec
        from cryptography.hazmat.primitives import hashes, serialization
        from datetime import datetime, timedelta
        import datetime as dt

        key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'test.bank.com')])
        cert = (x509.CertificateBuilder()
                .subject_name(subj).issuer_name(subj)
                .public_key(key.public_key())
                .serial_number(1).not_valid_before(dt.datetime.now(dt.timezone.utc) - timedelta(days=1))
                .not_valid_after(dt.datetime.now(dt.timezone.utc) + timedelta(days=30))
                .sign(key, hashes.SHA256()))
        der = cert.public_bytes(serialization.Encoding.DER)
        info = parse_cert(der)
        pub = extract_pubkey(info)
        rsa_pub = key.public_key().public_numbers()
        cert_ok = pub and pub[0] == 'RSA' and pub[1] == rsa_pub.n and pub[2] == rsa_pub.e
        ok = ok and cert_ok
        print(f"  [{'OK' if cert_ok else 'FAIL'}] 证书解析: {pub[0]} n/e 匹配")
        print(f"    subject CN = {info['subject'].get('CN')}")
    except ImportError:
        print("  [i] cryptography 未安装, 跳过证书自检")
    print(f"\n[{'全部通过' if ok else '存在失败'}] 证书/8583 自检")
    sys.exit(0 if ok else 1)


def main():
    ap = argparse.ArgumentParser(description='X.509 证书解析 + ISO 8583 报文')
    ap.add_argument('--selftest', action='store_true')
    ap.add_argument('--cert', help='证书文件 (DER/PEM)')
    ap.add_argument('--extract-pubkey', action='store_true', help='输出公钥参数')
    ap.add_argument('--8583-parse', help='解析 ISO 8583 报文 (hex)')
    ap.add_argument('--8583-build', action='store_true', help='组包 ISO 8583')
    ap.add_argument('--mti', default='0200', help='组包 MTI')
    ap.add_argument('--fields', action='append', help='组包字段, 格式 位:值 (可多次)')
    args = ap.parse_args()

    if args.selftest:
        selftest(); return

    if args.cert:
        try:
            der = load_cert(args.cert)
            info = parse_cert(der)
        except Exception as e:
            sys.exit(f"[-] 证书解析失败: {e}")
        print(f"[*] 证书信息:")
        print(f"    序列号 : {info.get('serial')}")
        print(f"    主体   : {info.get('subject')}")
        print(f"    签发者 : {info.get('issuer')}")
        print(f"    算法   : {info.get('algorithm')}")
        if args.extract_pubkey:
            pub = extract_pubkey(info)
            if pub is None:
                sys.exit("[-] 未提取到公钥")
            if pub[0] == 'RSA':
                print(f"\n[+] 公钥 (RSA):")
                print(f"    n = {pub[1]:x}")
                print(f"    e = {pub[2]}")
            else:
                print(f"\n[+] 公钥 ({pub[0]}):")
                print(f"    x = {pub[1]:064x}")
                print(f"    y = {pub[2]:064x}")
        return

    if args.__dict__.get('8583_parse'):
        parsed = parse_8583(args.__dict__['8583_parse'])
        print(f"[*] MTI = {parsed['mti']}")
        for bit in sorted(parsed['fields']):
            desc, val = parsed['fields'][bit]
            try:
                vs = val.decode('ascii')
            except Exception:
                vs = val.hex()
            print(f"    域 {bit:>3} {desc:<14} = {vs}")

    if args.__dict__.get('8583_build'):
        if not args.fields:
            sys.exit("[-] 组包需要 --fields 位:值")
        fields = {}
        for f in args.fields:
            k, v = f.split(':', 1)
            fields[int(k)] = v
        msg = build_8583(args.mti, fields)
        print(f"[*] 8583 报文 (hex): {msg}")


if __name__ == '__main__':
    main()
