# 信息收集速查（recon）

> 来源：jiejieskill SKILL.md 拆分（2026-08-11）。由 SKILL.md 相应章节按需加载。

## 四、Phase 2：信息收集 (Intelligence Gathering)

### 4.1 被动信息收集 (OSINT — 不直接接触目标)

#### DNS 枚举
```bash
# 域名信息
whois target.com
dig target.com ANY
dig axfr @ns1.target.com target.com          # 域传送漏洞

# 子域名发现
amass enum -d target.com -o subdomains.txt
subfinder -d target.com -o subdomains.txt
assetfinder --subs-only target.com
findomain -t target.com

# 证书透明度
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sort -u
```

#### 搜索引擎与公开情报
```bash
# Google Hacking / Dorking
site:target.com filetype:pdf
site:target.com inurl:admin
site:target.com intitle:"index of"
site:target.com ext:sql | ext:bak | ext:log
site:target.com intext:"password"

# Shodan / Censys / FOFA
# shodan search: org:"Target Org" port:3389
# FOFA: domain="target.com"

# GitHub 凭据泄露
gitleaks detect --source . --report-format json
truffleHog filesystem .
```

#### 邮箱与人员信息
```bash
theHarvester -d target.com -b google,linkedin,crtsh,hunter
# LinkedIn 员工名录 → 技术栈推断
# 招聘网站 → 技术栈（如 "熟悉 Spring Boot"）
```

#### 历史数据
```bash
# Wayback Machine
waybackurls target.com | sort -u > wayback_urls.txt
# 查看历史页面、已删除端点、旧API
```

### 4.2 主动信息收集 (直接交互)

#### Nmap 端口扫描
```bash
# 快速全端口扫描
sudo nmap -sS -p- -T4 --min-rate=10000 <target_ip> -oN nmap-tcp-full.txt

# 服务版本检测 + 默认脚本
sudo nmap -sS -sV -sC -p <open_ports> -T4 <target_ip> -oN nmap-svc.txt

# UDP Top 100
sudo nmap -sU --top-ports 100 -T4 <target_ip> -oN nmap-udp.txt

# NSE 漏洞扫描
sudo nmap --script vuln -p <open_ports> <target_ip> -oN nmap-vuln.txt
sudo nmap --script "smb-*,ftp-*,http-*" -p <ports> <target_ip>
```

#### Web 目录/文件枚举
```bash
# Gobuster
gobuster dir -u http://target.com -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt,js,asp,aspx -t 50 -o gobuster.txt

# ffuf (更快的替代)
ffuf -u http://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt -e .php,.html,.txt -t 100

# 递归扫描
ffuf -u http://target.com/FUZZ -w wordlist.txt -recursion -recursion-depth 2

# VHOST 发现
gobuster vhost -u http://target.com -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt --append-domain

# API 端点发现
ffuf -u http://api.target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api/objects.txt -H "Content-Type: application/json"
```

#### Web 指纹识别
```bash
whatweb http://target.com
wafw00f http://target.com                        # WAF 检测
nikto -h http://target.com -o nikto.txt           # Web 漏洞快速扫描
```

#### SMB / NetBIOS 枚举
```bash
# SMB 共享列出
smbclient -L //<target_ip> -N
smbmap -H <target_ip> -u guest
enum4linux-ng -A <target_ip>

# 若获得凭据
smbmap -H <target_ip> -u <user> -p <pass>
crackmapexec smb <target_ip> -u <user> -p <pass> --shares
```

#### SNMP 枚举
```bash
snmpwalk -v1 -c public <target_ip>
snmpwalk -v2c -c public <target_ip> 1.3.6.1.2.1.25    # 系统进程
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp-onesixtyone.txt <target_ip>
```

#### 其他服务枚举
```bash
# FTP
ftp <target_ip>   # 尝试 anonymous/anonymous

# SMTP
smtp-user-enum -M VRFY -U users.txt -t <target_ip>

# Oracle / MySQL / MSSQL / PostgreSQL
nmap --script "mysql-*,ms-sql-*,oracle-*" -p 3306,1433,1521 <target_ip>
```

### 4.3 信息收集输出物
- [ ] 子域名清单（含解析IP）
- [ ] 开放端口及服务版本矩阵
- [ ] Web 技术栈指纹
- [ ] 发现目录/文件/API端点
- [ ] 邮箱列表与组织架构
- [ ] WHOIS / DNS 记录
- [ ] 可能的凭据泄露
- [ ] 资产测绘结果（FOFA/Quake，旁站、关联域名）
- [ ] **CDN 判断与真实 IP**（如目标套 CDN，务必先找源站）
- [ ] 小程序资产（wxapkg 包 + 反编译 JS，如有小程序）
- [ ] App 资产处置（有 App → 转 `app-pentest` 技能单独测）
- [ ] JS 端点/密钥提取结果（详见 JS 源代码审查章节）
- [ ] **版本指纹 → CVE 探测结果**（nuclei / searchsploit 验证，详见 4.5 节）

### 4.4 国内资产测绘与 CDN / 真实 IP 发现

> 国内目标几乎都套 CDN/WAF。**先判断是否在 CDN 后，再找真实 IP**，否则扫到的全是 CDN 节点，毫无意义。

#### 空间测绘（找全资产、旁站、真实 IP）
```bash
# FOFA（https://fofa.info）常用语法
domain="target.com"                  # 主域全部子域资产
host="target.com"                    # 精准搜索主机
cert="target.com"                    # 证书搜索（常命中源站IP）
icon_hash="-247388890"               # favicon 图标哈希反查同源资产
body="target.com" && title="登录"     # 内容/标题特征组合

# Quake（https://quake.360.net）
service:http AND domain:target.com   # / cert:"target.com"

# Hunter（https://hunter.qianxin.com）
domain="target.com"                  # / component="Shiro" / web.title="后台"

# Shodan（国外资产）
hostname:target.com                  # / ssl.cert.subject.cn:target.com

# favicon hash（mmh3）→ 反查同 logo 的旁站/真实IP
python3 -c 'import mmh3,codecs;d=open("favicon.ico","rb").read();print(mmh3.hash(codecs.encode(d,"base64")))'
```

#### 备案 / 工商反查（国内资产扩展）
```bash
# ICP 备案查询（beian.miit.gov.cn）→ 备案主体 → 该主体名下其他域名
# 爱企查/天眼查：公司名 → 关联公司/子公司 → 新域名
# 站长之家 icp.chinaz.com：备案号反查全部域名
# 域名注册人反查：whois 邮箱 → 同注册人其他域名（whois反查站）
```

#### CDN 检测
```bash
# 多地 ping（chinaz ping 检测）：同一域名全球/全国解析是否不同
# 本地：nslookup target.com 看是否多条 A 记录或 CNAME 指向 CDN 厂商
dig +short target.com
# CNAME 命中以下特征 → 在 CDN 后：
#   akamai / cloudfront / alicdn / taobao / qcloud / edgekey
#   TencentCloud / BaiduYunjiasu / wangsu / chinanetcenter / 360wzws ...
```

#### 真实 IP 发现（CDN 绕过，逐条尝试）
```bash
# 1. 子域名：CDN 常只覆盖主域，子域裸奔
subfinder -d target.com -silent | httpx -silent | while read u; do
  ip=$(dig +short "${u#*://}" | tail -1); echo "$u -> $ip"; done

# 2. DNS 历史解析（高危未上 CDN 前的源站IP）
# 微步在线 x.threatbook.com / securitytrails.com / viewdns.info

# 3. SSL 证书反查：crt.sh 扩展字段常含源站 IP / 内网域名
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sort -u

# 4. 邮件头：给目标域邮箱发信，看 Received 头源 IP（发件服务器常直连源站）
dig mx target.com                     # 先找邮件服务器

# 5. 前端 JS / 接口内嵌源站 IP / 内网地址
grep -rhoE "[0-9]{1,3}(\.[0-9]{1,3}){3}|192\.168\.|10\." js_dir/ | sort -u

# 6. GitHub 代码泄露：gitleaks / truffleHog 搜源码仓库内的 IP/内网域名
# 7. 移动端 App：反编译抓接口，部分 App 直连源站 IP（绕过 CDN）
# 8. 未套 CDN 的边缘服务：FTP/邮件/Telnet/老子域 直连源站
```

### 4.5 版本指纹 → CVE 探测（版本泄露自动匹配漏洞）

> 信息收集阶段拿到**指纹 + 版本**后，立即用 CVE 模板探测是否命中已知漏洞——这是从「收集」跨入「漏洞分析」的最短路径，命中率远高于盲扫。

#### 1. 版本信息收集（从哪些地方泄露）
```bash
# 响应头（最常见）
curl -sI $URL
#   Server: nginx/1.18.0 | Apache/2.4.49 | Microsoft-IIS/10.0 | Tengine（阿里）
#   X-Powered-By: PHP/5.6.38 | ASP.NET | Express
#   X-AspNet-Version / X-Generator / X-Drupal-Cache 等

# 页面与静态资源
#   页脚版权/年份、报错页（debug 模式泄露框架+版本）、HTML 注释
#   JS/静态资源版本：jQuery / Bootstrap / 前端框架
#   可读的依赖清单：/package.json、/composer.json、/requirements.txt
#   登录页、README、CHANGELOG、/docs

# CMS / 框架指纹
#   WordPress: /wp-json、/wp-content 版本；dedecms、phpcms、帝国CMS、禅道 各指纹

# 指纹工具一键收集
httpx -l targets.txt -tech-detect -json -o tech.json     # 技术栈+版本 JSON
whatweb $URL
nuclei -u $URL -tags tech -silent | grep -iE 'tech|detect'
# ehole（红队指纹）/ wappalyzer（浏览器）/ fscan（内网批量）
```

#### 2. 版本 → CVE 检索与自动探测
```bash
# 本地漏洞库
searchsploit <product> <version>

# nuclei 自动 CVE 扫描（内置 4w+ 模板，最高效）
nuclei -u $URL -t cves/ -severity critical,high
# 定向：按产品 tag 只扫对应 CVE，减少误报
nuclei -u $URL -tags tomcat,apache,nginx,spring -t cves/
# 按指纹自动匹配模板（httpx -tech-detect 结果直接喂）
nuclei -l targets.txt -as                        # -as 自动选模板
# 更新模板：nuclei -ut

# 在线检索
#   NVD: nvd.nist.gov / cve.org
#   国内：CNVD(cnvd.org.cn)、漏洞盒子、补天、先知社区、微步情报 x.threatbook.com
#   FOFA/Quake：直接搜带 CVE 标记的同版本资产（参考利用方式）
```

#### 3. 常见产品版本 → CVE 速查表（版本命中直接验证）

| 产品 | 版本条件 | CVE | 危害 |
|------|---------|-----|------|
| Apache | 2.4.49 / 2.4.50 | CVE-2021-41773 / 42013 | 目录穿越 RCE |
| Nginx | 旧版 + alias 配置错误 | CVE-2021-23017 | 目录穿越 |
| Tomcat | 6.x-9.x | CVE-2020-1938 | AJP 文件读/RCE |
| Tomcat | 8.5.0-8.5.13 | CVE-2017-12615 | PUT 上传 |
| WebLogic | 10.3.6 / 12.1.x | CVE-2019-2725 / 2020-14882 | 反序列化 RCE |
| Fastjson | 1.2.24 / ≤1.2.47 / ≤1.2.68 | CVE-2017-18349 / autotype | 反序列化 RCE |
| Log4j2 | 2.x ≤2.14.1 | CVE-2021-44228 | JNDI RCE |
| Shiro | 1.x 默认 AES key | 反序列化 | RCE |
| Spring Cloud Gateway | ≤3.1.0 | CVE-2022-22947 | SpEL RCE |
| Struts2 | 2.x | S2-045/057/062/066 | RCE |
| ThinkPHP | 5.0.x / 5.1.x | RCE | 命令执行 |
| phpMyAdmin | 4.x/5.x | CVE 系列 | SQLi / RCE |
| WordPress | 核心/插件旧版 | 多 CVE | 多变 |

#### 4. 一键探测流程（信息收集 → CVE 结果）
```bash
# 全自动：指纹 → CVE 模板 → 结果
httpx -l targets.txt -tech-detect -json -o tech.json
nuclei -l targets.txt -t cves/ -severity critical,high -o cve-results.txt
# 按指纹定向（降低误报）
jq -r '.[].tech' tech.json | sort -u | while read t; do
  nuclei -u <target> -tags "$t" -t cves/; done
# 结果人工复核三要素：
#   1. 版本范围是否真的命中（版本伪装/误报排除）
#   2. 是否为可验证的漏洞（vs 只影响特定配置）
#   3. 用 dnslog / 响应差异做非破坏性确认，确认授权内再利用
```

> 🔗 **CVE 扫描深度方法论（L1-L5 分层/指纹驱动/平台专项/误报验证/性能适配）→ `cve-scanning.md`**；具体中间件/框架利用细节 → `middleware-unath.md` 6.10 中间件；CVE 深挖 → secknowledge `references/web-deployment-security.md`。

---

