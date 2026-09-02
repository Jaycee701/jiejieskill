---
name: jiejieskill
description: 全流程渗透测试一站式技能：资产探测(Web+小程序)→PTES 7阶段→报告。覆盖 SQL/XSS/越权/认证全流程/短信验证码爆破(测试号<测试手机号>)/JS审查/加解密国密(自带SM2/SM3/SM4工具)/WAF/中间件/新兴攻击面(AI-LLM/GraphQL)。App 转 app-pentest，小程序引 wxmini，payload 库引 secknowledge。命令速查拆于 references/ 按需加载。
metadata:
  type: user
  tags: [pentest, web-security, mobile, miniprogram, bank, crypto, gmssl, sm2, sm4, red-team, methodology]
---

# 全流程渗透测试技能 (JieJie Full Penetration Testing Workflow)

基于 PTES (Penetration Testing Execution Standard) 标准、OWASP WSTG / Top10 测试指南、MITRE ATT&CK 框架整合的**一站式全流程渗透测试方法论**。

**适用目标**：Web 网站 / 小程序 / 内网与域环境 / 云环境 / 金融与银行业务系统。**App（Android/iOS）单独使用 `app-pentest` 技能测试**；小程序深度自动化审计引用 `wxmini-security-audit` 技能；深层 payload 库引用 `secknowledge` 技能。

**本 skill 自带工具**：`scripts/` 目录（25 个零依赖 Python 工具，国密 SM2/SM3/SM4 + 通用加密攻击 + HTTP 表单爆破），一键入口见 `crypto_cli.py`（详见「加解密与国密测试」章节）。

---

## 一、整体流程概览 (7 阶段)

> ⚠️ **入口**：先做「资产探测」（见第二节），明确目标资产类型（Web/小程序/App/金融），再进入下列 7 阶段。

### ⚠️ 流程纪律（强制，禁止跳过）

> **每个目标必须执行以下 5 步，否则视为流程违规：**

1. **先加载 `references/checklist.md`**，把清单项转化为本次会话的任务清单（TaskCreate），逐项跟踪；
2. **逐项打勾**：测一项勾一项，禁止凭直觉跳项、禁止"觉得不重要就不测"；
3. **每阶段结束对照清单核对**：已测 / 未测 / 受限项（反爬/WAF/授权边界）分别标注；
4. **报告必须附「清单完成度」表**：未测项和受限项**必须显式列出原因**，禁止静默跳过、禁止以"时间不够"一笔带过；
5. **测试完成后自查复盘（出报告前必做，禁止测完直接交付）**：
   - **全清单逐类逐项检查，每一类都必须过一遍，无例外**（不是只看重点项）：
     对照 `references/checklist.md` 从头到尾，每个类别每项逐一核对「测了吗？结论是什么？证据在不在？」，包括但不限于：
     SQL 注入、XSS、越权/IDOR、**认证全流程**、业务逻辑、文件上传、SSRF、WAF、中间件/反序列化/未授权、加解密/国密、OAuth/WebSocket/API、资产探测、目录枚举、CVE 探测、JS 提取；
   - 任何一类**没测 → 要么补测，要么显式列明原因**，禁止当不存在；
   - 逐个漏洞自我质询：注入点真确认了吗（版本/列数/回显/绕过了哪层防护）？结论复核过吗（如版本差异致误判）？
   - 被反爬/WAF 中断的项，是否列明原因并给出浏览器手工复核步骤？
   - 自查发现遗漏 → **立即补测或显式标注，禁止直接出报告**。

> 特别提醒：**认证全流程（登录/注册/枚举/爆破/改密找回）、越权、业务逻辑、上传** 是最常被遗漏的四类，命中目标类型即优先测。

```
Asset Discovery → Pre-engagement → Intelligence Gathering → Threat Modeling
→ Vulnerability Analysis → Exploitation → Post-Exploitation → Reporting
```

| 阶段 | 核心目标 | 时间占比 |
|------|---------|---------|
| 1. 前期交互 | 范围界定、授权、ROE | 10-15% |
| 2. 信息收集 | OSINT + 主动侦察 | 15-20% |
| 3. 威胁建模 | 攻击路径映射、风险评估 | 5-10% |
| 4. 漏洞分析 | 自动扫描 + 人工验证 | 15-20% |
| 5. 漏洞利用 | 获取初始访问权限 | 20-30% |
| 6. 后渗透 | 提权、横向移动、持久化 | 15-20% |
| 7. 报告输出 | 执行摘要 + 技术报告 | 10-15% |

> 📋 **实战执行清单 → `references/checklist.md`**（按阶段逐项打勾，避免遗漏）

---

## 二、资产探测流程（Web + 小程序）

> **一切渗透从资产探测开始**。先搞清「目标有哪些资产、各是什么类型」，再决定走哪条测试线。探测结果决定后续流程：**Web** 走本 skill 全流程；**小程序**走本 skill + 引用 wxmini 深度审计；**App** 转 `app-pentest` 单独测；**金融业务**走认证+业务逻辑+加解密国密章节。

### 2.1 资产范围确定
- 已知范围：域名 / IP 段 / 备案号 / 公司名
- 扩展（国内）：ICP 备案反查 → 关联域名；工商信息（天眼查/爱企查）→ 关联公司 → 新域名；whois 邮箱反查
- 输出：**目标资产清单**（域名 → IP → 归属）

### 2.2 Web 资产探测
```bash
# 1. 子域名 + 空间测绘（详见 `recon.md` 4.4）
subfinder -d target.com -silent | httpx -silent -status-code -title
# FOFA/Quake/Hunter：domain="target.com" 拿全资产、旁站、真实IP

# 2. CDN / 真实 IP 判断（详见 `recon.md` 4.4）
dig +short target.com

# 3. 端口扫描 → Web 服务识别
nmap -sS -p- -T4 --min-rate=5000 target.com -oN ports.txt
httpx -l live.txt -ports 80,443,8080,8443,8888,9000 -title -tech-detect -status-code

# 4. 目录 / 文件 / API 枚举
ffuf -u https://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt -t 100
# 指纹：whatweb $URL / wappalyzer
```

### 2.3 小程序资产获取与反编译
```bash
# 获取 wxapkg 包
# 微信 v4：C:\Users\<用户>\AppData\Roaming\Tencent\xwechat\radium\Applet\packages
# 微信老版本：...\WeChat Files\Applet
# Android 模拟器(root)：/data/data/com.tencent.mm/MicroMsg/{32位MD5}/appbrand/pkg/
# macOS：~/Library/Containers/com.tencent.xinWeChat/.../Applet/...

# 清场法：先清空 pkg 目录 → 打开目标小程序 → 最新出现的 .wxapkg 即目标
# 主包 __APP__.wxapkg + 全部分包都要获取

# 反编译
npm i wedecode -g && wedecode ui               # 全自动跨平台 GUI
node wuWxapkg.js __APP__.wxapkg                 # wxappUnpacker；分包加 -s
wxapkg.exe scan                                 # wux1an/wxapkg（Windows 二进制）

# 静态分析要点（详见 JS 源码审查章节）
#   js/json 搜 password|secret|key|token|appid|appsecret
#   app.json 路由 + wx.request 调用 → 未暴露 API
#   sign 签名算法逆向（参数排序+拼接+MD5/自定义哈希）→ 重放/伪造
#   硬编码 AES/DES 密钥 → 解密全部流量
#   前端验证绕过：金额 / 优惠券 / role=admin
```

### 2.4 资产分类处置（决定测试路线）

| 资产类型 | 测试路线 |
|---------|---------|
| Web 网站 / 后台 / API | 本 skill 全流程（Phase 1-7 + Top10 + 认证全流程） |
| 微信小程序 | 本 skill 小程序静态分析 + **引用 wxmini-security-audit 深度审计** |
| Android / iOS App | **转用 app-pentest 技能单独测试** |
| App 后端 API | 本 skill API / 越权 / 认证 / JS 审查章节 |
| 银行 / 金融 / 支付系统 | 本 skill 认证全流程 + 业务逻辑 + 加解密国密章节 |
| 内网 / 域 / 云 | 本 skill 后渗透 / 域渗透 / 云深化章节 |

---

## 三、Phase 1：前期交互 (Pre-engagement)

### 3.1 法律与合规
- 签署 NDA（保密协议）
- 获取**书面授权书**（正式签字）
- 确认符合相关法规（GDPR、HIPAA、PCI DSS、等保2.0）
- 购买专业责任保险

### 3.2 范围定义
- 明确目标系统：IP 范围、域名、应用 URL
- 明确**范围内/范围外**系统清单
- 确定测试类型：黑盒/灰盒/白盒
- 设定测试时间窗口与限制行为（禁止 DoS、禁止社交工程等）

### 3.3 沟通计划
- 建立紧急联系人清单
- 定义数据处理、存储、销毁流程
- 约定沟通渠道与状态更新频率
- 灰盒/白盒测试提前收集凭据

### 3.4 工具准备
```
核心工具集：Kali Linux / Parrot OS
漏洞扫描：Nessus / OpenVAS / Nuclei
Web测试：Burp Suite Pro / OWASP ZAP
利用框架：Metasploit Framework
密码破解：hashcat / John the Ripper
代理工具：proxychains / Clash
C2框架：Cobalt Strike / Sliver / Havoc C2
```

---

## 四、Phase 2：信息收集 (Intelligence Gathering)

> 📄 **命令速查 → `references/recon.md`**（OSINT、主动侦察、资产测绘/CDN真实IP、版本指纹→CVE 探测）+ **`references/cve-scanning.md`**（**加强版 CVE 扫描策略**：五层框架 L1-L5 / 指纹驱动定向 / 平台专项检索 / 误报验证三步 / 性能适配）

核心产出（详见 references/recon.md + cve-scanning.md）：子域名/资产测绘、CDN 判断与真实 IP、端口与服务矩阵、**版本指纹→CVE 探测结果**、小程序资产、JS 端点/密钥提取。

---

## 五、Phase 3：威胁建模 (Threat Modeling)

### 5.1 资产识别
- 关键业务系统与数据
- 外部暴露面（互联网资产）
- 第三方依赖与供应链

### 5.2 攻击路径映射 (MITRE ATT&CK)
将后续所有操作映射到 ATT&CK 战术：

```
Reconnaissance → Resource Development → Initial Access → Execution →
Persistence → Privilege Escalation → Defense Evasion → Credential Access →
Discovery → Lateral Movement → Collection → Exfiltration → Impact
```

### 5.3 威胁场景构建
- 外部攻击者 → Web漏洞 → 初始立足点 → 提权 → 域控
- 钓鱼攻击 → 凭据窃取 → VPN接入 → 内网漫游
- 供应链攻击 → CI/CD管道 → 代码仓库 → 生产环境

---

## 六、Phase 4：漏洞分析 (Vulnerability Analysis)

> ⚠️ **实战前必读 `references/emerging-reflexion.md`**（搜索框回显/XSS、OR 型盲注、sqlmap 克制使用、**MySQL 8 移除 EXTRACTVALUE 错误注入失效→版本先行**、**内容级布尔差分验证链**、**LiteSpeed 反爬 JS 挑战**、**小白可操作复现手册**等踩坑教训）。

> ⚠️ **使用原则（重要）：本表及所有 references 是测试方向的「下限清单」，不是「上限」。**
> - **新增方向（SSTI/命令注入/XXE/CORS/子域接管/Host Header/缓存投毒/Mass Assignment/JWT/请求走私/NoSQL 等）必须实际使用**，禁止"加了不用"；
> - 但测试**不限于此清单**：先穷尽清单内全部方向，再按目标技术栈/业务/攻击面**动态扩展**——清单外遇到的新攻击面同样要测，并沉淀回技能；
> - 判定标准：**以「目标实际攻击面」为准，不以「清单有没有」为准**；技术栈命中（如 Node/Spring/云/小程序/LLM）即优先测对应专属方向。

漏洞分析拆分为 6 个方向速查文件，按目标类型选择加载：

| 测试环节 | 原小节 | 参考文件 |
|---------|--------|---------|
| **漏洞覆盖总目录（7 大类 66 项，逐项必测）** | 总纲 | `references/vuln-catalog.md` |
| OWASP Top10、Web 漏洞(WSTG)、WAF 绕过、**API Top10** | 6.1/6.2/6.9 | `references/web-vulns.md` |
| 认证全流程(注册/枚举/爆破/改密/**短信验证码爆破(测试号<测试手机号>)**)、OAuth、WebSocket、图形验证码 | 6.3 | `references/auth-testing.md` |
| **密码爆破专项**(在线服务/离线哈希/字典定制/绕过对抗) | 6.3 补充 | `references/password-cracking.md` |
| **全入口弱口令检测**(Web全入口/服务/中间件/后台默认口令) | 6.3 补充 | `references/weakpass-check.md` |
| 输入框/登录框/文件上传下载、JS 源码审查 | 6.4/6.5 | `references/input-upload-js.md` |
| 基础设施/网络、AD 侦察、云侦察、中间件/反序列化、未授权访问(数据库暴露) | 6.6-6.8/6.10/6.11 | `references/middleware-unath.md` |
| 加解密与国密测试（**自带 scripts/ 工具**） | 6.12 | `references/crypto-testing.md` |
| 新兴攻击面(AI/LLM/GraphQL/云原生)、实战复盘 | 6.13/6.14 | `references/emerging-reflexion.md` |
| **高级/补充漏洞方向**：SSTI、命令注入、XXE、CORS、子域接管、Host Header/缓存投毒、开放重定向、Mass Assignment、JWT、请求走私、NoSQL | 补充 | `references/web-advanced-vulns.md` |

---

## 七、Phase 5：漏洞利用 (Exploitation)

> 📄 **命令速查 → `references/exploitation.md`**

Reverse Shell / MSFVenom 载荷 / 监听器 / Web 利用关键场景 / Windows 特定攻击 / AD 攻击链 / **WebShell 管理与免杀**。

---

## 八、Phase 6：后渗透 (Post-Exploitation)

> 📄 **命令速查 → `references/post-exploitation.md`**

Shell 升级 / Linux+Windows 提权 / 凭据收集 / 横向移动 / 持久化 / 内网隧道 / **域渗透深化(委派/ADCS)** / **数据库提权** / **云环境深化**。

---

## 九、Phase 7：报告输出 (Reporting)

> 📄 **报告结构 + 可复制 Markdown 模板 → `references/report-template.md`**

执行摘要 / 技术发现(CVSS+CWE) / 攻击路径叙事 / 修复优先级矩阵 / 附录。

---

## 十、专项场景速查

> 📄 **快速启动命令 → `references/quickstarts.md`**

资产探测 / 版本CVE / 认证爆破 / Web / 内网 / 中间件 / 未授权 快速启动。

---

## 十一、工具速查表

| 类别 | 工具 | 用途 |
|------|------|------|
| 端口扫描 | nmap, masscan, rustscan | TCP/UDP 端口发现 |
| 子域名 | amass, subfinder, assetfinder | 子域名枚举 |
| 资产测绘 | FOFA, Quake, Hunter, Shodan | 空间测绘、真实IP、旁站 |
| Web目录 | gobuster, ffuf, dirsearch | 目录/文件爆破 |
| Web扫描 | Burp Suite, ZAP, Nikto | Web漏洞扫描 |
| 漏洞扫描 | Nuclei, Nessus, OpenVAS | CVE/配置检查 |
| 综合扫描 | fscan, nacs | 内网主机/未授权/常见Nday批量 |
| SQL注入 | sqlmap, Ghauri | 自动化SQLi |
| WAF检测/绕过 | wafw00f, identify-waf, chunked-coding-converter | WAF识别与分块绕过 |
| 反序列化 | ysoserial, JNDIExploit, shiro_attack, weblogicScan | Java 反序列化/框架利用 |
| 中间件指纹 | ehole, httpx -tech-detect, whatweb, wappalyzer, iis_shortname_Scanner | Web 中间件识别与版本探测 |
| Spring 专项 | SpringBootScan, spring4shell-scan, jhat, Eclipse MAT | Actuator 探测、Spring 系列 CVE、heapdump 分析 |
| 数据库测试 | hydra, fscan, sqsh, mssqlclient, mysql-client | 数据库弱口令/未授权/横向 |
| 利用框架 | Metasploit, CME, Impacket | 漏洞利用/横向移动 |
| 密码破解 | hashcat, John, Hydra | 哈希破解/爆破 |
| 凭据提取 | mimikatz, pypykatz, LaZagne | 系统凭据收集 |
| AD枚举 | BloodHound, SharpHound, PowerView | 域环境攻击路径 |
| 域攻击 | certipy, Rubeus, impacket-ntlmrelayx | 委派/票据/ADCS/ACL |
| WebShell | AntSword, Behinder, Godzilla, java-memshell | 木马管理、内存马注入 |
| 提权枚举 | linPEAS, winPEAS, PrivescCheck | 自动化提权检测 |
| 隧道 | Chisel, Ligolo-ng, SSH | 内网穿透 |
| C2 | Sliver, Havoc, Mythic, Metasploit | 命令与控制 |
| 云安全 | pacu, ScoutSuite, AADInternals, cdk | 云/容器提权与枚举 |
| 报告 | Dradis, Ghostwriter, Sysreptor | 渗透测试报告 |
| 在线爆破 | hydra, medusa, ncrack, crowbar, patator, CrackMapExec/NetExec, Burp Intruder, Turbo Intruder, 打码平台, **http_brute.py(自带)** | Web/服务/数据库/AD 弱口令爆破、密码喷射、验证码识别 |
| 离线哈希破解 | hashcat, John the Ripper, hashid, Name-That-Hash, cupp, cewl, crunch, princeprocessor | 哈希破解、规则/掩码、字典定制生成 |
| OAuth/WebSocket | oauth2-misconfig, jwt_tool, ws 客户端, Burp | 第三方登录、实时接口越权/CSWSH |
| JS 分析 | de4js, jsluice, LinkFinder, gau, Arjun, paramspider | JS 反混淆、端点/密钥提取 |
| 加解密/国密 | scripts/ 自带 24 工具, crypto_cli.py | SM2/SM3/SM4/AES/DES/RSA/JWT 加解密攻击 |
| 小程序 | wedecode, wxappUnpacker, wux1an/wxapkg, WechatOpenDevTools | wxapkg 反编译/调试/审计 |

---

## 十二、法律与道德红线

> ⚠️ **重要提醒：此技能仅供授权安全测试使用！**

1. **必须获得书面授权** — 未经授权的渗透测试是违法行为
2. **严格在范围内活动** — 不得超出约定的测试范围
3. **数据保护** — 测试中发现的敏感数据需安全存储，测试结束后销毁
4. **避免业务影响** — 不在生产环境执行高危操作（DoS、数据修改等）
5. **合规要求** — 遵守《网络安全法》《数据安全法》《个人信息保护法》等法律法规
6. **负责任的披露** — 发现0day漏洞优先联系厂商修复

---

## 十三、参考资源

- **PTES**: http://www.pentest-standard.org/
- **OWASP WSTG**: https://owasp.org/www-project-web-security-testing-guide/
- **MITRE ATT&CK**: https://attack.mitre.org/
- **GTFOBins**: https://gtfobins.github.io/
- **LOLBAS**: https://lolbas-project.github.io/
- **HackTricks**: https://book.hacktricks.xyz/
- **PayloadsAllTheThings**: https://github.com/swisskyrepo/PayloadsAllTheThings
- **SecLists**: https://github.com/danielmiessler/SecLists
- **PEASS-ng**: https://github.com/carlospolop/PEASS-ng

**资产测绘 / OSINT**：
- FOFA: https://fofa.info ｜ Quake: https://quake.360.net ｜ Hunter: https://hunter.qianxin.com ｜ Shodan: https://www.shodan.io
- 微步在线(DNS历史/威胁情报): https://x.threatbook.com ｜ SecurityTrails: https://securitytrails.com
- ICP备案查询: https://beian.miit.gov.cn

**中间件 / 反序列化利用**：
- Shiro 利用套件: https://github.com/SummerSec/ShiroAttack2
- JNDIExploit: https://github.com/feihong-cs/JNDIExploit
- ysoserial: https://github.com/frohoff/ysoserial ｜ weblogicScan: https://github.com/rabbitmask/WeblogicScan

**WebShell / 内网 / 云**：
- java-memshell: https://github.com/feihong-cs/memShell
- fscan: https://github.com/shadow1ng/fscan
- Certipy(ADCS): https://github.com/ly4k/Certipy ｜ Rubeus: https://github.com/GhostPack/Rubeus
- impacket: https://github.com/fortra/impacket
- cdk(容器逃逸): https://github.com/cdk-team/CDK

**小程序**：
- wedecode: `npm i wedecode -g`（全自动反编译 GUI）
- wxappUnpacker: https://github.com/gudqs7/wxappUnpacker ｜ wux1an/wxapkg（Windows 二进制）
- jaysenwxapkg（Burp 插件，新版本解包+敏感信息提取）
- WechatOpenDevTools-Python: https://github.com/JaveleyQAQ/WeChatOpenDevTools-Python

**加解密 / 国密（本 skill 自带）**：
- 入口：`python crypto_cli.py --list` / `jiejie_gui.pyw`；全部脚本见 `scripts/README.md`
- 参考：GmSSL（openssl 国密分支）、Python `gmssl` 库、Frida（运行时抓密钥）

---

## 十四、参考文件索引

| 文件 | 内容 |
|------|------|
| `references/vuln-catalog.md` | **漏洞覆盖总目录**：7 大类 66 项（认证授权/命令执行反序列化/业务逻辑/注入/客户端/信息泄漏/其他）+ 补充高级方向，逐项必测下限清单 |
| `references/recon.md` | 信息收集：OSINT、资产测绘/CDN真实IP、版本指纹→CVE |
| `references/cve-scanning.md` | **加强版 CVE 扫描策略**：五层框架(L1指纹→L2版本→L3定向→L4兜底→L5验证)、指纹驱动定向、平台专项检索、误报验证三步、WAF/NetFunnel 性能适配 |
| `references/web-vulns.md` | Top10、Web WSTG 全清单、WAF 绕过、API Top10 |
| `references/auth-testing.md` | 认证全流程、OAuth/OIDC、WebSocket、图形验证码 |
| `references/password-cracking.md` | 密码爆破专项：在线服务/离线哈希破解/字典定制/绕过对抗 |
| `references/weakpass-check.md` | 全入口弱口令检测：Web全入口/服务中间件数据库/后台默认口令 |
| `references/input-upload-js.md` | 输入框/上传下载、JS 源码审查 |
| `references/middleware-unath.md` | 中间件/反序列化/未授权、AD/云侦察 |
| `references/crypto-testing.md` | 加解密国密 + scripts/ 工具调用 |
| `references/emerging-reflexion.md` | 新兴攻击面 + 实战复盘踩坑 |
| `references/exploitation.md` | 漏洞利用、WebShell/免杀 |
| `references/post-exploitation.md` | 后渗透、域/数据库/云深化 |
| `references/report-template.md` | 报告结构 + 内部技术版模板 |
| `references/quickstarts.md` | 专项场景快速启动 |
| `references/checklist.md` | **全流程执行清单**（按阶段打勾，实战必用） |
| `references/web-advanced-vulns.md` | **高级/补充漏洞方向**：SSTI/命令注入/XXE/CORS/子域接管/Host头缓存投毒/开放重定向/MassAssignment/JWT/请求走私/NoSQL |
