# JieJieSkill — 全流程渗透测试一站式技能

> 一个流程、一个完整的 skill：从**资产探测（Web + 小程序）**到**报告输出**，覆盖 PTES 7 阶段，集成 Web / 内网 / AD / 云 / 金融业务逻辑 / 加解密国密 全方向。

## 技能定位

`jiejieskill` 是作者渗透测试的主力技能，把「资产探测 → 信息收集 → 漏洞分析 → 利用 → 后渗透 → 报告」串成一条完整流程，并提供**自带的加解密工具集**（`scripts/`，25 个零依赖 Python 工具）。

### 与其他技能的分工

| 目标 | 使用技能 |
|------|---------|
| Web 网站 / API / 后台 | **jiejieskill（本技能）** |
| 微信小程序 | **jiejieskill**（资产获取 + 静态分析）→ 深度审计引用 `wxmini-security-audit` |
| Android / iOS App | `app-pentest`（单独调用） |
| 银行 / 金融 / 支付 | **jiejieskill**（认证全流程 + 业务逻辑 + 加解密国密章节） |
| 深层 payload / 漏洞原理 | `secknowledge` 知识库 |

## 核心覆盖（SKILL.md 章节索引）

- **资产探测流程**（二）：Web 资产 + 小程序 wxapkg 获取反编译 + 分类处置
- **信息收集**（四）：OSINT / 空间测绘 / CDN 与真实 IP / 端口 / 目录
- **漏洞分析**（六）：
  - 6.1 OWASP Top 10 系统性测试总览
  - 6.2 Web 应用测试清单（SQL / XSS / SSRF / XXE / 越权 / 文件上传…）
  - 6.3 认证全流程（注册 / 枚举 / 密码爆破 / 改密找回 / **短信验证码爆破**）
  - **密码爆破专项**：在线服务爆破 / 离线哈希破解 / 字典定制生成 / 验证码与限流绕过
  - **全入口弱口令检测**：Web 全入口（登录/找回/注册/验证码/API）+ 服务/中间件/数据库 + 后台默认口令
  - 6.4 输入框 / 登录框 / 文件上传下载专项
  - 6.5 JS 源代码审查
  - 6.9 WAF 检测与绕过 ｜ 6.10 中间件/反序列化 ｜ 6.11 未授权访问（数据库暴露）
  - 6.12 **加解密与国密测试**（SM2 / SM3 / SM4 自带脚本）
- **漏洞利用**（七）：Reverse Shell / WebShell 管理与免杀 / AD 攻击链
- **后渗透**（八）：Linux/Windows 提权 / 横向 / 持久化 / 域渗透深化 / 数据库提权 / 云深化
- **专项速查**（十）：资产探测 / 认证爆破 / Web / 内网 / 中间件 / 未授权 快速启动

## 加解密工具集（scripts/）使用

```bash
cd <你的 jiejieskill 目录>
python crypto_cli.py --list                # 列出全部工具
python crypto_cli.py --selftest-all        # 全部自测（exit 0 = 全部可用）
python crypto_cli.py sm4 -m cbc -d --hex -k <key> --iv <iv> <cipher>   # SM4 解密
python scripts/crypto_scan.py /path/jadx_out -r --json                  # 硬编码密钥扫描
python scripts/sm2_k_reuse.py --selftest                                 # SM2 k 复用恢复私钥
python scripts/sm4_padding_oracle.py --selftest                          # SM4 padding oracle
python scripts/sm3_length_ext.py --selftest                              # SM3 长度扩展
python scripts/http_brute.py --selftest                                  # HTTP 表单爆破自检
```

GUI 入口：双击 `jiejie_gui.pyw`（tkinter，零依赖）。

详细工具清单见 `scripts/README.md` 与 SKILL.md「加解密与国密测试」章节。

## 目录结构

```
jiejieskill/
├── SKILL.md                # 流程控制器（约 320 行：流程+决策+索引，命令速查在 references/）
├── README.md               # 本说明
├── crypto_cli.py           # 加解密工具一键入口（CLI）
├── crypto-cli.bat          # Windows 快捷入口
├── jiejie_gui.pyw          # 加解密 GUI
├── references/             # 分方向命令速查（按需加载，节省 token）
│   ├── recon.md            # 信息收集、资产测绘/CDN真实IP、版本指纹→CVE
│   ├── web-vulns.md        # Top10、Web WSTG、WAF 绕过、API Top10
│   ├── auth-testing.md     # 认证全流程、OAuth、WebSocket、图形验证码
│   ├── password-cracking.md# 密码爆破专项（在线/离线/字典/绕过对抗）
│   ├── weakpass-check.md   # 全入口弱口令检测（Web/服务/中间件/后台默认口令）
│   ├── input-upload-js.md  # 输入框/上传下载、JS 源码审查
│   ├── middleware-unath.md # 中间件/反序列化/未授权、AD/云侦察
│   ├── crypto-testing.md   # 加解密国密 + 脚本调用自检
│   ├── emerging-reflexion.md # 新兴攻击面 + 实战复盘踩坑
│   ├── exploitation.md     # 漏洞利用、WebShell/免杀
│   ├── post-exploitation.md# 后渗透、域/数据库/云深化
│   ├── report-template.md  # 报告结构 + 可复制模板
│   ├── quickstarts.md      # 专项场景快速启动
│   └── checklist.md        # 全流程执行清单（按阶段打勾）
└── scripts/                # 25 个零依赖 Python 工具 + Frida 钩子
    ├── README.md
    ├── sm2_k_reuse.py  sm2_sign_tools.py  sm2_blind_sign.py  sm2_crypto.py
    ├── sm4.py  sm4_padding_oracle.py  sm3_tool.py  sm3_length_ext.py
    ├── aes.py  des3.py  rsa.py  jwt.py  totp.py  hash_le.py  hashencode.py
    ├── fin_mac.py  pin_dukpt.py  cert8583.py  card.py  tls.py
    ├── xor_decrypt.py  crypto_scan.py  frida_run.py  frida_hook_crypto.js
    ├── http_brute.py       # HTTP 表单/API 在线密码爆破 (零依赖)
    ├── wordlists/weakpass.txt # 分类弱口令字典 (web/service/db/middleware, --weakpass 用)
    └── ...
```

## 注意

- 短信验证码爆破测试手机号：**<测试手机号>**（自行填写）
- 所有测试必须在**授权范围**内进行，遵守《网络安全法》《数据安全法》《个人信息保护法》。
