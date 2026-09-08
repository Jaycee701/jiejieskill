# JieJieSkill — 全流程渗透测试一站式技能

> 一个流程、一个完整的 skill：从**资产探测（Web + 小程序）**到**报告输出**，覆盖 PTES 7 阶段，集成 Web / 内网 / AD / 云 / 金融业务逻辑 全方向。

## 功能介绍

`jiejieskill` 是作者渗透测试的主力技能，把「资产探测 → 信息收集 → 漏洞分析 → 利用 → 后渗透 → 报告」串成一条完整流程，主要功能：

- **全流程渗透测试**：基于 PTES 7 阶段，从资产探测（Web + 小程序）到报告输出一站式闭环
- **Web 漏洞分析**：OWASP Top10 / WSTG、SQLi / XSS / SSRF / XXE / 越权 / 上传 / WAF 绕过、认证全流程、密码爆破、弱口令检测
- **自带 Web 测试工具**：`scripts/` 提供零依赖 Python 工具（HTTP 表单爆破 `http_brute.py`、XSS 三型扫描 `xss_scan.py`）
- **内网 / 域 / 云深化**：后渗透提权、横向移动、域渗透、数据库与云环境利用
- **新兴攻击面**：AI-LLM / GraphQL / 云原生、实战踩坑复盘
- **流程纪律**：内置执行清单（checklist）、强制逐项打勾、报告附完成度表

### 与其他技能的分工

| 目标 | 使用技能 |
|------|---------|
| Web 网站 / API / 后台 | **jiejieskill（本技能）** |
| 微信小程序 | **jiejieskill**（资产获取 + 静态分析）→ 深度审计引用 `wxmini-security-audit` |
| Android / iOS App | `app-pentest`（单独调用） |
| 银行 / 金融 / 支付 | **jiejieskill**（认证全流程 + 业务逻辑章节） |
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
- **漏洞利用**（七）：Reverse Shell / WebShell 管理与免杀 / AD 攻击链
- **后渗透**（八）：Linux/Windows 提权 / 横向 / 持久化 / 域渗透深化 / 数据库提权 / 云深化
- **专项速查**（十）：资产探测 / 认证爆破 / Web / 内网 / 中间件 / 未授权 快速启动

## 自带 Web 测试工具（scripts/）使用

```bash
cd <你的 jiejieskill 目录>
python scripts/http_brute.py --selftest        # HTTP 表单爆破自检
python scripts/xss_scan.py --selftest          # XSS 三型扫描自检
```

详细用法见 `scripts/README.md`。

## 目录结构

```
jiejieskill/
├── SKILL.md                # 流程控制器（流程+决策+索引，命令速查在 references/）
├── README.md               # 本说明
├── references/             # 分方向命令速查（按需加载，节省 token）
│   ├── recon.md            # 信息收集、资产测绘/CDN真实IP、版本指纹→CVE
│   ├── web-vulns.md        # Top10、Web WSTG、WAF 绕过、API Top10
│   ├── auth-testing.md     # 认证全流程、OAuth、WebSocket、图形验证码
│   ├── password-cracking.md# 密码爆破专项（在线/离线/字典/绕过对抗）
│   ├── weakpass-check.md   # 全入口弱口令检测（Web/服务/中间件/后台默认口令）
│   ├── input-upload-js.md  # 输入框/上传下载、JS 源码审查
│   ├── middleware-unath.md # 中间件/反序列化/未授权、AD/云侦察
│   ├── emerging-reflexion.md # 新兴攻击面 + 实战复盘踩坑
│   ├── exploitation.md     # 漏洞利用、WebShell/免杀
│   ├── post-exploitation.md# 后渗透、域/数据库/云深化
│   ├── report-template.md  # 报告结构 + 可复制模板
│   ├── quickstarts.md      # 专项场景快速启动
│   └── checklist.md        # 全流程执行清单（按阶段打勾）
└── scripts/                # 零依赖 Python Web 测试工具
    ├── README.md
    ├── http_brute.py       # HTTP 表单/API 在线密码爆破
    ├── xss_scan.py         # XSS 三型扫描（反射/存储/DOM）
    ├── wordlists/weakpass.txt # 分类弱口令字典 (web/service/db/middleware, --weakpass 用)
    └── ...
```

## 注意

- 短信验证码爆破测试手机号：**<测试手机号>**（自行填写）
- 所有测试必须在**授权范围**内进行，遵守《网络安全法》《数据安全法》《个人信息保护法》。
