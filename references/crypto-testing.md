# 加解密与国密测试（crypto-testing）

> 来源：jiejieskill SKILL.md 拆分（2026-08-11）。由 SKILL.md 相应章节按需加载。

### 6.12 加解密与国密测试（含自带脚本工具）

> **核心思路：国密算法本身是安全的，测的是「实现」**——硬编码密钥、弱随机、IV 复用、padding oracle、k 复用、自研魔改。本 skill **自带 25 个零依赖 Python 工具**（`scripts/` 目录），覆盖 SM2/SM3/SM4 + AES/DES/RSA/JWT/PIN/DUKPT/金融MAC + HTTP 表单爆破 等。

#### 一键入口（脚本调用）
```bash
cd <jiejieskill 技能目录>
python crypto_cli.py --list              # 列出全部 25 个工具
python crypto_cli.py --selftest-all      # 全部自测（exit 0 = 全部可用）
# GUI：双击 jiejie_gui.pyw（tkinter，零依赖）

# 常用调用示例
python scripts/sm4.py -m cbc -d --hex -k <key_hex> --iv <iv_hex> <cipher_hex>
python scripts/aes.py -m gcm -d -k <key> --iv <iv> -b64 <cipher_b64>
python scripts/jwt.py decode <token>
python scripts/crypto_scan.py /path/jadx_out -r --json      # 硬编码密钥扫描
python scripts/sm2_k_reuse.py --selftest
python scripts/sm4_padding_oracle.py --selftest
python scripts/sm3_length_ext.py --selftest
```

#### SM2 攻击面
| 攻击面 | 说明 | 对应脚本 |
|-------|------|---------|
| **k 值复用** | 同一 k 签两条消息 → 恢复私钥（`k=(z1-z2)*inv(s1-s2)`，`d=(s1*k-z1)*inv(r1)`） | `sm2_k_reuse.py` |
| 弱随机 | 固定种子/时间种子 → 同上恢复私钥 | 分析 + `sm2_k_reuse.py` |
| 公钥点校验缺失 | 不验点 → 小阶点/签名伪造 | `sm2_sign_tools.py` |
| 验签范围校验缺失 | r/s 越界、t=0 未校验 → 畸形签名绕过 | `sm2_sign_tools.py --malformed` |
| 无前向保密 | ECDH 不 PFS → 私钥泄露后可解密历史流量 | - |
| 盲签名缺陷 | 盲签名协议的可链接/盲性缺陷（e-cash 场景） | `sm2_blind_sign.py` |

#### SM4 攻击面
| 攻击面 | 说明 | 对应脚本 |
|-------|------|---------|
| ECB 模式 | 相同明文块→相同密文块，泄露结构 | `sm4.py` |
| 固定/重用 IV | 相同明文→相同密文，可检测/重放 | `sm4.py` |
| **CBC padding oracle** | padding 报错差异 → 逐字节恢复明文 | `sm4_padding_oracle.py` |
| **硬编码密钥**（最常见） | 前端 JS/APK/so 明文密钥 | `crypto_scan.py` + 逆向 |

#### SM3 / 通用哈希
| 攻击面 | 说明 | 对应脚本 |
|-------|------|---------|
| **长度扩展** | `SM3(secret‖msg)` 当 MAC → 追加伪造 | `sm3_length_ext.py` |
| SHA 长度扩展 | 同家族 | `hash_le.py` |
| TOTP/HOTP | 动态口令可预测/重放 | `totp.py` |

#### 通用加密实现问题表
| 问题 | 说明 | 工具 |
|------|------|------|
| 硬编码密钥 | JS/APK/so 明文 | `crypto_scan.py` |
| 自定义 XOR/Base64 | 伪加密 | `xor_decrypt.py` |
| 固定随机种子 | `srand(time)` 可预测 | 分析 |
| 加密当认证 | 服务端只验非空不验内容 | 替换密文 |
| 魔改算法 | 自定义轮数/置换 | 逆向对比 |
| RSA 弱参数 | 小 e/共享 n/无填充 | `rsa.py` |
| AES-ECB 重复 | 密文块重复泄露结构 | `aes.py` |
| JWT 弱点 | alg:none/HS256 混淆/弱密钥 | `jwt.py` |

#### 典型场景 → 脚本映射
1. App/前端请求加密 → `crypto_scan.py` 提取密钥 → `sm4.py`/`aes.py` 解密流量 → 越权/逻辑测试
2. 交易 SM2 签名 → `sm2_k_reuse.py` 测 k 复用 → 伪造签名
3. 前端 JS 硬编码密钥 → 解密请求参数 → 改参数绕过风控
4. 动态密钥/加固 App → `frida_run.py` + `frida_hook_crypto.js` 运行时抓密钥/IV/明文
5. 加密参数绕过 → 服务端只验非空 → 替换密文为已知值
6. 验签端点健壮性 → `sm2_sign_tools.py --malformed` 畸形签名批量
7. POS/ATM PIN/DUKPT → `pin_dukpt.py`（PIN Block + DUKPT、KSN 重放）
8. 金融报文 MAC → `fin_mac.py`（X9.9/X9.19/CBC-MAC，弱密钥、MAC 伪造）
9. 证书 / ISO8583 → `cert8583.py`（X.509 公钥对比、报文敏感字段）

#### 提取密钥手法
```bash
# 静态提取
jadx -d out app.apk && grep -rE 'SM4|AES|key|密钥' out/
strings libnative.so | grep -iE 'key|iv|sm4|sm2'
# 动态抓取（运行时）
python scripts/frida_run.py com.bank.app --spawn   # 配合 frida_hook_crypto.js 钩 Cipher/SecretKeySpec
```


#### 脚本调用自检清单（维护用）
> 文档改动脚本命令后跑一遍，确认未失效（曾发生 `jwt.py parse`→`decode` 的文档与脚本不符错误）。
```bash
python crypto_cli.py --selftest-all           # 全部工具自检（exit 0 = 可用）
python scripts/sm2_k_reuse.py --selftest       # SM2 k 复用
python scripts/sm3_length_ext.py --selftest    # SM3 长度扩展
python scripts/sm4_padding_oracle.py --selftest# SM4 padding oracle
python scripts/jwt.py decode <token>           # 子命令是 decode（不是 parse）
python scripts/crypto_scan.py <dir> -r --json  # 硬编码密钥扫描
```
