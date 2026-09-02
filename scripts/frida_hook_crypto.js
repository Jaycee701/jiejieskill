/*
 * frida_hook_crypto.js —— 通用加密 hook 模板 (抓取运行时 key/iv/明文密文)
 * ======================================================================
 * 用途: 银行 App 的 SM4/AES/SM2/SM3 请求加密, 运行时提取:
 *         - SM4/AES 的 key 和 iv (硬编码/动态生成均可抓到)
 *         - 加解密明文/密文 (解密后的业务报文, 继续测越权/逻辑)
 *         - SM2 签名用私钥 (若传入明文私钥)
 * 加载: frida -U -f com.bank.app -l frida_hook_crypto.js   (冷启动)
 *       frida -U com.bank.app -l frida_hook_crypto.js      (热附加)
 * 或配合本目录 frida_run.py:
 *       python frida_run.py com.bank.app --spawn
 * 日志: 控制台 + 设备 /data/local/tmp/frida_crypto.log
 * 说明: 各 hook 均 try/catch 隔离, 类不存在自动跳过; 按需增删方法。
 */
'use strict';

// ===== 配置 =====
const CONFIG = {
    log_to_device: true,     // 同时写设备 /data/local/tmp/frida_crypto.log
    max_dump: 1024,          // 单次字节 dump 上限 (hex 长度上限)
    hook_digest: false,      // 是否 hook MessageDigest/SM3 (较吵, 默认关)
};

// ===== 日志 =====
let _devlog = null;
function log(msg) {
    const line = '[' + new Date().toISOString() + '] ' + msg;
    console.log(line);
    if (CONFIG.log_to_device) {
        try {
            if (_devlog === null) _devlog = new File('/data/local/tmp/frida_crypto.log', 'a');
            _devlog.write(line + '\n');
            _devlog.flush();
        } catch (e) { /* 设备路径不可写则忽略 */ }
    }
}
function hex(buf) {
    if (!buf) return 'null';
    const n = Math.min(buf.length, CONFIG.max_dump);
    let s = '';
    for (let i = 0; i < n; i++) s += ('0' + (buf[i] & 0xff).toString(16)).slice(-2);
    return buf.length > n ? s + '…(+' + (buf.length - n) + 'B)' : s;
}
function utf8(buf) {
    try {
        return buf && buf.length ? JSON.stringify(buf.toString()) : 'null';
    } catch (e) {
        return '(非utf8)';
    }
}
function modeName(m) {
    return m === 1 ? 'ENCRYPT' : m === 2 ? 'DECRYPT' : String(m);
}

// ===== 1. Java 层加密 API =====
function hookJavaCrypto() {
    if (!Java.available) {
        log('[-] Java 不可用 (纯 native? 跳到 hookNative 模板)');
        return;
    }
    Java.perform(function () {
        // --- 1.1 SecretKeySpec: SM4/AES 密钥 ---
        try {
            const SKS = Java.use('javax.crypto.spec.SecretKeySpec');
            SKS.$init.overload('[B', 'java.lang.String').implementation = function (key, alg) {
                log('[JAVA][SecretKeySpec] alg=' + alg + ' key=' + hex(key) + ' ascii=' + utf8(key));
                return this.$init(key, alg);
            };
        } catch (e) { /* 类不存在 */ }

        // --- 1.2 IvParameterSpec: IV ---
        try {
            const IVS = Java.use('javax.crypto.spec.IvParameterSpec');
            IVS.$init.overload('[B').implementation = function (iv) {
                log('[JAVA][IvParameterSpec] iv=' + hex(iv));
                return this.$init(iv);
            };
        } catch (e) {}

        // --- 1.3 Cipher: 模式 + 明文/密文 ---
        try {
            const Cipher = Java.use('javax.crypto.Cipher');
            Cipher.init.overload('int', 'java.security.Key').implementation = function (m, k) {
                log('[JAVA][Cipher.init] mode=' + modeName(m) + ' alg=' + k.getAlgorithm());
                return this.init(m, k);
            };
            Cipher.init.overload('int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec').implementation = function (m, k, p) {
                log('[JAVA][Cipher.init] mode=' + modeName(m) + ' alg=' + k.getAlgorithm() + ' params=' + p);
                return this.init(m, k, p);
            };
            Cipher.doFinal.overload('[B').implementation = function (data) {
                log('[JAVA][Cipher.doFinal] in =' + hex(data) + ' ' + utf8(data));
                const out = this.doFinal(data);
                log('[JAVA][Cipher.doFinal] out=' + hex(out) + ' ' + utf8(out));
                return out;
            };
            Cipher.update.overload('[B').implementation = function (data) {
                log('[JAVA][Cipher.update] in=' + hex(data));
                const out = this.update(data);
                log('[JAVA][Cipher.update] out=' + hex(out));
                return out;
            };
        } catch (e) {}

        // --- 1.4 BouncyCastle SM4 引擎层 (许多国产库底层走这里) ---
        try {
            const SM4E = Java.use('org.bouncycastle.crypto.engines.SM4Engine');
            SM4E.processBlock.overload('[B', 'int', '[B', 'int').implementation = function (inB, inOff, outB, outOff) {
                log('[JAVA][SM4Engine] in@' + inOff + '=' + hex(inB));
                const r = this.processBlock(inB, inOff, outB, outOff);
                log('[JAVA][SM4Engine] out@' + outOff + '=' + hex(outB));
                return r;
            };
        } catch (e) {}

        // --- 1.5 BouncyCastle KeyParameter: SM4 密钥 (字节形式) ---
        try {
            const KP = Java.use('org.bouncycastle.crypto.params.KeyParameter');
            KP.$init.overload('[B').implementation = function (key) {
                log('[JAVA][KeyParameter] key=' + hex(key) + ' ascii=' + utf8(key));
                return this.$init(key);
            };
        } catch (e) {}

        // --- 1.6 GMHelper (常见国密封装库, 类名/方法名需按目标实际调整) ---
        try {
            const GM = Java.use('com.gmssl.GMHelper');
            const m1 = Java.use('java.lang.String');
            // 通用: 记录 SM4 加解密与 SM2 签名入口
            GM.sm4encDataECB.overload('java.lang.String', 'java.lang.String').implementation = function (d, k) {
                log('[JAVA][GMHelper.sm4encDataECB] data=' + d + ' key=' + k);
                return this.sm4encDataECB(d, k);
            };
            GM.sm4decDataECB.overload('java.lang.String', 'java.lang.String').implementation = function (d, k) {
                log('[JAVA][GMHelper.sm4decDataECB] data=' + d + ' key=' + k);
                return this.sm4decDataECB(d, k);
            };
            GM.sm2Sign.overload('java.lang.String', 'java.lang.String').implementation = function (d, priv) {
                log('[JAVA][GMHelper.sm2Sign] data=' + d + ' privKey=' + priv);
                return this.sm2Sign(d, priv);
            };
        } catch (e) { /* GMHelper 类不存在则跳过 */ }

        // --- 1.7 MessageDigest / SM3 (可选, 默认关) ---
        if (CONFIG.hook_digest) {
            try {
                const MD = Java.use('java.security.MessageDigest');
                MD.digest.overload().implementation = function () {
                    log('[JAVA][MessageDigest.' + this.getAlgorithm() + '] out=' + hex(this.digest()));
                    return this.digest();
                };
            } catch (e) {}
        }

        log('[+] Java 加密 API hook 就绪');
    });
}

// ===== 2. Native 层 (so) 模板 =====
function hookNative() {
    /*
     * 银行 App 常用 so 库: libsm4.so / libgmssl.so / libNativeCrypto.so / libbankcrypt.so
     * 若 Java 层加密被下沉到 native, 且符号未 strip, 可直接按导出名 hook:
     *
     *   const SO = 'libNativeCrypto.so';
     *   const addr = Module.findExportByName(SO, 'SM4_Encrypt');
     *   if (addr) {
     *       Interceptor.attach(addr, {
     *           onEnter(args) {
     *               // 按函数签名读取: 通常 key/inLen/in/out...
     *               log('[NATIVE][SM4_Encrypt] key=' + hex(Memory.readByteArray(args[0], 16)));
     *               const inLen = args[1].toInt32();
     *               log('[NATIVE][SM4_Encrypt] in=' + hex(Memory.readByteArray(args[2], inLen)));
     *           },
     *           onLeave(retval) {
     *               // 读取输出缓冲区, 按需
     *           }
     *       });
     *       log('[+] hooked ' + SO + '!SM4_Encrypt');
     *   }
     *
     * 若符号被 strip, 思路:
     *   1. 先枚举模块导出/字符串确认符号:  Module.enumerateExports(SO)
     *   2. 或用 JNI 动态绑定拿函数地址:
     *        const env = Java.vm.getEnv();
     *        const cls = env.findClass('com/bank/crypto/Sm4Util');
     *        const mid = env.getStaticMethodId(cls, 'encryptNative', '([B[B)[B');
     *        const fn = env.getStaticMethodAddress(cls, mid);   // → Interceptor.attach
     *   3. 或配合 IDA/Ghidra 静态定位后直接给地址 (需先绕过反调试/加固)
     */
    log('[i] native hook: 已加载模板, 按目标修改 SO 名/函数签名后启用');
}

// ===== 入口 =====
log('[+] frida_hook_crypto.js loaded');
if (Java.available) {
    Java.perform(hookJavaCrypto);
} else {
    log('[-] Java 不可用');
}
hookNative();
