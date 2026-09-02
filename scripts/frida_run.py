#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Frida 加密 hook 启动器 (配合 frida_hook_crypto.js)
===================================================
用法:
    # USB 真机热附加
    python frida_run.py com.bank.app
    # USB 冷启动 (先启动再 hook, 能抓到启动阶段的加密)
    python frida_run.py com.bank.app --spawn
    # 模拟器
    python frida_run.py com.bank.app --device emulator
    # 远程 frida-server (USB 代理常用)
    python frida_run.py com.bank.app --device 127.0.0.1:27042
    # 指定脚本/输出/时长
    python frida_run.py com.bank.app -s my_hook.js -o log.txt -t 60

依赖: pip install frida-tools     (设备端需 root + frida-server, 见 README)
"""
import argparse
import datetime
import sys

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')


def resolve_device(dev):
    import frida
    if dev == 'usb':
        return frida.get_usb_device(timeout=10000)
    if dev == 'emulator':
        return frida.get_usb_device(timeout=10000, id=1)
    if dev == 'local':
        return frida.get_local_device()
    if ':' in dev or dev.replace('.', '').isdigit():
        mgr = frida.get_device_manager()
        return mgr.add_remote_device(dev)
    return frida.get_device(dev)


def main():
    ap = argparse.ArgumentParser(description='Frida 加密 hook 启动器')
    ap.add_argument('target', help='目标: App 包名 / 进程名 / PID')
    ap.add_argument('-d', '--device', default='usb',
                    help='usb | emulator | local | ip:port (默认 usb)')
    ap.add_argument('--spawn', action='store_true', help='冷启动 (默认热附加)')
    ap.add_argument('-s', '--script', default='frida_hook_crypto.js', help='JS 脚本路径')
    ap.add_argument('-o', '--out', help='本地日志文件 (默认 frida_crypto_<时间>.log)')
    ap.add_argument('-t', '--timeout', type=int, default=0, help='运行秒数 (0=直到 Ctrl+C)')
    args = ap.parse_args()

    # 延迟导入, 未装 frida 时给出友好提示
    try:
        import frida
    except ImportError:
        sys.exit("[-] 未安装 frida, 请执行: pip install frida-tools\n"
                 "    设备端还需 root + 对应架构的 frida-server (见 scripts/README.md)")

    out = args.out or 'frida_crypto_' + datetime.datetime.now().strftime('%Y%m%d_%H%M%S') + '.log'
    logfile = open(out, 'w', encoding='utf-8')

    def on_message(message, data):
        if message['type'] == 'send':
            line = str(message['payload'])
        elif message['type'] == 'error':
            line = '[JS ERROR] ' + message.get('stack', message.get('description', ''))
        else:
            line = str(message)
        print(line)
        logfile.write(line + '\n')
        logfile.flush()

    print(f"[*] 连接设备: {args.device}")
    device = resolve_device(args.device)
    print(f"[*] 目标: {args.target} ({'spawn' if args.spawn else 'attach'})")

    if args.spawn:
        pid = device.spawn(args.target)
        session = device.attach(pid)
        loaded = True
    else:
        if args.target.isdigit():
            session = device.attach(int(args.target))
        else:
            session = device.attach(args.target)
        pid = session.pid if hasattr(session, 'pid') else '?'
        loaded = False

    print(f"[*] PID: {pid}, 加载脚本: {args.script}")
    with open(args.script, 'r', encoding='utf-8') as f:
        source = f.read()
    script = session.create_script(source)
    script.on('message', on_message)
    script.load()
    print(f"[*] hook 就绪, 日志 -> {out}  (Ctrl+C 退出)")

    if args.spawn:
        device.resume(pid)
        print("[*] 已 resume, 等待 App 加密操作...")

    try:
        if args.timeout > 0:
            import time
            time.sleep(args.timeout)
            print(f"[*] 超时 {args.timeout}s, 退出")
        else:
            while True:
                import time
                time.sleep(3600)
    except KeyboardInterrupt:
        print("\n[*] 用户中断")
    finally:
        try:
            script.unload()
        except Exception:
            pass
        try:
            session.detach()
        except Exception:
            pass
        logfile.close()
        print(f"[*] 日志已保存: {out}")


if __name__ == '__main__':
    main()
