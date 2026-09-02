#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
JieJie加解密 —— 国密/加密攻击工具 图形界面 (tkinter, 零依赖)
===========================================================
双击本文件 (.pyw) 以 pythonw 启动, 无命令行黑框。

功能:
    SM4 解密/加密   XOR 破解   密钥扫描   全部自检   通用控制台
后台直接调用 scripts/ 下工具, 与命令行版本功能一致。
"""
import ctypes
import os
import queue
import subprocess
import sys
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

# ---- 高DPI 支持 (Windows) ----
# 不开启 DPI 感知时, 系统会把窗口按位图放大 → 字体发虚。此函数必须在创建窗口前调用。
def _enable_dpi_awareness():
    try:
        # Per-Monitor V2 (最佳): DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 = -4
        ctypes.windll.user32.SetProcessDpiAwarenessContext(ctypes.c_void_p(-4))
    except Exception:
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(1)   # System DPI aware
        except Exception:
            try:
                ctypes.windll.user32.SetProcessDPIAware()    # 旧系统
            except Exception:
                pass


_enable_dpi_awareness()


def _get_dpi() -> float:
    """获取系统 DPI (需先开启 DPI 感知)。"""
    try:
        return float(ctypes.windll.user32.GetDpiForSystem())
    except Exception:
        return 96.0


# 显示缩放系数 (100% = 1.0, 125% = 1.25, 150% = 1.5 ...)
DPI_SCALE = max(1.0, _get_dpi() / 96.0)

# ---- 工具注册表 ----
TOOLS = [
    ('sm2-kreuse',    'sm2_k_reuse',        'SM2 k 复用恢复私钥'),
    ('sm2-blind',     'sm2_blind_sign',     'SM2 盲签名协议'),
    ('sm2-sign',      'sm2_sign_tools',     'SM2 畸形签名/验签测试'),
    ('jwt',           'jwt',                'JWT 解析/伪造/攻击'),
    ('sm2-crypto',    'sm2_crypto',         'SM2 加解密 (C1C3C2)'),
    ('sm4',           'sm4',                'SM4 加解密 (ECB/CBC/CTR)'),
    ('aes',           'aes',                'AES 加解密 (含 GCM)'),
    ('des3',          'des3',               'DES/3DES 加解密'),
    ('rsa',           'rsa',                'RSA 加解密/签名'),
    ('fin-mac',       'fin_mac',            '金融报文 MAC 计算'),
    ('padding-oracle','sm4_padding_oracle', 'SM4-CBC padding oracle'),
    ('pin-dukpt',     'pin_dukpt',          'PIN Block + DUKPT'),
    ('sm3',           'sm3_tool',           'SM3 哈希 / HMAC-SM3'),
    ('sm3-le',        'sm3_length_ext',     'SM3 长度扩展攻击'),
    ('hash-le',       'hash_le',            'SHA 长度扩展攻击'),
    ('totp',          'totp',               'TOTP/HOTP 动态口令'),
    ('hashencode',    'hashencode',         '哈希+编码转换'),
    ('xor',           'xor_decrypt',        '自定义 XOR/Base64 破解'),
    ('scan',          'crypto_scan',        '硬编码密钥扫描'),
    ('cert8583',      'cert8583',           '证书解析+8583报文'),
    ('tls',           'tls',                'TLS 弱配置检测'),
    ('card',          'card',               '卡号/磁道工具'),
    ('frida',         'frida_run',          'Frida 运行时抓 key/iv'),
    ('xss-scan',      'xss_scan',           'XSS 三型检测 (反射/存储/DOM)'),
]
TOOL_NAMES = [n for n, *_ in TOOLS]


def find_tools_dir():
    """优先本包 scripts/, 其次环境变量。"""
    local = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'scripts')
    for c in (local, os.environ.get('CRYPTO_TOOLS_DIR')):
        if c and os.path.isdir(c) and os.path.isfile(os.path.join(c, 'sm4.py')):
            return os.path.abspath(c)
    raise SystemExit("[-] 未找到 scripts 目录")


TOOLS_DIR = find_tools_dir()


class TabBar(ttk.Frame):
    """两行页签栏: 上部两行切换按钮 + 单一内容区。替代 ttk.Notebook。"""

    def __init__(self, root):
        super().__init__(root)
        self.root = root
        self.tabs = []            # [(名称, 内容Frame)]
        self.buttons = {}
        self.vars = {}
        self.current = None
        # 两行按钮
        self.toolbar = ttk.Frame(self)
        self.toolbar.pack(fill='x', padx=8, pady=(8, 0))
        self.rows = [ttk.Frame(self.toolbar), ttk.Frame(self.toolbar)]
        self.rows[0].pack(fill='x')
        self.rows[1].pack(fill='x', pady=(2, 0))
        self._row = 0
        # 单一内容区
        self.content = ttk.Frame(self)
        self.content.pack(fill='both', expand=True, padx=8, pady=(6, 0))
        self.content.grid_rowconfigure(0, weight=1)
        self.content.grid_columnconfigure(0, weight=1)

    def add(self, frame, text='', row=None):
        """注册一个页签 (兼容 Notebook.add 接口)。row 指定行号 (0/1), 否则两行交替。"""
        name = text.strip()
        self.tabs.append((name, frame))
        frame.grid(in_=self.content, row=0, column=0, sticky='nsew')
        frame.grid_remove()
        var = tk.IntVar()
        self.vars[name] = var
        if row is None:
            row = self._row
            self._row ^= 1                      # 两行交替
        btn = ttk.Checkbutton(self.rows[row], text=name, variable=var,
                              command=lambda n=name: self.show(n))
        btn.pack(side='left', padx=(0, 3))
        self.buttons[name] = btn
        if self.current is None:
            var.set(1)
            self.show(name)
        return frame

    def show(self, name):
        for n, f in self.tabs:
            if n == name:
                f.grid()
            else:
                f.grid_remove()
        for n, v in self.vars.items():
            v.set(1 if n == name else 0)
        self.current = name


class CryptoGUI:
    def __init__(self, root):
        self.root = root
        root.title(f"JieJie加解密 · 国密/加密攻击工具")
        # 按 DPI 校正 tk 缩放 (1点 = DPI/72 像素), 消除字体模糊/偏小
        try:
            root.tk.call('tk', 'scaling', DPI_SCALE * 96.0 / 72.0)
        except Exception:
            pass
        root.geometry(f"{int(860 * DPI_SCALE)}x{int(640 * DPI_SCALE)}")
        root.minsize(int(720 * DPI_SCALE), int(520 * DPI_SCALE))
        self.q = queue.Queue()
        self.worker_running = threading.Event()

        style = ttk.Style()
        try:
            style.theme_use('vista')
        except Exception:
            pass

        # 上部: 两行页签工具栏 (TabBar 替代 Notebook)
        nb = TabBar(root)
        nb.pack(fill='both', expand=True, padx=8, pady=(8, 0))

        self.tab_sm4 = self._build_sm4_tab(nb)
        self.tab_sm2 = self._build_sm2_tab(nb)
        self.tab_sm2sig = self._build_sm2sig_tab(nb)
        self.tab_jwt = self._build_jwt_tab(nb)
        self.tab_sm3 = self._build_sm3_tab(nb)
        self.tab_totp = self._build_totp_tab(nb)
        self.tab_aes = self._build_aes_tab(nb)
        self.tab_des3 = self._build_des3_tab(nb)
        self.tab_rsa = self._build_rsa_tab(nb)
        self.tab_mac = self._build_mac_tab(nb)
        self.tab_pin = self._build_pin_tab(nb)
        self.tab_he = self._build_he_tab(nb)
        self.tab_hle = self._build_hle_tab(nb)
        self.tab_tls = self._build_tls_tab(nb)
        self.tab_card = self._build_card_tab(nb)
        self.tab_cert = self._build_cert_tab(nb)
        self.tab_xor = self._build_xor_tab(nb)
        self.tab_scan = self._build_scan_tab(nb)
        self.tab_console = self._build_console_tab(nb)
        self.tab_selftest = self._build_selftest_tab(nb)
        self.tab_about = self._build_about_tab(nb)

        # 下部: 输出区
        out_frame = ttk.LabelFrame(root, text=' 输出 ')
        out_frame.pack(fill='both', expand=True, padx=8, pady=(0, 8))
        self.out = tk.Text(out_frame, height=14, font=('Consolas', 9),
                           bg='#1e1e1e', fg='#dcdcdc', wrap='none',
                           insertbackground='white')
        sb = ttk.Scrollbar(out_frame, command=self.out.yview)
        self.out.configure(yscrollcommand=sb.set)
        self.out.pack(side='left', fill='both', expand=True)
        sb.pack(side='right', fill='y')
        self.out.bind('<Key>', lambda e: 'break')  # 只读

        self.log("[i] 就绪。选择功能页签 → 填写参数 → 点击运行。")
        self.log(f"[i] 工具目录: {TOOLS_DIR}\n")
        self._poll()

    # ---------------- 输出 ----------------
    def log(self, text):
        self.q.put(text)

    def _poll(self):
        try:
            while True:
                self.out.insert('end', self.q.get_nowait())
                self.out.see('end')
        except queue.Empty:
            pass
        self.root.after(80, self._poll)

    # ---------------- 运行 ----------------
    def run_tool(self, tool_name, args):
        if self.worker_running.is_set():
            messagebox.showwarning('提示', '已有任务在运行, 请等待完成')
            return
        mod = next(m for n, m, _ in TOOLS if n == tool_name)
        self.worker_running.set()
        threading.Thread(target=self._worker, args=(tool_name, mod, args),
                         daemon=True).start()

    def _worker(self, tool_name, mod, args):
        cmd = [sys.executable, os.path.join(TOOLS_DIR, mod + '.py')] + args
        self.log(f"\n$ {tool_name} {' '.join(args)}\n{'─' * 66}\n")
        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, encoding='utf-8', errors='replace',
                cwd=TOOLS_DIR, bufsize=1)
            for line in iter(proc.stdout.readline, ''):
                self.log(line)
            proc.stdout.close()
            proc.wait()
            self.log(f"[退出码 {proc.returncode}]\n")
        except Exception as e:
            self.log(f"[错误] {e}\n")
        self.worker_running.clear()

    # ---------------- 通用小部件 ----------------
    def _file_row(self, parent, text_var, label='输入'):
        row = ttk.Frame(parent)
        row.pack(fill='x', pady=2)
        ttk.Button(row, text=label, command=lambda: self._pick_file(text_var)) \
            .pack(side='left')
        ttk.Entry(row, textvariable=text_var).pack(side='left', fill='x', expand=True,
                                                   padx=(4, 0))
        return row

    def _pick_file(self, var):
        p = filedialog.askopenfilename()
        if p:
            var.set(p)

    def _pick_dir(self, var):
        p = filedialog.askdirectory()
        if p:
            var.set(p)

    def _run_btn(self, parent, text, cmd):
        ttk.Button(parent, text=text, command=cmd).pack(anchor='w', pady=4)

    # ---------------- SM4 页签 ----------------
    def _build_sm4_tab(self, nb):
        f = ttk.Frame(nb, padding=10)
        nb.add(f, text=' SM4 解密/加密 ')

        row1 = ttk.Frame(f); row1.pack(fill='x')
        ttk.Label(row1, text='操作').pack(side='left')
        self.sm4_op = ttk.Combobox(row1, values=['解密', '加密'], width=6,
                                   state='readonly')
        self.sm4_op.current(0); self.sm4_op.pack(side='left', padx=(4, 16))
        ttk.Label(row1, text='模式').pack(side='left')
        self.sm4_mode = ttk.Combobox(row1, values=['CBC', 'ECB', 'CTR'], width=6,
                                     state='readonly')
        self.sm4_mode.current(0); self.sm4_mode.pack(side='left', padx=(4, 16))
        ttk.Label(row1, text='输入格式').pack(side='left')
        self.sm4_fmt = ttk.Combobox(row1, values=['hex', 'base64', 'utf8'],
                                    width=8, state='readonly')
        self.sm4_fmt.current(0); self.sm4_fmt.pack(side='left', padx=(4, 0))

        row2 = ttk.Frame(f); row2.pack(fill='x', pady=(6, 0))
        ttk.Label(row2, text='Key (hex 32)').pack(side='left')
        self.sm4_key = tk.StringVar()
        ttk.Entry(row2, width=40, textvariable=self.sm4_key).pack(
            side='left', fill='x', expand=True, padx=(4, 0))

        row3 = ttk.Frame(f); row3.pack(fill='x', pady=(6, 0))
        ttk.Label(row3, text='IV  (hex 32)').pack(side='left')
        self.sm4_iv = tk.StringVar()
        ttk.Entry(row3, width=40, textvariable=self.sm4_iv).pack(
            side='left', fill='x', expand=True, padx=(4, 0))
        ttk.Label(row3, text=' (CBC/CTR 需填)').pack(side='left')

        row4 = ttk.Frame(f); row4.pack(fill='x', pady=(6, 0))
        self.sm4_file = tk.StringVar()
        self._file_row(row4, self.sm4_file, label='从文件读入')

        ttk.Label(f, text='数据 (密文/明文, 支持跨行)').pack(anchor='w', pady=(6, 2))
        self.sm4_data = tk.Text(f, height=5, font=('Consolas', 10))
        self.sm4_data.pack(fill='x')

        self._run_btn(f, '▶  运行 SM4', self._sm4_run)
        ttk.Label(f, text='说明: 也可在「通用控制台」页签直接传参数, 如: sm4 -m cbc -d --hex -k <key> --iv <iv> <密文>',
                  foreground='gray').pack(anchor='w', pady=(4, 0))
        return f

    def _sm4_run(self):
        op = '加密' if self.sm4_op.get() == '加密' else '解密'
        args = ['-m', self.sm4_mode.get().lower(), '-e' if op == '加密' else '-d',
                '-k', self.sm4_key.get().strip()]
        fmt = self.sm4_fmt.get()
        if fmt == 'hex':
            args += ['--hex']
        elif fmt == 'base64':
            args += ['--b64']   # 脚本只认 --b64
        iv = self.sm4_iv.get().strip()
        if self.sm4_mode.get() in ('CBC', 'CTR'):
            if not iv:
                messagebox.showerror('参数缺失', 'CBC/CTR 需要 IV')
                return
            args += ['--iv', iv]
        data = self.sm4_file.get().strip() or self.sm4_data.get('1.0', 'end').strip()
        if not data:
            messagebox.showerror('参数缺失', '请输入数据或选择文件')
            return
        args.append(data)
        self.run_tool('sm4', args)

    # ---------------- SM2 页签 ----------------
    def _build_sm2_tab(self, nb):
        f = ttk.Frame(nb, padding=10)
        nb.add(f, text=' SM2 加解密 ')

        row1 = ttk.Frame(f); row1.pack(fill='x')
        ttk.Label(row1, text='操作').pack(side='left')
        self.sm2_op = ttk.Combobox(row1, values=['加密', '解密'], width=6,
                                   state='readonly')
        self.sm2_op.current(0)
        self.sm2_op.bind('<<ComboboxSelected>>', lambda e: self._sm2_switch())
        self.sm2_op.pack(side='left', padx=(4, 16))
        ttk.Label(row1, text='C1格式').pack(side='left')
        self.sm2_comp = ttk.Combobox(row1, values=['非压缩', '压缩'], width=8,
                                     state='readonly')
        self.sm2_comp.current(0); self.sm2_comp.pack(side='left', padx=(4, 16))
        ttk.Label(row1, text='顺序').pack(side='left')
        self.sm2_order = ttk.Combobox(row1, values=['c1c3c2', 'c1c2c3'],
                                      width=8, state='readonly')
        self.sm2_order.current(0); self.sm2_order.pack(side='left', padx=(4, 16))
        ttk.Label(row1, text='输入格式').pack(side='left')
        self.sm2_fmt = ttk.Combobox(row1, values=['utf8', 'hex'], width=6,
                                    state='readonly')
        self.sm2_fmt.current(0); self.sm2_fmt.pack(side='left', padx=(4, 0))

        row2 = ttk.Frame(f); row2.pack(fill='x', pady=(6, 0))
        ttk.Label(row2, text='公钥 px (hex)').pack(side='left')
        self.sm2_px = tk.StringVar()
        self.sm2_px_ent = ttk.Entry(row2, textvariable=self.sm2_px)
        self.sm2_px_ent.pack(side='left', fill='x', expand=True, padx=(4, 0))
        row3 = ttk.Frame(f); row3.pack(fill='x', pady=(2, 0))
        ttk.Label(row3, text='公钥 py (hex)').pack(side='left')
        self.sm2_py = tk.StringVar()
        self.sm2_py_ent = ttk.Entry(row3, textvariable=self.sm2_py)
        self.sm2_py_ent.pack(side='left', fill='x', expand=True, padx=(4, 0))
        row4 = ttk.Frame(f); row4.pack(fill='x', pady=(2, 0))
        ttk.Label(row4, text='私钥 d  (hex)').pack(side='left')
        self.sm2_priv = tk.StringVar()
        self.sm2_priv_ent = ttk.Entry(row4, textvariable=self.sm2_priv)
        self.sm2_priv_ent.pack(side='left', fill='x', expand=True, padx=(4, 0))

        row5 = ttk.Frame(f); row5.pack(fill='x', pady=(6, 0))
        self.sm2_file = tk.StringVar()
        self._file_row(row5, self.sm2_file, label='从文件读入')

        ttk.Label(f, text='数据 (加密=明文 / 解密=密文hex或utf8)').pack(anchor='w', pady=(6, 2))
        self.sm2_data = tk.Text(f, height=5, font=('Consolas', 10))
        self.sm2_data.pack(fill='x')

        self._run_btn(f, '▶  运行 SM2', self._sm2_run)
        ttk.Label(f, text='SM2 非对称: 公钥加密, 私钥解密 (GB/T 32918.4)。可用「通用控制台」sm2-crypto --genkey 生成密钥对',
                  foreground='gray').pack(anchor='w', pady=(4, 0))
        self._sm2_switch()
        return f

    def _sm2_switch(self):
        is_enc = self.sm2_op.get() == '加密'
        self.sm2_px_ent.configure(state='normal' if is_enc else 'disabled')
        self.sm2_py_ent.configure(state='normal' if is_enc else 'disabled')
        self.sm2_priv_ent.configure(state='normal' if not is_enc else 'disabled')

    def _sm2_run(self):
        op = self.sm2_op.get()
        fmt = self.sm2_fmt.get()
        data = self.sm2_file.get().strip() or self.sm2_data.get('1.0', 'end').strip()
        if not data:
            messagebox.showerror('参数缺失', '请输入数据或选择文件')
            return
        args = ['--' + ('encrypt' if op == '加密' else 'decrypt')]
        if op == '加密':
            px, py = self.sm2_px.get().strip(), self.sm2_py.get().strip()
            if not (px and py):
                messagebox.showerror('参数缺失', '加密需要公钥 px/py')
                return
            args += ['--px', px, '--py', py]
            if self.sm2_comp.get() == '压缩':
                args += ['--compress']
        else:
            d = self.sm2_priv.get().strip()
            if not d:
                messagebox.showerror('参数缺失', '解密需要私钥 d')
                return
            args += ['--priv', d]
        if self.sm2_order.get() == 'c1c2c3':
            args += ['--order', 'c1c2c3']
        if fmt == 'hex':
            args += ['--hex']
        args.append(data)
        self.run_tool('sm2-crypto', args)

    # ---------------- SM2 签名/验签 页签 ----------------
    def _build_sm2sig_tab(self, nb):
        f = ttk.Frame(nb, padding=10)
        nb.add(f, text=' SM2 签名/验签 ')

        row1 = ttk.Frame(f); row1.pack(fill='x')
        ttk.Label(row1, text='操作').pack(side='left')
        self.s2s_op = ttk.Combobox(row1, values=['签名', '验签'], width=6,
                                   state='readonly')
        self.s2s_op.current(0)
        self.s2s_op.bind('<<ComboboxSelected>>', lambda e: self._sm2sig_switch())
        self.s2s_op.pack(side='left', padx=(4, 16))
        ttk.Label(row1, text='消息格式').pack(side='left')
        self.s2s_fmt = ttk.Combobox(row1, values=['utf8', 'hex'], width=6,
                                    state='readonly')
        self.s2s_fmt.current(0); self.s2s_fmt.pack(side='left', padx=(4, 0))

        # 签名字段
        row2 = ttk.Frame(f); row2.pack(fill='x', pady=(6, 0))
        ttk.Label(row2, text='私钥 d (hex)').pack(side='left')
        self.s2s_priv = tk.StringVar()
        self.s2s_priv_ent = ttk.Entry(row2, textvariable=self.s2s_priv)
        self.s2s_priv_ent.pack(side='left', fill='x', expand=True, padx=(4, 0))
        ttk.Label(row2, text=' (空=测试私钥)').pack(side='left')

        row3 = ttk.Frame(f); row3.pack(fill='x', pady=(2, 0))
        ttk.Label(row3, text='指定 nonce k').pack(side='left')
        self.s2s_k = tk.StringVar()
        self.s2s_k_ent = ttk.Entry(row3, textvariable=self.s2s_k, width=14)
        self.s2s_k_ent.pack(side='left', padx=(4, 0))
        ttk.Label(row3, text='(可选, 可预测 nonce 测试用)').pack(side='left', padx=(8, 0))

        # 验签字段
        self._sig_field_frames = []
        for label, key in (('签名 r (hex)', 's2s_r'), ('签名 s (hex)', 's2s_s'),
                           ('公钥 px (hex)', 's2s_px'), ('公钥 py (hex)', 's2s_py')):
            row = ttk.Frame(f); row.pack(fill='x', pady=(2, 0))
            ttk.Label(row, text=label).pack(side='left')
            setattr(self, key, tk.StringVar())
            ent = ttk.Entry(row, textvariable=getattr(self, key))
            ent.pack(side='left', fill='x', expand=True, padx=(4, 0))
            self._sig_field_frames.append(row)

        rowf = ttk.Frame(f); rowf.pack(fill='x', pady=(6, 0))
        self.s2s_file = tk.StringVar()
        self._file_row(rowf, self.s2s_file, label='从文件读入')

        ttk.Label(f, text='消息 (签名=待签内容 / 验签=被签内容)').pack(anchor='w', pady=(6, 2))
        self.s2s_data = tk.Text(f, height=5, font=('Consolas', 10))
        self.s2s_data.pack(fill='x')

        self._run_btn(f, '▶  运行 SM2 签名/验签', self._sm2sig_run)
        btnrow = ttk.Frame(f)
        btnrow.pack(fill='x', pady=(4, 0))
        ttk.Button(btnrow, text='生成密钥对 (输出 d/px/py)',
                   command=self._sm2sig_genkey).pack(side='left')
        ttk.Button(btnrow, text='畸形签名测试 (验签健壮性)',
                   command=self._sm2sig_malformed).pack(side='left', padx=(8, 0))
        ttk.Label(f, text='签名输出包含 r/s 与公钥 px/py, 可直接复制去验签; 畸形签名测试生成 10 种边界签名 (r=0/s=0/越界/t=0) 提交目标验签接口, 任一被接受=验签校验缺失',
                  foreground='gray', wraplength=700, justify='left').pack(
            anchor='w', pady=(4, 0))
        self._sm2sig_switch()
        return f

    def _sm2sig_switch(self):
        is_sign = self.s2s_op.get() == '签名'
        self.s2s_priv_ent.configure(state='normal' if is_sign else 'disabled')
        self.s2s_k_ent.configure(state='normal' if is_sign else 'disabled')
        for row in self._sig_field_frames:
            row.pack_forget()
        if not is_sign:
            for row in self._sig_field_frames:
                row.pack(fill='x', pady=(2, 0))

    def _sm2sig_genkey(self):
        self.run_tool('sm2-crypto', ['--genkey'])

    def _sm2sig_malformed(self):
        """畸形签名测试: 生成 10 种边界签名, 供提交目标验签接口验证健壮性。"""
        data = self.s2s_file.get().strip() or self.s2s_data.get('1.0', 'end').strip()
        if not data:
            messagebox.showerror('参数缺失', '请输入要测试的消息')
            return
        args = ['--malformed']
        if self.s2s_fmt.get() == 'hex':
            args += ['--message-hex', data]
        else:
            args += ['--message', data]
        self.run_tool('sm2-sign', args)

    def _sm2sig_run(self):
        is_sign = self.s2s_op.get() == '签名'
        data = self.s2s_file.get().strip() or self.s2s_data.get('1.0', 'end').strip()
        if not data:
            messagebox.showerror('参数缺失', '请输入消息')
            return
        fmt = self.s2s_fmt.get()
        args = ['--sign' if is_sign else '--verify']
        if fmt == 'hex':
            args += ['--message-hex', data]
        else:
            args += ['--message', data]
        if is_sign:
            priv = self.s2s_priv.get().strip()
            if priv:
                args += ['--d', priv]
            k = self.s2s_k.get().strip()
            if k:
                args += ['--k', k]
        else:
            r, s = self.s2s_r.get().strip(), self.s2s_s.get().strip()
            px, py = self.s2s_px.get().strip(), self.s2s_py.get().strip()
            if not (r and s and px and py):
                messagebox.showerror('参数缺失', '验签需要 r / s / 公钥 px / py')
                return
            args += ['--r', r, '--s', s, '--px', px, '--py', py]
        self.run_tool('sm2-sign', args)

    # ---------------- SM3 页签 ----------------
    def _build_sm3_tab(self, nb):
        f = ttk.Frame(nb, padding=10)
        nb.add(f, text=' SM3 哈希 ')

        row1 = ttk.Frame(f); row1.pack(fill='x')
        ttk.Label(row1, text='模式').pack(side='left')
        self.sm3_mode = ttk.Combobox(row1, values=['SM3 摘要', 'HMAC-SM3'],
                                     width=12, state='readonly')
        self.sm3_mode.current(0)
        self.sm3_mode.bind('<<ComboboxSelected>>', lambda e: self._sm3_switch())
        self.sm3_mode.pack(side='left', padx=(4, 16))
        ttk.Label(row1, text='输入格式').pack(side='left')
        self.sm3_fmt = ttk.Combobox(row1, values=['utf8', 'hex'], width=6,
                                    state='readonly')
        self.sm3_fmt.current(0); self.sm3_fmt.pack(side='left', padx=(4, 0))

        row2 = ttk.Frame(f); row2.pack(fill='x', pady=(6, 0))
        ttk.Label(row2, text='HMAC 密钥 (可选)').pack(side='left')
        self.sm3_key = tk.StringVar()
        ttk.Entry(row2, textvariable=self.sm3_key).pack(side='left', fill='x',
                                                        expand=True, padx=(4, 0))
        ttk.Label(row2, text=' (HMAC 模式必填)').pack(side='left')

        row3 = ttk.Frame(f); row3.pack(fill='x', pady=(6, 0))
        self.sm3_file = tk.StringVar()
        self._file_row(row3, self.sm3_file, label='对文件计算')

        ttk.Label(f, text='数据').pack(anchor='w', pady=(6, 2))
        self.sm3_data = tk.Text(f, height=6, font=('Consolas', 10))
        self.sm3_data.pack(fill='x')

        self._run_btn(f, '▶  计算', self._sm3_run)
        ttk.Label(f, text='SM3 是单向哈希 (不可逆), 256bit 输出。HMAC-SM3 带密钥做消息认证。',
                  foreground='gray').pack(anchor='w', pady=(4, 0))
        return f

    def _sm3_switch(self):
        pass  # 留空, HMAC 密钥非必填 (空则按纯摘要处理)

    def _sm3_run(self):
        data = self.sm3_file.get().strip() or self.sm3_data.get('1.0', 'end').strip()
        if not data:
            messagebox.showerror('参数缺失', '请输入数据')
            return
        args = []
        if self.sm3_mode.get() == 'HMAC-SM3':
            key = self.sm3_key.get().strip()
            if not key:
                messagebox.showerror('参数缺失', 'HMAC 模式需要密钥')
                return
            args += ['--hmac', key]
        if self.sm3_fmt.get() == 'hex':
            args += ['--hex']
        args.append(data)
        self.run_tool('sm3', args)

    # ---------------- TOTP/HOTP 页签 ----------------
    def _build_totp_tab(self, nb):
        f = ttk.Frame(nb, padding=10)
        nb.add(f, text=' 动态口令 ')
        row = ttk.Frame(f); row.pack(fill='x')
        ttk.Label(row, text='Secret').pack(side='left')
        self.totp_secret = tk.StringVar()
        ttk.Entry(row, textvariable=self.totp_secret, width=28).pack(
            side='left', fill='x', expand=True, padx=(4, 8))
        ttk.Label(row, text='位数').pack(side='left')
        self.totp_digits = ttk.Combobox(row, values=['6', '8'], width=3, state='readonly')
        self.totp_digits.current(0); self.totp_digits.pack(side='left', padx=(2, 8))
        ttk.Label(row, text='算法').pack(side='left')
        self.totp_algo = ttk.Combobox(row, values=['sha1', 'sha256', 'sha512'],
                                      width=8, state='readonly')
        self.totp_algo.current(0); self.totp_algo.pack(side='left', padx=(2, 8))
        ttk.Label(row, text='步长').pack(side='left')
        self.totp_period = tk.StringVar(value='30')
        ttk.Entry(row, textvariable=self.totp_period, width=5).pack(side='left', padx=(2, 0))

        row2 = ttk.Frame(f); row2.pack(fill='x', pady=(6, 0))
        ttk.Label(row2, text='指定时间').pack(side='left')
        self.totp_time = tk.StringVar()
        ttk.Entry(row2, textvariable=self.totp_time, width=14).pack(side='left', padx=(4, 8))
        ttk.Label(row2, text='计数器(HOTP)').pack(side='left')
        self.totp_counter = tk.StringVar()
        ttk.Entry(row2, textvariable=self.totp_counter, width=10).pack(side='left', padx=(4, 8))
        ttk.Label(row2, text='窗口±').pack(side='left')
        self.totp_window = tk.StringVar()
        ttk.Entry(row2, textvariable=self.totp_window, width=4).pack(side='left', padx=(4, 0))

        row3 = ttk.Frame(f); row3.pack(fill='x', pady=(6, 0))
        ttk.Label(row3, text='验证码(验证)').pack(side='left')
        self.totp_verify = tk.StringVar()
        ttk.Entry(row3, textvariable=self.totp_verify, width=12).pack(side='left', padx=(4, 0))

        self._run_btn(f, '▶  计算', self._totp_run)
        ttk.Label(f, text='银行动态令牌/手机银行/短信码。不填时间=当前; 填窗口可测重放窗口; 填验证码可验证',
                  foreground='gray').pack(anchor='w', pady=(4, 0))
        return f

    def _totp_run(self):
        if not self.totp_secret.get().strip():
            messagebox.showerror('参数缺失', '请输入 Secret')
            return
        args = ['--secret', self.totp_secret.get().strip(),
                '--digits', self.totp_digits.get(), '--algo', self.totp_algo.get()]
        if self.totp_period.get().strip():
            args += ['--period', self.totp_period.get().strip()]
        t, c, w = self.totp_time.get().strip(), self.totp_counter.get().strip(), self.totp_window.get().strip()
        v = self.totp_verify.get().strip()
        if c:
            args += ['--counter', c]
        elif v:
            args += ['--verify', v]
            if w:
                args += ['--window', w]
        else:
            if t:
                args += ['--time', t]
            if w:
                args += ['--window', w]
        self.run_tool('totp', args)

    # ---------------- DES/3DES 页签 ----------------
    def _build_des3_tab(self, nb):
        f = ttk.Frame(nb, padding=10)
        nb.add(f, text=' DES/3DES ')
        row1 = ttk.Frame(f); row1.pack(fill='x')
        ttk.Label(row1, text='操作').pack(side='left')
        self.d3_op = ttk.Combobox(row1, values=['解密', '加密'], width=6, state='readonly')
        self.d3_op.current(0); self.d3_op.pack(side='left', padx=(4, 12))
        ttk.Label(row1, text='模式').pack(side='left')
        self.d3_mode = ttk.Combobox(row1, values=['CBC', 'ECB'], width=6, state='readonly')
        self.d3_mode.current(0); self.d3_mode.pack(side='left', padx=(4, 12))
        ttk.Label(row1, text='格式').pack(side='left')
        self.d3_fmt = ttk.Combobox(row1, values=['hex', 'base64', 'utf8'], width=8, state='readonly')
        self.d3_fmt.current(0); self.d3_fmt.pack(side='left', padx=(4, 12))
        ttk.Label(row1, text='填充').pack(side='left')
        self.d3_pad = ttk.Combobox(row1, values=['pkcs7', 'none'], width=7, state='readonly')
        self.d3_pad.current(0); self.d3_pad.pack(side='left', padx=(4, 0))

        row2 = ttk.Frame(f); row2.pack(fill='x', pady=(6, 0))
        ttk.Label(row2, text='Key (8/16/24B hex)').pack(side='left')
        self.d3_key = tk.StringVar()
        ttk.Entry(row2, textvariable=self.d3_key).pack(side='left', fill='x', expand=True, padx=(4, 0))

        row3 = ttk.Frame(f); row3.pack(fill='x', pady=(2, 0))
        ttk.Label(row3, text='IV (16 hex)').pack(side='left')
        self.d3_iv = tk.StringVar()
        ttk.Entry(row3, textvariable=self.d3_iv).pack(side='left', fill='x', expand=True, padx=(4, 0))
        ttk.Label(row3, text=' (CBC 需填)').pack(side='left')

        ttk.Label(f, text='数据').pack(anchor='w', pady=(6, 2))
        self.d3_data = tk.Text(f, height=5, font=('Consolas', 10))
        self.d3_data.pack(fill='x')

        self._run_btn(f, '▶  运行', self._des3_run)
        ttk.Label(f, text='DES 8B / 3DES 16B(双长) 或 24B(三长), 自动识别。遗留 POS/支付报文常用',
                  foreground='gray').pack(anchor='w', pady=(4, 0))
        return f

    def _des3_run(self):
        data = self.d3_data.get('1.0', 'end').strip()
        key = self.d3_key.get().strip()
        if not data or not key:
            messagebox.showerror('参数缺失', '请输入数据与 Key')
            return
        args = ['-m', self.d3_mode.get().lower(), '-e' if self.d3_op.get() == '加密' else '-d',
                '-k', key, '--padding', self.d3_pad.get()]
        fmt = self.d3_fmt.get()
        if fmt == 'hex':
            args += ['--hex']
        elif fmt == 'base64':
            args += ['--b64']   # 脚本只认 --b64
        if self.d3_mode.get() == 'CBC':
            iv = self.d3_iv.get().strip()
            if not iv:
                messagebox.showerror('参数缺失', 'CBC 需要 IV')
                return
            args += ['--iv', iv]
        args.append(data)
        self.run_tool('des3', args)

    # ---------------- AES 页签 ----------------
    def _build_aes_tab(self, nb):
        f = ttk.Frame(nb, padding=10)
        nb.add(f, text=' AES ')
        row1 = ttk.Frame(f); row1.pack(fill='x')
        ttk.Label(row1, text='操作').pack(side='left')
        self.ae_op = ttk.Combobox(row1, values=['解密', '加密'], width=6, state='readonly')
        self.ae_op.current(0); self.ae_op.pack(side='left', padx=(4, 10))
        ttk.Label(row1, text='模式').pack(side='left')
        self.ae_mode = ttk.Combobox(row1, values=['CBC', 'ECB', 'CTR', 'GCM'], width=6,
                                    state='readonly')
        self.ae_mode.current(0); self.ae_mode.pack(side='left', padx=(4, 10))
        ttk.Label(row1, text='格式').pack(side='left')
        self.ae_fmt = ttk.Combobox(row1, values=['hex', 'base64', 'utf8'], width=8,
                                   state='readonly')
        self.ae_fmt.current(0); self.ae_fmt.pack(side='left', padx=(4, 0))

        row2 = ttk.Frame(f); row2.pack(fill='x', pady=(6, 0))
        ttk.Label(row2, text='Key (16/24/32B)').pack(side='left')
        self.ae_key = tk.StringVar()
        ttk.Entry(row2, textvariable=self.ae_key).pack(side='left', fill='x',
                                                        expand=True, padx=(4, 0))
        row3 = ttk.Frame(f); row3.pack(fill='x', pady=(2, 0))
        ttk.Label(row3, text='IV (CBC/CTR=16B, GCM=12B)').pack(side='left')
        self.ae_iv = tk.StringVar()
        ttk.Entry(row3, textvariable=self.ae_iv).pack(side='left', fill='x',
                                                      expand=True, padx=(4, 0))
        ttk.Label(row3, text='GCM标签').pack(side='left')
        self.ae_tag = tk.StringVar()
        ttk.Entry(row3, textvariable=self.ae_tag, width=34).pack(side='left', padx=(4, 0))

        ttk.Label(f, text='数据').pack(anchor='w', pady=(6, 2))
        self.ae_data = tk.Text(f, height=5, font=('Consolas', 10))
        self.ae_data.pack(fill='x')

        self._run_btn(f, '▶  运行 AES', self._aes_run)
        ttk.Label(f, text='银行现代 API 国际算法主力; GCM 输出认证标签, 解密需填标签',
                  foreground='gray').pack(anchor='w', pady=(4, 0))
        return f

    def _aes_run(self):
        data = self.ae_data.get('1.0', 'end').strip()
        key = self.ae_key.get().strip()
        if not data or not key:
            messagebox.showerror('参数缺失', '请输入数据与 Key')
            return
        args = ['-m', self.ae_mode.get().lower(),
                '-e' if self.ae_op.get() == '加密' else '-d',
                '-k', key]
        fmt = self.ae_fmt.get()
        if fmt == 'hex':
            args += ['--hex']
        elif fmt == 'base64':
            args += ['--b64']   # 脚本只认 --b64
        iv = self.ae_iv.get().strip()
        if self.ae_mode.get() in ('CBC', 'CTR', 'GCM'):
            if not iv:
                messagebox.showerror('参数缺失', '需要 IV')
                return
            args += ['--iv', iv]
        tag = self.ae_tag.get().strip()
        if self.ae_mode.get() == 'GCM' and self.ae_op.get() == '解密':
            if not tag:
                messagebox.showerror('参数缺失', 'GCM 解密需要标签')
                return
            args += ['--tag', tag]
        args.append(data)
        self.run_tool('aes', args)

    # ---------------- RSA 页签 ----------------
    def _build_rsa_tab(self, nb):
        f = ttk.Frame(nb, padding=10)
        nb.add(f, text=' RSA ')
        row1 = ttk.Frame(f); row1.pack(fill='x')
        ttk.Label(row1, text='操作').pack(side='left')
        self.rs_op = ttk.Combobox(row1, values=['加密', '解密', '签名', '验签'], width=6,
                                  state='readonly')
        self.rs_op.current(0); self.rs_op.pack(side='left', padx=(4, 10))
        ttk.Label(row1, text='格式').pack(side='left')
        self.rs_fmt = ttk.Combobox(row1, values=['utf8', 'hex'], width=6, state='readonly')
        self.rs_fmt.current(0); self.rs_fmt.pack(side='left', padx=(4, 0))

        for label, key in (('模数 n (hex)', 'rs_n'), ('公钥 e', 'rs_e'),
                           ('私钥 d (hex)', 'rs_d'), ('签名 (hex, 验签用)', 'rs_sig')):
            r = ttk.Frame(f); r.pack(fill='x', pady=(2, 0))
            ttk.Label(r, text=label).pack(side='left')
            setattr(self, key, tk.StringVar())
            v = '65537' if key == 'rs_e' else ''
            getattr(self, key).set(v)
            ttk.Entry(r, textvariable=getattr(self, key)).pack(side='left', fill='x',
                                                               expand=True, padx=(4, 0))

        ttk.Label(f, text='数据 (明文/密文/消息)').pack(anchor='w', pady=(6, 2))
        self.rs_data = tk.Text(f, height=5, font=('Consolas', 10))
        self.rs_data.pack(fill='x')

        btnrow = ttk.Frame(f); btnrow.pack(fill='x', pady=(6, 0))
        self._run_btn(btnrow, '▶  运行 RSA', self._rsa_run)
        ttk.Button(btnrow, text='生成密钥对', command=self._rsa_genkey).pack(side='left', padx=8)

        ttk.Label(f, text='加解密/签名用 PKCS#1 v1.5; 也可在控制台用 --genkey/--factorize 测弱密钥',
                  foreground='gray').pack(anchor='w', pady=(4, 0))
        return f

    def _rsa_genkey(self):
        self.run_tool('rsa', ['--genkey', '1024'])

    def _rsa_run(self):
        op = self.rs_op.get()
        data = self.rs_data.get('1.0', 'end').strip()
        n = self.rs_n.get().strip()
        if not data or not n:
            messagebox.showerror('参数缺失', '请输入数据与模数 n')
            return
        args = []
        if op == '加密':
            args = ['--encrypt', '--n', n, '--e', self.rs_e.get().strip() or '65537']
        elif op == '解密':
            d = self.rs_d.get().strip()
            if not d:
                messagebox.showerror('参数缺失', '解密需要私钥 d'); return
            args = ['--decrypt', '--d', d, '--n', n]
        elif op == '签名':
            d = self.rs_d.get().strip()
            if not d:
                messagebox.showerror('参数缺失', '签名需要私钥 d'); return
            args = ['--sign', '--d', d, '--n', n]
        else:
            sig = self.rs_sig.get().strip()
            if not sig:
                messagebox.showerror('参数缺失', '验签需要签名'); return
            args = ['--verify', '--e', self.rs_e.get().strip() or '65537', '--n', n, '--sig', sig]
        if self.rs_fmt.get() == 'hex':
            args += ['--hex']
        args.append(data)
        self.run_tool('rsa', args)

    # ---------------- 哈希/编码 页签 ----------------
    def _build_he_tab(self, nb):
        f = ttk.Frame(nb, padding=10)
        nb.add(f, text=' 哈希/编码 ')
        row1 = ttk.Frame(f); row1.pack(fill='x')
        ttk.Label(row1, text='操作').pack(side='left')
        self.he_op = ttk.Combobox(row1, values=['哈希', 'HMAC', '编码转换'], width=10,
                                  state='readonly')
        self.he_op.current(0); self.he_op.pack(side='left', padx=(4, 10))
        ttk.Label(row1, text='算法').pack(side='left')
        self.he_algo = ttk.Combobox(row1, values=['sha256', 'sha1', 'md5', 'sha512', 'sha384'],
                                    width=8, state='readonly')
        self.he_algo.current(0); self.he_algo.pack(side='left', padx=(4, 10))
        ttk.Label(row1, text='HMAC密钥').pack(side='left')
        self.he_key = tk.StringVar()
        ttk.Entry(row1, textvariable=self.he_key, width=16).pack(side='left', padx=(4, 0))

        row2 = ttk.Frame(f); row2.pack(fill='x', pady=(6, 0))
        ttk.Label(row2, text='编码: 从').pack(side='left')
        self.he_from = ttk.Combobox(row2, values=['hex', 'base64', 'utf8', 'url'], width=7,
                                    state='readonly')
        self.he_from.current(0); self.he_from.pack(side='left', padx=(2, 6))
        ttk.Label(row2, text='到').pack(side='left')
        self.he_to = ttk.Combobox(row2, values=['utf8', 'hex', 'base64', 'url'], width=7,
                                  state='readonly')
        self.he_to.current(0); self.he_to.pack(side='left', padx=(2, 0))

        ttk.Label(f, text='数据').pack(anchor='w', pady=(6, 2))
        self.he_data = tk.Text(f, height=5, font=('Consolas', 10))
        self.he_data.pack(fill='x')

        self._run_btn(f, '▶  运行', self._he_run)
        return f

    def _he_run(self):
        data = self.he_data.get('1.0', 'end').strip()
        if not data:
            messagebox.showerror('参数缺失', '请输入数据')
            return
        op = self.he_op.get()
        if op == '哈希':
            self.run_tool('hashencode', ['hash', data, '--algo', self.he_algo.get()])
        elif op == 'HMAC':
            key = self.he_key.get().strip()
            if not key:
                messagebox.showerror('参数缺失', 'HMAC 需要密钥'); return
            self.run_tool('hashencode', ['hmac', data, '--key', key, '--algo', self.he_algo.get()])
        else:
            self.run_tool('hashencode', ['conv', data, '--from', self.he_from.get(),
                                         '--to', self.he_to.get()])

    # ---------------- 证书/8583 页签 ----------------
    def _build_cert_tab(self, nb):
        f = ttk.Frame(nb, padding=10)
        nb.add(f, text=' 证书8583 ')
        row1 = ttk.Frame(f); row1.pack(fill='x')
        ttk.Label(row1, text='证书文件').pack(side='left')
        self.ce_cert = tk.StringVar()
        ttk.Entry(row1, textvariable=self.ce_cert).pack(side='left', fill='x',
                                                        expand=True, padx=(4, 4))
        ttk.Button(row1, text='浏览', command=lambda: self._pick_file(self.ce_cert)).pack(side='left')
        ttk.Button(row1, text='解析证书', command=self._cert_run).pack(side='left', padx=(8, 0))

        row2 = ttk.Frame(f); row2.pack(fill='x', pady=(6, 0))
        ttk.Label(row2, text='8583 报文 (hex)').pack(side='left')
        self.ce_msg = tk.StringVar()
        ttk.Entry(row2, textvariable=self.ce_msg).pack(side='left', fill='x',
                                                       expand=True, padx=(4, 4))
        ttk.Button(row2, text='解析8583', command=self._c8583_parse).pack(side='left')

        ttk.Label(f, text='8583 组包 (位:值, 逗号分隔)').pack(anchor='w', pady=(6, 2))
        self.ce_build = tk.Text(f, height=4, font=('Consolas', 10))
        self.ce_build.pack(fill='x')
        self.ce_build.insert('1.0', '3:123456, 4:000000010000, 11:000001, 41:TERM0001')

        self._run_btn(f, '▶  组包8583', self._c8583_build)
        ttk.Label(f, text='证书: DER/PEM 均支持, 提取 RSA/EC/SM2 公钥。8583: 银联/POS 报文域解析',
                  foreground='gray').pack(anchor='w', pady=(4, 0))
        return f

    def _cert_run(self):
        p = self.ce_cert.get().strip()
        if not p:
            messagebox.showerror('参数缺失', '请选择证书文件'); return
        self.run_tool('cert8583', ['--cert', p, '--extract-pubkey'])

    def _c8583_parse(self):
        msg = self.ce_msg.get().strip()
        if not msg:
            messagebox.showerror('参数缺失', '请输入 8583 报文 hex'); return
        self.run_tool('cert8583', ['--8583-parse', msg])

    def _c8583_build(self):
        raw = self.ce_build.get('1.0', 'end').strip()
        if not raw:
            messagebox.showerror('参数缺失', '请输入字段'); return
        fields = []
        for part in raw.replace('，', ',').split(','):
            part = part.strip()
            if part:
                fields.append('--fields')
                fields.append(part)
        self.run_tool('cert8583', ['--8583-build', '--mti', '0200'] + fields)

    # ---------------- 金融 MAC 页签 ----------------
    def _build_mac_tab(self, nb):
        f = ttk.Frame(nb, padding=10)
        nb.add(f, text=' 金融MAC ')
        row = ttk.Frame(f); row.pack(fill='x')
        ttk.Label(row, text='算法').pack(side='left')
        self.mac_algo = ttk.Combobox(row, values=['x9.19', 'x9.9', 'cbc-mac', 'sm4'],
                                     width=9, state='readonly')
        self.mac_algo.current(0); self.mac_algo.pack(side='left', padx=(4, 12))
        ttk.Label(row, text='Key (hex)').pack(side='left')
        self.mac_key = tk.StringVar()
        ttk.Entry(row, textvariable=self.mac_key).pack(side='left', fill='x', expand=True, padx=(4, 0))

        ttk.Label(f, text='报文数据 (8字节对齐; sm4 自动填充)').pack(anchor='w', pady=(6, 2))
        self.mac_data = tk.Text(f, height=6, font=('Consolas', 10))
        self.mac_data.pack(fill='x')

        self._run_btn(f, '▶  计算 MAC', self._mac_run)
        ttk.Label(f, text='X9.19=3DES双长(16B) X9.9=DES(8B) SM4=16B。篡改报文→MAC变化→测试目标是否校验',
                  foreground='gray').pack(anchor='w', pady=(4, 0))
        return f

    def _mac_run(self):
        data = self.mac_data.get('1.0', 'end').strip()
        key = self.mac_key.get().strip()
        if not data or not key:
            messagebox.showerror('参数缺失', '请输入报文与 Key')
            return
        self.run_tool('fin-mac', ['-a', self.mac_algo.get(), '-k', key, data])

    # ---------------- PIN/DUKPT 页签 ----------------
    def _build_pin_tab(self, nb):
        f = ttk.Frame(nb, padding=10)
        nb.add(f, text=' PIN/DUKPT ')
        row = ttk.Frame(f); row.pack(fill='x')
        ttk.Label(row, text='操作').pack(side='left')
        self.pin_op = ttk.Combobox(row, values=['生成PIN块', '恢复PIN', '生成IPEK', '派生密钥', 'BDK加密PIN'],
                                   width=12, state='readonly')
        self.pin_op.current(0); self.pin_op.pack(side='left', padx=(4, 12))
        ttk.Label(row, text='格式').pack(side='left')
        self.pin_fmt = ttk.Combobox(row, values=['0', '1'], width=4, state='readonly')
        self.pin_fmt.current(0); self.pin_fmt.pack(side='left', padx=(4, 0))

        for label, key in (('PIN', 'pin_pin'), ('PAN 卡号', 'pin_pan'),
                           ('PIN Block hex', 'pin_block'),
                           ('BDK (16B hex)', 'pin_bdk'), ('KSN (10B hex)', 'pin_ksn'),
                           ('IPEK (16B hex)', 'pin_ipek')):
            r = ttk.Frame(f); r.pack(fill='x', pady=(2, 0))
            ttk.Label(r, text=label).pack(side='left')
            setattr(self, key, tk.StringVar())
            ttk.Entry(r, textvariable=getattr(self, key)).pack(side='left', fill='x',
                                                                expand=True, padx=(4, 0))

        self._run_btn(f, '▶  运行', self._pin_run)
        ttk.Label(f, text='PIN Block=ISO9564-1(Format0=ANSI X9.8) DUKPT=ANSI X9.24-1 POS交易密钥派生',
                  foreground='gray').pack(anchor='w', pady=(4, 0))
        return f

    def _pin_run(self):
        op = self.pin_op.get()
        args = []
        fmt = self.pin_fmt.get()
        if op == '生成PIN块':
            if not (self.pin_pin.get().strip() and self.pin_pan.get().strip()):
                messagebox.showerror('参数缺失', '需要 PIN 和 PAN'); return
            args = ['--pin', self.pin_pin.get().strip(), '--pan', self.pin_pan.get().strip(),
                    '--format', fmt]
        elif op == '恢复PIN':
            if not (self.pin_block.get().strip() and self.pin_pan.get().strip()):
                messagebox.showerror('参数缺失', '需要 PIN Block 和 PAN'); return
            args = ['--block', self.pin_block.get().strip(), '--pan', self.pin_pan.get().strip(),
                    '--format', fmt]
        elif op == '生成IPEK':
            if not (self.pin_bdk.get().strip() and self.pin_ksn.get().strip()):
                messagebox.showerror('参数缺失', '需要 BDK 和 KSN'); return
            args = ['--ipek', '--bdk', self.pin_bdk.get().strip(), '--ksn', self.pin_ksn.get().strip()]
        elif op == '派生密钥':
            if not (self.pin_ipek.get().strip() and self.pin_ksn.get().strip()):
                messagebox.showerror('参数缺失', '需要 IPEK 和 KSN'); return
            args = ['--derive', '--ipek', self.pin_ipek.get().strip(), '--ksn', self.pin_ksn.get().strip()]
        else:  # BDK加密PIN
            if not (self.pin_bdk.get().strip() and self.pin_ksn.get().strip()
                    and self.pin_pin.get().strip() and self.pin_pan.get().strip()):
                messagebox.showerror('参数缺失', '需要 BDK/KSN/PIN/PAN'); return
            args = ['--bdk', self.pin_bdk.get().strip(), '--ksn', self.pin_ksn.get().strip(),
                    '--pin', self.pin_pin.get().strip(), '--pan', self.pin_pan.get().strip()]
        self.run_tool('pin-dukpt', args)

    # ---------------- JWT 页签 ----------------
    def _build_jwt_tab(self, nb):
        f = ttk.Frame(nb, padding=10)
        nb.add(f, text=' JWT ')
        row1 = ttk.Frame(f); row1.pack(fill='x')
        ttk.Label(row1, text='操作').pack(side='left')
        self.jw_op = ttk.Combobox(row1, values=['解析', '伪造HS256', '伪造none', '爆破HS256'],
                                  width=12, state='readonly')
        self.jw_op.current(0); self.jw_op.pack(side='left', padx=(4, 10))
        ttk.Label(row1, text='HS密钥').pack(side='left')
        self.jw_secret = tk.StringVar()
        ttk.Entry(row1, textvariable=self.jw_secret, width=18).pack(side='left', padx=(4, 0))

        row2 = ttk.Frame(f); row2.pack(fill='x', pady=(4, 0))
        ttk.Label(row2, text='字典文件').pack(side='left')
        self.jw_wordlist = tk.StringVar()
        ttk.Entry(row2, textvariable=self.jw_wordlist, width=30).pack(side='left', padx=(4, 0))

        ttk.Label(f, text='Token / Payload (JSON)').pack(anchor='w', pady=(6, 2))
        self.jw_data = tk.Text(f, height=5, font=('Consolas', 10))
        self.jw_data.pack(fill='x')

        self._run_btn(f, '▶  运行', self._jwt_run)
        ttk.Label(f, text='伪造 Payload 填 {"uid":1,"role":"admin"}; 爆破需 Token+字典文件',
                  foreground='gray').pack(anchor='w', pady=(4, 0))
        return f

    def _jwt_run(self):
        data = self.jw_data.get('1.0', 'end').strip()
        op = self.jw_op.get()
        if not data:
            messagebox.showerror('参数缺失', '请输入 Token 或 Payload')
            return
        if op == '解析':
            self.run_tool('jwt', ['decode', data])
        elif op == '伪造HS256':
            if not self.jw_secret.get().strip():
                messagebox.showerror('参数缺失', 'HS256 需要密钥'); return
            self.run_tool('jwt', ['forge', '--algo', 'HS256', '--secret',
                                  self.jw_secret.get().strip(), '--payload', data])
        elif op == '伪造none':
            self.run_tool('jwt', ['forge', '--algo', 'none', '--payload', data])
        else:
            wl = self.jw_wordlist.get().strip()
            if not wl:
                messagebox.showerror('参数缺失', '爆破需要字典文件'); return
            self.run_tool('jwt', ['crack', '--wordlist', wl, data])

    # ---------------- SHA 长度扩展 页签 ----------------
    def _build_hle_tab(self, nb):
        f = ttk.Frame(nb, padding=10)
        nb.add(f, text=' SHA扩展 ')
        row1 = ttk.Frame(f); row1.pack(fill='x')
        ttk.Label(row1, text='算法').pack(side='left')
        self.hl_algo = ttk.Combobox(row1, values=['sha256', 'sha1', 'sha512'], width=8,
                                    state='readonly')
        self.hl_algo.current(0); self.hl_algo.pack(side='left', padx=(4, 10))
        ttk.Label(row1, text='secret长度').pack(side='left')
        self.hl_slen = tk.StringVar(value='16')
        ttk.Entry(row1, textvariable=self.hl_slen, width=6).pack(side='left', padx=(4, 10))
        ttk.Label(row1, text='已知摘要').pack(side='left')
        self.hl_digest = tk.StringVar()
        ttk.Entry(row1, textvariable=self.hl_digest).pack(side='left', fill='x',
                                                          expand=True, padx=(4, 0))

        ttk.Label(f, text='原始消息').pack(anchor='w', pady=(6, 2))
        self.hl_msg = tk.Text(f, height=3, font=('Consolas', 10))
        self.hl_msg.pack(fill='x')
        ttk.Label(f, text='追加内容').pack(anchor='w', pady=(4, 2))
        self.hl_append = tk.Text(f, height=2, font=('Consolas', 10))
        self.hl_append.pack(fill='x')

        self._run_btn(f, '▶  长度扩展', self._hle_run)
        ttk.Label(f, text='MAC=hash(secret‖msg) 拼接可伪造; 输出 消息‖padding‖追加 及伪造摘要',
                  foreground='gray').pack(anchor='w', pady=(4, 0))
        return f

    def _hle_run(self):
        msg = self.hl_msg.get('1.0', 'end').strip()
        ap = self.hl_append.get('1.0', 'end').strip()
        dg = self.hl_digest.get().strip()
        if not (msg and dg):
            messagebox.showerror('参数缺失', '需要消息与已知摘要')
            return
        args = ['--algo', self.hl_algo.get(), '--secret-len', self.hl_slen.get().strip(),
                '--message', msg, '--digest', dg, '--append', ap]
        self.run_tool('hash-le', args)

    # ---------------- TLS 页签 ----------------
    def _build_tls_tab(self, nb):
        f = ttk.Frame(nb, padding=10)
        nb.add(f, text=' TLS ')
        row = ttk.Frame(f); row.pack(fill='x')
        ttk.Label(row, text='主机').pack(side='left')
        self.tl_host = tk.StringVar()
        ttk.Entry(row, textvariable=self.tl_host, width=24).pack(side='left', padx=(4, 10))
        ttk.Label(row, text='端口').pack(side='left')
        self.tl_port = tk.StringVar(value='443')
        ttk.Entry(row, textvariable=self.tl_port, width=6).pack(side='left', padx=(4, 10))
        ttk.Label(row, text='超时').pack(side='left')
        self.tl_to = tk.StringVar(value='6')
        ttk.Entry(row, textvariable=self.tl_to, width=4).pack(side='left', padx=(4, 0))

        self._run_btn(f, '▶  检测 TLS', self._tls_run)
        ttk.Label(f, text='扫描协议版本/弱套件/国密支持/证书信息。需目标可达网络',
                  foreground='gray').pack(anchor='w', pady=(4, 0))
        return f

    def _tls_run(self):
        host = self.tl_host.get().strip()
        if not host:
            messagebox.showerror('参数缺失', '请输入主机'); return
        self.run_tool('tls', ['--host', host, '--port', self.tl_port.get().strip() or '443',
                              '--timeout', self.tl_to.get().strip() or '6'])

    # ---------------- 卡号 页签 ----------------
    def _build_card_tab(self, nb):
        f = ttk.Frame(nb, padding=10)
        nb.add(f, text=' 卡号/磁道 ')
        row1 = ttk.Frame(f); row1.pack(fill='x')
        ttk.Label(row1, text='操作').pack(side='left')
        self.ca_op = ttk.Combobox(row1, values=['Luhn校验', '生成卡号', '磁道解析'],
                                  width=10, state='readonly')
        self.ca_op.current(0); self.ca_op.pack(side='left', padx=(4, 10))
        ttk.Label(row1, text='BIN(生成)').pack(side='left')
        self.ca_bin = tk.StringVar(value='622202')
        ttk.Entry(row1, textvariable=self.ca_bin, width=10).pack(side='left', padx=(4, 0))

        ttk.Label(f, text='卡号 / 磁道数据').pack(anchor='w', pady=(6, 2))
        self.ca_data = tk.Text(f, height=5, font=('Consolas', 10))
        self.ca_data.pack(fill='x')

        self._run_btn(f, '▶  运行', self._card_run)
        ttk.Label(f, text='磁道1: %B卡号^姓名^有效期^...?   磁道2: ;卡号=有效期...?',
                  foreground='gray').pack(anchor='w', pady=(4, 0))
        return f

    def _card_run(self):
        data = self.ca_data.get('1.0', 'end').strip()
        op = self.ca_op.get()
        if not data and op != '生成卡号':
            messagebox.showerror('参数缺失', '请输入卡号或磁道数据'); return
        if op == 'Luhn校验':
            self.run_tool('card', ['luhn', data])
        elif op == '生成卡号':
            self.run_tool('card', ['gen', '--bin', self.ca_bin.get().strip() or '622202'])
        else:
            self.run_tool('card', ['track', data])

    # ---------------- XOR 页签 ----------------
    def _build_xor_tab(self, nb):
        f = ttk.Frame(nb, padding=10)
        nb.add(f, text=' XOR 破解 ')

        row1 = ttk.Frame(f); row1.pack(fill='x')
        ttk.Label(row1, text='输入格式').pack(side='left')
        self.xor_fmt = ttk.Combobox(row1, values=['base64', 'hex', '文本'],
                                    width=8, state='readonly')
        self.xor_fmt.current(0); self.xor_fmt.pack(side='left', padx=(4, 16))
        ttk.Label(row1, text='已知 key (可选)').pack(side='left')
        self.xor_key = tk.StringVar()
        ttk.Entry(row1, width=24, textvariable=self.xor_key).pack(
            side='left', fill='x', expand=True, padx=(4, 0))

        row2 = ttk.Frame(f); row2.pack(fill='x', pady=(6, 0))
        ttk.Label(row2, text='已知明文前缀 (可选, 推导多字节key)').pack(side='left')
        self.xor_known = tk.StringVar()
        ttk.Entry(row2, width=30, textvariable=self.xor_known).pack(
            side='left', fill='x', expand=True, padx=(4, 0))

        row3 = ttk.Frame(f); row3.pack(fill='x', pady=(6, 0))
        self.xor_file = tk.StringVar()
        self._file_row(row3, self.xor_file, label='从文件读入')

        ttk.Label(f, text='密文/输入').pack(anchor='w', pady=(6, 2))
        self.xor_data = tk.Text(f, height=6, font=('Consolas', 10))
        self.xor_data.pack(fill='x')

        self._run_btn(f, '▶  破解', self._xor_run)
        ttk.Label(f, text='无 key: 自动单字节爆破; 有 key: 直接解密; 有已知明文: 推导多字节key',
                  foreground='gray').pack(anchor='w', pady=(4, 0))
        return f

    def _xor_run(self):
        data = self.xor_file.get().strip() or self.xor_data.get('1.0', 'end').strip()
        if not data:
            messagebox.showerror('参数缺失', '请输入数据')
            return
        fmt = self.xor_fmt.get()
        args = []
        if fmt == 'base64':
            args = ['-b64']
        elif fmt == 'hex':
            args = ['--hex']
        args.append(data)
        key = self.xor_key.get().strip()
        known = self.xor_known.get().strip()
        if key:
            args += ['--key', key]
        elif known:
            args += ['--known', known]
        else:
            args += ['--auto']
        self.run_tool('xor', args)

    # ---------------- 扫描页签 ----------------
    def _build_scan_tab(self, nb):
        f = ttk.Frame(nb, padding=10)
        nb.add(f, text=' 密钥扫描 ')

        row = ttk.Frame(f); row.pack(fill='x')
        self.scan_dir = tk.StringVar()
        self._file_row(row, self.scan_dir, label='目标文件/目录')
        ttk.Button(row, text='浏览目录', command=lambda: self._pick_dir(self.scan_dir)) \
            .pack(side='left', padx=(4, 0))

        row2 = ttk.Frame(f); row2.pack(fill='x', pady=(6, 0))
        self.scan_rec = tk.BooleanVar(value=True)
        ttk.Checkbutton(row2, text='递归扫描目录', variable=self.scan_rec).pack(side='left')
        self.scan_json = tk.BooleanVar(value=False)
        ttk.Checkbutton(row2, text='JSON 输出', variable=self.scan_json).pack(side='left', padx=16)
        ttk.Label(row2, text='扩展名(逗号分隔, 默认常用)').pack(side='left', padx=(16, 4))
        self.scan_ext = tk.StringVar()
        ttk.Entry(row2, width=18, textvariable=self.scan_ext).pack(side='left')

        self._run_btn(f, '▶  开始扫描', self._scan_run)
        ttk.Label(f, text='扫描反编译产物/JS 中硬编码的 SM4/AES key、IV (配合 SM4 页签解密流量)',
                  foreground='gray').pack(anchor='w', pady=(4, 0))
        return f

    def _scan_run(self):
        target = self.scan_dir.get().strip()
        if not target:
            messagebox.showerror('参数缺失', '请选择目标文件或目录')
            return
        args = [target]
        if self.scan_rec.get():
            args += ['-r']
        if self.scan_json.get():
            args += ['--json']
        ext = self.scan_ext.get().strip()
        if ext:
            args += ['-e', ext]
        self.run_tool('scan', args)

    # ---------------- 通用控制台 ----------------
    def _build_console_tab(self, nb):
        f = ttk.Frame(nb, padding=10)
        nb.add(f, text=' 通用控制台 ')

        row = ttk.Frame(f); row.pack(fill='x')
        ttk.Label(row, text='工具').pack(side='left')
        self.con_tool = ttk.Combobox(row, values=TOOL_NAMES, state='readonly', width=18)
        self.con_tool.current(3)
        self.con_tool.pack(side='left', padx=(4, 16))
        ttk.Label(row, text='参数 (与命令行一致)').pack(side='left')
        self.con_args = tk.StringVar()
        ttk.Entry(row, textvariable=self.con_args).pack(
            side='left', fill='x', expand=True, padx=(4, 0))

        row2 = ttk.Frame(f); row2.pack(fill='x', pady=(8, 0))
        self._run_btn(row2, '▶  运行', self._con_run)
        ttk.Button(row2, text='帮助', command=self._con_help).pack(side='left', padx=8)

        ttk.Label(f, text='示例参数:\n'
                          '  sm4:        -m cbc -d --hex -k 0123456789abcdeffedcba9876543210 --iv 0000... 681edf34...\n'
                          '  sm2-kreuse: --selftest\n'
                          '  sm3-le:     --secret-len 16 --message "amount=100" --digest <hex> --append "&x=1"\n'
                          '  padding-oracle: --selftest\n'
                          '  scan:       D:\\jadx_out -r --json',
                  foreground='gray', justify='left').pack(anchor='w', pady=(10, 0))
        return f

    def _con_run(self):
        tool = self.con_tool.get()
        if not tool:
            messagebox.showerror('提示', '请选择工具')
            return
        args = self.con_args.get().split()
        self.run_tool(tool, args)

    def _con_help(self):
        tool = self.con_tool.get()
        if tool:
            self.run_tool(tool, ['--help'])

    # ---------------- 自检页签 ----------------
    def _build_selftest_tab(self, nb):
        f = ttk.Frame(nb, padding=10)
        nb.add(f, text=' 全部自检 ')
        ttk.Label(f, text='对全部工具运行内建自检, 验证工具可用性。',
                  foreground='gray').pack(anchor='w')
        ttk.Button(f, text='▶  运行全部自检', command=self._selftest_run) \
            .pack(anchor='w', pady=8)
        return f

    def _selftest_run(self):
        if self.worker_running.is_set():
            messagebox.showwarning('提示', '已有任务在运行')
            return
        self.worker_running.set()
        threading.Thread(target=self._selftest_worker, daemon=True).start()

    def _selftest_worker(self):
        """与 CLI --selftest-all 等价: 原生 --selftest + 内联测试 (sm4/xor/scan/frida)。"""
        import tempfile as _tf
        native = {'sm2_k_reuse', 'sm2_blind_sign', 'sm2_sign_tools',
                  'sm2_crypto', 'sm4_padding_oracle', 'sm3_tool',
                  'sm3_length_ext', 'des3', 'fin_mac', 'totp', 'pin_dukpt',
                  'aes', 'rsa', 'hashencode', 'cert8583',
                  'jwt', 'hash_le', 'tls', 'card'}
        for name, mod, desc in TOOLS:
            self.log(f"\n[自检] {name} — {desc}\n")
            ok, note = False, ''
            try:
                if mod in native:
                    r = subprocess.run([sys.executable, os.path.join(TOOLS_DIR, mod + '.py'), '--selftest'],
                                       capture_output=True, text=True, encoding='utf-8',
                                       errors='replace', cwd=TOOLS_DIR, timeout=120)
                    ok = r.returncode == 0
                    tail = [l for l in (r.stdout + r.stderr).strip().splitlines() if l][-3:]
                    note = '\n'.join('  ' + l for l in tail)
                elif mod == 'sm4':          # SM4 国标向量
                    code = ("from sm4 import sm4_ecb; k=bytes.fromhex('0123456789abcdeffedcba9876543210');"
                            "assert sm4_ecb(bytes.fromhex('0123456789abcdeffedcba9876543210'),k,None,False,'none')"
                            ".hex()=='681edf34d206965e86b3e94f536e4246'")
                    ok = subprocess.run([sys.executable, '-c', code], cwd=TOOLS_DIR,
                                        capture_output=True).returncode == 0
                    note = '  国标向量'
                elif mod == 'xor_decrypt':  # XOR 单字节爆破
                    code = ("import xor_decrypt as x;"
                            "pt=b'{\"amt\":\"100.00\",\"to\":\"6222\",\"acct\":\"6217\"}';"
                            "ct=bytes(c^0x5a for c in pt);"
                            "assert x.xor_decrypt(ct, b'\x5a')==pt;"
                            "hits=x.brute_single(ct, 3);"
                            "assert hits and any(k==0x5a for _,k,_ in hits)")
                    ok = subprocess.run([sys.executable, '-c', code], cwd=TOOLS_DIR,
                                        capture_output=True).returncode == 0
                    note = '  单字节爆破'
                elif mod == 'crypto_scan':  # 硬编码 key 扫描
                    sample = ('const SM4_KEY = "0123456789ABCDEFFEDCBA9876543210";\n'
                              'var iv = "000102030405060708090A0B0C0D0E0F";\n')
                    fd, path = _tf.mkstemp(suffix='.js')
                    try:
                        with os.fdopen(fd, 'w') as f:
                            f.write(sample)
                        r = subprocess.run([sys.executable, os.path.join(TOOLS_DIR, 'crypto_scan.py'),
                                            path, '--json'], capture_output=True, text=True,
                                           encoding='utf-8', errors='replace', cwd=TOOLS_DIR, timeout=120)
                        ok = r.returncode == 0 and '0123456789ABCDEFFEDCBA9876543210' in r.stdout
                    finally:
                        os.unlink(path)
                    note = '  硬编码key命中'
                elif mod == 'frida_run':    # frida 加载
                    r = subprocess.run([sys.executable, os.path.join(TOOLS_DIR, 'frida_run.py'), '--help'],
                                       capture_output=True, cwd=TOOLS_DIR)
                    ok = r.returncode == 0
                    note = '  加载'
                else:
                    note = '  无自检方式'
            except Exception as e:
                note = f'  [错误] {e}'
            if note:
                self.log(note + '\n')
            self.log(f"[{'通过' if ok else '失败'}]\n")
        self.log("\n[自检完成]\n")
        self.worker_running.clear()

    # ---------------- 关于声明 页签 ----------------
    def _build_about_tab(self, nb):
        f = ttk.Frame(nb, padding=10)
        nb.add(f, text=' 关于声明 ', row=1)   # 固定放第 2 行最右

        ttk.Label(f, text='JieJie加解密 · 使用声明',
                  font=('Microsoft YaHei', 11, 'bold')).pack(anchor='w', pady=(0, 6))

        box = ttk.Frame(f)
        box.pack(fill='both', expand=True)
        txt = ('【使用范围】\n'
               '本工具集仅用于:\n'
               '  · 加密算法原理的学习与研究\n'
               '  · 教学演示与 CTF / 授权靶场练习\n'
               '  · 已获得书面授权的安全测试 (渗透测试)\n'
               '\n'
               '【重要声明】\n'
               '1. 请勿将本工具用于任何未经授权的系统测试、数据解密或破解行为。\n'
               '2. 使用者须确保对全部测试目标拥有合法授权, 并自行承担一切法律责任。\n'
               '3. 本工具输出的密钥 / 明文等敏感信息, 仅限授权范围内使用, 严禁外泄。\n'
               '\n'
               '【免责条款】\n'
               '作者不对因使用本工具造成的任何直接或间接损失承担责任。\n'
               '擅自使用本工具进行非法活动产生的后果, 由使用者自负。\n'
               '\n'
               '【合规提醒】\n'
               '未经授权的加密破解、密钥提取或系统入侵可能违反《中华人民共和国'
               '网络安全法》及相关法律法规。请遵守所在国家/地区的法律以及目标机构'
               '的授权要求。\n'
               '\n'
               '使用本工具即视为已阅读并同意以上全部条款。')
        w = tk.Text(box, height=16, font=('Microsoft YaHei', 9), wrap='word',
                    bg='#f7f7f7', fg='#222222', relief='flat', padx=10, pady=8)
        w.insert('1.0', txt)
        w.configure(state='disabled')   # 只读
        w.pack(fill='both', expand=True)
        return f


def main():
    root = tk.Tk()
    CryptoGUI(root)
    root.mainloop()


if __name__ == '__main__':
    main()
