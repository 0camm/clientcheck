# Sentinel.py
# Sentinel: local client check tool.
# Needs a key. The key (plus a hashed PC id) is checked online once at startup.
# Nothing about your scan results is ever sent anywhere.

import hashlib
import json
import os
import socket
import subprocess
import threading
import urllib.error
import urllib.request
import uuid
import webbrowser
from datetime import datetime

import psutil
import customtkinter as ctk

PC_NAME = socket.gethostname()

API_BASE = 'https://sentinalkeys.onrender.com'  # your Render key server
DISCORD_URL = 'https://discord.gg/XxqjtYDrrV'
LICENSE_DIR = os.path.join(
    os.getenv('APPDATA') or os.path.expanduser('~'), 'Sentinel'
)
LICENSE_FILE = os.path.join(LICENSE_DIR, 'license.json')


def device_id():
    """Anonymous id for this PC (hash only; the raw values never leave it)."""
    raw = f'{socket.gethostname()}|{uuid.getnode()}'
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


def load_saved_key():
    try:
        with open(LICENSE_FILE, encoding='utf-8') as fh:
            return str(json.load(fh).get('key', '')).strip()
    except (OSError, ValueError):
        return ''


def save_key(key):
    try:
        os.makedirs(LICENSE_DIR, exist_ok=True)
        with open(LICENSE_FILE, 'w', encoding='utf-8') as fh:
            json.dump({'key': key}, fh)
    except OSError:
        pass


def verify_key(key):
    """Returns (ok, message)."""
    body = json.dumps({'key': key, 'device': device_id()}).encode()
    req = urllib.request.Request(
        f'{API_BASE}/api/verify',
        data=body,
        method='POST',
        headers={'Content-Type': 'application/json', 'User-Agent': 'Sentinel/1.0'},
    )
    try:
        with urllib.request.urlopen(req, timeout=75) as resp:
            return resp.status == 200, 'OK'
    except urllib.error.HTTPError as exc:
        try:
            msg = json.loads(exc.read().decode()).get('error', 'invalid key')
        except (ValueError, OSError):
            msg = 'invalid key'
        return False, msg.capitalize() + '.'
    except (urllib.error.URLError, OSError, ValueError):
        return False, 'Could not reach the key server. Check your internet and try again.'

KEYWORDS = [
    'krnl', 'fluxus', 'synapse', 'scriptware', 'electron', 'hydrogen',
    'delta', 'codex', 'arceus', 'vega', 'comet', 'oxygen', 'evon',
    'nihon', 'valyse', 'jjsploit', 'furk', 'kiwi', 'coco', 'skisploit',
    'xeno', 'bootstrapper', 'wave', 'incognito', 'carbon', 'velocity',
    'clumsy', 'seliware', 'krampus', 'ro-exec', 'macsploit', 'vegax',
    'nemesis', 'proxo', 'calamari', 'shadow', 'vaper', 'fates',
    'infiniteyield', 'dex-explorer', 'remote-spy', 'dark-dex', 'celery',
    'zentinel', 'athena', 'bloxstrap', 'voidstrap', 'fishstrap', 'suncat',
    'memsweep', 'swift'
]

STRAPPER_TARGETS = ['bloxstrap', 'fishstrap', 'voidstrap']


def get_file_info(path):
    try:
        m_time = datetime.fromtimestamp(
            os.path.getmtime(path)
        ).strftime('%Y-%m-%d %H:%M:%S')
        ext = os.path.splitext(path)[1].upper().replace('.', '') or 'DIR'
        return m_time, ext
    except (OSError, TypeError, ValueError):
        return 'Unknown', 'FILE'


class CyberUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title('SENTINEL')
        self.geometry('1200x750')
        self.configure(fg_color='#050505')

        self.setup_login()

    def setup_login(self):
        self.login_overlay = ctk.CTkFrame(self, fg_color='#000')
        self.login_overlay.place(relx=0, rely=0, relwidth=1, relheight=1)

        ctk.CTkLabel(
            self.login_overlay,
            text='SENTINEL',
            font=('Fixedsys', 40),
            text_color='#00FFFF'
        ).pack(pady=(160, 10))

        ctk.CTkLabel(
            self.login_overlay,
            text='Enter your key to continue.',
            text_color='#AAAAAA'
        ).pack(pady=(0, 16))

        self.key_entry = ctk.CTkEntry(
            self.login_overlay,
            width=360,
            height=42,
            placeholder_text='SNTL-XXXX-XXXX-XXXX-XXXX',
            justify='center'
        )
        self.key_entry.pack(pady=6)
        self.key_entry.bind('<Return>', lambda _e: self.activate())

        self.activate_btn = ctk.CTkButton(
            self.login_overlay,
            text='ACTIVATE',
            command=self.activate,
            fg_color='#00FF41',
            text_color='#000',
            width=360,
            height=40
        )
        self.activate_btn.pack(pady=(10, 6))

        ctk.CTkButton(
            self.login_overlay,
            text='NEED A KEY? JOIN THE DISCORD',
            command=lambda: webbrowser.open(DISCORD_URL),
            fg_color='#111',
            border_width=1,
            border_color='#00FFFF',
            text_color='#00FFFF',
            hover_color='#222',
            width=360,
            height=36
        ).pack(pady=6)

        self.key_status = ctk.CTkLabel(
            self.login_overlay, text='', text_color='#FF5555', wraplength=520
        )
        self.key_status.pack(pady=(14, 6))

        ctk.CTkLabel(
            self.login_overlay,
            text=(
                'Your key and an anonymous PC id are checked online, and the key is '
                'tied to this PC.\nScan results stay on this computer. '
                'Only scan systems you are authorized to inspect.'
            ),
            text_color='#777777',
            wraplength=560
        ).pack(pady=(10, 0))

        saved = load_saved_key()
        if saved:
            self.key_entry.insert(0, saved)
            self.after(400, self.activate)

    def activate(self):
        key = self.key_entry.get().strip()
        if not key:
            self.key_status.configure(text='Enter your key first.', text_color='#FF5555')
            return
        self.activate_btn.configure(state='disabled')
        self.key_status.configure(
            text='Checking key... (the server can take up to a minute to wake up)',
            text_color='#AAAAAA'
        )

        def run():
            ok, msg = verify_key(key)
            self.after(0, lambda: self.on_activation(ok, msg, key))

        threading.Thread(target=run, daemon=True).start()

    def on_activation(self, ok, msg, key):
        self.activate_btn.configure(state='normal')
        if ok:
            save_key(key)
            self.continue_to_app()
        else:
            self.key_status.configure(text=msg, text_color='#FF5555')

    def continue_to_app(self):
        self.login_overlay.place_forget()
        self.setup_main_ui()

    def setup_main_ui(self):
        self.top_bar = ctk.CTkFrame(
            self, height=40, fg_color='#111', corner_radius=0
        )
        self.top_bar.pack(side='top', fill='x')

        ctk.CTkLabel(
            self.top_bar,
            text=f'● SYS: ACTIVE | HOST: {PC_NAME}',
            font=('Consolas', 12),
            text_color='#00FF41'
        ).pack(side='left', padx=20)

        self.main_container = ctk.CTkFrame(self, fg_color='transparent')
        self.main_container.pack(fill='both', expand=True, padx=20, pady=10)

        self.left_panel = ctk.CTkFrame(
            self.main_container, fg_color='transparent', width=300
        )
        self.left_panel.pack(side='left', fill='y', padx=(0, 20))

        ctk.CTkLabel(
            self.left_panel,
            text='SENTINEL',
            font=('Fixedsys', 42, 'bold'),
            text_color='#00FFFF'
        ).pack(anchor='w', pady=(20, 0))

        self.create_neon_btn('PROCESSES', self.run_process_scan, '#00FF41')
        self.create_neon_btn('STRAPPERS', self.run_strapper_scan, '#FF00FF')
        self.create_neon_btn('PREFETCH', self.run_prefetch_scan, '#FFFF00')
        self.create_neon_btn('DELETED FILES', self.run_bin_scan, '#FF8C00')
        self.create_neon_btn('EXPLOIT SCAN', self.run_full_disk_scan, '#00FFFF')

        self.right_panel = ctk.CTkFrame(
            self.main_container,
            fg_color='#000',
            border_width=1,
            border_color='#333',
            corner_radius=5
        )
        self.right_panel.pack(side='right', fill='both', expand=True)

        self.console = ctk.CTkTextbox(
            self.right_panel,
            fg_color='transparent',
            text_color='#00FF41',
            font=('Consolas', 12)
        )
        self.console.pack(fill='both', expand=True, padx=10, pady=10)

        self.overlay = ctk.CTkFrame(self, fg_color='#030303')
        self.scan_text = ctk.CTkLabel(
            self.overlay,
            text='EXECUTING...',
            font=('Fixedsys', 40),
            text_color='#FF00FF'
        )
        self.scan_text.pack(pady=(250, 20))

        self.progress = ctk.CTkProgressBar(
            self.overlay,
            width=400,
            progress_color='#FF00FF',
            mode='indeterminate'
        )
        self.progress.pack()

    def create_neon_btn(self, text, cmd, color):
        ctk.CTkButton(
            self.left_panel,
            text=text,
            fg_color='#111',
            border_width=1,
            border_color=color,
            text_color=color,
            hover_color='#222',
            font=('Fixedsys', 14),
            height=40,
            command=cmd
        ).pack(pady=8, fill='x')

    def log_to_ui(self, msg):
        self.console.insert('end', f'{msg}\n\n')
        self.console.see('end')

    def show_scan(self, txt):
        self.scan_text.configure(text=txt)
        self.overlay.place(relx=0, rely=0, relwidth=1, relheight=1)
        self.progress.start()

    def hide_scan(self):
        self.progress.stop()
        self.overlay.place_forget()

    def run_prefetch_scan(self):
        self.show_scan('PREFETCH_AUDIT')

        def run():
            found = False
            try:
                prefetch = os.path.join(
                    os.getenv('SystemRoot', r'C:\Windows'), 'Prefetch'
                )
                for f in os.listdir(prefetch):
                    if any(k in f.lower() for k in KEYWORDS):
                        full_p = os.path.join(prefetch, f)
                        m_date, _ = get_file_info(full_p)
                        self.log_to_ui(
                            f"X {f}\n"
                            f"  Path          : {full_p}\n"
                            f"  Last Modified : {m_date}\n"
                            f"  Source        : Prefetch\n"
                            f"  Keywords      : {f.split('.')[0].lower()}"
                        )
                        found = True
            except OSError:
                self.log_to_ui('ACCESS_DENIED')

            if not found:
                self.log_to_ui('NO PREFETCH HITS')
            self.after(0, self.hide_scan)

        threading.Thread(target=run, daemon=True).start()

    def run_process_scan(self):
        self.show_scan('PROC_AUDIT')

        def run():
            found = False
            for p in psutil.process_iter(['name', 'exe']):
                try:
                    name = (p.info.get('name') or '').lower()
                    if any(k in name for k in KEYWORDS):
                        exe = p.info.get('exe')
                        m_date, f_type = get_file_info(exe)
                        self.log_to_ui(
                            f"PROCESS | Modified: {m_date} | "
                            f"Type: {f_type} | Dir: {exe}"
                        )
                        found = True
                except (psutil.Error, OSError, AttributeError):
                    continue

            if not found:
                self.log_to_ui('NOTHING FOUND')
            self.after(0, self.hide_scan)

        threading.Thread(target=run, daemon=True).start()

    def run_strapper_scan(self):
        self.show_scan('STRAP_CHECK')

        def run():
            found = False

            for base in (os.getenv('APPDATA'), os.getenv('LOCALAPPDATA')):
                if not base:
                    continue

                try:
                    for item in os.listdir(base):
                        if any(s in item.lower() for s in STRAPPER_TARGETS):
                            full_p = os.path.join(base, item)
                            m_date, f_type = get_file_info(full_p)
                            self.log_to_ui(
                                f'STRAPPER | Modified: {m_date} | '
                                f'Type: {f_type} | Dir: {full_p}'
                            )
                            found = True
                except OSError:
                    continue

            if not found:
                self.log_to_ui('NO STRAPPER FOUND')
            self.after(0, self.hide_scan)

        threading.Thread(target=run, daemon=True).start()

    def run_full_disk_scan(self):
        self.show_scan('DISK_DEEP_SCAN')

        def run():
            found = False
            try:
                for root, _, files in os.walk(r'C:\\'):
                    for f in files:
                        if any(k in f.lower() for k in KEYWORDS):
                            full_p = os.path.join(root, f)
                            m_date, f_type = get_file_info(full_p)
                            self.log_to_ui(
                                f'EXPLOIT | Modified: {m_date} | '
                                f'Type: {f_type} | Dir: {full_p}'
                            )
                            found = True
            except OSError:
                self.log_to_ui('ACCESS_DENIED')

            if not found:
                self.log_to_ui('NO EXPLOITS FOUND')
            self.after(0, self.hide_scan)

        threading.Thread(target=run, daemon=True).start()

    def run_bin_scan(self):
        self.show_scan('BIN_AUDIT')

        def run():
            found = False
            try:
                recycle_bin = r'C:\$Recycle.Bin'
                if os.path.exists(recycle_bin):
                    for root, _, files in os.walk(recycle_bin):
                        for f in files:
                            full_p = os.path.join(root, f)
                            if any(k in full_p.lower() for k in KEYWORDS):
                                m_date, f_type = get_file_info(full_p)
                                self.log_to_ui(
                                    f'DELETED | Modified: {m_date} | '
                                    f'Type: {f_type} | Dir: {full_p}'
                                )
                                found = True
            except OSError:
                pass

            if not found:
                self.log_to_ui('NOTHING FOUND')
            self.after(0, self.hide_scan)

        threading.Thread(target=run, daemon=True).start()


if __name__ == '__main__':
    app = CyberUI()
    app.mainloop()
