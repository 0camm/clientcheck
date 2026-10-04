# Sentinel.py
# Sentinel: local client check tool.
# Needs a site key. The key (plus a hashed PC id) is checked online at startup and is
# NEVER written to disk: it lives in memory for the session and the textbox is cleared
# as soon as it is submitted.
# The Discord ID of the person being checked is remembered on this computer and
# pre-filled on the next launch. It is also sent along with each scan's output.
# After each scan finishes, that scan's output (the same text shown in the console),
# the Discord ID and the PC name are posted to the Sentinel server, which forwards
# them to a Discord webhook. The webhook URL is NOT stored here; it lives only on
# the server.

import hashlib
import json
import os
import re
import socket
import threading
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime

import psutil
import customtkinter as ctk

PC_NAME = socket.gethostname()

API_BASE = 'https://sentinelkeys.onrender.com'  # your Render key server
DATA_DIR = os.path.join(
    os.getenv('APPDATA') or os.path.expanduser('~'), 'Sentinel'
)
SETTINGS_FILE = os.path.join(DATA_DIR, 'settings.json')
LEGACY_LICENSE_FILE = os.path.join(DATA_DIR, 'license.json')  # old builds saved the key here

# ---- Black & white theme ----------------------------------------------------
BG = '#000000'
PANEL = '#0a0a0a'
PANEL_2 = '#141414'
LINE = '#262626'
LINE_HOVER = '#4a4a4a'
TEXT = '#ffffff'
MUTED = '#a3a3a3'
FAINT = '#6b6b6b'
FONT = 'Segoe UI'
MONO = 'Consolas'

# Discord IDs are "snowflakes": numeric, currently 17-20 digits.
DISCORD_ID_RE = re.compile(r'^\d{17,20}$')


def parse_discord_id(raw):
    """Returns (discord_id, error). Accepts a plain ID or a <@id> mention."""
    value = (raw or '').strip()
    mention = re.fullmatch(r'<@!?(\d+)>', value)
    if mention:
        value = mention.group(1)
    if not value:
        return None, 'Enter the Discord ID of the person being checked.'
    if not DISCORD_ID_RE.fullmatch(value):
        return None, 'Invalid Discord ID. It should be 17-20 digits (numbers only).'
    return value, None


def device_id():
    """Anonymous id for this PC (hash only; the raw values never leave it).
    Intentionally independent of the Discord ID."""
    raw = f'{socket.gethostname()}|{uuid.getnode()}'
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


def load_saved_discord_id():
    try:
        with open(SETTINGS_FILE, encoding='utf-8') as fh:
            value = str(json.load(fh).get('discord_id', '')).strip()
        return value if DISCORD_ID_RE.fullmatch(value) else ''
    except (OSError, ValueError, AttributeError):
        return ''


def save_discord_id(discord_id):
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        with open(SETTINGS_FILE, 'w', encoding='utf-8') as fh:
            json.dump({'discord_id': discord_id}, fh)
    except OSError:
        pass


def remove_legacy_saved_key():
    """Older builds stored the site key on disk. Delete it so it no longer lingers."""
    try:
        os.remove(LEGACY_LICENSE_FILE)
    except OSError:
        pass


def _http_error_message(exc, default):
    try:
        msg = json.loads(exc.read().decode()).get('error', default)
    except (ValueError, OSError, AttributeError):
        msg = default
    return msg if isinstance(msg, str) and msg else default


def verify_key(key):
    """Returns (ok, message). Only the site key + hashed PC id are sent."""
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
        return False, _http_error_message(exc, 'invalid key').capitalize() + '.'
    except (urllib.error.URLError, OSError, ValueError):
        return False, 'Could not reach the key server. Check your internet and try again.'


MAX_REPORT_CHARS = 100_000
REPORT_ATTEMPTS = 3          # the free Render server may be asleep on the first try
RETRY_STATUSES = {429, 500, 502, 503, 504}


def send_report(key, discord_id, scan, log_text):
    """Posts the console log to the key server. Returns (ok, message).
    Retries on cold-start / transient failures."""
    body = json.dumps({
        'key': key,
        'device': device_id(),
        'discord_id': discord_id,
        'host': PC_NAME,
        'scan': scan,
        'log': log_text[-MAX_REPORT_CHARS:],
    }).encode()
    headers = {
        'Content-Type': 'application/json',
        'User-Agent': 'Sentinel/1.0',
        # The key is also sent as headers so servers that authenticate in
        # middleware (before the JSON body is read) can see it.
        'Authorization': f'Bearer {key}',
        'X-Sentinel-Key': key,
        'X-Sentinel-Device': device_id(),
    }

    last = 'log not sent (unknown error).'
    for attempt in range(REPORT_ATTEMPTS):
        req = urllib.request.Request(
            f'{API_BASE}/api/report', data=body, method='POST', headers=headers
        )
        try:
            with urllib.request.urlopen(req, timeout=75) as resp:
                if resp.status == 200:
                    return True, 'log sent.'
                last = f'log not sent (HTTP {resp.status}).'
        except urllib.error.HTTPError as exc:
            msg = _http_error_message(exc, 'rejected')
            last = f'log not sent (HTTP {exc.code}: {msg}).'
            if exc.code not in RETRY_STATUSES:
                return False, last      # 400/401/403: retrying will not help
        except (urllib.error.URLError, OSError, ValueError):
            last = 'log not sent (could not reach the server).'
        if attempt < REPORT_ATTEMPTS - 1:
            time.sleep(3 * (attempt + 1))
    return False, last


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
        ctk.set_appearance_mode('dark')
        self.title('Sentinel')
        self.geometry('1200x750')
        self.minsize(900, 600)
        self.configure(fg_color=BG)

        self.discord_id = ''
        self.scanning = False     # prevents overlapping scans
        self.site_key = ''        # memory only; never written to disk
        self.scan_buffer = []     # output of the scan currently running

        remove_legacy_saved_key()
        self.setup_login()

    # ------------------------------------------------------------------
    # Small UI helpers
    # ------------------------------------------------------------------
    def entry(self, parent, placeholder, show=None):
        return ctk.CTkEntry(
            parent,
            width=380,
            height=44,
            placeholder_text=placeholder,
            justify='center',
            fg_color=PANEL,
            border_color=LINE,
            border_width=1,
            text_color=TEXT,
            placeholder_text_color=FAINT,
            corner_radius=8,
            font=(FONT, 13),
            show=show,
        )

    def primary_btn(self, parent, text, cmd, **kw):
        return ctk.CTkButton(
            parent,
            text=text,
            command=cmd,
            fg_color=TEXT,
            hover_color='#d4d4d4',
            text_color=BG,
            text_color_disabled='#555555',
            corner_radius=8,
            font=(FONT, 13, 'bold'),
            height=44,
            **kw,
        )

    # ------------------------------------------------------------------
    # Login / verification
    # ------------------------------------------------------------------
    def setup_login(self):
        self.login_overlay = ctk.CTkFrame(self, fg_color=BG, corner_radius=0)
        self.login_overlay.place(relx=0, rely=0, relwidth=1, relheight=1)

        card = ctk.CTkFrame(self.login_overlay, fg_color='transparent')
        card.place(relx=0.5, rely=0.5, anchor='center')

        ctk.CTkLabel(
            card, text='SENTINEL', font=(FONT, 34, 'bold'), text_color=TEXT
        ).pack(pady=(0, 6))

        ctk.CTkLabel(
            card,
            text='Enter the Discord ID of the person being checked and your site key.',
            font=(FONT, 13),
            text_color=MUTED,
        ).pack(pady=(0, 24))

        self.discord_entry = self.entry(card, 'Discord ID (e.g. 123456789012345678)')
        self.discord_entry.pack(pady=6)
        self.discord_entry.bind('<Return>', lambda _e: self.key_entry.focus_set())

        # show='•' keeps the key off-screen while it is typed.
        self.key_entry = self.entry(card, 'Site key (SNTL-XXXX-XXXX-XXXX-XXXX)', show='•')
        self.key_entry.pack(pady=6)
        self.key_entry.bind('<Return>', lambda _e: self.activate())

        self.activate_btn = self.primary_btn(
            card, 'Activate', self.activate, width=380
        )
        self.activate_btn.pack(pady=(14, 6))

        self.key_status = ctk.CTkLabel(
            card, text='', font=(FONT, 12), text_color=MUTED, wraplength=380
        )
        self.key_status.pack(pady=(10, 0))

        ctk.CTkLabel(
            card,
            text=(
                'Your site key and an anonymous PC id are checked online, and the key is '
                'tied to this PC. The key is never saved.\n\n'
                'The Discord ID is remembered on this computer for next time. When a scan '
                'finishes, its output, the Discord ID and the PC name are sent '
                'automatically to the Sentinel server.\n\n'
                'Only scan systems you are authorized to inspect.'
            ),
            font=(FONT, 11),
            text_color=FAINT,
            wraplength=420,
            justify='center',
        ).pack(pady=(26, 0))

        # Restore the last Discord ID. The site key is never restored.
        saved = load_saved_discord_id()
        if saved:
            self.discord_entry.insert(0, saved)
            self.key_entry.focus_set()
        else:
            self.discord_entry.focus_set()

    def set_status(self, text, error=True):
        self.key_status.configure(text=text, text_color=TEXT if error else MUTED)

    def activate(self):
        if self.activate_btn.cget('state') == 'disabled':
            return

        discord_id, err = parse_discord_id(self.discord_entry.get())
        if err:
            self.set_status(err)
            return

        key = self.key_entry.get().strip()
        if not key:
            self.set_status('Enter your site key first.')
            return

        # The key leaves the textbox the moment it is submitted.
        self.key_entry.delete(0, 'end')
        self.activate_btn.configure(state='disabled')
        self.set_status(
            'Checking key... (the server can take up to a minute to wake up)',
            error=False,
        )

        def run():
            try:
                ok, msg = verify_key(key)
            except Exception:  # never let a worker thread die silently
                ok, msg = False, 'Unexpected error while checking the key.'
            self.after(0, lambda: self.on_activation(ok, msg, key, discord_id))

        threading.Thread(target=run, daemon=True).start()

    def on_activation(self, ok, msg, key, discord_id):
        self.activate_btn.configure(state='normal')
        if ok:
            save_discord_id(discord_id)
            self.site_key = key          # memory only
            self.discord_id = discord_id
            self.continue_to_app()
        else:
            self.set_status(msg)
            self.key_entry.focus_set()

    def continue_to_app(self):
        self.login_overlay.place_forget()
        self.setup_main_ui()

    # ------------------------------------------------------------------
    # Main UI
    # ------------------------------------------------------------------
    def setup_main_ui(self):
        self.top_bar = ctk.CTkFrame(
            self, height=48, fg_color=PANEL, corner_radius=0
        )
        self.top_bar.pack(side='top', fill='x')
        self.top_bar.pack_propagate(False)

        ctk.CTkLabel(
            self.top_bar,
            text=f'Host: {PC_NAME}',
            font=(MONO, 12),
            text_color=MUTED,
        ).pack(side='left', padx=20)

        ctk.CTkLabel(
            self.top_bar,
            text=f'Checking Discord ID: {self.discord_id}',
            font=(MONO, 12, 'bold'),
            text_color=TEXT,
        ).pack(side='right', padx=20)

        ctk.CTkFrame(self, height=1, fg_color=LINE, corner_radius=0).pack(
            side='top', fill='x'
        )

        self.main_container = ctk.CTkFrame(self, fg_color='transparent')
        self.main_container.pack(fill='both', expand=True, padx=24, pady=20)

        self.left_panel = ctk.CTkFrame(
            self.main_container, fg_color='transparent', width=260
        )
        self.left_panel.pack(side='left', fill='y', padx=(0, 24))
        self.left_panel.pack_propagate(False)

        ctk.CTkLabel(
            self.left_panel,
            text='SENTINEL',
            font=(FONT, 28, 'bold'),
            text_color=TEXT,
        ).pack(anchor='w', pady=(4, 0))

        ctk.CTkLabel(
            self.left_panel,
            text='Client check',
            font=(FONT, 12),
            text_color=FAINT,
        ).pack(anchor='w', pady=(0, 22))

        self.create_scan_btn('Processes', self.run_process_scan)
        self.create_scan_btn('Strappers', self.run_strapper_scan)
        self.create_scan_btn('Prefetch', self.run_prefetch_scan)
        self.create_scan_btn('Deleted files', self.run_bin_scan)
        self.create_scan_btn('Exploit scan', self.run_full_disk_scan)

        self.right_panel = ctk.CTkFrame(
            self.main_container,
            fg_color=PANEL,
            border_width=1,
            border_color=LINE,
            corner_radius=10,
        )
        self.right_panel.pack(side='right', fill='both', expand=True)

        self.console = ctk.CTkTextbox(
            self.right_panel,
            fg_color='transparent',
            text_color=TEXT,
            font=(MONO, 12),
            wrap='word',
        )
        self.console.pack(fill='both', expand=True, padx=12, pady=12)

        self.overlay = ctk.CTkFrame(self, fg_color=BG, corner_radius=0)
        center = ctk.CTkFrame(self.overlay, fg_color='transparent')
        center.place(relx=0.5, rely=0.5, anchor='center')

        self.scan_text = ctk.CTkLabel(
            center, text='Running...', font=(FONT, 30, 'bold'), text_color=TEXT
        )
        self.scan_text.pack(pady=(0, 8))

        self.scan_target = ctk.CTkLabel(
            center, text='', font=(MONO, 13), text_color=MUTED
        )
        self.scan_target.pack(pady=(0, 24))

        self.progress = ctk.CTkProgressBar(
            center,
            width=380,
            height=4,
            fg_color=LINE,
            progress_color=TEXT,
            mode='indeterminate',
        )
        self.progress.pack()

    def create_scan_btn(self, text, cmd):
        ctk.CTkButton(
            self.left_panel,
            text=text,
            fg_color=PANEL,
            hover_color=PANEL_2,
            border_width=1,
            border_color=LINE,
            text_color=TEXT,
            corner_radius=8,
            font=(FONT, 13),
            anchor='w',
            height=44,
            command=cmd,
        ).pack(pady=5, fill='x')

    # ------------------------------------------------------------------
    # Console / scan overlay helpers
    # ------------------------------------------------------------------
    def log_to_ui(self, msg, record=True):
        """Safe to call from worker threads: the widget update runs on the UI thread.
        record=True also adds the line to the current scan's upload buffer."""
        if record:
            self.scan_buffer.append(str(msg))

        def _write():
            self.console.insert('end', f'{msg}\n\n')
            self.console.see('end')
        self.after(0, _write)

    def show_scan(self, txt):
        """Returns False if a scan is already running."""
        if self.scanning:
            return False
        self.scanning = True
        self.scan_buffer = []
        self.scan_text.configure(text=txt)
        self.scan_target.configure(text=f'Checking Discord ID: {self.discord_id}')
        self.overlay.place(relx=0, rely=0, relwidth=1, relheight=1)
        self.overlay.lift()
        self.progress.start()
        stamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self.log_to_ui(f'=== {txt} | Discord ID: {self.discord_id} | {stamp} ===')
        return True

    def hide_scan(self):
        self.progress.stop()
        self.overlay.place_forget()
        self.scanning = False

    def send_log(self, title, text):
        try:
            ok, msg = send_report(self.site_key, self.discord_id, title, text)
        except Exception:
            ok, msg = False, 'log not sent (unexpected error).'
        self.log_to_ui(f'WEBHOOK: {msg}', record=False)

    def start_scan(self, title, worker):
        """Runs `worker` on a background thread, releases the overlay, then
        automatically uploads that scan's output."""
        if not self.show_scan(title):
            return

        def run():
            try:
                worker()
            except Exception as exc:  # keep UI alive on any unexpected scan error
                self.log_to_ui(f'SCAN_ERROR: {exc}')
            finally:
                report = '\n\n'.join(self.scan_buffer)
                self.after(0, self.hide_scan)
            self.send_log(title, report)

        threading.Thread(target=run, daemon=True).start()

    # ------------------------------------------------------------------
    # Scans
    # ------------------------------------------------------------------
    def run_prefetch_scan(self):
        def work():
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

        self.start_scan('PREFETCH_AUDIT', work)

    def run_process_scan(self):
        def work():
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

        self.start_scan('PROC_AUDIT', work)

    def run_strapper_scan(self):
        def work():
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

        self.start_scan('STRAP_CHECK', work)

    def run_full_disk_scan(self):
        def work():
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

        self.start_scan('DISK_DEEP_SCAN', work)

    def run_bin_scan(self):
        def work():
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

        self.start_scan('BIN_AUDIT', work)


if __name__ == '__main__':
    app = CyberUI()
    app.mainloop()
