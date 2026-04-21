"""
SecureHAWK v0.3 - File Integrity Monitor with GUI
==================================================
A graphical interface for configuring and running the file monitor.
Features:
  - Native Windows folder/file picker dialogs
  - Live event viewer inside the GUI
  - One-click start/stop
  - Automatic browser dashboard launch
  - All settings remembered between sessions (optional save)

Requirements (when running as .py):
    pip install watchdog flask flask-cors psutil

When built with build_exe.bat, users don't need Python at all.
"""

import os
import sys
import time
import json
import hmac
import secrets
import hashlib
import getpass
import socket
import threading
import webbrowser
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from datetime import datetime
from pathlib import Path
from queue import Queue, Empty
from collections import defaultdict

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
except ImportError:
    tk.Tk().withdraw()
    messagebox.showerror("Missing Dependency",
        "The 'watchdog' library is not installed.\n\n"
        "Run: pip install watchdog flask flask-cors psutil")
    sys.exit(1)

try:
    from flask import Flask, Response, render_template_string, jsonify, request, abort
    from flask_cors import CORS
except ImportError:
    tk.Tk().withdraw()
    messagebox.showerror("Missing Dependency",
        "The 'flask' and 'flask-cors' libraries are not installed.\n\n"
        "Run: pip install watchdog flask flask-cors psutil")
    sys.exit(1)

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False


# ===================================================================
# CONSTANTS & GLOBAL STATE
# ===================================================================
APP_VERSION = "0.3"
SESSION_TOKEN = secrets.token_urlsafe(32)
CONFIG_FILE = Path.home() / ".securehawk_config.json"

event_queue = Queue()
event_history = []
MAX_HISTORY = 300

session_info = {
    "watch_directory": "",
    "log_file": "",
    "started_at": "",
    "user": "",
    "host": "",
    "event_count": 0,
    "atime_enabled": False,
    "version": APP_VERSION,
}

hash_registry = defaultdict(list)
hash_registry_lock = threading.Lock()
access_tracker = {}
access_tracker_lock = threading.Lock()

# GUI will set this reference so the detection code can post to the GUI log
gui_log_callback = None


# ===================================================================
# DETECTION HELPERS
# ===================================================================

def verify_token():
    provided = request.args.get("token") or request.headers.get("X-Session-Token", "")
    if not provided:
        return False
    return hmac.compare_digest(provided, SESSION_TOKEN)


def compute_file_hash(path, full=False):
    try:
        if not os.path.isfile(path):
            return None
        sha = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha.update(chunk)
        return sha.hexdigest() if full else sha.hexdigest()[:16]
    except (OSError, PermissionError):
        return None


def check_downloaded_marker(path):
    if os.name != "nt":
        return None
    try:
        zone_stream = path + ":Zone.Identifier"
        if not os.path.exists(zone_stream):
            return None
        with open(zone_stream, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        zone_id, referrer, host_url = None, None, None
        for line in content.splitlines():
            line = line.strip()
            if line.startswith("ZoneId="):
                zone_id = line.split("=", 1)[1].strip()
            elif line.startswith("ReferrerUrl="):
                referrer = line.split("=", 1)[1].strip()
            elif line.startswith("HostUrl="):
                host_url = line.split("=", 1)[1].strip()
        if zone_id in ("3", "4"):
            source = host_url or referrer or "unknown source"
            return f"from={source}"
        elif zone_id == "2":
            return "from=trusted zone"
        elif zone_id == "1":
            return "from=intranet"
        return None
    except (OSError, PermissionError):
        return None


def find_copy_source(file_path, file_hash):
    if not file_hash:
        return None
    with hash_registry_lock:
        existing = hash_registry.get(file_hash, [])
        for other in existing:
            if os.path.normcase(other) != os.path.normcase(file_path):
                if os.path.exists(other):
                    return other
    return None


def register_hash(file_path, file_hash):
    if not file_hash:
        return
    with hash_registry_lock:
        if file_path not in hash_registry[file_hash]:
            hash_registry[file_hash].append(file_path)


def unregister_hash(file_path):
    with hash_registry_lock:
        for h, paths in list(hash_registry.items()):
            if file_path in paths:
                paths.remove(file_path)
                if not paths:
                    del hash_registry[h]


def get_active_process_hint():
    if not PSUTIL_AVAILABLE:
        return None
    try:
        procs = []
        for p in psutil.process_iter(["name", "cpu_percent", "username"]):
            try:
                info = p.info
                if info.get("username") and session_info["user"] in str(info["username"]):
                    procs.append(info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        if not procs:
            return None
        procs.sort(key=lambda x: x.get("cpu_percent") or 0, reverse=True)
        top = procs[0].get("name")
        return f"likely_process={top}" if top else None
    except Exception:
        return None


def check_atime_enabled(watch_dir):
    try:
        test_file = os.path.join(watch_dir, f".atime_test_{secrets.token_hex(4)}.tmp")
        with open(test_file, "w") as f:
            f.write("test")
        time.sleep(0.2)
        initial_atime = os.path.getatime(test_file)
        time.sleep(1.2)
        with open(test_file, "r") as f:
            _ = f.read()
        time.sleep(0.2)
        new_atime = os.path.getatime(test_file)
        os.remove(test_file)
        return new_atime > initial_atime
    except Exception:
        return False


# ===================================================================
# ACCESS POLLER (detects opens)
# ===================================================================

class AccessPoller(threading.Thread):
    def __init__(self, watch_dir, recursive, callback, interval=3.0):
        super().__init__(daemon=True)
        self.watch_dir = watch_dir
        self.recursive = recursive
        self.callback = callback
        self.interval = interval
        self.running = True

    def run(self):
        self._scan(emit=False)
        while self.running:
            time.sleep(self.interval)
            try:
                self._scan(emit=True)
            except Exception:
                pass

    def _scan(self, emit=True):
        if self.recursive:
            walker = os.walk(self.watch_dir)
        else:
            try:
                entries = os.listdir(self.watch_dir)
            except OSError:
                return
            walker = [(self.watch_dir, [], [e for e in entries if os.path.isfile(os.path.join(self.watch_dir, e))])]

        current_paths = set()
        for root, dirs, files in walker:
            for name in files:
                path = os.path.join(root, name)
                current_paths.add(path)
                try:
                    atime = os.path.getatime(path)
                    mtime = os.path.getmtime(path)
                except OSError:
                    continue
                with access_tracker_lock:
                    prev = access_tracker.get(path)
                    access_tracker[path] = atime
                if emit and prev is not None and atime > prev + 0.5:
                    if abs(atime - mtime) > 1.0:
                        self.callback(path)

        with access_tracker_lock:
            for stale in list(access_tracker.keys()):
                if stale not in current_paths and stale.startswith(self.watch_dir):
                    del access_tracker[stale]

    def stop(self):
        self.running = False


# ===================================================================
# FILE WATCHER
# ===================================================================

class FileChangeLogger(FileSystemEventHandler):
    def __init__(self, log_file_path, watch_directory):
        super().__init__()
        self.log_file_path = log_file_path
        self.watch_directory = watch_directory
        self._write_session_header()
        self._seed_hash_registry()

    def _seed_hash_registry(self):
        count = 0
        for root, dirs, files in os.walk(self.watch_directory):
            for name in files:
                path = os.path.join(root, name)
                try:
                    if os.path.getsize(path) > 50 * 1024 * 1024:
                        continue
                except OSError:
                    continue
                full_hash = compute_file_hash(path, full=True)
                if full_hash:
                    register_hash(path, full_hash)
                    count += 1
        if gui_log_callback:
            gui_log_callback(f"[INIT] Indexed {count} existing files for copy detection")

    def _write_session_header(self):
        header = (
            "\n" + "=" * 70 + "\n"
            f"  SECUREHAWK v{APP_VERSION} - SESSION STARTED\n"
            f"  Time:      {session_info['started_at']}\n"
            f"  Watching:  {self.watch_directory}\n"
            f"  User:      {session_info['user']}\n"
            f"  Host:      {session_info['host']}\n"
            + "=" * 70 + "\n\n"
        )
        self._write_to_log(header)

    def _write_to_log(self, message):
        try:
            with open(self.log_file_path, "a", encoding="utf-8") as log:
                log.write(message)
        except Exception as e:
            if gui_log_callback:
                gui_log_callback(f"[ERROR] Log write failed: {e}")

    def _get_file_size(self, path):
        try:
            if os.path.isfile(path):
                return os.path.getsize(path)
        except OSError:
            return None
        return None

    def emit_event(self, event_type, file_path, extras_list=None):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        kind = "DIR" if os.path.isdir(file_path) else "FILE"
        extras = extras_list or []
        extra_str = " ".join(extras)

        log_entry = f"[{timestamp}] {event_type:<10} {kind:<4} | {file_path}"
        if extra_str:
            log_entry += f" | {extra_str}"
        log_entry += "\n"
        self._write_to_log(log_entry)

        if gui_log_callback:
            gui_log_callback(log_entry.rstrip(), event_type=event_type)

        web_event = {
            "timestamp": timestamp,
            "type": event_type,
            "kind": kind,
            "path": file_path,
            "extra": extra_str,
        }
        event_queue.put(web_event)
        event_history.append(web_event)
        if len(event_history) > MAX_HISTORY:
            event_history.pop(0)
        session_info["event_count"] += 1

    def on_created(self, event):
        if event.is_directory:
            self.emit_event("CREATED", event.src_path)
            return
        path = event.src_path
        size = self._get_file_size(path)
        full_hash = compute_file_hash(path, full=True)
        short_hash = full_hash[:16] if full_hash else None
        extras = []
        if size is not None:
            extras.append(f"size={size}B")
        if short_hash:
            extras.append(f"sha256={short_hash}")
        proc_hint = get_active_process_hint()
        if proc_hint:
            extras.append(proc_hint)
        self.emit_event("CREATED", path, extras)

        download_info = check_downloaded_marker(path)
        if download_info:
            self.emit_event("DOWNLOADED", path, [download_info])

        copy_source = find_copy_source(path, full_hash)
        if copy_source:
            self.emit_event("COPIED", path, [f"source={copy_source}"])

        if full_hash:
            register_hash(path, full_hash)

    def on_deleted(self, event):
        self.emit_event("DELETED", event.src_path)
        unregister_hash(event.src_path)

    def on_modified(self, event):
        if event.is_directory:
            return
        path = event.src_path
        size = self._get_file_size(path)
        full_hash = compute_file_hash(path, full=True)
        short_hash = full_hash[:16] if full_hash else None
        extras = []
        if size is not None:
            extras.append(f"size={size}B")
        if short_hash:
            extras.append(f"sha256={short_hash}")
        proc_hint = get_active_process_hint()
        if proc_hint:
            extras.append(proc_hint)
        self.emit_event("MODIFIED", path, extras)
        unregister_hash(path)
        if full_hash:
            register_hash(path, full_hash)

    def on_moved(self, event):
        self.emit_event("MOVED", event.src_path, [f"-> {event.dest_path}"])
        unregister_hash(event.src_path)
        full_hash = compute_file_hash(event.dest_path, full=True)
        if full_hash:
            register_hash(event.dest_path, full_hash)

    def on_opened(self, file_path):
        size = self._get_file_size(file_path)
        extras = []
        if size is not None:
            extras.append(f"size={size}B")
        proc_hint = get_active_process_hint()
        if proc_hint:
            extras.append(proc_hint)
        self.emit_event("OPENED", file_path, extras)


# ===================================================================
# HTML DASHBOARD (same as enhanced version - embedded)
# ===================================================================

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>SecureHAWK - Live Dashboard</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',system-ui,sans-serif;background:#0a0e1a;color:#c5d1e6;min-height:100vh;padding:20px}
header{background:linear-gradient(135deg,#0f1729,#1a2540);border:1px solid #2a3a5a;border-radius:12px;padding:20px 24px;margin-bottom:16px;display:flex;justify-content:space-between;align-items:center}
h1{font-size:22px;color:#5aefff;letter-spacing:2px;font-weight:700}
.header-right{display:flex;align-items:center;gap:16px}
.secure-badge{display:flex;align-items:center;gap:6px;padding:4px 10px;background:#2aff6b15;border:1px solid #2aff6b44;border-radius:4px;font-size:10px;color:#2aff6b;letter-spacing:1.5px;font-weight:600}
.secure-badge::before{content:"🔒";font-size:11px}
.live-indicator{display:flex;align-items:center;gap:8px;font-size:12px;color:#2aff6b;font-weight:600;letter-spacing:1.5px}
.pulse{width:10px;height:10px;border-radius:50%;background:#2aff6b;box-shadow:0 0 12px #2aff6b;animation:pulse 1.5s ease-in-out infinite}
@keyframes pulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.4;transform:scale(.85)}}
.session-info{background:#0f1729;border:1px solid #2a3a5a;border-radius:12px;padding:16px 24px;margin-bottom:16px;display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px}
.info-item{display:flex;flex-direction:column;gap:4px}
.info-label{font-size:10px;color:#5a7a9a;letter-spacing:1.5px;text-transform:uppercase}
.info-value{font-size:13px;color:#c5d1e6;font-family:'Consolas','Courier New',monospace;word-break:break-all}
.stats{display:grid;grid-template-columns:repeat(7,1fr);gap:10px;margin-bottom:16px}
.stat-card{background:#0f1729;border:1px solid #2a3a5a;border-radius:10px;padding:12px 14px}
.stat-label{font-size:9px;color:#5a7a9a;letter-spacing:1.5px;text-transform:uppercase;margin-bottom:4px}
.stat-value{font-size:22px;font-weight:700;font-family:'Consolas',monospace}
.stat-value.created{color:#2aff6b}.stat-value.modified{color:#ffc42a}.stat-value.deleted{color:#ff2a2a}
.stat-value.moved{color:#2ad4ff}.stat-value.opened{color:#b967ff}.stat-value.copied{color:#ff8c42}
.stat-value.downloaded{color:#ff4785}.stat-value.total{color:#5aefff}
.filters{display:flex;gap:6px;flex-wrap:wrap;padding:10px 16px;background:#0f1729;border:1px solid #2a3a5a;border-radius:10px;margin-bottom:12px}
.filter-btn{background:#1a2540;border:1px solid #2a3a5a;color:#8aa4c0;padding:5px 12px;border-radius:4px;cursor:pointer;font-size:10px;letter-spacing:1px;text-transform:uppercase;font-family:inherit}
.filter-btn:hover{background:#2a3a5a;color:#c5d1e6}
.filter-btn.active{background:#2ad4ff22;border-color:#2ad4ff66;color:#5aefff}
.events-container{background:#0f1729;border:1px solid #2a3a5a;border-radius:12px;overflow:hidden}
.events-header{padding:14px 20px;border-bottom:1px solid #2a3a5a;display:flex;justify-content:space-between;align-items:center}
.events-title{font-size:12px;color:#5a7a9a;letter-spacing:2px;text-transform:uppercase}
.clear-btn{background:#1a2540;border:1px solid #2a3a5a;color:#5a7a9a;padding:6px 14px;border-radius:6px;cursor:pointer;font-size:11px;letter-spacing:1px;text-transform:uppercase;font-family:inherit}
.clear-btn:hover{background:#2a3a5a;color:#c5d1e6}
.events-list{max-height:calc(100vh - 450px);overflow-y:auto;font-family:'Consolas',monospace;font-size:12px}
.events-list::-webkit-scrollbar{width:6px}
.events-list::-webkit-scrollbar-track{background:#0a0e1a}
.events-list::-webkit-scrollbar-thumb{background:#2a3a5a;border-radius:3px}
.event{padding:10px 20px;border-bottom:1px solid #1a2540;display:grid;grid-template-columns:160px 100px 50px 1fr 240px;gap:12px;align-items:center;animation:slideIn .3s ease-out}
@keyframes slideIn{from{opacity:0;transform:translateX(-10px);background:#1a2540}to{opacity:1;transform:translateX(0);background:transparent}}
.event-time{color:#5a7a9a}
.event-type{font-weight:700;text-transform:uppercase;letter-spacing:1px;font-size:10px;padding:3px 8px;border-radius:4px;text-align:center}
.event-type.created{background:#2aff6b22;color:#2aff6b}
.event-type.modified{background:#ffc42a22;color:#ffc42a}
.event-type.deleted{background:#ff2a2a22;color:#ff2a2a}
.event-type.moved{background:#2ad4ff22;color:#2ad4ff}
.event-type.opened{background:#b967ff22;color:#b967ff}
.event-type.copied{background:#ff8c4222;color:#ff8c42}
.event-type.downloaded{background:#ff478522;color:#ff4785}
.event-kind{font-size:10px;color:#5a7a9a;letter-spacing:1px}
.event-path{color:#c5d1e6;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.event-extra{color:#5a7a9a;font-size:11px;text-align:right;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.empty-state{padding:60px 20px;text-align:center;color:#3a5a7a}
.connection-status{position:fixed;bottom:20px;right:20px;padding:8px 16px;border-radius:6px;font-size:11px;letter-spacing:1px;text-transform:uppercase;background:#0f1729;border:1px solid #2a3a5a}
.connection-status.connected{color:#2aff6b;border-color:#2aff6b44}
.connection-status.disconnected{color:#ff2a2a;border-color:#ff2a2a44}
</style></head><body>
<header>
<h1>SECUREHAWK v__VERSION__ &middot; LIVE DASHBOARD</h1>
<div class="header-right">
<div class="secure-badge">AUTHENTICATED</div>
<div class="live-indicator"><div class="pulse"></div><span>STREAMING</span></div>
</div></header>
<div class="session-info">
<div class="info-item"><span class="info-label">Watching</span><span class="info-value" id="watchDir">Loading...</span></div>
<div class="info-item"><span class="info-label">Log File</span><span class="info-value" id="logFile">Loading...</span></div>
<div class="info-item"><span class="info-label">User</span><span class="info-value" id="user">Loading...</span></div>
<div class="info-item"><span class="info-label">Host</span><span class="info-value" id="host">Loading...</span></div>
<div class="info-item"><span class="info-label">Started</span><span class="info-value" id="started">Loading...</span></div>
</div>
<div class="stats">
<div class="stat-card"><div class="stat-label">Total</div><div class="stat-value total" id="statTotal">0</div></div>
<div class="stat-card"><div class="stat-label">Created</div><div class="stat-value created" id="statCREATED">0</div></div>
<div class="stat-card"><div class="stat-label">Modified</div><div class="stat-value modified" id="statMODIFIED">0</div></div>
<div class="stat-card"><div class="stat-label">Opened</div><div class="stat-value opened" id="statOPENED">0</div></div>
<div class="stat-card"><div class="stat-label">Copied</div><div class="stat-value copied" id="statCOPIED">0</div></div>
<div class="stat-card"><div class="stat-label">Downloaded</div><div class="stat-value downloaded" id="statDOWNLOADED">0</div></div>
<div class="stat-card"><div class="stat-label">Deleted</div><div class="stat-value deleted" id="statDELETED">0</div></div>
</div>
<div class="filters">
<button class="filter-btn active" data-filter="ALL">All Events</button>
<button class="filter-btn" data-filter="CREATED">Created</button>
<button class="filter-btn" data-filter="MODIFIED">Modified</button>
<button class="filter-btn" data-filter="OPENED">Opened</button>
<button class="filter-btn" data-filter="COPIED">Copied</button>
<button class="filter-btn" data-filter="DOWNLOADED">Downloaded</button>
<button class="filter-btn" data-filter="DELETED">Deleted</button>
<button class="filter-btn" data-filter="MOVED">Moved</button>
</div>
<div class="events-container">
<div class="events-header"><span class="events-title">Real-Time Event Stream</span><button class="clear-btn" onclick="clearEvents()">Clear View</button></div>
<div class="events-list" id="eventsList"><div class="empty-state">Waiting for file system events...</div></div>
</div>
<div class="connection-status connected" id="connectionStatus">CONNECTED</div>
<script>
const SESSION_TOKEN="__SESSION_TOKEN__";
const stats={};const eventsList=document.getElementById('eventsList');let isEmpty=true;let activeFilter='ALL';
function authFetch(url){return fetch(url,{headers:{'X-Session-Token':SESSION_TOKEN}})}
authFetch('/api/session').then(r=>r.json()).then(data=>{
document.getElementById('watchDir').textContent=data.watch_directory||'N/A';
document.getElementById('logFile').textContent=data.log_file||'N/A';
document.getElementById('user').textContent=data.user||'N/A';
document.getElementById('host').textContent=data.host||'N/A';
document.getElementById('started').textContent=data.started_at||'N/A';
});
authFetch('/api/history').then(r=>r.json()).then(events=>events.forEach(addEvent));
const eventSource=new EventSource('/stream?token='+encodeURIComponent(SESSION_TOKEN));
eventSource.onmessage=(e)=>addEvent(JSON.parse(e.data));
eventSource.onopen=()=>{document.getElementById('connectionStatus').textContent='CONNECTED';document.getElementById('connectionStatus').className='connection-status connected'};
eventSource.onerror=()=>{document.getElementById('connectionStatus').textContent='DISCONNECTED';document.getElementById('connectionStatus').className='connection-status disconnected'};
document.querySelectorAll('.filter-btn').forEach(btn=>{btn.addEventListener('click',()=>{document.querySelectorAll('.filter-btn').forEach(b=>b.classList.remove('active'));btn.classList.add('active');activeFilter=btn.dataset.filter;applyFilter()})});
function applyFilter(){document.querySelectorAll('.event').forEach(el=>{if(activeFilter==='ALL'||el.dataset.type===activeFilter){el.style.display=''}else{el.style.display='none'}})}
function addEvent(event){if(isEmpty){eventsList.innerHTML='';isEmpty=false}
stats[event.type]=(stats[event.type]||0)+1;updateStats();
const d=document.createElement('div');d.className='event';d.dataset.type=event.type;
if(activeFilter!=='ALL'&&activeFilter!==event.type){d.style.display='none'}
d.innerHTML=`<span class="event-time">${event.timestamp}</span><span class="event-type ${event.type.toLowerCase()}">${event.type}</span><span class="event-kind">${event.kind}</span><span class="event-path" title="${esc(event.path)}">${esc(event.path)}</span><span class="event-extra" title="${esc(event.extra||'')}">${esc(event.extra||'')}</span>`;
eventsList.insertBefore(d,eventsList.firstChild);while(eventsList.children.length>400){eventsList.removeChild(eventsList.lastChild)}}
function updateStats(){['CREATED','MODIFIED','DELETED','MOVED','OPENED','COPIED','DOWNLOADED'].forEach(t=>{const el=document.getElementById('stat'+t);if(el)el.textContent=stats[t]||0});
document.getElementById('statTotal').textContent=Object.values(stats).reduce((a,b)=>a+b,0)}
function clearEvents(){eventsList.innerHTML='<div class="empty-state">View cleared. Waiting for new events...</div>';isEmpty=true}
function esc(t){const d=document.createElement('div');d.textContent=t;return d.innerHTML}
</script></body></html>"""

UNAUTHORIZED_HTML = """<!DOCTYPE html><html><head><title>Unauthorized</title><style>
body{font-family:system-ui,sans-serif;background:#0a0e1a;color:#c5d1e6;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
.box{text-align:center;padding:40px;border:1px solid #ff2a2a44;border-radius:12px;background:#0f1729;max-width:500px}
h1{color:#ff2a2a;margin:0 0 16px;font-size:22px}
p{color:#8aa4c0;line-height:1.6;margin:0 0 12px}
</style></head><body><div class="box"><h1>🔒 UNAUTHORIZED</h1>
<p>Valid session token required. Use the dashboard link from the SecureHAWK application window.</p>
</div></body></html>"""


# ===================================================================
# WEB SERVER
# ===================================================================

app = Flask(__name__)
import logging
logging.getLogger("werkzeug").setLevel(logging.ERROR)
app.logger.setLevel(logging.ERROR)


@app.route("/")
def dashboard():
    if not verify_token():
        return Response(UNAUTHORIZED_HTML, status=401, mimetype="text/html")
    html = DASHBOARD_HTML.replace("__SESSION_TOKEN__", SESSION_TOKEN).replace("__VERSION__", APP_VERSION)
    return render_template_string(html)


@app.route("/api/session")
def api_session():
    if not verify_token():
        abort(401)
    return jsonify(session_info)


@app.route("/api/history")
def api_history():
    if not verify_token():
        abort(401)
    return jsonify(event_history)


@app.route("/stream")
def stream():
    if not verify_token():
        abort(401)
    def generate():
        while True:
            try:
                event = event_queue.get(timeout=15)
                yield f"data: {json.dumps(event)}\n\n"
            except Empty:
                yield ": heartbeat\n\n"
    return Response(generate(), mimetype="text/event-stream", headers={
        "Cache-Control": "no-cache", "X-Accel-Buffering": "no",
    })


# ===================================================================
# GUI APPLICATION
# ===================================================================

class SecureHAWKApp:
    # Color palette matching the web dashboard
    BG_DARK = "#0a0e1a"
    BG_PANEL = "#0f1729"
    BG_ELEVATED = "#1a2540"
    BORDER = "#2a3a5a"
    TEXT_PRIMARY = "#c5d1e6"
    TEXT_SECONDARY = "#8aa4c0"
    TEXT_MUTED = "#5a7a9a"
    ACCENT = "#5aefff"
    ACCENT_GREEN = "#2aff6b"
    ACCENT_YELLOW = "#ffc42a"
    ACCENT_RED = "#ff2a2a"
    ACCENT_BLUE = "#2ad4ff"
    ACCENT_PURPLE = "#b967ff"
    ACCENT_ORANGE = "#ff8c42"
    ACCENT_PINK = "#ff4785"

    EVENT_COLORS = {
        "CREATED": "#2aff6b", "MODIFIED": "#ffc42a", "DELETED": "#ff2a2a",
        "MOVED": "#2ad4ff", "OPENED": "#b967ff", "COPIED": "#ff8c42",
        "DOWNLOADED": "#ff4785",
    }

    def __init__(self):
        self.root = tk.Tk()
        self.root.title(f"SecureHAWK v{APP_VERSION}")
        self.root.geometry("900x700")
        self.root.configure(bg=self.BG_DARK)
        self.root.minsize(750, 600)

        # Try to set a nice icon if available
        try:
            self.root.iconbitmap(default="")  # no icon file, just skip
        except Exception:
            pass

        # State
        self.observer = None
        self.access_poller = None
        self.event_handler = None
        self.server_thread = None
        self.monitoring = False
        self.port = 8080
        self.stats = {"CREATED": 0, "MODIFIED": 0, "DELETED": 0, "MOVED": 0,
                      "OPENED": 0, "COPIED": 0, "DOWNLOADED": 0}

        # Load last session's config
        self.config = self._load_config()

        self._build_ui()
        self._setup_log_callback()

        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _load_config(self):
        try:
            if CONFIG_FILE.exists():
                with open(CONFIG_FILE, "r") as f:
                    return json.load(f)
        except Exception:
            pass
        return {}

    def _save_config(self):
        try:
            cfg = {
                "watch_directory": self.watch_var.get(),
                "log_file": self.log_var.get(),
                "recursive": self.recursive_var.get(),
                "detect_opens": self.detect_opens_var.get(),
                "port": self.port_var.get(),
            }
            with open(CONFIG_FILE, "w") as f:
                json.dump(cfg, f, indent=2)
        except Exception:
            pass

    def _setup_log_callback(self):
        """Wire the global log callback to post to the GUI's event view."""
        global gui_log_callback
        gui_log_callback = self._gui_log

    def _build_ui(self):
        # --- Header ---
        header = tk.Frame(self.root, bg=self.BG_PANEL, height=70)
        header.pack(fill="x", padx=12, pady=(12, 6))
        header.pack_propagate(False)

        title_frame = tk.Frame(header, bg=self.BG_PANEL)
        title_frame.pack(side="left", padx=20, pady=14)

        tk.Label(title_frame, text="🦅 SECUREHAWK", bg=self.BG_PANEL,
                 fg=self.ACCENT, font=("Segoe UI", 16, "bold")).pack(anchor="w")
        tk.Label(title_frame, text=f"FILE INTEGRITY MONITOR · v{APP_VERSION}",
                 bg=self.BG_PANEL, fg=self.TEXT_MUTED,
                 font=("Segoe UI", 8)).pack(anchor="w")

        self.status_label = tk.Label(header, text="● IDLE", bg=self.BG_PANEL,
                                      fg=self.TEXT_MUTED,
                                      font=("Consolas", 11, "bold"))
        self.status_label.pack(side="right", padx=20)

        # --- Configuration Panel ---
        config_frame = tk.LabelFrame(self.root, text=" CONFIGURATION ",
                                      bg=self.BG_PANEL, fg=self.TEXT_MUTED,
                                      font=("Segoe UI", 9, "bold"),
                                      bd=1, relief="solid", labelanchor="nw")
        config_frame.pack(fill="x", padx=12, pady=6)

        # Watch directory row
        row1 = tk.Frame(config_frame, bg=self.BG_PANEL)
        row1.pack(fill="x", padx=12, pady=(12, 6))
        tk.Label(row1, text="WATCH DIRECTORY", bg=self.BG_PANEL,
                 fg=self.TEXT_MUTED, font=("Segoe UI", 8, "bold"),
                 width=18, anchor="w").pack(side="left")
        self.watch_var = tk.StringVar(value=self.config.get("watch_directory", ""))
        watch_entry = tk.Entry(row1, textvariable=self.watch_var,
                               bg=self.BG_ELEVATED, fg=self.TEXT_PRIMARY,
                               insertbackground=self.TEXT_PRIMARY,
                               relief="flat", font=("Consolas", 9),
                               disabledbackground=self.BG_ELEVATED,
                               disabledforeground=self.TEXT_SECONDARY)
        watch_entry.pack(side="left", fill="x", expand=True, padx=(0, 8), ipady=6)
        self.watch_entry = watch_entry
        self.browse_watch_btn = tk.Button(row1, text="Browse...",
                                           bg=self.BG_ELEVATED,
                                           fg=self.ACCENT,
                                           activebackground=self.BORDER,
                                           activeforeground=self.ACCENT,
                                           relief="flat", bd=0,
                                           font=("Segoe UI", 9),
                                           cursor="hand2",
                                           command=self._browse_watch_dir)
        self.browse_watch_btn.pack(side="left", ipadx=10, ipady=4)

        # Log file row
        row2 = tk.Frame(config_frame, bg=self.BG_PANEL)
        row2.pack(fill="x", padx=12, pady=6)
        tk.Label(row2, text="LOG FILE (.txt)", bg=self.BG_PANEL,
                 fg=self.TEXT_MUTED, font=("Segoe UI", 8, "bold"),
                 width=18, anchor="w").pack(side="left")
        self.log_var = tk.StringVar(value=self.config.get("log_file", ""))
        log_entry = tk.Entry(row2, textvariable=self.log_var,
                             bg=self.BG_ELEVATED, fg=self.TEXT_PRIMARY,
                             insertbackground=self.TEXT_PRIMARY,
                             relief="flat", font=("Consolas", 9),
                             disabledbackground=self.BG_ELEVATED,
                             disabledforeground=self.TEXT_SECONDARY)
        log_entry.pack(side="left", fill="x", expand=True, padx=(0, 8), ipady=6)
        self.log_entry = log_entry
        self.browse_log_btn = tk.Button(row2, text="Browse...",
                                         bg=self.BG_ELEVATED,
                                         fg=self.ACCENT,
                                         activebackground=self.BORDER,
                                         activeforeground=self.ACCENT,
                                         relief="flat", bd=0,
                                         font=("Segoe UI", 9),
                                         cursor="hand2",
                                         command=self._browse_log_file)
        self.browse_log_btn.pack(side="left", ipadx=10, ipady=4)

        # Options row
        row3 = tk.Frame(config_frame, bg=self.BG_PANEL)
        row3.pack(fill="x", padx=12, pady=(6, 12))
        tk.Label(row3, text="OPTIONS", bg=self.BG_PANEL,
                 fg=self.TEXT_MUTED, font=("Segoe UI", 8, "bold"),
                 width=18, anchor="w").pack(side="left")

        self.recursive_var = tk.BooleanVar(value=self.config.get("recursive", True))
        rec_cb = tk.Checkbutton(row3, text="Include subdirectories",
                                 variable=self.recursive_var,
                                 bg=self.BG_PANEL, fg=self.TEXT_PRIMARY,
                                 activebackground=self.BG_PANEL,
                                 activeforeground=self.TEXT_PRIMARY,
                                 selectcolor=self.BG_ELEVATED,
                                 font=("Segoe UI", 9),
                                 bd=0, highlightthickness=0)
        rec_cb.pack(side="left", padx=(0, 16))

        self.detect_opens_var = tk.BooleanVar(value=self.config.get("detect_opens", True))
        open_cb = tk.Checkbutton(row3, text="Detect file opens",
                                  variable=self.detect_opens_var,
                                  bg=self.BG_PANEL, fg=self.TEXT_PRIMARY,
                                  activebackground=self.BG_PANEL,
                                  activeforeground=self.TEXT_PRIMARY,
                                  selectcolor=self.BG_ELEVATED,
                                  font=("Segoe UI", 9),
                                  bd=0, highlightthickness=0)
        open_cb.pack(side="left", padx=(0, 16))

        tk.Label(row3, text="Port:", bg=self.BG_PANEL,
                 fg=self.TEXT_SECONDARY, font=("Segoe UI", 9)).pack(side="left")
        self.port_var = tk.StringVar(value=str(self.config.get("port", 8080)))
        port_entry = tk.Entry(row3, textvariable=self.port_var,
                              bg=self.BG_ELEVATED, fg=self.TEXT_PRIMARY,
                              insertbackground=self.TEXT_PRIMARY,
                              relief="flat", font=("Consolas", 9), width=8)
        port_entry.pack(side="left", padx=(6, 0), ipady=4)
        self.port_entry = port_entry

        # --- Control Buttons ---
        ctrl_frame = tk.Frame(self.root, bg=self.BG_DARK)
        ctrl_frame.pack(fill="x", padx=12, pady=6)

        self.start_btn = tk.Button(ctrl_frame, text="▶  START MONITORING",
                                    bg=self.ACCENT_GREEN, fg="#003311",
                                    activebackground="#20dd55",
                                    activeforeground="#003311",
                                    font=("Segoe UI", 10, "bold"),
                                    relief="flat", bd=0, cursor="hand2",
                                    command=self._start_monitoring)
        self.start_btn.pack(side="left", ipadx=16, ipady=10, padx=(0, 6))

        self.stop_btn = tk.Button(ctrl_frame, text="■  STOP",
                                   bg=self.BG_ELEVATED, fg=self.TEXT_MUTED,
                                   activebackground=self.BORDER,
                                   activeforeground=self.TEXT_PRIMARY,
                                   font=("Segoe UI", 10, "bold"),
                                   relief="flat", bd=0, cursor="hand2",
                                   state="disabled",
                                   command=self._stop_monitoring)
        self.stop_btn.pack(side="left", ipadx=16, ipady=10, padx=6)

        self.dashboard_btn = tk.Button(ctrl_frame, text="🌐 OPEN DASHBOARD",
                                        bg=self.BG_ELEVATED, fg=self.ACCENT,
                                        activebackground=self.BORDER,
                                        activeforeground=self.ACCENT,
                                        font=("Segoe UI", 10, "bold"),
                                        relief="flat", bd=0, cursor="hand2",
                                        state="disabled",
                                        command=self._open_dashboard)
        self.dashboard_btn.pack(side="left", ipadx=16, ipady=10, padx=6)

        tk.Button(ctrl_frame, text="📂 Open Log Folder",
                  bg=self.BG_ELEVATED, fg=self.TEXT_SECONDARY,
                  activebackground=self.BORDER,
                  activeforeground=self.TEXT_PRIMARY,
                  font=("Segoe UI", 9), relief="flat", bd=0,
                  cursor="hand2",
                  command=self._open_log_folder).pack(side="right", ipadx=10, ipady=8)

        # --- Stats Strip ---
        self.stats_frame = tk.Frame(self.root, bg=self.BG_DARK)
        self.stats_frame.pack(fill="x", padx=12, pady=6)
        self.stat_labels = {}
        for name, color in [("TOTAL", self.ACCENT), ("CREATED", self.ACCENT_GREEN),
                             ("MODIFIED", self.ACCENT_YELLOW), ("OPENED", self.ACCENT_PURPLE),
                             ("COPIED", self.ACCENT_ORANGE), ("DOWNLOADED", self.ACCENT_PINK),
                             ("DELETED", self.ACCENT_RED)]:
            cell = tk.Frame(self.stats_frame, bg=self.BG_PANEL,
                             highlightbackground=self.BORDER, highlightthickness=1)
            cell.pack(side="left", fill="both", expand=True, padx=2)
            tk.Label(cell, text=name, bg=self.BG_PANEL, fg=self.TEXT_MUTED,
                     font=("Segoe UI", 7, "bold")).pack(pady=(6, 0))
            lbl = tk.Label(cell, text="0", bg=self.BG_PANEL, fg=color,
                           font=("Consolas", 16, "bold"))
            lbl.pack(pady=(0, 6))
            self.stat_labels[name] = lbl

        # --- Event Log View ---
        log_frame = tk.LabelFrame(self.root, text=" LIVE EVENT LOG ",
                                   bg=self.BG_PANEL, fg=self.TEXT_MUTED,
                                   font=("Segoe UI", 9, "bold"),
                                   bd=1, relief="solid")
        log_frame.pack(fill="both", expand=True, padx=12, pady=(6, 12))

        self.log_view = scrolledtext.ScrolledText(log_frame,
                                                    bg=self.BG_DARK,
                                                    fg=self.TEXT_PRIMARY,
                                                    insertbackground=self.TEXT_PRIMARY,
                                                    font=("Consolas", 9),
                                                    relief="flat", bd=0,
                                                    wrap="none", state="disabled")
        self.log_view.pack(fill="both", expand=True, padx=2, pady=2)

        # Configure tags for colored event types
        for event_type, color in self.EVENT_COLORS.items():
            self.log_view.tag_config(event_type, foreground=color)
        self.log_view.tag_config("INFO", foreground=self.TEXT_MUTED)
        self.log_view.tag_config("ERROR", foreground=self.ACCENT_RED)

        # Welcome message
        self._gui_log(f"SecureHAWK v{APP_VERSION} ready.", event_type="INFO")
        self._gui_log("Select a directory to watch and a log file, then click START MONITORING.", event_type="INFO")
        if not PSUTIL_AVAILABLE:
            self._gui_log("Note: psutil not installed - process attribution disabled.", event_type="INFO")

    # =================================================================
    # BUTTON HANDLERS
    # =================================================================

    def _browse_watch_dir(self):
        initial = self.watch_var.get() or str(Path.home())
        if not os.path.isdir(initial):
            initial = str(Path.home())
        selected = filedialog.askdirectory(
            title="Select directory to monitor",
            initialdir=initial,
            mustexist=True,
        )
        if selected:
            self.watch_var.set(os.path.normpath(selected))

    def _browse_log_file(self):
        initial_dir = str(Path.home() / "Desktop")
        if self.log_var.get():
            parent = os.path.dirname(self.log_var.get())
            if os.path.isdir(parent):
                initial_dir = parent
        selected = filedialog.asksaveasfilename(
            title="Choose location for log file",
            initialdir=initial_dir,
            initialfile="securehawk_log.txt",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
        )
        if selected:
            if not selected.lower().endswith(".txt"):
                selected += ".txt"
            self.log_var.set(os.path.normpath(selected))

    def _open_log_folder(self):
        log_path = self.log_var.get()
        if not log_path:
            messagebox.showinfo("No log file", "Choose a log file first.")
            return
        folder = os.path.dirname(log_path) or str(Path.home())
        if os.path.isdir(folder):
            try:
                os.startfile(folder)
            except Exception as e:
                messagebox.showerror("Error", f"Could not open folder:\n{e}")
        else:
            messagebox.showinfo("Folder not found",
                                f"The folder does not exist yet:\n{folder}\n\nIt will be created when monitoring starts.")

    def _validate_inputs(self):
        watch_dir = self.watch_var.get().strip().strip('"')
        log_file = self.log_var.get().strip().strip('"')

        if not watch_dir:
            messagebox.showerror("Missing directory",
                                  "Please select a directory to watch.")
            return None
        if not os.path.isdir(watch_dir):
            messagebox.showerror("Invalid directory",
                                  f"The directory does not exist:\n{watch_dir}")
            return None
        if not log_file:
            messagebox.showerror("Missing log file",
                                  "Please choose a log file path.")
            return None

        # Ensure .txt extension
        if not log_file.lower().endswith(".txt"):
            log_file += ".txt"

        # Make sure log parent folder exists
        log_parent = os.path.dirname(log_file)
        if log_parent and not os.path.exists(log_parent):
            try:
                os.makedirs(log_parent, exist_ok=True)
            except Exception as e:
                messagebox.showerror("Cannot create folder",
                                      f"Could not create log folder:\n{e}")
                return None

        # Parse port
        try:
            port = int(self.port_var.get())
            if not (1024 <= port <= 65535):
                raise ValueError
        except ValueError:
            messagebox.showerror("Invalid port",
                                  "Port must be a number between 1024 and 65535.")
            return None

        return {
            "watch_dir": os.path.normpath(watch_dir),
            "log_file": os.path.normpath(log_file),
            "recursive": self.recursive_var.get(),
            "detect_opens": self.detect_opens_var.get(),
            "port": port,
        }

    def _start_monitoring(self):
        if self.monitoring:
            return
        cfg = self._validate_inputs()
        if not cfg:
            return

        # Save config
        self.watch_var.set(cfg["watch_dir"])
        self.log_var.set(cfg["log_file"])
        self._save_config()

        # Reset stats
        self.stats = {k: 0 for k in self.stats}
        for k, lbl in self.stat_labels.items():
            lbl.config(text="0")

        # Populate session info
        session_info["watch_directory"] = cfg["watch_dir"]
        session_info["log_file"] = cfg["log_file"]
        session_info["started_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        session_info["user"] = getpass.getuser()
        session_info["host"] = socket.gethostname()
        session_info["event_count"] = 0

        self._gui_log(f"Starting monitor on: {cfg['watch_dir']}", event_type="INFO")
        self._gui_log(f"Log file: {cfg['log_file']}", event_type="INFO")

        # Check atime support if requested
        if cfg["detect_opens"]:
            self._gui_log("Testing last-access-time support...", event_type="INFO")
            atime_ok = check_atime_enabled(cfg["watch_dir"])
            session_info["atime_enabled"] = atime_ok
            if atime_ok:
                self._gui_log("atime enabled - OPEN detection active.", event_type="INFO")
            else:
                self._gui_log("atime NOT updating - OPEN detection limited.", event_type="INFO")
                self._gui_log("  To enable: run 'fsutil behavior set DisableLastAccess 0' (admin) and reboot.", event_type="INFO")

        # CORS
        self.port = cfg["port"]
        CORS(app, origins=[f"http://localhost:{self.port}", f"http://127.0.0.1:{self.port}"])

        try:
            # File watcher
            self.event_handler = FileChangeLogger(cfg["log_file"], cfg["watch_dir"])
            self.observer = Observer()
            self.observer.schedule(self.event_handler, cfg["watch_dir"], recursive=cfg["recursive"])
            self.observer.start()

            # Access poller
            if cfg["detect_opens"]:
                self.access_poller = AccessPoller(
                    cfg["watch_dir"], cfg["recursive"],
                    self.event_handler.on_opened, interval=3.0
                )
                self.access_poller.start()

            # Web server
            if self.server_thread is None or not self.server_thread.is_alive():
                self.server_thread = threading.Thread(
                    target=lambda: app.run(host="127.0.0.1", port=self.port,
                                            threaded=True, use_reloader=False),
                    daemon=True
                )
                self.server_thread.start()

            self.monitoring = True
            self.status_label.config(text="● MONITORING", fg=self.ACCENT_GREEN)
            self.start_btn.config(state="disabled", bg=self.BG_ELEVATED, fg=self.TEXT_MUTED)
            self.stop_btn.config(state="normal", bg=self.ACCENT_RED, fg="#330000")
            self.dashboard_btn.config(state="normal")
            self.watch_entry.config(state="disabled")
            self.log_entry.config(state="disabled")
            self.browse_watch_btn.config(state="disabled")
            self.browse_log_btn.config(state="disabled")
            self.port_entry.config(state="disabled")

            self._gui_log(f"Monitoring active. Dashboard: http://localhost:{self.port}", event_type="INFO")

            # Auto-open dashboard after a moment
            threading.Timer(1.5, self._open_dashboard).start()

        except Exception as e:
            messagebox.showerror("Error starting monitor",
                                  f"Could not start monitoring:\n{e}")
            self._gui_log(f"Start failed: {e}", event_type="ERROR")

    def _stop_monitoring(self):
        if not self.monitoring:
            return
        self._gui_log("Stopping monitor...", event_type="INFO")

        if self.observer:
            self.observer.stop()
            self.observer.join(timeout=3)
        if self.access_poller:
            self.access_poller.stop()

        # Write footer
        log_file = session_info["log_file"]
        if log_file:
            footer = (
                "\n" + "-" * 70 + "\n"
                f"  SESSION ENDED: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
                f"  Total events logged: {session_info['event_count']}\n"
                + "-" * 70 + "\n"
            )
            try:
                with open(log_file, "a", encoding="utf-8") as log:
                    log.write(footer)
            except Exception:
                pass

        self.monitoring = False
        self.status_label.config(text="● IDLE", fg=self.TEXT_MUTED)
        self.start_btn.config(state="normal", bg=self.ACCENT_GREEN, fg="#003311")
        self.stop_btn.config(state="disabled", bg=self.BG_ELEVATED, fg=self.TEXT_MUTED)
        self.dashboard_btn.config(state="disabled")
        self.watch_entry.config(state="normal")
        self.log_entry.config(state="normal")
        self.browse_watch_btn.config(state="normal")
        self.browse_log_btn.config(state="normal")
        self.port_entry.config(state="normal")

        self._gui_log(f"Monitor stopped. Total events: {session_info['event_count']}", event_type="INFO")

    def _open_dashboard(self):
        if not self.monitoring:
            return
        url = f"http://localhost:{self.port}/?token={SESSION_TOKEN}"
        webbrowser.open(url)

    # =================================================================
    # LOGGING
    # =================================================================

    def _gui_log(self, message, event_type="INFO"):
        """Thread-safe append to the log view."""
        def do_append():
            self.log_view.config(state="normal")
            # Insert a timestamped line
            now = datetime.now().strftime("%H:%M:%S")

            tag = event_type if event_type in self.EVENT_COLORS else "INFO"
            if event_type == "ERROR":
                tag = "ERROR"

            self.log_view.insert("end", f"[{now}] ", "INFO")
            self.log_view.insert("end", f"{message}\n", tag)

            # Trim if too long
            line_count = int(self.log_view.index("end-1c").split(".")[0])
            if line_count > 1000:
                self.log_view.delete("1.0", f"{line_count - 800}.0")

            self.log_view.see("end")
            self.log_view.config(state="disabled")

            # Update stats if this was an event
            if event_type in self.stats:
                self.stats[event_type] += 1
                self.stat_labels[event_type].config(text=str(self.stats[event_type]))
                total = sum(self.stats.values())
                self.stat_labels["TOTAL"].config(text=str(total))

        # Safely queue the update on the main thread
        try:
            self.root.after(0, do_append)
        except Exception:
            pass

    def _on_close(self):
        if self.monitoring:
            if messagebox.askyesno("Stop monitoring?",
                                    "Monitoring is still active. Stop and exit?"):
                self._stop_monitoring()
                self.root.destroy()
        else:
            self.root.destroy()

    def run(self):
        self.root.mainloop()


# ===================================================================
# ENTRY POINT
# ===================================================================

def main():
    try:
        SecureHAWKApp().run()
    except Exception as e:
        try:
            messagebox.showerror("Fatal error", f"SecureHAWK crashed:\n{e}")
        except Exception:
            print(f"FATAL: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
