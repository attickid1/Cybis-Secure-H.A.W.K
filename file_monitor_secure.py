"""
File Change Monitor with Live Web Dashboard (Hardened)
-------------------------------------------------------
Watches a directory for file changes, logs them to a .txt file,
AND streams them in real time to a web browser dashboard.

Security features in this version:
  - Server binds to 127.0.0.1 only (not reachable from network)
  - Random session token required for all dashboard/API/stream access
  - CORS restricted to the dashboard origin only
  - Token is embedded in the auto-opened URL and never logged

Requirements:
    pip install watchdog flask flask-cors

Usage:
    python file_monitor_secure.py

Press Ctrl+C to stop monitoring.
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
from datetime import datetime
from pathlib import Path
from queue import Queue, Empty

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
except ImportError:
    print("ERROR: The 'watchdog' library is not installed.")
    print("Install it by running: pip install watchdog")
    sys.exit(1)

try:
    from flask import Flask, Response, render_template_string, jsonify, request, abort
    from flask_cors import CORS
except ImportError:
    print("ERROR: The 'flask' and 'flask-cors' libraries are not installed.")
    print("Install them by running: pip install flask flask-cors")
    sys.exit(1)


# ===================================================================
# SECURITY: Generate a random session token at startup.
# This token is required to access ANY endpoint of the dashboard.
# It is generated fresh each run and exists only in memory.
# ===================================================================
SESSION_TOKEN = secrets.token_urlsafe(32)


# Global event queue and state
event_queue = Queue()
event_history = []
MAX_HISTORY = 200
session_info = {
    "watch_directory": "",
    "log_file": "",
    "started_at": "",
    "user": "",
    "host": "",
    "event_count": 0,
}


def verify_token():
    """
    Verifies the request carries the correct session token.
    Accepts the token from either:
      - the 'token' query parameter (used by initial page load + EventSource)
      - the 'X-Session-Token' header (used by fetch() calls from the dashboard)
    Uses constant-time comparison to prevent timing attacks.
    """
    provided = request.args.get("token") or request.headers.get("X-Session-Token", "")
    if not provided:
        return False
    # hmac.compare_digest is constant-time — protects against timing-based token guessing
    return hmac.compare_digest(provided, SESSION_TOKEN)


# ===================================================================
# HTML DASHBOARD - served by Flask
# Token is injected at render time via a placeholder
# ===================================================================

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>File Monitor - Live Dashboard</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: 'Segoe UI', system-ui, sans-serif;
    background: #0a0e1a;
    color: #c5d1e6;
    min-height: 100vh;
    padding: 20px;
  }
  header {
    background: linear-gradient(135deg, #0f1729, #1a2540);
    border: 1px solid #2a3a5a;
    border-radius: 12px;
    padding: 20px 24px;
    margin-bottom: 16px;
    display: flex;
    justify-content: space-between;
    align-items: center;
  }
  h1 {
    font-size: 22px;
    color: #5aefff;
    letter-spacing: 2px;
    font-weight: 700;
  }
  .header-right {
    display: flex;
    align-items: center;
    gap: 16px;
  }
  .secure-badge {
    display: flex;
    align-items: center;
    gap: 6px;
    padding: 4px 10px;
    background: #2aff6b15;
    border: 1px solid #2aff6b44;
    border-radius: 4px;
    font-size: 10px;
    color: #2aff6b;
    letter-spacing: 1.5px;
    font-weight: 600;
  }
  .secure-badge::before {
    content: "🔒";
    font-size: 11px;
  }
  .live-indicator {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 12px;
    color: #2aff6b;
    font-weight: 600;
    letter-spacing: 1.5px;
  }
  .pulse {
    width: 10px;
    height: 10px;
    border-radius: 50%;
    background: #2aff6b;
    box-shadow: 0 0 12px #2aff6b;
    animation: pulse 1.5s ease-in-out infinite;
  }
  @keyframes pulse {
    0%, 100% { opacity: 1; transform: scale(1); }
    50% { opacity: 0.4; transform: scale(0.85); }
  }
  .session-info {
    background: #0f1729;
    border: 1px solid #2a3a5a;
    border-radius: 12px;
    padding: 16px 24px;
    margin-bottom: 16px;
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 16px;
  }
  .info-item { display: flex; flex-direction: column; gap: 4px; }
  .info-label {
    font-size: 10px;
    color: #5a7a9a;
    letter-spacing: 1.5px;
    text-transform: uppercase;
  }
  .info-value {
    font-size: 13px;
    color: #c5d1e6;
    font-family: 'Consolas', 'Courier New', monospace;
    word-break: break-all;
  }
  .stats {
    display: grid;
    grid-template-columns: repeat(5, 1fr);
    gap: 12px;
    margin-bottom: 16px;
  }
  .stat-card {
    background: #0f1729;
    border: 1px solid #2a3a5a;
    border-radius: 10px;
    padding: 14px 18px;
  }
  .stat-label {
    font-size: 10px;
    color: #5a7a9a;
    letter-spacing: 1.5px;
    text-transform: uppercase;
    margin-bottom: 6px;
  }
  .stat-value { font-size: 24px; font-weight: 700; font-family: 'Consolas', monospace; }
  .stat-value.created { color: #2aff6b; }
  .stat-value.modified { color: #ffc42a; }
  .stat-value.deleted { color: #ff2a2a; }
  .stat-value.moved { color: #2ad4ff; }
  .stat-value.total { color: #5aefff; }
  .events-container {
    background: #0f1729;
    border: 1px solid #2a3a5a;
    border-radius: 12px;
    overflow: hidden;
  }
  .events-header {
    padding: 14px 20px;
    border-bottom: 1px solid #2a3a5a;
    display: flex;
    justify-content: space-between;
    align-items: center;
  }
  .events-title {
    font-size: 12px;
    color: #5a7a9a;
    letter-spacing: 2px;
    text-transform: uppercase;
  }
  .clear-btn {
    background: #1a2540;
    border: 1px solid #2a3a5a;
    color: #5a7a9a;
    padding: 6px 14px;
    border-radius: 6px;
    cursor: pointer;
    font-size: 11px;
    letter-spacing: 1px;
    text-transform: uppercase;
    transition: all 0.2s;
  }
  .clear-btn:hover { background: #2a3a5a; color: #c5d1e6; }
  .events-list {
    max-height: calc(100vh - 380px);
    overflow-y: auto;
    font-family: 'Consolas', monospace;
    font-size: 12px;
  }
  .events-list::-webkit-scrollbar { width: 6px; }
  .events-list::-webkit-scrollbar-track { background: #0a0e1a; }
  .events-list::-webkit-scrollbar-thumb { background: #2a3a5a; border-radius: 3px; }
  .event {
    padding: 10px 20px;
    border-bottom: 1px solid #1a2540;
    display: grid;
    grid-template-columns: 160px 90px 50px 1fr 200px;
    gap: 12px;
    align-items: center;
    animation: slideIn 0.3s ease-out;
  }
  @keyframes slideIn {
    from { opacity: 0; transform: translateX(-10px); background: #1a2540; }
    to { opacity: 1; transform: translateX(0); background: transparent; }
  }
  .event-time { color: #5a7a9a; }
  .event-type {
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 1px;
    font-size: 10px;
    padding: 3px 8px;
    border-radius: 4px;
    text-align: center;
  }
  .event-type.created { background: #2aff6b22; color: #2aff6b; }
  .event-type.modified { background: #ffc42a22; color: #ffc42a; }
  .event-type.deleted { background: #ff2a2a22; color: #ff2a2a; }
  .event-type.moved { background: #2ad4ff22; color: #2ad4ff; }
  .event-kind { font-size: 10px; color: #5a7a9a; letter-spacing: 1px; }
  .event-path {
    color: #c5d1e6;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .event-extra {
    color: #5a7a9a;
    font-size: 11px;
    text-align: right;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .empty-state {
    padding: 60px 20px;
    text-align: center;
    color: #3a5a7a;
  }
  .connection-status {
    position: fixed;
    bottom: 20px;
    right: 20px;
    padding: 8px 16px;
    border-radius: 6px;
    font-size: 11px;
    letter-spacing: 1px;
    text-transform: uppercase;
    background: #0f1729;
    border: 1px solid #2a3a5a;
  }
  .connection-status.connected { color: #2aff6b; border-color: #2aff6b44; }
  .connection-status.disconnected { color: #ff2a2a; border-color: #ff2a2a44; }
</style>
</head>
<body>

<header>
  <h1>FILE MONITOR &middot; LIVE DASHBOARD</h1>
  <div class="header-right">
    <div class="secure-badge">AUTHENTICATED SESSION</div>
    <div class="live-indicator">
      <div class="pulse"></div>
      <span>STREAMING</span>
    </div>
  </div>
</header>

<div class="session-info" id="sessionInfo">
  <div class="info-item">
    <span class="info-label">Watching</span>
    <span class="info-value" id="watchDir">Loading...</span>
  </div>
  <div class="info-item">
    <span class="info-label">Log File</span>
    <span class="info-value" id="logFile">Loading...</span>
  </div>
  <div class="info-item">
    <span class="info-label">User</span>
    <span class="info-value" id="user">Loading...</span>
  </div>
  <div class="info-item">
    <span class="info-label">Host</span>
    <span class="info-value" id="host">Loading...</span>
  </div>
  <div class="info-item">
    <span class="info-label">Started</span>
    <span class="info-value" id="started">Loading...</span>
  </div>
</div>

<div class="stats">
  <div class="stat-card">
    <div class="stat-label">Total Events</div>
    <div class="stat-value total" id="statTotal">0</div>
  </div>
  <div class="stat-card">
    <div class="stat-label">Created</div>
    <div class="stat-value created" id="statCreated">0</div>
  </div>
  <div class="stat-card">
    <div class="stat-label">Modified</div>
    <div class="stat-value modified" id="statModified">0</div>
  </div>
  <div class="stat-card">
    <div class="stat-label">Deleted</div>
    <div class="stat-value deleted" id="statDeleted">0</div>
  </div>
  <div class="stat-card">
    <div class="stat-label">Moved</div>
    <div class="stat-value moved" id="statMoved">0</div>
  </div>
</div>

<div class="events-container">
  <div class="events-header">
    <span class="events-title">Real-Time Event Stream</span>
    <button class="clear-btn" onclick="clearEvents()">Clear View</button>
  </div>
  <div class="events-list" id="eventsList">
    <div class="empty-state">Waiting for file system events...</div>
  </div>
</div>

<div class="connection-status connected" id="connectionStatus">CONNECTED</div>

<script>
  // The session token is injected by the server when this page is rendered.
  // Stored only in this page's memory - never written to localStorage or cookies.
  const SESSION_TOKEN = "__SESSION_TOKEN__";

  const stats = { CREATED: 0, MODIFIED: 0, DELETED: 0, MOVED: 0 };
  const eventsList = document.getElementById('eventsList');
  let isEmpty = true;

  // Helper that adds the auth token header to every fetch
  function authFetch(url) {
    return fetch(url, {
      headers: { 'X-Session-Token': SESSION_TOKEN }
    });
  }

  // Load session info
  authFetch('/api/session')
    .then(r => r.json())
    .then(data => {
      document.getElementById('watchDir').textContent = data.watch_directory || 'N/A';
      document.getElementById('logFile').textContent = data.log_file || 'N/A';
      document.getElementById('user').textContent = data.user || 'N/A';
      document.getElementById('host').textContent = data.host || 'N/A';
      document.getElementById('started').textContent = data.started_at || 'N/A';
    });

  // Load history
  authFetch('/api/history')
    .then(r => r.json())
    .then(events => events.forEach(addEvent));

  // EventSource doesn't support custom headers, so the token goes in the URL.
  // This is fine because it stays on localhost and never crosses the network.
  const eventSource = new EventSource('/stream?token=' + encodeURIComponent(SESSION_TOKEN));

  eventSource.onmessage = (e) => {
    const event = JSON.parse(e.data);
    addEvent(event);
  };

  eventSource.onopen = () => {
    document.getElementById('connectionStatus').textContent = 'CONNECTED';
    document.getElementById('connectionStatus').className = 'connection-status connected';
  };

  eventSource.onerror = () => {
    document.getElementById('connectionStatus').textContent = 'DISCONNECTED';
    document.getElementById('connectionStatus').className = 'connection-status disconnected';
  };

  function addEvent(event) {
    if (isEmpty) {
      eventsList.innerHTML = '';
      isEmpty = false;
    }

    stats[event.type] = (stats[event.type] || 0) + 1;
    updateStats();

    const eventDiv = document.createElement('div');
    eventDiv.className = 'event';
    eventDiv.innerHTML = `
      <span class="event-time">${event.timestamp}</span>
      <span class="event-type ${event.type.toLowerCase()}">${event.type}</span>
      <span class="event-kind">${event.kind}</span>
      <span class="event-path" title="${escapeHtml(event.path)}">${escapeHtml(event.path)}</span>
      <span class="event-extra" title="${escapeHtml(event.extra || '')}">${escapeHtml(event.extra || '')}</span>
    `;

    eventsList.insertBefore(eventDiv, eventsList.firstChild);

    while (eventsList.children.length > 300) {
      eventsList.removeChild(eventsList.lastChild);
    }
  }

  function updateStats() {
    document.getElementById('statCreated').textContent = stats.CREATED || 0;
    document.getElementById('statModified').textContent = stats.MODIFIED || 0;
    document.getElementById('statDeleted').textContent = stats.DELETED || 0;
    document.getElementById('statMoved').textContent = stats.MOVED || 0;
    const total = (stats.CREATED || 0) + (stats.MODIFIED || 0) + (stats.DELETED || 0) + (stats.MOVED || 0);
    document.getElementById('statTotal').textContent = total;
  }

  function clearEvents() {
    eventsList.innerHTML = '<div class="empty-state">View cleared. Waiting for new events...</div>';
    isEmpty = true;
  }

  function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }
</script>

</body>
</html>
"""


# ===================================================================
# UNAUTHORIZED PAGE - shown when token is missing/invalid
# ===================================================================

UNAUTHORIZED_HTML = """<!DOCTYPE html>
<html><head><title>Unauthorized</title>
<style>
body { font-family: system-ui, sans-serif; background: #0a0e1a; color: #c5d1e6;
  display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; }
.box { text-align: center; padding: 40px; border: 1px solid #ff2a2a44;
  border-radius: 12px; background: #0f1729; max-width: 500px; }
h1 { color: #ff2a2a; margin: 0 0 16px; font-size: 22px; letter-spacing: 1px; }
p { color: #8aa4c0; line-height: 1.6; margin: 0 0 12px; }
code { background: #1a2540; padding: 2px 6px; border-radius: 3px;
  font-family: Consolas, monospace; color: #5aefff; font-size: 12px; }
</style></head>
<body><div class="box">
<h1>🔒 UNAUTHORIZED</h1>
<p>This dashboard requires a valid session token.</p>
<p>The token is generated each time the monitor is started and printed to the console.
Open the URL shown in the terminal that started this program — it includes the token.</p>
<p>If you closed the original browser tab, copy the full URL from the console
(including the <code>?token=...</code> portion) and paste it here.</p>
</div></body></html>"""


# ===================================================================
# FILE WATCHER (unchanged from previous version)
# ===================================================================

class FileChangeLogger(FileSystemEventHandler):
    def __init__(self, log_file_path, watch_directory):
        super().__init__()
        self.log_file_path = log_file_path
        self.watch_directory = watch_directory
        self._write_session_header()

    def _write_session_header(self):
        header = (
            "\n" + "=" * 70 + "\n"
            f"  FILE CHANGE MONITOR - SESSION STARTED\n"
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
            print(f"[ERROR] Could not write to log file: {e}")

    def _get_file_size(self, path):
        try:
            if os.path.isfile(path):
                return os.path.getsize(path)
        except OSError:
            return None
        return None

    def _get_file_hash(self, path):
        try:
            if not os.path.isfile(path):
                return None
            sha = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    sha.update(chunk)
            return sha.hexdigest()[:16]
        except (OSError, PermissionError):
            return None

    def _emit_event(self, event_type, file_path, extra=""):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        kind = "DIR" if os.path.isdir(file_path) else "FILE"

        log_entry = f"[{timestamp}] {event_type:<10} {kind:<4} | {file_path}"
        if extra:
            log_entry += f" | {extra}"
        log_entry += "\n"
        self._write_to_log(log_entry)
        print(log_entry.rstrip())

        web_event = {
            "timestamp": timestamp,
            "type": event_type,
            "kind": kind,
            "path": file_path,
            "extra": extra,
        }
        event_queue.put(web_event)
        event_history.append(web_event)
        if len(event_history) > MAX_HISTORY:
            event_history.pop(0)

        session_info["event_count"] += 1

    def on_created(self, event):
        size = self._get_file_size(event.src_path)
        extra = f"size={size}B" if size is not None else ""
        self._emit_event("CREATED", event.src_path, extra)

    def on_deleted(self, event):
        self._emit_event("DELETED", event.src_path)

    def on_modified(self, event):
        if event.is_directory:
            return
        size = self._get_file_size(event.src_path)
        file_hash = self._get_file_hash(event.src_path)
        extras = []
        if size is not None:
            extras.append(f"size={size}B")
        if file_hash is not None:
            extras.append(f"sha256={file_hash}")
        self._emit_event("MODIFIED", event.src_path, " ".join(extras))

    def on_moved(self, event):
        self._emit_event("MOVED", event.src_path, f"-> {event.dest_path}")


# ===================================================================
# WEB SERVER (HARDENED)
# ===================================================================

app = Flask(__name__)

# Restrict CORS to only the dashboard origin (will be set after we know the port)
# Initialized in main() once the port is chosen
cors_instance = None

import logging
logging.getLogger("werkzeug").setLevel(logging.ERROR)
app.logger.setLevel(logging.ERROR)


@app.route("/")
def dashboard():
    """Serve the dashboard. Requires valid token in query string."""
    if not verify_token():
        return Response(UNAUTHORIZED_HTML, status=401, mimetype="text/html")
    # Inject the session token into the page so the JS can use it for API calls
    return render_template_string(DASHBOARD_HTML.replace("__SESSION_TOKEN__", SESSION_TOKEN))


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
    """SSE endpoint. Token verified before stream is established."""
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
        "Cache-Control": "no-cache",
        "X-Accel-Buffering": "no",
    })


# ===================================================================
# USER INPUT
# ===================================================================

def get_user_input():
    print("=" * 70)
    print("  FILE CHANGE MONITOR - WITH SECURE LIVE WEB DASHBOARD")
    print("=" * 70)
    print()

    while True:
        watch_dir = input("Enter the directory to watch (full path): ").strip().strip('"')
        if not watch_dir:
            print("  -> Path cannot be empty.\n")
            continue
        watch_path = Path(watch_dir).expanduser().resolve()
        if not watch_path.exists():
            print(f"  -> Path does not exist: {watch_path}\n")
            continue
        if not watch_path.is_dir():
            print(f"  -> Path is not a directory: {watch_path}\n")
            continue
        break

    while True:
        log_input = input("Enter the path for the log file (.txt): ").strip().strip('"')
        if not log_input:
            print("  -> Path cannot be empty.\n")
            continue
        log_path = Path(log_input).expanduser().resolve()
        if log_path.suffix.lower() != ".txt":
            log_path = log_path.with_suffix(".txt")
            print(f"  -> Adjusted log file path to: {log_path}")
        if not log_path.parent.exists():
            try:
                log_path.parent.mkdir(parents=True, exist_ok=True)
                print(f"  -> Created log directory: {log_path.parent}")
            except Exception as e:
                print(f"  -> Could not create log directory: {e}\n")
                continue
        break

    recursive_input = input("Watch subdirectories too? (Y/n): ").strip().lower()
    recursive = recursive_input != "n"

    port_input = input("Web dashboard port (default 8080): ").strip()
    try:
        port = int(port_input) if port_input else 8080
    except ValueError:
        port = 8080
        print(f"  -> Invalid port. Using default: {port}")

    return str(watch_path), str(log_path), recursive, port


# ===================================================================
# MAIN
# ===================================================================

def main():
    global cors_instance

    watch_directory, log_file, recursive, port = get_user_input()

    session_info["watch_directory"] = watch_directory
    session_info["log_file"] = log_file
    session_info["started_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    session_info["user"] = getpass.getuser()
    session_info["host"] = socket.gethostname()

    # Restrict CORS to the dashboard origin only (defense in depth - even though
    # the server is bound to localhost, this stops other localhost origins from
    # making cross-origin API calls)
    dashboard_origin = f"http://localhost:{port}"
    cors_instance = CORS(app, origins=[dashboard_origin, f"http://127.0.0.1:{port}"])

    dashboard_url = f"http://localhost:{port}/?token={SESSION_TOKEN}"

    print()
    print("-" * 70)
    print(f"  Watching:    {watch_directory}")
    print(f"  Log file:    {log_file}")
    print(f"  Recursive:   {'Yes' if recursive else 'No'}")
    print(f"  Bind addr:   127.0.0.1 (localhost only - not network accessible)")
    print(f"  Auth:        Required (token-based)")
    print("-" * 70)
    print(f"  Dashboard URL (copy if browser doesn't auto-open):")
    print(f"  {dashboard_url}")
    print("-" * 70)
    print("  Press Ctrl+C to stop monitoring.")
    print("-" * 70)
    print()

    # Start the file system watcher
    event_handler = FileChangeLogger(log_file, watch_directory)
    observer = Observer()
    observer.schedule(event_handler, watch_directory, recursive=recursive)
    observer.start()

    # Start the web server bound STRICTLY to localhost
    server_thread = threading.Thread(
        target=lambda: app.run(host="127.0.0.1", port=port, threaded=True, use_reloader=False),
        daemon=True
    )
    server_thread.start()

    # Open the dashboard in the default browser with the token
    threading.Timer(1.5, lambda: webbrowser.open(dashboard_url)).start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n\n[STOPPING] Shutting down monitor...")
        observer.stop()

        footer = (
            "\n" + "-" * 70 + "\n"
            f"  SESSION ENDED: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"  Total events logged: {session_info['event_count']}\n"
            + "-" * 70 + "\n"
        )
        try:
            with open(log_file, "a", encoding="utf-8") as log:
                log.write(footer)
        except Exception as e:
            print(f"[ERROR] Could not write session footer: {e}")

        print(f"[DONE] Logged {session_info['event_count']} events to: {log_file}")

    observer.join()


if __name__ == "__main__":
    main()
