# SecureHAWK

**Heuristic Analysis & Watchguard Kernel**

An AI-inspired file integrity monitoring system that watches directories for changes, logs every event with cryptographic hashes, and (in advanced versions) streams real-time activity to a live dashboard.

SecureHAWK is an educational project that demonstrates the core concepts behind enterprise-grade file integrity monitoring. The project is organized as a series of progressively more capable versions — each one builds on the previous one, and each can be used independently depending on what you need.

---

## Table of Contents

1. [Project Overview](#project-overview)
2. [Quick Version Picker](#quick-version-picker)
3. [Prerequisites (Read First)](#prerequisites-read-first)
4. **Per-Version Guides:**
   - [Version 1 — Basic Windows Monitor](#version-1--basic-windows-monitor)
   - [Version 2 — macOS Basic Monitor](#version-2--macos-basic-monitor)
   - [Version 3 — Windows with Web Dashboard](#version-3--windows-with-web-dashboard)
   - [Version 4 — Windows with Secure Dashboard](#version-4--windows-with-secure-dashboard)
   - [Version 5 — Windows with Enhanced Detection](#version-5--windows-with-enhanced-detection)
   - [Version 6 — SecureHAWK v0.3 Desktop GUI](#version-6--securehawk-v03-desktop-gui)
5. [Building a Standalone Windows Executable](#building-a-standalone-windows-executable)
6. [Understanding the Log File](#understanding-the-log-file)
7. [Global Troubleshooting](#global-troubleshooting)
8. [Security Notes](#security-notes)
9. [Limitations](#limitations)

---

## Project Overview

SecureHAWK watches a folder on your computer and records every file system event it detects. The baseline feature — present in every version — is **real-time logging of all file system activity to a `.txt` file** with millisecond-precision timestamps, SHA-256 hashes, and structured log entries.

The project is intentionally split across multiple scripts so you can pick exactly the level of capability you need — from a simple 100-line terminal logger to a full desktop application with a real-time web dashboard.

---

## Quick Version Picker

| # | File | Platform | Use This If You Want... |
|---|------|----------|-------------------------|
| 1 | `file_monitor.py` | Windows | The simplest possible logger — terminal prompts, `.txt` output, no extras |
| 2 | `file_monitor_mac.py` | macOS | Same as v1 but for Mac (handles `.DS_Store`, Finder drag-and-drop) |
| 3 | `file_monitor_web.py` | Windows | Live browser dashboard alongside the text log |
| 4 | `file_monitor_secure.py` | Windows | Everything in v3, plus token-based dashboard authentication |
| 5 | `file_monitor_enhanced.py` | Windows | Adds Open, Copy, and Download detection + process attribution |
| 6 | `SecureHAWK.py` | Windows | Full desktop GUI with folder pickers, one-click start/stop, all features |

All versions produce the same style of `.txt` log file, so logs from different versions are interchangeable.

---

## Prerequisites (Read First)

Every version requires **Python 3.10 or newer**. The Windows versions also need some libraries installed via `pip`. The macOS version only needs one library.

### Installing Python on Windows

Download Python from `python.org/downloads` and run the installer. **During installation, you must check the box labeled "Add Python to PATH"** at the bottom of the first screen — without this, the `python` command won't work from Command Prompt. After installation, close and reopen any existing Command Prompt windows for the PATH change to take effect.

If Windows tries to redirect `python` to the Microsoft Store, disable that redirect: press the Windows key, type "app execution aliases", press Enter, and toggle off "App Installer python.exe" and "App Installer python3.exe".

To verify Python is installed correctly, open a **fresh** Command Prompt and run:
```
python --version
```
You should see `Python 3.12.x` or similar. If not, reinstall and make sure the PATH box is checked.

### Installing Python on macOS

macOS often has Python 2 pre-installed, but you need Python 3. The easiest options are:
- **Homebrew:** `brew install python`
- **Official installer:** download from `python.org/downloads/macos`

Verify in Terminal:
```
python3 --version
```

### Getting the project files

Save all the `.py` files and `build_exe.bat` into a single folder of your choice — for example, `C:\Users\YourName\Documents\SecureHAWK\` on Windows or `~/Documents/SecureHAWK/` on macOS.

---

# Version 1 — Basic Windows Monitor

**File:** `file_monitor.py`
**Platform:** Windows 10 / 11
**UI:** Command Prompt text prompts
**Output:** `.txt` log file only (no dashboard)

The simplest version of SecureHAWK. Monitors a directory you specify and writes every file system event to a plain text log file. No web server, no GUI, no authentication — just clean logging.

## What it detects

- **CREATED** — New files or folders appearing in the watched area
- **MODIFIED** — Existing files being changed
- **DELETED** — Files or folders being removed
- **MOVED** — Files being renamed or relocated within the watched area

For every modification, it computes a SHA-256 hash of the new contents and records the file size, so you can verify integrity later.

## Installation

Open Command Prompt and install the one required library:
```
pip install watchdog
```

If `pip` isn't recognized, try:
```
python -m pip install watchdog
```

## How to run

Navigate to the folder where you saved `file_monitor.py`:
```
cd C:\Users\YourName\Documents\SecureHAWK
```

Run it:
```
python file_monitor.py
```

The program will ask three questions in order:

1. **"Enter the directory to watch (full path):"** — Type or paste the path of the folder you want to monitor, like `C:\Users\YourName\Documents`. The fastest way to get a path: open File Explorer, navigate to the folder, click in the address bar, and copy (Ctrl+C). Then paste into the terminal (right-click or Ctrl+V). Quotation marks are handled automatically.

2. **"Enter the path for the log file (.txt):"** — Type where you want the log saved, like `C:\Users\YourName\Desktop\changes.txt`. If the file doesn't exist, it will be created. If the parent folder doesn't exist, it will be created too. If you forget the `.txt` extension, it will be added automatically.

3. **"Watch subdirectories too? (Y/n):"** — Type `Y` (or just press Enter) to monitor everything recursively, or `n` to only monitor the top-level folder.

After that, monitoring starts immediately. Events print to the terminal as they happen and are written to the log file. Press `Ctrl+C` to stop. A session footer is automatically written to the log when you stop.

## Example log output

```
======================================================================
  FILE CHANGE MONITOR - SESSION STARTED
  Time:      2026-04-21 14:30:00
  Watching:  C:\Users\Alex\Documents\TestFolder
  User:      Alex
  Host:      DESKTOP-ABC123
======================================================================

[2026-04-21 14:30:15.847] CREATED    FILE | C:\Users\Alex\Documents\TestFolder\note.txt | size=0B
[2026-04-21 14:30:22.102] MODIFIED   FILE | C:\Users\Alex\Documents\TestFolder\note.txt | size=128B sha256=a3f9b8c1d4e7f2a9
[2026-04-21 14:30:45.334] MOVED      FILE | C:\Users\Alex\Documents\TestFolder\note.txt | -> C:\Users\Alex\Documents\TestFolder\archive\note.txt
[2026-04-21 14:31:00.127] DELETED    FILE | C:\Users\Alex\Documents\TestFolder\archive\note.txt

----------------------------------------------------------------------
  SESSION ENDED: 2026-04-21 14:35:00
  Total events logged: 4
----------------------------------------------------------------------
```

---

# Version 2 — macOS Basic Monitor

**File:** `file_monitor_mac.py`
**Platform:** macOS 11 (Big Sur) or newer
**UI:** Terminal text prompts
**Output:** `.txt` log file only (no dashboard)

The macOS equivalent of Version 1. Monitors a directory using macOS's native FSEvents API (which is faster and more efficient than the Windows equivalent) and logs every event to a plain text file.

## What it detects

Same as Version 1: CREATED, MODIFIED, DELETED, MOVED — with SHA-256 hashes and file sizes.

## macOS-specific improvements

- **Drag and drop paths from Finder** — When the program asks for a directory, just drag any folder from Finder into the Terminal window to paste its full path automatically.
- **Tilde expansion** — You can use `~/Desktop/logs.txt` instead of `/Users/YourName/Desktop/logs.txt`.
- **Automatic filtering of macOS noise** — Hidden files like `.DS_Store`, `._resource_forks`, Spotlight metadata, and Trash state are silently filtered out so they don't flood your log.
- **FSEvents efficiency** — Lower CPU usage and fewer duplicate notifications than polling-based approaches.

## Installation

Open Terminal (Command+Space → type "Terminal" → Enter) and install the one required library:
```
pip3 install watchdog
```

If `pip3` isn't found:
```
python3 -m pip install watchdog
```

## How to run

Navigate to wherever you saved the script:
```
cd ~/Documents/SecureHAWK
```

Run it:
```
python3 file_monitor_mac.py
```

You'll get the same three prompts as the Windows version:

1. **"Enter the directory to watch (full path):"** — Drag a folder from Finder into the Terminal, or type `~/Documents` or any other path.
2. **"Enter the path for the log file (.txt):"** — Example: `~/Desktop/changes.txt`.
3. **"Watch subdirectories too? (Y/n):"** — Press Enter for yes.

Press `Ctrl+C` to stop. Session footer is written automatically.

## macOS permissions note

If you try to monitor system folders (like `~/Library/Mail`, other users' home directories, or anywhere requiring elevated privileges), macOS will block the monitor and show a permission error. To fix this, grant Terminal "Full Disk Access":

1. Open **System Settings → Privacy & Security → Full Disk Access**
2. Click the `+` button
3. Add Terminal (or your terminal app of choice)
4. Restart Terminal

For normal folders like Desktop, Documents, or Downloads, no special permissions are needed.

## Example log output

```
======================================================================
  FILE CHANGE MONITOR - SESSION STARTED
  Time:      2026-04-21 14:30:00
  Watching:  /Users/alex/Documents/TestFolder
  User:      alex
  Host:      Alexs-MacBook-Pro.local
  Platform:  macOS 14.4.1
======================================================================

[2026-04-21 14:30:15.847] CREATED    FILE | /Users/alex/Documents/TestFolder/note.txt | size=0B
[2026-04-21 14:30:22.102] MODIFIED   FILE | /Users/alex/Documents/TestFolder/note.txt | size=128B sha256=a3f9b8c1d4e7f2a9
```

---

# Version 3 — Windows with Web Dashboard

**File:** `file_monitor_web.py`
**Platform:** Windows 10 / 11
**UI:** Terminal prompts + live browser dashboard
**Output:** `.txt` log file **and** real-time web dashboard

Everything Version 1 does, plus a live browser dashboard that shows events as they happen. A small Flask web server runs alongside the file monitor and streams events via Server-Sent Events (SSE) to your browser.

## Additional features beyond Version 1

- **Live web dashboard** at `http://localhost:8080` (or your chosen port)
- **Real-time event stream** — events appear in the browser within milliseconds
- **Stats dashboard** — live counters for each event type
- **Session info panel** — shows what's being watched, where logs go, user/host
- **Event history replay** — the dashboard remembers the last 200 events, so opening the dashboard late still shows what happened
- **Multi-browser support** — open the dashboard in multiple tabs or browsers simultaneously

## Installation

```
pip install watchdog flask flask-cors
```

## How to run

```
python file_monitor_web.py
```

Same three prompts as Version 1, plus a fourth:

4. **"Web dashboard port (default 8080):"** — Press Enter for 8080, or enter any port number 1024–65535.

About 1.5 seconds after monitoring starts, your default browser opens automatically to the dashboard. The dashboard shows all the same events that are being written to the log file, plus color-coded stats, filterable lists, and real-time updating.

## Using the dashboard

- **Top header** displays the live "STREAMING" indicator — if this turns red, the connection to the Python program has dropped
- **Session info panel** shows the watch directory, log path, user, and host
- **Stats row** shows counts for Total / Created / Modified / Deleted / Moved events
- **Live event list** streams new events to the top, with timestamps, event types, and full paths
- **Clear View button** wipes the visible list (doesn't affect the log file)

## Security consideration

This version has **no authentication** on the dashboard. Anything running on your machine (other programs, browser extensions, visited websites that attack localhost) could theoretically read the dashboard data. The server only binds to `127.0.0.1` so network machines can't reach it, but for better security use Version 4.

---

# Version 4 — Windows with Secure Dashboard

**File:** `file_monitor_secure.py`
**Platform:** Windows 10 / 11
**UI:** Terminal prompts + authenticated web dashboard
**Output:** `.txt` log file **and** token-protected web dashboard

Same functionality as Version 3, but with a fresh 256-bit random session token generated each launch. The token is required to access any dashboard endpoint, eliminating the risk of other processes or websites reading your dashboard data.

## Additional features beyond Version 3

- **Random 256-bit session token** generated at startup using Python's `secrets` module
- **Token required for every endpoint** — dashboard HTML, session info API, event history API, and live stream all verify the token
- **Constant-time token comparison** using `hmac.compare_digest` to prevent timing attacks
- **Restricted CORS policy** — only the dashboard origin can make API requests
- **"Authenticated" badge** on the dashboard confirming the secure session
- **Custom 401 Unauthorized page** with clear instructions for recovering the session URL

## Installation

Same as Version 3:
```
pip install watchdog flask flask-cors
```

## How to run

```
python file_monitor_secure.py
```

Same four prompts. When monitoring starts, the terminal prints a special URL that includes the session token:

```
Dashboard URL (copy if browser doesn't auto-open):
http://localhost:8080/?token=Xz7a9BcD3eF...your_unique_token...
```

The browser auto-opens to that URL. If you close the tab, you need that URL (with the token) to reopen it — a plain `http://localhost:8080/` will show the unauthorized page.

## Security properties

- The token exists only in the program's memory and the browser tab's memory. It's never saved to disk.
- Stopping and restarting the program generates a new token, invalidating all previous URLs.
- The token travels via the `X-Session-Token` HTTP header for API calls and as a URL query parameter for the dashboard and SSE stream — safe on localhost, but don't share the URL.

Everything else — dashboard features, event detection, log format — is identical to Version 3.

---

# Version 5 — Windows with Enhanced Detection

**File:** `file_monitor_enhanced.py`
**Platform:** Windows 10 / 11
**UI:** Terminal prompts + secure web dashboard
**Output:** `.txt` log file **and** secure web dashboard with extended event types

The most feature-complete command-line version. Everything Version 4 does, plus three additional event types and process attribution.

## Additional event types beyond Version 4

- **OPENED** — logs when a file is read by a program (not just modified)
- **COPIED** — detects when a new file matches the SHA-256 hash of an existing file in the watched area
- **DOWNLOADED** — detects files that carry the Windows Zone.Identifier marker indicating they came from the internet
- **Process attribution** — each event includes a `likely_process=` hint showing the most CPU-active user process at that moment

## How each detection works

**OPENED detection** uses a background thread that polls every file in the watched directory every 3 seconds, comparing last-access timestamps. When a file's access time jumps forward but its modification time didn't, it means something read the file — and an OPENED event is logged.

**COPIED detection** maintains a running SHA-256 hash index of every file in the watched area. When a new file appears, the program hashes it and checks the index — if any existing file has the same hash, it's logged as COPIED with a pointer to the original source.

**DOWNLOADED detection** reads the Windows `Zone.Identifier` alternate data stream, a hidden metadata stream that browsers and email clients attach to files that came from the internet. When present, the program extracts the source URL (when available) and logs it as `from=https://...`.

**Process attribution** snapshots running processes at each event and logs the most CPU-active user process as a hint.

## Installation

```
pip install watchdog flask flask-cors psutil
```

The new dependency is `psutil`, which enables process attribution.

## How to run

```
python file_monitor_enhanced.py
```

You get one additional prompt compared to Version 4:

5. **"Detect file opens via atime polling? (Y/n):"** — Press Enter for yes. This enables the OPENED event detection.

When monitoring starts, the program automatically tests whether your drive has last-access-time tracking enabled and warns you if not. To enable it, open an **admin Command Prompt** and run:

```
fsutil behavior set DisableLastAccess 0
```

Then reboot. After that, OPENED events will work reliably.

## Enhanced dashboard

The dashboard now shows seven stat cards (Total, Created, Modified, Opened, Copied, Downloaded, Deleted) with color-coded event types — purple for opens, orange for copies, pink for downloads. Filter buttons let you view one event type at a time. The rest of the dashboard is identical to Version 4.

## Example enhanced log output

```
[2026-04-21 14:32:15.847] CREATED    FILE | C:\Users\Alex\Documents\report.docx | size=24576B sha256=a3f9b8c1d4e7f2a9 likely_process=winword.exe
[2026-04-21 14:32:16.102] DOWNLOADED FILE | C:\Users\Alex\Downloads\invoice.pdf | from=https://example.com/invoice.pdf
[2026-04-21 14:33:45.891] COPIED     FILE | C:\Users\Alex\Desktop\backup.docx | source=C:\Users\Alex\Documents\report.docx
[2026-04-21 14:34:12.334] OPENED     FILE | C:\Users\Alex\Documents\report.docx | size=24576B likely_process=explorer.exe
```

---

# Version 6 — SecureHAWK v0.3 Desktop GUI

**File:** `SecureHAWK.py`
**Platform:** Windows 10 / 11
**UI:** Native Tkinter desktop application
**Output:** `.txt` log file **and** secure web dashboard **and** live GUI event viewer

The most polished version. All detection capabilities of Version 5, but wrapped in a native Windows desktop application with graphical folder pickers, embedded event viewer, start/stop buttons, and config persistence.

## Additional features beyond Version 5

- **Native Windows GUI** — no more terminal prompts, runs as a proper windowed app
- **"Browse..." buttons** — native Windows folder and file-save dialogs instead of typing paths
- **Embedded event viewer** — watch events stream by inside the app window with color coding
- **Live stats strip** — 7 color-coded counters update in real time at the top of the window
- **One-click start/stop** — big green START button, big red STOP button
- **One-click dashboard** — dedicated button opens the web dashboard in your browser
- **"Open Log Folder" button** — reveals the log file in File Explorer
- **Config persistence** — remembers your last watch directory, log file, recursive setting, open-detection setting, and port across launches (stored at `%USERPROFILE%\.securehawk_config.json`)
- **Lock-while-running** — config fields disable while monitoring is active so you can't accidentally change them
- **Session-locked browser tokens** — same security model as Version 4/5, token regenerated each launch

## Installation

```
pip install watchdog flask flask-cors psutil
```

## How to run

```
python SecureHAWK.py
```

No terminal prompts. A native Windows window opens with three main sections:

**Configuration panel (top):**
- **Watch Directory** field with a "Browse..." button — click to open a Windows folder picker
- **Log File** field with a "Browse..." button — click to open a Save As dialog pre-filled with `securehawk_log.txt`
- **Options row** with checkboxes for subdirectory monitoring and file-open detection, plus a port input

**Control row (middle):**
- **START MONITORING** — green button that begins watching and opens the dashboard
- **STOP** — red button that stops monitoring cleanly and writes the session footer
- **OPEN DASHBOARD** — cyan button that re-opens the browser dashboard in a new tab
- **Open Log Folder** — opens File Explorer to where your log file lives

**Stats strip:**
Seven color-coded cells (Total / Created / Modified / Opened / Copied / Downloaded / Deleted) that update live as events occur.

**Live Event Log (bottom):**
A scrolling view of every event with millisecond timestamps and color-coded event types — purple for opens, orange for copies, pink for downloads, green for creates, yellow for modifies, red for deletes, cyan for moves.

## First-run workflow

1. Click "Browse..." next to Watch Directory, pick a folder
2. Click "Browse..." next to Log File, pick where to save the log
3. (Optional) Adjust recursive, open detection, or port
4. Click START MONITORING
5. Your browser opens to the dashboard automatically
6. Watch events stream in both the desktop app and the browser
7. Click STOP when done

Next time you launch, all your settings are pre-filled from last time.

## Why choose this version

If you're using SecureHAWK as an everyday tool rather than reading the source code for educational purposes, this is the one to use. It's the only version that doesn't require typing paths or using Command Prompt prompts. It's also the version designed to be built into a standalone `.exe` for distribution.

---

## Building a Standalone Windows Executable

Only applies to Version 6 (`SecureHAWK.py`). Produces a single `SecureHAWK.exe` that runs on any Windows 10/11 machine without Python installed.

### Requirements

- Windows machine with Python properly installed (from `python.org`, with "Add Python to PATH" enabled)
- Internet connection (for the build script to install PyInstaller and dependencies)

### Build steps

1. Put `SecureHAWK.py` and `build_exe.bat` in the same folder
2. Double-click `build_exe.bat`
3. Wait 1–3 minutes for the build to complete
4. Find `SecureHAWK.exe` in the `dist` folder that appears

The build script automatically:
- Verifies Python is available
- Installs `pyinstaller` and all required libraries
- Cleans any previous build artifacts
- Runs PyInstaller with all the correct flags (--onefile, --windowed, --collect-all for each dependency)

### Distributing the executable

You can copy `SecureHAWK.exe` to any Windows 10/11 machine and it will run standalone. The target machine does **not** need Python, pip, or any libraries installed — everything is bundled into the executable.

### First-run caveats for .exe

- **Windows SmartScreen warning:** On first launch, Windows may show "Windows protected your PC". Click "More info" then "Run anyway". This happens because the executable isn't signed with a code-signing certificate. Subsequent launches don't show the warning.
- **Antivirus false positives:** Some antivirus programs flag PyInstaller executables because malware authors also sometimes use PyInstaller. If this happens, add an exclusion for `SecureHAWK.exe` in your antivirus settings.
- **Slow first launch:** The first time you run the executable, Windows needs 3–8 seconds to unpack the bundled Python runtime into a temp folder. Subsequent launches are faster thanks to Windows caching.
- **File size:** The executable is 35–45 MB because it contains the entire Python interpreter plus all dependencies. This is normal for PyInstaller bundles.

---

## Understanding the Log File

Every version writes to `.txt` using the same format so logs are interoperable across versions.

### Line format

```
[TIMESTAMP] EVENT_TYPE KIND | FULL_PATH | EXTRA_DATA
```

- **TIMESTAMP** — `YYYY-MM-DD HH:MM:SS.mmm` with millisecond precision
- **EVENT_TYPE** — one of CREATED / MODIFIED / DELETED / MOVED / OPENED / COPIED / DOWNLOADED
- **KIND** — either `FILE` or `DIR`
- **FULL_PATH** — the complete file system path
- **EXTRA_DATA** — optional pipe-separated key=value pairs like `size=1024B sha256=a3f9... likely_process=chrome.exe`

### Session boundaries

Every monitoring session begins with a banner header and ends with a footer, so you can tell separate sessions apart when browsing a long log:

```
======================================================================
  FILE CHANGE MONITOR - SESSION STARTED
  Time:      2026-04-21 14:30:00
  Watching:  C:\Users\Alex\Documents
  User:      Alex
  Host:      DESKTOP-ABC123
======================================================================

...events...

----------------------------------------------------------------------
  SESSION ENDED: 2026-04-21 15:45:22
  Total events logged: 147
----------------------------------------------------------------------
```

Sessions append to the existing file, building up a continuous history.

### Parsing the log programmatically

The format is stable and line-oriented, which makes it easy to parse with tools like `grep`, PowerShell, or Python. For example, to find all DOWNLOADED events in a log:

**Windows PowerShell:**
```powershell
Select-String -Path "changes.txt" -Pattern "DOWNLOADED"
```

**macOS/Linux:**
```bash
grep DOWNLOADED changes.txt
```

---

## Global Troubleshooting

### "Python was not found" when running any command

Python isn't installed or isn't on your PATH. Reinstall from `python.org/downloads` and make sure the "Add Python to PATH" box is checked during installation. Close and reopen your terminal.

### "'install' is invalid syntax" when running `pip install`

You're inside the Python interpreter — you see `>>>` prompts. Type `exit()` and press Enter to leave Python, then run the pip command in regular Command Prompt.

### "pip is not recognized"

Python is installed but pip isn't on your PATH. Use this alternative:
```
python -m pip install watchdog
```

### "Path does not exist" when entering a directory

Check in order:
- Remove any trailing `\` or `/` from the path
- Make sure there are no typos — copy the path from File Explorer/Finder instead of typing
- Check whether OneDrive/iCloud has moved your folders (Documents might actually be at `C:\Users\You\OneDrive\Documents`)
- Test with `dir "your_path"` (Windows) or `ls "your_path"` (macOS) — if that fails too, the path is genuinely wrong

### Dashboard won't open / won't connect

- Make sure the port isn't already in use. Try 8081, 8888, or any other number 1024–65535.
- If you closed the browser tab on a secure version, you need the full URL with the token from the terminal output. Plain `http://localhost:8080` will show the unauthorized page.
- Check that your antivirus isn't blocking the local web server.

### Many MODIFIED events for a single save

This is normal. Windows applications often save files using a "write-to-temp-then-rename" pattern that triggers 2–3 MODIFIED events per actual save. The hashes in the log tell you whether the content actually changed.

### OPENED events never appear

Windows has probably disabled last-access-time tracking. Open an **admin** Command Prompt and run:
```
fsutil behavior set DisableLastAccess 0
```
Then reboot. After that, OPENED events work.

### Antivirus flagged the .exe

This is a false positive common to PyInstaller outputs. Add an exclusion in your antivirus settings for `SecureHAWK.exe`.

### macOS says the script can't be run

In Terminal, navigate to the script's folder and run `python3 file_monitor_mac.py`. Don't double-click the `.py` file — macOS doesn't know what to do with Python files by default.

---

## Security Notes

**Network exposure:** All web dashboards bind strictly to `127.0.0.1` (localhost only). They're not reachable from other machines on your network. Do **not** change this to `0.0.0.0` unless you understand what that exposes.

**Log file sensitivity:** The log records every file path that changes, revealing folder structures, document names, and potentially sensitive information. Store the log file somewhere only you can read it.

**Token handling:** On secure versions, the dashboard URL contains the session token. Don't screenshot or share it. Anyone with that URL can view the dashboard while the program is running.

**Not a security boundary:** This tool logs activity — it doesn't prevent or detect malicious activity. A privileged attacker can stop the program, delete the log, or modify the code. For production-grade integrity monitoring, look at Wazuh, OSSEC, Tripwire, or commercial endpoint security platforms.

---

## Limitations

This is an educational project. Compared to production file integrity monitoring systems, SecureHAWK is missing:

- **Tamper-evident logging** (append-only storage, cryptographic chaining, off-machine log forwarding)
- **Real source validation** (the "likely_process" field is correlation, not proof — a proper implementation would use Windows Event Auditing or kernel drivers)
- **Behavioral anomaly detection** (the architecture diagram describes ML-based behavior profiling, but this codebase doesn't implement it)
- **Kernel-level hooks** (for reliable open/copy/process detection, you'd need ETW on Windows or Endpoint Security Framework on macOS)
- **Centralized management** (no SIEM integration, no fleet management, no policy distribution)
- **Network integrity monitoring** (only watches local file systems)

These limitations are by design — the project is intended to teach the concepts, not to be a production security tool.

---

## Quick Start Commands

**Windows, basic logging only:**
```
pip install watchdog
python file_monitor.py
```

**Windows, full dashboard with all features:**
```
pip install watchdog flask flask-cors psutil
python SecureHAWK.py
```

**Windows, build standalone .exe:**
```
Double-click build_exe.bat
Find SecureHAWK.exe in the dist folder
```

**macOS, basic logging:**
```
pip3 install watchdog
python3 file_monitor_mac.py
```

---

*SecureHAWK is an educational demonstration project. Use it to learn about file integrity monitoring, understand how these systems work, and experiment with security concepts. For production security needs, use established tools like Wazuh, OSSEC, Tripwire, CrowdStrike Falcon, or SentinelOne.*
