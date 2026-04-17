# Cybis-Secure-H.A.W.K
Cybersecurity branch of IBIS Private Sector.
	-- For File Monitoring System With HTML DashBoard --
	
	How to set it up on Windows:
	Open Command Prompt and install the additional libraries:
	pip install watchdog flask flask-cors
	Then run it:
	python file_monitor_secure.py
	It'll prompt you for the watch directory, log file path, recursive option, and the port for the web dashboard (default 8080). After about 1.5 seconds, your default browser will automatically open to http://localhost:8080 showing the live dashboard.
	The program asks you for both paths through simple text prompts in the terminal. Here's exactly how it works step by step.
	When you run the program, you'll see something like this in your Command Prompt or PowerShell window:
	======================================================================
	  FILE CHANGE MONITOR - WITH SECURE LIVE WEB DASHBOARD
	======================================================================
	
	Enter the directory to watch (full path):
	At this first prompt, you type or paste the full path to the folder you want to monitor. For example:
	Enter the directory to watch (full path): C:\Users\YourName\Documents\TestFolder
	Then press Enter. The program will verify the path exists and is actually a directory before moving on.
	After that, it asks for the log file path:
	Enter the path for the log file (.txt): C:\Users\YourName\Desktop\file_changes.txt
	Press Enter again and the program will create that file (and any missing folders in the path) automatically.

--How the communication actually works under the hood--

	The Python program runs three things at once. The file watcher detects changes and pushes events into a shared queue. The log writer pulls from that queue and writes to your .txt file. The Flask web server runs on a background thread and exposes three endpoints — the dashboard HTML, an API for session info, and /stream which uses Server-Sent Events to push new events to any connected browser as they happen.
	When you open the dashboard, your browser opens a persistent connection to /stream. Every time a file changes, the Python program writes JSON to that open connection, and the browser's JavaScript receives it within milliseconds and updates the UI. No polling, no refreshing — true real-time push.
	A few useful behaviors built in: The dashboard remembers the last 200 events even if you close and reopen the browser (loaded via /api/history on page load). Multiple browser tabs can connect simultaneously and all receive the same live stream. The connection status indicator in the bottom-right turns red if the Python program stops, so you'll immediately know if you've lost the stream. Stats update in real time across all five categories (Total, Created, Modified, Deleted, Moved).
	The browser will auto-open with the token already in the URL. The terminal also prints the full URL in case you need to open it in a different browser or paste it into another tab. If you accidentally close the tab, just copy the URL from the terminal and you're back in.
-- Security Features --

	Even if a malicious website tried to attack localhost:8080, it would need to know your exact token to read any data — and the token isn't discoverable through any side channel. Other processes on your machine that aren't browsers can still technically read the dashboard if they can read your browser's memory or your terminal scrollback, but that requires capabilities far beyond a typical web-based attack.
	A 256-bit random session token is generated at startup using Python's secrets module — this is the same cryptographic library Python uses for generating secure passwords and API keys. The token is fresh every time you start the program and exists only in memory, so closing the program destroys it permanently.
	Every endpoint now requires the token. The dashboard HTML page, the session info API, the event history API, and the live event stream all check for a valid token before responding. Requests without a token (or with the wrong token) get a 401 Unauthorized response and a clean error page explaining what to do.
	Token comparison uses hmac.compare_digest instead of regular ==. This is a constant-time comparison function that prevents timing attacks — an attacker can't measure how long the comparison takes to figure out which characters of the token are correct. Even though the attack vector is theoretical for localhost, it's the right way to compare secrets and costs nothing.
	CORS is now restricted to only accept requests from http://localhost:8080 and http://127.0.0.1:8080 (or whichever port you choose). Previously any website could attempt cross-origin requests; now only the dashboard itself can call the API endpoints.
	The token travels in two ways depending on the request type. Regular API calls from the dashboard use the X-Session-Token HTTP header (cleaner, doesn't appear in browser history). The Server-Sent Events stream and the initial page load have to use a query parameter because EventSource doesn't support custom headers — but since traffic never leaves localhost, this doesn't expose the token to any network observer.
	The token is never logged or stored anywhere persistent. Not in the .txt log file, not in cookies, not in localStorage — just held in memory by the running Python process and the open browser tab. If you accidentally screenshot your browser or share your terminal, you've leaked the token, but restarting the program generates a new one and invalidates the old.
