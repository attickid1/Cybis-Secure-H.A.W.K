# Security Policy

Thank you for taking the time to investigate SecureHAWK's security. This document explains how to report vulnerabilities responsibly, what kinds of issues are in scope, and what to expect after you report.

SecureHAWK is an educational project, not production security software — but it still handles user files, runs a local web server, and persists sensitive metadata, so genuine security issues are taken seriously and patched promptly.

---

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.** Public disclosure before a fix is available puts users at risk.

Instead, report security issues privately via one of these channels:

- **Email:** Send a detailed report to the maintainer email listed in the project's main README. Use a clear subject line like "SECURITY: <brief description>" so it doesn't get lost in regular project mail.
- **GitHub Security Advisories:** If the repository has Security Advisories enabled, you can submit a report through the "Security" tab → "Report a vulnerability" button. This is the preferred method when available because it provides a private discussion thread.

Please include in your report:

- A clear description of the vulnerability
- The version of SecureHAWK you're reporting against (visible in the app title bar or `APP_VERSION` constant in the source)
- Your operating system and version
- Steps to reproduce the issue — ideally a minimal sequence that consistently triggers the problem
- The impact you believe the vulnerability has — what could an attacker do?
- Any proof-of-concept code or screenshots that demonstrate the issue
- Your assessment of severity (your judgment is helpful, even if we disagree)
- Whether you've shared this information with anyone else
- How you'd like to be credited (or not credited) when the fix is published

You do not need to have a complete fix prepared — a clear report of the issue is enough. If you do have a proposed patch, that's welcome but not required.

---

## What to Expect After Reporting

**Acknowledgment within 7 days.** Someone will respond confirming the report was received and is being looked at. This is just acknowledgment, not a fix timeline.

**Initial assessment within 14 days.** We'll evaluate the report's severity, confirm whether it's reproducible, and either accept it as a valid vulnerability or explain why it doesn't qualify. We aim to be transparent — if we don't consider something a vulnerability, we'll explain our reasoning rather than just dismissing the report.

**Fix timeline depends on severity:**

- **Critical issues** (remote code execution, authentication bypass affecting all users, exposure of sensitive data without authentication): We aim for a patch within 14 days.
- **High severity issues** (local privilege escalation, predictable token generation, log file exposure): Patch within 30 days.
- **Medium severity issues** (information disclosure with limited impact, dashboard XSS that requires specific user actions): Patch within 60 days.
- **Low severity issues** (theoretical timing attacks, minor information leaks in error messages): Patched in the next regular release.

These are targets, not hard guarantees. Personal-project maintenance happens around real-life constraints. We'll communicate honestly if a fix is taking longer than the target.

**Disclosure coordination.** Once a fix is ready and released, we'll work with you on disclosure timing. The default plan is: release the fix, wait 7 days for users to update, then publish a security advisory describing the vulnerability and crediting you (if you want credit). If the vulnerability is being actively exploited in the wild, we may publish the advisory sooner. If you have a specific disclosure deadline tied to a publication or conference talk, let us know in your initial report and we'll plan accordingly.

---

## What Counts as a Vulnerability

Given SecureHAWK's threat model, these are the categories that genuinely qualify as security issues.

### High Priority — Definitely In Scope

**Authentication bypass on the web dashboard.** Any way to access the dashboard, API endpoints, or event stream without a valid session token. The token-based authentication is the primary security control between the running monitor and other processes on the machine, so any bypass is taken seriously.

**Token predictability or leakage.** If the session token can be guessed, brute-forced in a reasonable time, derived from observable state, or extracted from a place it shouldn't be (logs, error messages, on-disk files), that's a vulnerability. Tokens are generated with Python's `secrets` module and are supposed to be cryptographically unpredictable.

**Path traversal in file operations.** SecureHAWK reads user-specified paths for the watch directory, the log file, and the baseline storage. Any way to make the program read, write, or expose files outside its intended scope by manipulating those paths is a vulnerability.

**Privilege escalation.** Anything that lets a non-administrator user gain administrator privileges by interacting with SecureHAWK, or that lets one user account read/write files belonging to another user account.

**Code injection.** Any way to make SecureHAWK execute arbitrary code through user input — particularly through paths, log file content, dashboard requests, or configuration values. The dashboard renders HTML server-side using `render_template_string`, so injection vulnerabilities there are particularly important.

**Cryptographic weaknesses in baseline comparison.** SecureHAWK uses SHA-256 for file hashing. Vulnerabilities would include hash collision exploitation (theoretical for SHA-256 but worth reporting if practical), comparison bypass that makes the program treat different files as identical, or storage of hashes in a way that allows tampering without detection.

**Cross-site request forgery (CSRF) against the dashboard.** Even though the dashboard binds to localhost, if a malicious webpage could make a user's browser send authenticated requests to the local SecureHAWK server (perhaps via DNS rebinding or token leakage through Referer headers), that would be a vulnerability.

### Medium Priority — In Scope

**Information disclosure beyond the threat model.** SecureHAWK intentionally logs file paths, hashes, and process names — that's its job. But if it exposes credentials, encryption keys, network configuration, or other secrets it shouldn't have access to, that's a vulnerability.

**Denial of service against the local user.** Crafted inputs that crash SecureHAWK in ways the user can't recover from without manual file deletion, or that make the program consume excessive CPU/memory/disk indefinitely.

**Cross-origin issues.** Despite CORS being restricted to `localhost:<port>`, any way for a different origin to read SecureHAWK's data via the API would be a vulnerability.

**Sensitive data left on disk after uninstall.** The installer offers to remove baselines and config files. If files containing sensitive information remain after the user opts to remove everything, that's a vulnerability.

### Low Priority — Borderline / Worth Reporting

**Timing attacks on token comparison.** We use `hmac.compare_digest` to prevent these, but if you find a way around it, please report.

**Predictable port selection.** Ports start at 8080 and increment. If knowing the port is somehow useful to an attacker (it generally isn't, given the token), report it.

**Configuration file injection.** If specially-crafted config file content can cause SecureHAWK to do something unintended on load, report it.

---

## What's Out of Scope

These are explicitly **not** vulnerabilities for SecureHAWK, given its educational scope and threat model.

**Unsigned executable.** SecureHAWK is distributed as an unsigned executable that triggers Windows SmartScreen. This is an acknowledged limitation, not a vulnerability. Code signing certificates cost $100–300/year and aren't justified for an educational project.

**Antivirus false positives.** PyInstaller-built executables sometimes get flagged by antivirus tools. This is a known limitation of any Python-to-exe technology, not a SecureHAWK problem.

**Local attacker with admin privileges can stop the monitor or modify logs.** Yes, they can. SecureHAWK is not designed to defend against attackers who already have administrator access to the machine — and pretending otherwise would be security theater. Real tamper-evident logging requires append-only storage on a separate system, off-host log forwarding, and other infrastructure that's intentionally out of scope.

**Log files contain sensitive information.** They're supposed to. The README explicitly warns about this. If you're concerned about log file contents, store them somewhere only you can read.

**Token visible in dashboard URL bar.** The token has to travel somehow, and on localhost where traffic never leaves the machine, the query parameter approach is fine. If you have access to the URL bar of someone's browser, you have bigger problems than reading their file monitor.

**Dashboard accessible to other processes on the same machine via the token.** SecureHAWK isn't designed to defend against arbitrary other processes running as the same user — those processes already have access to all the files the monitor is watching. The token prevents *unintentional* access (browser extensions, visited websites attacking localhost), not *intentional* local attacks.

**Lack of TLS on the local web server.** HTTPS for localhost-only traffic would require self-signed certificates that browsers reject, providing no actual security benefit while degrading usability. This is intentional.

**Missing security headers (HSTS, CSP, etc.) on the dashboard.** These are designed for public-facing web servers. For a localhost-only authenticated dashboard, they're not meaningful.

**Theoretical vulnerabilities without a practical exploit.** "An attacker who already controls X could do Y" reports where X already gives the attacker far more than Y. Be realistic about whether your finding represents an actual reduction in user safety.

**Issues in third-party dependencies.** If `watchdog`, `flask`, `flask-cors`, or `psutil` has a vulnerability, please report it to those projects directly. We'll update our dependencies when they patch, but we can't fix bugs in code we don't maintain.

**Performance issues, crashes from invalid input that don't have a security impact, or general bugs.** Open a regular GitHub issue for these. They might still get fixed, just not under the security process.

**Social engineering attacks** ("an attacker could trick the user into running a malicious version"). True of any software. Not a SecureHAWK-specific vulnerability.

---

## Threat Model

It helps to be explicit about what SecureHAWK is and isn't trying to defend against. This helps you calibrate whether something you've found qualifies as a vulnerability.

### Adversaries We Try to Defend Against

**Unauthenticated network attackers.** SecureHAWK binds strictly to `127.0.0.1`, so attackers on the same Wi-Fi or corporate network cannot reach the dashboard. This is enforced regardless of token state — the OS rejects the connection at the network layer.

**Malicious websites attacking localhost.** Some attacks (DNS rebinding, CSRF against local services) target services running on localhost. Our token requirement and restricted CORS policy defend against these.

**Other processes on the same machine that don't have access to the token.** A random browser extension or a visited website's JavaScript can't read the dashboard because they don't have the token. This is enforced cryptographically.

**Casual snooping.** Someone who briefly looks over your shoulder or sees your task bar can't immediately access the dashboard URL without the token.

### Adversaries We Do NOT Try to Defend Against

**A local user with administrator privileges.** They can stop SecureHAWK, modify its files, or replace it with a malicious version. No defense is possible without separating the monitor from the system it's monitoring, which is out of scope.

**A local user running as the same account as SecureHAWK.** They can read the process memory (which contains the token), read all the same files SecureHAWK can read, and effectively bypass any process-level security boundary. SecureHAWK shares a security boundary with everything else running as your user account.

**Physical access to the machine.** Someone with physical access can do anything. SecureHAWK is not a substitute for full-disk encryption.

**Sophisticated targeted attacks.** This is an educational project. If you're being specifically targeted by skilled adversaries, you need professional security tools and incident response services, not a hobby project.

**Forensic investigators with legal authority.** The log files are not designed to be tamper-evident or to provide chain-of-custody. They're useful for personal awareness, not legal evidence.

---

## Hall of Fame

We genuinely appreciate security researchers who report issues responsibly. When valid vulnerabilities are reported and you'd like to be credited, your name and the issue you found will be acknowledged in:

- The CHANGELOG.md entry for the version that includes the fix
- The published security advisory (if applicable)
- A "Security researchers who have helped SecureHAWK" section in this document (added when the first credit is earned)

If you'd prefer to remain anonymous, we'll honor that. Let us know in your initial report.

---

## What We Don't Do

To be upfront about the limits of what this project can offer:

**No bug bounties.** This is an unfunded educational project. We cannot pay for vulnerability reports. Researchers who only report bugs for money should focus on commercial bug bounty programs instead.

**No legal threats.** We will not pursue legal action against good-faith security researchers, even if we ultimately disagree with their severity assessment. Researching this code's security is welcome.

**No NDA requirements.** You don't have to sign anything to report a vulnerability. We just ask that you give us a reasonable window to fix it before public disclosure.

**No promises about response speed.** Personal-project maintenance happens around real life. We aim for the timelines listed above but cannot guarantee them. If we miss a target, we'll communicate honestly about why.

---

## For Researchers Using SecureHAWK in Their Own Research

If you want to use SecureHAWK as a target for security research, education, or training purposes — go ahead. The code is open, the architecture is documented, and the project actively welcomes scrutiny. A few suggestions:

**Run it in a virtual machine** if you're testing exploits, to avoid affecting your real working environment.

**Test against a fresh install with default settings** to make sure you're seeing baseline behavior, not the result of a misconfigured deployment.

**Read the architecture documentation in the README** to understand what each component is supposed to do before evaluating whether it does it correctly.

**Check the CONTRIBUTING.md for the project's design philosophy** — some design choices that look like vulnerabilities are actually intentional trade-offs for educational clarity. Calling those out is fine, but understand they may not result in code changes.

**Try the older versions too.** The progression from v1.0.6 to v1.0.7 fixed a real issue (event spam), and similar patterns might reveal interesting security observations across versions.

---

## Questions

If you're unsure whether something qualifies as a vulnerability, err on the side of reporting. We'd rather receive a report we ultimately classify as out-of-scope than miss a real issue because someone wasn't sure.

If you have general security questions about the project (not vulnerability reports), those can go in public GitHub Discussions or issues. Only the specific exploitation details need to be kept private.

Thanks for helping keep SecureHAWK's users safe.
