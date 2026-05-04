[CONTRIBUTING.md](https://github.com/user-attachments/files/27366234/CONTRIBUTING.md)
# Contributing to SecureHAWK

Thank you for your interest in contributing to SecureHAWK. This is an educational project focused on demonstrating file integrity monitoring concepts, and contributions that improve clarity, reliability, security, or educational value are genuinely welcome.

This document explains what kinds of contributions are useful, how to submit them, what coding standards to follow, and what the project explicitly does **not** want to become.

---

## Table of Contents

1. [Project Philosophy](#project-philosophy)
2. [What We're Looking For Right Now](#what-were-looking-for-right-now)
3. [Acceptable Contributions](#acceptable-contributions)
4. [Out of Scope](#out-of-scope)
5. [Before You Start](#before-you-start)
6. [Coding Standards](#coding-standards)
7. [Security Considerations](#security-considerations)
8. [How to Submit a Contribution](#how-to-submit-a-contribution)
9. [Pull Request Checklist](#pull-request-checklist)
10. [Reporting Bugs](#reporting-bugs)
11. [Suggesting Features](#suggesting-features)
12. [Code of Conduct](#code-of-conduct)

---

## Project Philosophy

SecureHAWK is built on three core principles that guide every contribution decision:

**Education over completeness.** This project exists to teach how file integrity monitoring works, not to be a competitor to enterprise security tools like Wazuh or Tripwire. Contributions that add complexity without educational value will likely be declined. A simpler implementation that someone can read and understand is preferred over a sophisticated one that requires deep expertise to follow.

**Each version should stand alone.** The progression from `file_monitor.py` (basic) through `SecureHAWK.py` (full GUI) is intentional. New users should be able to start with v1 and learn one new concept at a time. Contributions shouldn't collapse versions together or remove the simpler ones.

**Honest about limitations.** The README and documentation are explicit that this is not production security software. Contributions should maintain that honesty. We don't want to oversell what the tool does or imply it provides protections it doesn't.

---

## What We're Looking For Right Now

These are the highest-priority areas where help would make the biggest impact. Contributions in these areas are most likely to be accepted quickly.

### High Priority

**Cross-platform parity for advanced versions.** Currently only the basic monitor has a macOS version (`file_monitor_mac.py`). Building macOS equivalents of the web dashboard, secure dashboard, enhanced detection, and GUI versions would significantly broaden the project's reach. The Tkinter GUI would need adjustments for native macOS look-and-feel; the web dashboard would mostly work as-is but needs testing.

**A Linux version of the basic monitor.** Following the same pattern as the macOS version — terminal prompts, `.txt` logging, native event handling via `inotify`. The `watchdog` library handles this transparently, so the main work is writing platform-appropriate documentation and filtering patterns.

**Test coverage.** The project currently has no automated tests. A pytest test suite covering the core detection logic, deduplication patches, hash computation, noise filtering, and configuration persistence would dramatically improve maintainability. Even partial coverage of the most-used code paths would be valuable.

**Documentation improvements.** Particularly screenshots of the dashboard and GUI in action, a video walkthrough of the build-to-executable process, and clearer explanations of when each version is appropriate to use.

**Sample/demo log files.** Pre-generated example log files showing what typical output looks like for common scenarios (a normal workday, a file copy operation, a download from the internet). These help users understand what the tool produces without having to run it themselves first.

### Medium Priority

**Email/webhook alerting.** A simple notification module that fires when specific event types occur — for example, sending a desktop notification or webhook POST when a `DOWNLOADED` event is logged. Should be opt-in via the config and shouldn't add new required dependencies.

**Export/reporting capabilities.** Tools for converting the `.txt` log into other formats (CSV, JSON, HTML report). Would be useful for users who want to analyze logs in spreadsheets or feed them into other tools.

**Configurable noise patterns.** Currently the noise file patterns in v1.0.7 are hardcoded. Moving them into a config file (or the existing `.securehawk_config.json`) would let users customize without editing source.

**Better Office save handling.** The v1.0.7 patch handles most Office noise, but Office 365 with cloud autosave produces patterns we haven't tested thoroughly. Real-world testing reports and refinements to the filter logic would be welcome.

**A "shadow mode" for the enhanced detection.** Currently if you enable open detection without atime support, you get nothing. A shadow mode that warns once and continues with reduced functionality would be friendlier than silent failure.

### Low Priority but Welcome

**Translations of the README and dashboard.** The dashboard UI has some hardcoded English strings; a basic i18n layer would let it run in other languages.

**Alternative visualizations on the dashboard.** Things like a timeline view of events, a treemap of which folders see the most activity, or a network graph showing file relationships.

**A dark/light theme toggle for the dashboard.** Currently it's dark-only. Some users prefer light themes for screen-recording or presentation use.

**Additional file format support for the log.** A structured JSONL log format alongside the current `.txt` format would make programmatic analysis easier without breaking the human-readable default.

---

## Acceptable Contributions

We welcome contributions across all of these categories. Each one has its own conventions outlined below.

### Bug fixes

Always welcome. Include a clear description of the bug, steps to reproduce, the expected versus actual behavior, and an explanation of your fix. If the bug affects multiple versions of the project, mention which ones.

### Performance improvements

Welcome if they don't sacrifice readability or add new dependencies. Include before/after measurements when possible — for example, "indexing 10,000 files reduced from 8.2s to 1.4s." Avoid micro-optimizations that hurt code clarity for marginal gains.

### Security improvements

Highly welcome, especially around the web dashboard auth, token handling, CORS configuration, or path validation. Include reasoning about the threat model — what attack does the change prevent, and is that attack realistic for this project's intended use?

### Code clarity refactors

Welcome but should preserve the educational character of the code. Don't refactor for the sake of "best practices" if it makes the code harder for a beginner to follow. The Python style here is intentionally straightforward — no clever metaclasses, no decorators where a function would do, no abstract base classes for things used in one place.

### New event detection types

Welcome but evaluate carefully. New event types should be useful for understanding file integrity monitoring concepts and shouldn't require admin/kernel privileges to function (or if they do, they should clearly communicate that requirement and degrade gracefully without those privileges).

### Documentation contributions

Always welcome — typo fixes, clarifications, expanded examples, screenshots, video walkthroughs, translated docs. Documentation contributions are reviewed less strictly than code contributions because they have lower risk of breaking things.

### New version variants

These need to fit the educational progression. If you want to add a "Version 7," it should teach a concept that isn't covered in versions 1–6 and should be roughly the same complexity step from v6 as v6 is from v5. Don't add versions that just combine existing features differently.

---

## Out of Scope

These contributions will be declined regardless of how well-written they are. This isn't a judgment of the work itself — it's just not what this project is trying to be.

### Production-ready security claims

Anything that frames SecureHAWK as a production security tool. The README is explicit that this is educational; contributions that add language like "enterprise-grade," "production-ready," "compliance certified," or imply the tool provides real attack protection will be reverted.

### Kernel-mode drivers or low-level OS hooks

These are out of scope for several reasons: they require admin/root privileges, they're platform-specific in ways that don't generalize, they're a significant security risk if implemented incorrectly, and they're far too complex for an educational project. If you want to implement kernel-level monitoring, you're working on a different project than this one.

### Removing existing versions

The progression from v1 to v6 is the project's main educational structure. Contributions that delete v1 because v6 "does the same thing better" miss the point. Each version teaches something specific about the buildup.

### Adding heavy dependencies

The project intentionally uses a small set of libraries. Contributions that add large dependencies (machine learning frameworks, full database engines, complex UI frameworks like PyQt or Electron) won't be accepted unless they enable a clearly-defined feature that can't be done another way. Even then, the dependency should be optional — the basic functionality should keep working without it.

### Cloud/server-side components

SecureHAWK runs entirely on the user's own machine. Contributions that move data to remote servers, add cloud sync of logs, or require any external service won't be accepted. Privacy and local-only operation are core values of the project.

### Mass file modification or "active defense" features

Anything that automatically modifies, quarantines, or deletes files based on detected events. This is a monitoring tool, not an antivirus. Active response capabilities are dangerous and out of scope. Logging an event is acceptable; deleting a file because of an event is not.

### AI-generated boilerplate without testing

We use AI tools as part of the development workflow ourselves, and that's fine. But contributions that are clearly AI-generated bulk code dumps, with no evidence that the contributor actually tested, understood, or thoughtfully reviewed what was generated, will be declined. If you can't explain what your code does or why, please don't submit it.

### Cryptocurrency, NFTs, or blockchain integrations

Hard no. There's no realistic file integrity monitoring use case for these technologies that wouldn't be better served by a simple append-only log on commodity storage. Don't propose them.

### Telemetry or analytics

The project collects no user data and never will. Don't propose adding it.

### Bundled marketing or sponsorship content

The README links to relevant educational resources only. We won't add sponsor logos, affiliate links, "Powered by..." badges, or commercial promotion.

---

## Before You Start

For contributions larger than a typo fix or small bug, please open an **issue** describing what you want to do before writing the code. This isn't bureaucracy — it's to make sure your work doesn't go to waste because the change isn't aligned with the project's direction.

Specifically, open an issue first if you're planning to:

- Add a new feature, event type, or version
- Refactor any file by more than ~50 lines
- Change the behavior of existing detection logic
- Add a new dependency
- Modify the dashboard UI in any non-trivial way
- Change the log file format

Small contributions that don't need pre-discussion include:

- Typo fixes
- Documentation clarifications
- Bug fixes for clearly-defined issues
- Small performance improvements with measurements
- Adding tests for existing behavior
- Translation of existing strings

---

## Coding Standards

The project follows a deliberately straightforward Python style. The goal is code that someone learning Python and learning about file monitoring can read and understand without needing to look up unfamiliar idioms.

### Python style

Use four-space indentation. Use snake_case for variables and functions, PascalCase for classes, UPPER_SNAKE for constants. Keep lines under 100 characters where reasonable, but don't break readable code just to fit a line limit.

Type hints are encouraged but not required. If you add them, add them consistently within a function rather than half-typing a function signature.

Docstrings on classes and non-trivial functions are appreciated. They should explain what the function does and why, not paraphrase the code.

Avoid clever Python features unless they meaningfully improve the code. List comprehensions are good; nested ternaries inside generator expressions are not. Decorators are fine for Flask routes; custom decorators for things used once are unnecessary complexity.

### File organization

Each version is a single self-contained file. Resist the urge to refactor shared code into a separate module — the educational value comes from being able to read each version in isolation. If you genuinely think shared code should be extracted, open an issue first.

Within a file, keep this rough order: imports, constants, helper functions, main classes, web/UI code, entry point. Group related functions together with comment dividers.

### Logging and error handling

User-facing errors should be friendly and actionable. "Path does not exist: C:\Users\Alex\Doc — try removing the trailing space" is better than "FileNotFoundError: [Errno 2]". The user might not be a developer.

Errors that aren't the user's fault (a transient permission denied on a single file, for example) should be logged but shouldn't crash the program. The monitor should keep running even if individual operations fail.

Don't catch `Exception` broadly unless you're at a top-level boundary. Catch specific exceptions where possible.

### Comments

Comments should explain **why** something is the way it is, not **what** the code does. The code itself should make the "what" clear.

```python
# GOOD: explains why
# Use compare_digest to prevent timing-based token guessing attacks
return hmac.compare_digest(provided, SESSION_TOKEN)

# BAD: paraphrases the code
# Compare provided token to session token
return hmac.compare_digest(provided, SESSION_TOKEN)
```

When you add a patch like the v1.0.7 deduplication, leave a `# v1.0.7 PATCH:` marker comment so future readers can find the rationale.

---

## Security Considerations

This project handles user file paths and runs a local web server, so contributions touching these areas need extra care.

### Path handling

Always validate user-provided paths before using them. Resolve them with `Path(input).expanduser().resolve()` to handle symlinks and relative paths. Never construct paths by string concatenation if user input is involved — use `os.path.join` or `pathlib`.

Do not trust path normalization to prevent directory traversal in security contexts. If you're adding any feature that lets the user reference paths in places the program writes to, audit it carefully.

### Web server

The dashboard server must remain bound to `127.0.0.1`. Do not change this to `0.0.0.0` or add a configuration option to do so without prominent warnings — exposing the dashboard to network access defeats the security model.

CORS should remain restricted to the dashboard origin. The session token check must run on every endpoint, including any new endpoints you add.

When you add a new endpoint, copy the `if not verify_token(): abort(401)` pattern from existing endpoints. Don't bypass it.

### Token handling

The session token must never be:

- Written to disk
- Logged anywhere
- Sent to any service outside localhost
- Used in error messages or stack traces
- Passed through query parameters in places where it would appear in browser history (the existing query-param usage is for the SSE stream where that constraint doesn't apply)

### Hash computation

The SHA-256 implementation uses the standard library — don't replace it. If you want to add additional hash algorithms (SHA-512, BLAKE3) for performance comparisons or educational variety, add them as alternatives, not replacements.

### Dependencies

Before adding a new dependency, consider:

- Is this in the standard library? Use that if possible.
- Is the dependency well-maintained? Check the release history.
- Does it pull in many transitive dependencies? Each one is a supply-chain risk.
- Is it cross-platform? The project supports Windows and macOS at minimum.

Don't pin versions tightly unless there's a reason — `watchdog>=3.0` is fine, `watchdog==3.0.4` is too restrictive. If you do need a tight pin, document why.

---

## How to Submit a Contribution

The project uses standard Git/GitHub workflow.

**Step 1: Fork the repository.** Click the Fork button on the project page to create your own copy.

**Step 2: Clone your fork locally.**
```
git clone https://github.com/YOUR_USERNAME/SecureHAWK.git
cd SecureHAWK
```

**Step 3: Create a branch for your work.** Use a descriptive name.
```
git checkout -b fix-modified-spam-on-office-files
```

Branch name conventions: `fix-...` for bug fixes, `add-...` for new features, `docs-...` for documentation, `refactor-...` for refactors, `test-...` for tests.

**Step 4: Make your changes.** Test them locally before committing. For changes to the file monitor itself, test with several real-world scenarios — opening Office documents, copying files, downloading something from a browser, monitoring a folder during normal work.

**Step 5: Commit with clear messages.** Each commit should be a single logical change with a message that explains what and why.

```
git commit -m "fix(v6): suppress duplicate MODIFIED events for Office files

Office applications fire 5+ MODIFIED events per save due to their
write-temp-then-rename save pattern. This patch adds three layers
of filtering: noise file patterns, hash-change detection, and a
2-second deduplication window. Result is 80-95% fewer log entries
while preserving every real content change.

Closes #42"
```

**Step 6: Push to your fork and open a pull request.**
```
git push origin fix-modified-spam-on-office-files
```

Then go to GitHub and open a pull request from your branch to the main repository's `main` branch.

---

## Pull Request Checklist

Before submitting your PR, confirm:

- [ ] The code runs without errors on at least one platform (specify which)
- [ ] You've tested the feature/fix manually with real files
- [ ] The change doesn't break any existing version of the monitor
- [ ] Any new constants or config options have sensible defaults
- [ ] You've added or updated documentation if user-facing behavior changed
- [ ] Comments explain the *why* of non-obvious code
- [ ] No new dependencies were added without discussion
- [ ] Token authentication, CORS restrictions, and localhost binding are preserved (if you touched the web server)
- [ ] The change is consistent with the project philosophy
- [ ] Your commit messages are clear and explain the reasoning

For larger changes, also include in the PR description:

- The motivating issue or problem
- A brief explanation of the approach you took
- Any alternatives you considered and why you didn't choose them
- Screenshots or example log output if visual/output changed
- Notes on how you tested

---

## Reporting Bugs

If you find a bug, please open an issue on the project's issue tracker. A good bug report includes:

- **Which version** you're using (v1 through v6, or the patched v1.0.7)
- **Your operating system** and version (Windows 11 22H2, macOS 14.4, etc.)
- **Your Python version** (`python --version`)
- **What you were trying to do** in plain language
- **What you expected to happen**
- **What actually happened** — exact error messages, screenshots, or log file excerpts
- **Steps to reproduce** — ideally a minimal sequence that consistently triggers the bug
- **What you've already tried** — workarounds attempted, related forum posts checked

Bug reports without reproduction steps are very hard to act on. If you can't reproduce the bug consistently, say so explicitly so we know not to ask.

### Security vulnerabilities

If you discover a security vulnerability, **do not open a public issue.** Instead, contact the maintainers privately via the contact method listed in the project README. Give us a reasonable window to address the issue before public disclosure.

For this project's threat model, "security vulnerability" means something like:

- A way to make the dashboard accessible without the session token
- A way to read the log file from a different user account
- A way to make the program write outside its intended locations
- A path traversal allowing access to files outside the watch directory

It does **not** include things like "the .exe isn't code-signed" (acknowledged limitation), "antivirus flags it" (false positive), or "it doesn't have feature X" (feature request).

---

## Suggesting Features

Feature suggestions are welcome but please check the [Out of Scope](#out-of-scope) section first to make sure your idea isn't already on the "no" list.

Good feature suggestions include:

- The use case — who would benefit and how
- The proposed approach — how would this work technically
- Alternatives considered — why this approach over others
- Dependency implications — does this need new libraries, OS APIs, etc.
- Backward compatibility — does it affect existing log formats, configs, etc.

Open feature suggestions as issues with the label "enhancement." Don't open a pull request for a feature without first opening an issue and getting alignment on whether it fits the project — large feature PRs that don't match the project's direction are sad to decline after you've already done the work.

---

## Code of Conduct

Be respectful. Disagree on technical merits, not personalities. Assume good faith — if a contribution seems wrong, ask why the contributor did it that way before assuming carelessness.

We expect contributors to:

- Treat others with kindness and patience
- Welcome newcomers, including those new to programming or file monitoring
- Give constructive feedback that helps the contributor improve
- Accept feedback gracefully even when it's "this won't be merged"
- Recognize that maintainer time is finite and reviews aren't instant

We will not tolerate:

- Personal attacks, harassment, or discriminatory language
- Demanding free work from maintainers or other contributors
- Bad-faith arguments or sealioning
- Posting other contributors' private information without permission

Maintainers reserve the right to close issues, decline PRs, or block users who violate these expectations.

---

## A Note on AI-Assisted Contributions

Using AI tools to help write code, documentation, or commit messages is fine. We use them ourselves. What matters is that you understand and stand behind what you submit.

If your PR is reviewed and a reviewer asks "why did you do it this way?", you should be able to answer. "The AI suggested it" is not an answer that will lead to your PR being merged. Treat AI-generated code the way you'd treat code from any colleague — review it, test it, modify it where needed, and only submit it if you genuinely believe it's right.

PRs that are clearly bulk AI generations submitted without thought (multiple unrelated changes, generic boilerplate that doesn't fit the codebase style, code that obviously wasn't tested) will be declined regardless of whether the underlying change would have been welcome from a careful contributor.

---

## Thank You

Every contribution — code, documentation, bug reports, feature suggestions, even just sharing the project with someone who'd find it useful — helps make SecureHAWK better as an educational resource. Whether you're fixing a typo or building a major new feature, the time you spend is genuinely appreciated.

If you're contributing for the first time and any part of this document is unclear, please ask. Confusion in this guide is a problem we want to fix.
