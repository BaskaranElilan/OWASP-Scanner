# Changelog

## v1.4.2-owasp-scanner.2 - 2026-07-06

### Installation Fix

- Updated the README to avoid Kali/Debian `externally-managed-environment` pip errors.
- Documented the recommended `.venv` installation flow.
- Added `install.sh` to create a virtual environment and install requirements safely.
## v1.4.2-owasp-scanner.1 - 2026-07-06

### Rebrand and Documentation

- Rebranded the project as **OWASP Scanner**.
- Updated the primary repository reference to `BaskaranElilan/OWASP-Scanner`.
- Updated maintainer identity to **Elilan Baskaran**.
- Renamed the primary CLI entry point to `owasp-scanner.py`.
- Rewrote the README in English.
- Added `LICENSE` and `NOTICE.md`.
- Updated generated report branding to OWASP Scanner.
- Updated argparse help text and examples to the new command name.

### Verification

- Python AST parsing passes for `owasp-scanner.py`.
- `python owasp-scanner.py --version` returns `OWASP Scanner v1.4.2`.

## Current Capabilities

- Multi-target scanning with interactive and batch modes.
- Authentication-aware directory fuzzing with redirect resolution.
- API security testing with report-integrated findings.
- Nmap, Nuclei, ffuf, WhatWeb, WPScan, and SecLists integrations.
- Advanced security checks for SSRF, SSTI, XXE, CRLF injection, HTTP request smuggling, and cache poisoning.
- Source-code analysis for exposed secrets and sensitive implementation details.
- WordPress detection, enumeration, vulnerability parsing, and brute-force workflows.
- Active Directory workflows using Kerbrute, LDAP, NetExec/NXC, and Impacket tooling.
- TXT, JSON, Markdown, and standalone HTML dashboard report generation.