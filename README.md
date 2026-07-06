# OWASP Scanner

OWASP Scanner is an interactive web security testing toolkit based on the OWASP Web Security Testing Guide (WSTG) and OWASP API Security testing concepts. It helps authorized testers perform reconnaissance, mapping, vulnerability discovery, API checks, authentication-aware testing, and report generation from one Python CLI.

> OWASP Scanner is an independent open-source project. It is not affiliated with, endorsed by, or sponsored by the OWASP Foundation.

## Features

- Authentication-aware testing with Basic Auth, form login, manual session data, and optional Playwright-based headless login for SPAs and OAuth-style flows.
- Reconnaissance for headers, cookies, server details, robots.txt, sitemap.xml, HTTP methods, SSL/TLS, CORS, and technology detection.
- Nmap service/version scanning with XML parsing and report integration.
- Nuclei vulnerability scanning with JSON export parsing and severity summaries.
- Directory and virtual-host fuzzing with ffuf when available, plus internal fallback methods.
- Site spidering with form and parameter discovery.
- Source-code analysis for exposed secrets, credentials, API keys, JWTs, private keys, comments, internal paths, and source maps.
- Injection checks for SQLi, XSS, path traversal/LFI, command injection, and open redirect vectors.
- Advanced checks for SSRF, SSTI, XXE, CRLF injection, HTTP request smuggling, and cache poisoning.
- API testing for endpoint discovery, BOLA/IDOR, auth bypass, JWT weaknesses, mass assignment, verbose errors, GraphQL, CORS, and rate limiting.
- WordPress enumeration and attack workflows through WPScan when available.
- Active Directory workflows for Kerbrute, LDAP, NetExec/NXC, and Impacket-based roasting checks.
- Reports in TXT, JSON, Markdown, and standalone HTML dashboard formats.

## Requirements

| Dependency | Required | Notes |
| --- | --- | --- |
| Python 3.8+ | Yes | Main runtime |
| requests | Yes | Installed from `requirements.txt` |
| beautifulsoup4 | Yes | HTML parsing |
| colorama | Yes | Colored terminal output |
| tqdm | Yes | Progress bars |
| ffuf | Optional | Faster directory and vhost fuzzing |
| nmap | Optional | Port and service scanning |
| nuclei | Optional | Template-based vulnerability scanning |
| whatweb | Optional | Technology fingerprinting |
| hydra | Optional | Login brute force support |
| wpscan | Optional | WordPress testing |
| SecLists | Optional | Recommended wordlists |
| Playwright | Optional | Headless login for SPAs/OAuth-style flows |
| Kerbrute, ldap-utils, NetExec/NXC, Impacket | Optional | Active Directory module |

## Installation

```bash
git clone https://github.com/BaskaranElilan/OWASP-Scanner.git
cd OWASP-Scanner
python3 -m pip install -r requirements.txt
```

Optional tools can be installed through your operating system package manager or their official installation methods. On Kali Linux, many of them are available through `apt`.

## Usage

Start the interactive scanner:

```bash
python3 owasp-scanner.py
```

Scan a single target:

```bash
python3 owasp-scanner.py --url https://example.com
```

Save reports with a custom output base:

```bash
python3 owasp-scanner.py --url https://example.com --output report.txt
```

Scan multiple targets interactively:

```bash
python3 owasp-scanner.py -u https://a.example -u https://b.example
python3 owasp-scanner.py -u https://a.example,https://b.example
```

Run a non-interactive full pentest for each target in a list:

```bash
python3 owasp-scanner.py -L targets.txt --batch
```

## CLI Options

| Option | Description |
| --- | --- |
| `-u, --url URL` | Target URL. Can be repeated and can contain comma-separated values. |
| `-L, --list FILE` | File containing one URL per line. Supports comments with `#`. |
| `--batch` | Run the full pentest for each target and save one report per target. Requires `-u` or `-L`. |
| `-o, --output FILE` | Output path or base name for generated reports. |
| `-t, --threads N` | Number of worker threads. |
| `--timeout S` | Request timeout in seconds. |
| `-d, --delay S` | Delay between requests in seconds. |
| `-k, --insecure` | Disable TLS certificate verification for lab and test environments. |
| `--no-color` | Disable colored terminal output. |
| `-V, --version` | Print the tool version. |

## Reports

By default, reports are written under:

```text
reports/<host>/<host>.txt
reports/<host>/<host>.json
reports/<host>/<host>.html
reports/<host>/<host>.md
```

The HTML report is a standalone dashboard with a sidebar, filters, dark/light theme support, searchable tables, and print-to-PDF support.

## Configuration

Common defaults are defined near the top of `owasp-scanner.py`:

```python
DEFAULT_TIMEOUT = 10
MAX_REDIRECTS = 10
THREADS = 5
REQUEST_DELAY = 0.0
```

Default SecLists paths are also configured in the script and can be changed to match your local Kali, Debian, Ubuntu, or WSL environment.

## Responsible Use

Only run OWASP Scanner against systems you own or have explicit written permission to test. Unauthorized scanning, brute forcing, exploitation, or access attempts may be illegal.

Recommended safeguards:

- Get written authorization before testing.
- Define scope, dates, rate limits, and allowed techniques.
- Avoid destructive payloads unless explicitly approved.
- Preserve logs and evidence for reporting.
- Follow applicable laws and program rules.

## Project Status

Current adapted version: `1.4.2`

Primary repository: https://github.com/BaskaranElilan/OWASP-Scanner

## Credits

Maintainer: Elilan Baskaran

Additional ecosystem credits:

- OWASP for the Web Security Testing Guide and API Security resources.
- ProjectDiscovery for Nuclei.
- ffuf contributors.
- van Hauser and THC Hydra contributors.
- Daniel Miessler and SecLists contributors.
- WPScan contributors.

## License

This project is distributed under the MIT License. See `LICENSE` and `NOTICE.md`.