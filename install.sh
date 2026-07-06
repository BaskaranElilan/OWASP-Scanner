#!/usr/bin/env bash
set -euo pipefail

VENV_DIR="${VENV_DIR:-.venv}"
PYTHON_BIN="${PYTHON_BIN:-python3}"

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "[!] python3 was not found. Install Python 3 first."
  exit 1
fi

if [ ! -d "$VENV_DIR" ]; then
  echo "[*] Creating virtual environment in $VENV_DIR"
  "$PYTHON_BIN" -m venv "$VENV_DIR"
fi

echo "[*] Upgrading pip inside the virtual environment"
"$VENV_DIR/bin/python" -m pip install --upgrade pip

echo "[*] Installing Python requirements"
"$VENV_DIR/bin/python" -m pip install -r requirements.txt

echo "[+] Installation complete"
echo "    Run: source $VENV_DIR/bin/activate"
echo "    Then: python owasp-scanner.py --help"
