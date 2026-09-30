#!/bin/zsh
set -e

cd "$(dirname "$0")"
export PATH="/opt/homebrew/bin:/usr/local/bin:${PATH:-/usr/bin:/bin}"

python3.12 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/pip install -r requirements.txt
.venv/bin/python packaging/install_aapt2.py

echo "Setup terminé. Lancez ./run_mac.command"
