#!/bin/zsh
set -e

cd "$(dirname "$0")"

# Finder and other GUI launchers often omit Homebrew from PATH.
export PATH="/opt/homebrew/bin:/usr/local/bin:${PATH:-/usr/bin:/bin}"

if [ ! -x ".venv/bin/python" ]; then
  python3.12 -m venv .venv
  .venv/bin/python -m pip install --upgrade pip
  .venv/bin/pip install -r requirements.txt
fi

exec .venv/bin/python main.py
