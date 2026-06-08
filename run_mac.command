#!/bin/zsh
set -e

cd "$(dirname "$0")"

if [ ! -x ".venv/bin/python" ]; then
  python3.12 -m venv .venv
  .venv/bin/python -m pip install --upgrade pip
  .venv/bin/pip install -r requirements.txt
fi

exec .venv/bin/python main.py
