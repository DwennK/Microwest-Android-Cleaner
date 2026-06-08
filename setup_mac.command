#!/bin/zsh
set -e

cd "$(dirname "$0")"

python3.12 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/pip install -r requirements.txt

echo "Setup terminé. Lancez ./run_mac.command"
