from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path
from typing import Any

PROJECT_DIR = Path(__file__).resolve().parent
DATA_DIR = PROJECT_DIR / "data"
LOG_DIR = PROJECT_DIR / "logs"
REPORTS_DIR = PROJECT_DIR / "reports"
CACHE_DIR = PROJECT_DIR / "cache"
SETTINGS_PATH = DATA_DIR / "ui_settings.json"
ENV_PATH = PROJECT_DIR / ".env"


def setup_logging() -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        handlers=[
            logging.FileHandler(LOG_DIR / "app.log", encoding="utf-8"),
            logging.StreamHandler(sys.stderr),
        ],
    )


def load_ui_settings() -> dict[str, Any]:
    try:
        if SETTINGS_PATH.exists():
            raw = json.loads(SETTINGS_PATH.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                return raw
    except Exception:  # noqa: BLE001 - invalid local settings should not prevent startup.
        logging.exception("Unable to load UI settings")
    return {}


def save_ui_settings(settings: dict[str, Any]) -> None:
    SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
    SETTINGS_PATH.write_text(json.dumps(settings, indent=2, ensure_ascii=False), encoding="utf-8")


def save_env_value(key: str, value: str) -> None:
    lines = ENV_PATH.read_text(encoding="utf-8").splitlines() if ENV_PATH.exists() else []
    output: list[str] = []
    replaced = False
    for line in lines:
        if line.startswith(f"{key}="):
            output.append(f"{key}={value}")
            replaced = True
        else:
            output.append(line)
    if not replaced:
        output.append(f"{key}={value}")
    ENV_PATH.write_text("\n".join(output).rstrip() + "\n", encoding="utf-8")
    os.environ[key] = value


def portable_runtime_checks() -> list[tuple[str, str, str]]:
    checks: list[tuple[str, str, str]] = []
    paths = [
        ("Dossier app", PROJECT_DIR),
        ("Base locale", DATA_DIR),
        ("Logs", LOG_DIR),
        ("Cache", CACHE_DIR),
        ("Rapports", REPORTS_DIR),
        ("ADB portable", PROJECT_DIR / "adb"),
        ("Outils", PROJECT_DIR / "tools"),
    ]
    for label, path in paths:
        try:
            path.mkdir(parents=True, exist_ok=True)
            probe = path / ".write_test"
            probe.write_text("ok", encoding="utf-8")
            probe.unlink(missing_ok=True)
            checks.append((label, str(path), "OK écriture"))
        except Exception as exc:  # noqa: BLE001 - diagnostic reports every filesystem failure.
            checks.append((label, str(path), f"ERREUR écriture : {exc}"))
    return checks
