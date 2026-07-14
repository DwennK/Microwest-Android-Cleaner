from __future__ import annotations

import csv
from datetime import datetime
from pathlib import Path
from typing import Any

from adb_client import DeviceInfo
from app_config import REPORTS_DIR
from scanner import AppInfo
from workflow_helpers import build_action_plan, launcher_text, priority_text


def export_diagnostic_text(text: str) -> Path:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    path = REPORTS_DIR / f"diagnostic_adb_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.txt"
    path.write_text(text, encoding="utf-8")
    return path


def export_scan_csv(rows: list[dict[str, Any]]) -> Path:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    path = REPORTS_DIR / f"apps_android_cleaner_{datetime.now().strftime('%Y-%m-%d_%H-%M')}.csv"
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "score",
                "priority",
                "category",
                "recommended_action",
                "technician_validation",
                "app_name",
                "package",
                "installer",
                "system",
                "launcher_visible",
                "permissions_requested",
                "permissions_granted",
                "capabilities_active",
                "risk_reasons",
                "technician_note",
                "metadata_error",
            ]
        )
        for row in rows:
            app: AppInfo = row["app"]
            risk = row["risk"]
            writer.writerow(
                [
                    risk.score,
                    priority_text(row),
                    risk.category,
                    risk.recommended_action,
                    row.get("validation", "unreviewed"),
                    app.display_name(),
                    app.package_name,
                    app.installer or "inconnu",
                    "oui" if app.is_system_app else "non",
                    launcher_text(app),
                    "; ".join(app.requested_permissions),
                    "; ".join(app.granted_permissions),
                    "; ".join(app.active_capabilities),
                    "; ".join(risk.reasons),
                    row.get("note", ""),
                    app.dumpsys_error,
                ]
            )
    return path


def export_action_plan_text(
    device: DeviceInfo,
    rows: list[dict[str, Any]],
    selected_rows: list[dict[str, Any]],
) -> Path:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    path = REPORTS_DIR / f"plan_action_android_cleaner_{datetime.now().strftime('%Y-%m-%d_%H-%M')}.txt"
    path.write_text(build_action_plan(device, rows, selected_rows), encoding="utf-8")
    return path
