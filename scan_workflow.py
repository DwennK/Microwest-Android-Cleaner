from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from adb_client import ADBClient, DeviceInfo
from database import ReputationDatabase
from risk_rules import evaluate_app
from scanner import AppScanner

ProgressCallback = Callable[[int, int, str], None]
CancelCallback = Callable[[], bool]


@dataclass(slots=True)
class ScanResult:
    rows: list[dict[str, Any]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    cancelled: bool = False
    total: int = 0


def run_scan(
    serial: str,
    include_system: bool,
    device: DeviceInfo,
    *,
    adb: ADBClient | None = None,
    db: ReputationDatabase | None = None,
    progress: ProgressCallback | None = None,
    should_cancel: CancelCallback | None = None,
) -> ScanResult:
    adb = adb or ADBClient()
    db = db or ReputationDatabase()
    scanner = AppScanner(adb)
    packages = adb.list_packages(serial, include_system=include_system)
    launcher_packages = adb.list_launcher_packages(serial)
    result = ScanResult(total=len(packages))

    for index, (package, installer) in enumerate(packages.items(), start=1):
        if should_cancel and should_cancel():
            result.cancelled = True
            break
        if progress:
            progress(index, result.total, package)

        app = scanner.scan_package(
            serial=serial,
            package=package,
            installer=installer,
            include_system=include_system,
            launcher_packages=launcher_packages,
        )
        if app.dumpsys_error:
            result.errors.append(f"{package}: {app.dumpsys_error}")

        risk = evaluate_app(app, db.reputation_for(app.package_name))
        result.rows.append({"app": app, "risk": risk, "ai": None, "ai_text": "", "note": db.note_for(app.package_name)})

    result.rows.sort(key=lambda item: item["risk"].score, reverse=True)
    if result.rows:
        db.record_scan(
            datetime.now().isoformat(timespec="seconds"),
            device.model,
            device.android_version,
            len(result.rows),
            len(
                [
                    row
                    for row in result.rows
                    if row["risk"].score >= 60 and row["risk"].recommended_action != "do_not_touch"
                ]
            ),
        )
    return result
