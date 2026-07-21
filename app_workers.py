from __future__ import annotations

import logging
import time
from datetime import datetime
from typing import Any

from PySide6.QtCore import QThread, Signal

from adb_client import ADBClient, ADBError, ADBNotFoundError, DeviceInfo, parse_devices_l
from ai_analyzer import AIAnalyzer, ai_payload_from_row, analyze_in_batches
from apk_metadata import ApkMetadataExtractor
from app_config import portable_runtime_checks
from database import ReputationDatabase
from scan_workflow import run_scan
from scanner import AppInfo


class DetectWorker(QThread):
    succeeded = Signal(object)
    failed = Signal(str)

    def __init__(self, serial: str = "") -> None:
        super().__init__()
        self.serial = serial

    def run(self) -> None:
        try:
            client = ADBClient()
            devices = client.detailed_devices()
            device = client.detect_device(self.serial)
            self.succeeded.emit({"device": device, "devices": devices, "adb_path": client.adb_path})
        except ADBNotFoundError as exc:
            self.failed.emit(str(exc))
        except Exception as exc:  # noqa: BLE001 - worker reports failures to the UI.
            logging.exception("Device detection failed")
            self.failed.emit(f"Détection impossible : {exc}")


class ADBDaemonWorker(QThread):
    succeeded = Signal(str)
    failed = Signal(str)

    def __init__(self, action: str) -> None:
        super().__init__()
        self.action = action

    def run(self) -> None:
        try:
            client = ADBClient()
            if self.action == "start":
                output = client.start_server()
            elif self.action == "kill":
                output = client.kill_server()
            elif self.action == "restart":
                output = client.restart_server()
            else:
                raise ValueError(f"Action ADB inconnue : {self.action}")
            self.succeeded.emit(output)
        except Exception as exc:  # noqa: BLE001 - worker reports failures to the UI.
            logging.exception("ADB daemon action failed")
            self.failed.emit(f"Action daemon ADB impossible : {exc}")


class ADBDiagnosticWorker(QThread):
    succeeded = Signal(object)
    failed = Signal(str)

    def __init__(self, repair: bool = False, serial: str = "") -> None:
        super().__init__()
        self.repair = repair
        self.serial = serial

    def run(self) -> None:
        try:
            report: dict[str, Any] = {
                "repair": self.repair,
                "portable": portable_runtime_checks(),
                "adb_path": "",
                "adb_version": "",
                "adb_restart": "",
                "adb_error": "",
                "devices_output": "",
                "devices": [],
                "device": DeviceInfo(),
                "aapt2_path": "",
                "aapt2_available": False,
            }
            extractor = ApkMetadataExtractor()
            report["aapt2_path"] = extractor.aapt2_path
            report["aapt2_available"] = extractor.available
            try:
                client = ADBClient()
                report["adb_path"] = client.adb_path
                if self.repair:
                    report["adb_restart"] = client.restart_server()
                    time.sleep(1)
                report["adb_version"] = client.version()
                devices_output = client.devices_output()
                devices = parse_devices_l(devices_output)
                report["devices_output"] = devices_output
                report["devices"] = devices
                report["device"] = client.detect_device(self.serial) if devices else DeviceInfo()
            except ADBError as exc:
                report["adb_error"] = str(exc)
            self.succeeded.emit(report)
        except Exception as exc:  # noqa: BLE001 - worker reports failures to the UI.
            logging.exception("ADB diagnostic failed")
            self.failed.emit(f"Diagnostic ADB impossible : {exc}")


class DevicesRefreshWorker(QThread):
    succeeded = Signal(object)

    def run(self) -> None:
        try:
            client = ADBClient()
            self.succeeded.emit(client.detailed_devices())
        except ADBError:
            self.succeeded.emit([])


class ScanWorker(QThread):
    succeeded = Signal(object)
    failed = Signal(str)
    progress = Signal(int, int, str)

    def __init__(self, serial: str, include_system: bool, device: DeviceInfo) -> None:
        super().__init__()
        self.serial = serial
        self.include_system = include_system
        self.device = device
        self.cancel_requested = False

    def cancel(self) -> None:
        self.cancel_requested = True
        self.requestInterruption()

    def run(self) -> None:
        try:
            result = run_scan(
                self.serial,
                self.include_system,
                self.device,
                progress=lambda current, total, package: self.progress.emit(current, total, package),
                should_cancel=lambda: self.cancel_requested or self.isInterruptionRequested(),
            )
            self.succeeded.emit(
                {
                    "rows": result.rows,
                    "errors": result.errors,
                    "cancelled": result.cancelled,
                    "total": result.total,
                    "scan_id": result.scan_id,
                    "comparison": result.comparison,
                }
            )
        except Exception as exc:  # noqa: BLE001 - worker reports failures to the UI.
            logging.exception("Scan failed")
            self.failed.emit(f"Scan impossible : {exc}")


class AIWorker(QThread):
    succeeded = Signal(object)
    failed = Signal(str)

    def __init__(self, rows: list[dict[str, Any]], settings: dict[str, Any]) -> None:
        super().__init__()
        self.rows = rows
        self.settings = dict(settings)

    def run(self) -> None:
        try:
            analyzer = AIAnalyzer(self.settings)
            candidates = [
                ai_payload_from_row(row)
                for row in self.rows
                if row["risk"].score >= 30 and row["risk"].recommended_action != "do_not_touch"
            ]
            self.succeeded.emit(analyze_in_batches(analyzer, candidates, batch_size=40))
        except Exception as exc:  # noqa: BLE001 - worker reports failures to the UI.
            logging.exception("AI analysis failed")
            self.failed.emit(f"Analyse IA impossible : {exc}")


class UninstallWorker(QThread):
    succeeded = Signal(object)
    failed = Signal(str)

    def __init__(self, serial: str, apps: list[AppInfo], scan_id: int | None) -> None:
        super().__init__()
        self.serial = serial
        self.apps = apps
        self.scan_id = scan_id

    def run(self) -> None:
        try:
            adb = ADBClient()
            db = ReputationDatabase()
            results = []
            for app in self.apps:
                ok, output = adb.uninstall_user_package(self.serial, app.package_name)
                result_text = output or ("Success" if ok else "Failure")
                db.record_uninstall(
                    datetime.now().isoformat(timespec="seconds"),
                    app.package_name,
                    app.display_name(),
                    result_text,
                )
                if ok and self.scan_id is not None:
                    db.set_validation(
                        self.scan_id,
                        app.package_name,
                        "removed",
                        datetime.now().isoformat(timespec="seconds"),
                    )
                results.append(
                    {"package": app.package_name, "label": app.display_name(), "result": result_text, "success": ok}
                )
            self.succeeded.emit(results)
        except Exception as exc:  # noqa: BLE001 - worker reports failures to the UI.
            logging.exception("Uninstall failed")
            self.failed.emit(f"Désinstallation impossible : {exc}")


class OpenAppSettingsWorker(QThread):
    succeeded = Signal(str)
    failed = Signal(str)

    def __init__(self, serial: str, package: str) -> None:
        super().__init__()
        self.serial = serial
        self.package = package

    def run(self) -> None:
        try:
            output = ADBClient().open_app_settings(self.serial, self.package)
            self.succeeded.emit(output or "Paramètres ouverts sur le téléphone.")
        except Exception as exc:  # noqa: BLE001 - worker reports failures to the UI.
            logging.exception("Open app settings failed")
            self.failed.emit(f"Ouverture des paramètres impossible : {exc}")
