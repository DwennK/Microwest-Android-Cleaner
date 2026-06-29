from __future__ import annotations

import csv
import json
import logging
import os
import platform
import subprocess
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from PySide6.QtCore import QLockFile, Qt, QThread, QTimer, Signal, qVersion
from PySide6.QtGui import QAction, QColor, QIcon
from PySide6.QtWidgets import (
    QApplication,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QMainWindow,
    QMenu,
    QMessageBox,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from adb_client import ADBClient, ADBDevice, ADBError, ADBNotFoundError, DeviceInfo, parse_devices_l
from ai_analyzer import AIAnalyzer, AIResult, ai_payload_from_row
from apk_metadata import ApkMetadataExtractor
from app_style import APP_STYLESHEET
from connection_tab import ConnectionTab
from database import ReputationDatabase
from details_tab import DetailsTab
from exports_tab import ExportsTab
from report_generator import export_html_report
from results_tab import ResultsTab
from risk_rules import evaluate_app
from scan_tab import ScanTab
from scan_workflow import run_scan
from scanner import AppInfo
from settings_tab import SettingsTab
from workflow_helpers import (
    build_action_plan,
    hidden_summary,
    is_hidden_or_low_visibility,
    is_sideloaded,
    launcher_text,
    notification_summary,
    permission_matches,
    priority_text,
    scan_summary,
)

PROJECT_DIR = Path(__file__).resolve().parent
LOG_DIR = PROJECT_DIR / "logs"
REPORTS_DIR = PROJECT_DIR / "reports"
SETTINGS_PATH = PROJECT_DIR / "data" / "ui_settings.json"
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
    except Exception:  # noqa: BLE001
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
        ("Base locale", PROJECT_DIR / "data"),
        ("Logs", PROJECT_DIR / "logs"),
        ("Cache", PROJECT_DIR / "cache"),
        ("Rapports", PROJECT_DIR / "reports"),
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
        except Exception as exc:  # noqa: BLE001
            checks.append((label, str(path), f"ERREUR écriture : {exc}"))
    return checks


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
        except Exception as exc:  # noqa: BLE001
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
        except Exception as exc:  # noqa: BLE001
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
        except Exception as exc:  # noqa: BLE001
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
                }
            )
        except Exception as exc:  # noqa: BLE001
            logging.exception("Scan failed")
            self.failed.emit(f"Scan impossible : {exc}")


class AIWorker(QThread):
    succeeded = Signal(object)
    failed = Signal(str)

    def __init__(self, rows: list[dict[str, Any]]) -> None:
        super().__init__()
        self.rows = rows

    def run(self) -> None:
        try:
            analyzer = AIAnalyzer()
            candidates = [
                ai_payload_from_row(row)
                for row in self.rows
                if row["risk"].score >= 30 and row["risk"].recommended_action != "do_not_touch"
            ][:40]
            result = analyzer.analyze(candidates)
            self.succeeded.emit(result)
        except Exception as exc:  # noqa: BLE001
            logging.exception("AI analysis failed")
            self.failed.emit(f"Analyse IA impossible : {exc}")


class UninstallWorker(QThread):
    succeeded = Signal(object)
    failed = Signal(str)

    def __init__(self, serial: str, apps: list[AppInfo]) -> None:
        super().__init__()
        self.serial = serial
        self.apps = apps

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
                results.append({"package": app.package_name, "label": app.display_name(), "result": result_text})
            self.succeeded.emit(results)
        except Exception as exc:  # noqa: BLE001
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
        except Exception as exc:  # noqa: BLE001
            logging.exception("Open app settings failed")
            self.failed.emit(f"Ouverture des paramètres impossible : {exc}")


def build_app_details_text(row: dict[str, Any]) -> str:
    app: AppInfo = row["app"]
    risk = row["risk"]
    command = "Suppression interdite pour cette application."
    if not app.is_system_app and risk.recommended_action != "do_not_touch":
        command = f"adb shell pm uninstall --user 0 {app.package_name}"
    settings_command = (
        "adb shell am start -a android.settings.APPLICATION_DETAILS_SETTINGS "
        f"-d package:{app.package_name}"
    )

    return (
        f"Nom : {app.display_name()}\n"
        f"Source du nom : {'APK/aapt2' if app.app_label_source == 'apk' else 'package'}\n"
        f"Icône : {app.icon_path or 'non disponible'}\n"
        f"Launcher visible : {launcher_text(app)}\n"
        f"Audit app cachée : {', '.join(app.hidden_audit) if app.hidden_audit else 'aucun signal'}\n"
        f"Audit notifications : {', '.join(app.notification_audit) if app.notification_audit else 'aucun signal'}\n"
        f"Package : {app.package_name}\n"
        f"Installateur : {app.installer or 'inconnu'}\n"
        f"Système : {'oui' if app.is_system_app else 'non'}\n"
        f"Version : {app.version_name or 'non disponible'}\n"
        f"Target SDK : {app.target_sdk or 'non disponible'}\n"
        f"Date installation : {app.install_date or 'non disponible'}\n"
        f"État : {app.enabled or 'non disponible'}\n\n"
        f"Score : {risk.score}\n"
        f"Catégorie : {risk.category}\n"
        f"Action proposée : {risk.recommended_action}\n"
        f"Raisons :\n- " + "\n- ".join(risk.reasons) + "\n\n"
        "Permissions sensibles :\n- "
        + ("\n- ".join(app.sensitive_permissions) if app.sensitive_permissions else "Aucune détectée")
        + f"\n\nCommande ADB prévue :\n{command}\n\n"
        f"Commande paramètres app :\n{settings_command}\n\n"
        f"Analyse IA :\n{row.get('ai_text') or 'Non effectuée'}"
        + f"\n\nNote technicien :\n{row.get('note') or 'Aucune'}"
    )


def display_action(action: str) -> str:
    return {
        "keep": "Garder",
        "review": "Vérifier",
        "suggest_uninstall": "À valider",
        "do_not_touch": "Ne pas toucher",
    }.get(action, action)


def display_category(category: str) -> str:
    return {
        "do_not_touch_system": "Système protégé",
        "trusted_official_review": "Officielle à vérifier",
        "trusted_official": "Officielle",
        "safe": "Sûre",
        "probably_safe": "Probablement sûre",
        "unknown_review_manually": "À vérifier",
        "spyware_suspect": "Suspect spyware",
        "scam_suspect": "Suspect arnaque",
        "adware_suspect": "Suspect pub",
    }.get(category, category)


class MainWindow(QMainWindow):
    COLUMNS = [
        "",
        "Priorité",
        "Score",
        "Catégorie",
        "Action",
        "Nom app",
        "Package",
        "Installer",
        "Cachée",
        "Notifications",
        "Note",
        "Raisons",
        "IA",
    ]
    COL_CHECK = 0
    COL_PRIORITY = 1
    COL_SCORE = 2
    COL_PACKAGE = 6
    COL_NOTE = 10
    COL_REASONS = 11

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Microwest Android Cleaner")
        self.resize(1440, 860)
        self.setMinimumSize(1120, 720)
        self.db = ReputationDatabase()
        self.ui_settings = load_ui_settings()
        self.ai_analyzer = AIAnalyzer(self.ui_settings)
        self.device = DeviceInfo()
        self.rows: list[dict[str, Any]] = []
        self.uninstalled: list[dict[str, str]] = []
        self.current_worker: QThread | None = None
        self.scan_worker: ScanWorker | None = None
        self.refresh_worker: DevicesRefreshWorker | None = None
        self.last_diagnostic_text = ""
        self.last_devices_signature = ""
        self.is_busy = False
        self.quick_scan_pending = False
        self._build_ui()
        self._apply_ai_button_state()
        self.device_refresh_timer = QTimer(self)
        self.device_refresh_timer.setInterval(8000)
        self.device_refresh_timer.timeout.connect(self.refresh_devices_if_idle)
        self.device_refresh_timer.start()

    def _build_ui(self) -> None:
        root = QWidget()
        main_layout = QVBoxLayout(root)
        main_layout.setContentsMargins(18, 14, 18, 18)
        main_layout.setSpacing(10)

        self._build_header(main_layout)
        self._build_workflow_strip(main_layout)

        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)
        self.tabs.setObjectName("WorkspaceTabs")
        main_layout.addWidget(self.tabs, 1)

        self.connection_tab_index = self.tabs.addTab(ConnectionTab(self).build(), "Connexion")
        self.scan_tab_index = self.tabs.addTab(ScanTab(self).build(), "Scan")
        self.results_tab_index = self.tabs.addTab(ResultsTab(self).build(), "Résultats")
        self.details_tab_index = self.tabs.addTab(DetailsTab(self).build(), "Détails")
        self.exports_tab_index = self.tabs.addTab(ExportsTab(self).build(), "Exports")
        self.settings_tab_index = self.tabs.addTab(SettingsTab(self).build(), "Paramètres")

        self.setCentralWidget(root)
        self._connect_actions()
        self.update_ai_settings_status()
        self.setStyleSheet(APP_STYLESHEET)
        self.update_workflow_state("connect")

    def _build_header(self, main_layout: QVBoxLayout) -> None:
        header_layout = QHBoxLayout()
        title_block = QVBoxLayout()
        title_block.setSpacing(2)

        title = QLabel("Microwest Android Cleaner")
        title.setObjectName("Title")
        subtitle = QLabel("Diagnostic Android / Samsung")
        subtitle.setObjectName("Subtitle")
        title_block.addWidget(title)
        title_block.addWidget(subtitle)

        self.status_label = QLabel("Aucun appareil détecté")
        self.status_label.setObjectName("StatusPill")
        self.status_label.setMinimumWidth(320)
        self.status_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)

        header_layout.addLayout(title_block, 1)
        header_layout.addWidget(self.status_label)
        main_layout.addLayout(header_layout)

    def _build_workflow_strip(self, main_layout: QVBoxLayout) -> None:
        workflow_layout = QHBoxLayout()
        workflow_layout.setSpacing(8)
        self.workflow_step_labels = []
        for key, label in (
            ("connect", "1 Connexion"),
            ("scan", "2 Scan"),
            ("results", "3 Résultats"),
            ("validate", "4 Validation"),
            ("export", "5 Export"),
        ):
            step = QLabel(label)
            step.setProperty("step_key", key)
            step.setObjectName("WorkflowStep")
            workflow_layout.addWidget(step)
            self.workflow_step_labels.append(step)
        workflow_layout.addStretch(1)
        main_layout.addLayout(workflow_layout)

    def _connect_actions(self) -> None:
        self.quick_scan_button.clicked.connect(self.start_quick_diagnostic)
        self.scan_quick_button.clicked.connect(self.start_quick_diagnostic)
        self.detect_button.clicked.connect(self.detect_phone)
        self.adb_diagnostic_button.clicked.connect(lambda: self.run_adb_diagnostic(repair=False))
        self.adb_repair_button.clicked.connect(lambda: self.run_adb_diagnostic(repair=True))
        self.adb_daemon_button.clicked.connect(lambda: self.run_adb_daemon_action("restart"))
        self.adb_daemon_button.customContextMenuRequested.connect(self.open_adb_daemon_menu)
        self.scan_button.clicked.connect(self.scan_apps)
        self.cancel_scan_button.clicked.connect(self.cancel_scan)
        self.ai_button.clicked.connect(self.analyze_with_ai)
        self.open_settings_button.clicked.connect(self.open_selected_app_settings)
        self.uninstall_button.clicked.connect(self.uninstall_selected)
        self.report_button.clicked.connect(self.export_report)
        self.csv_button.clicked.connect(self.export_csv)
        self.copy_diagnostic_button.clicked.connect(self.copy_diagnostic)
        self.export_diagnostic_button.clicked.connect(self.export_diagnostic)
        self.history_button.clicked.connect(self.show_scan_history)
        self.demo_button.clicked.connect(self.load_demo_data)
        self.action_plan_button.clicked.connect(self.export_action_plan)
        self.copy_plan_button.clicked.connect(self.copy_action_plan)
        self.open_reports_button.clicked.connect(self.open_reports_folder)
        self.reload_button.clicked.connect(self.reload_reputation)
        self.save_settings_button.clicked.connect(self.save_settings_from_ui)
        self.open_data_button.clicked.connect(lambda: self.open_folder(PROJECT_DIR / "data"))
        self.open_logs_button.clicked.connect(lambda: self.open_folder(LOG_DIR))
        self.ai_provider_combo.currentIndexChanged.connect(self.update_ai_settings_status)
        self.select_high_button.clicked.connect(lambda: self.check_rows("high"))
        self.select_review_button.clicked.connect(lambda: self.check_rows("review"))
        self.clear_checks_button.clicked.connect(lambda: self.check_rows("clear"))
        self.note_button.clicked.connect(self.edit_note_for_selected)
        self.search_input.textChanged.connect(self.apply_filters)
        self.hide_safe_checkbox.stateChanged.connect(self.apply_filters)
        self.hidden_apps_checkbox.stateChanged.connect(self.apply_filters)
        self.notification_audit_checkbox.stateChanged.connect(self.apply_filters)
        self.sideload_checkbox.stateChanged.connect(self.apply_filters)
        self.score_filter.currentIndexChanged.connect(self.apply_filters)
        self.permission_filter.currentIndexChanged.connect(self.apply_filters)
        self.table.customContextMenuRequested.connect(self.open_context_menu)
        self.table.itemSelectionChanged.connect(self.update_details_from_selection)
        self.table.itemChanged.connect(self.on_table_item_changed)
        self.table.cellDoubleClicked.connect(self.open_details_for_cell)

    def _apply_ai_button_state(self) -> None:
        if self.ai_analyzer.enabled:
            self.ai_button.setEnabled(True)
            self.ai_button.setText(f"Analyser avec IA ({self.ai_analyzer.provider_label})")
            self.ai_button.setToolTip(f"Analyse les apps déjà suspectes avec {self.ai_analyzer.provider_label}.")
        else:
            key_name = "MINIMAX_API_KEY" if self.ai_analyzer.provider == "minimax" else "OPENAI_API_KEY"
            self.ai_button.setEnabled(False)
            self.ai_button.setText("Analyser avec IA (clé .env absente)")
            self.ai_button.setToolTip(f"Ajoutez {key_name} dans .env pour activer cette option.")

    def update_ai_settings_status(self) -> None:
        provider = str(self.ai_provider_combo.currentData() or "openai")
        key_name = "MINIMAX_API_KEY" if provider == "minimax" else "OPENAI_API_KEY"
        key_present = bool(os.getenv(key_name, "").strip())
        status = "clé détectée" if key_present else f"{key_name} absent"
        self.ai_key_status_label.setText(status)
        self.ai_api_key_input.setPlaceholderText(f"Coller {key_name} ici")
        self.ai_api_key_input.clear()
        for widget in self.openai_settings_widgets:
            widget.setVisible(provider == "openai")
        for widget in self.minimax_settings_widgets:
            widget.setVisible(provider == "minimax")

    def save_settings_from_ui(self) -> None:
        provider = str(self.ai_provider_combo.currentData() or "openai")
        api_key = self.ai_api_key_input.text().strip()
        key_name = "MINIMAX_API_KEY" if provider == "minimax" else "OPENAI_API_KEY"
        self.ui_settings = {
            "ai_provider": provider,
            "openai_model": self.openai_model_input.text().strip() or "gpt-4.1-mini",
            "openai_base_url": self.openai_base_url_input.text().strip(),
            "minimax_model": self.minimax_model_input.text().strip() or "MiniMax-M3",
            "minimax_base_url": self.minimax_base_url_input.text().strip() or "https://api.minimax.io/v1",
        }
        try:
            save_ui_settings(self.ui_settings)
            if api_key:
                save_env_value(key_name, api_key)
        except Exception as exc:  # noqa: BLE001
            logging.exception("Unable to save UI settings")
            QMessageBox.warning(self, "Paramètres", f"Enregistrement impossible : {exc}")
            return
        self.ai_api_key_input.clear()
        self.ai_analyzer = AIAnalyzer(self.ui_settings)
        self._apply_ai_button_state()
        self.update_ai_settings_status()
        self.status_label.setText("Paramètres enregistrés.")

    def set_busy(self, busy: bool, message: str = "") -> None:
        self.is_busy = busy
        for widget in (
            self.detect_button,
            self.quick_scan_button,
            self.adb_diagnostic_button,
            self.adb_repair_button,
            self.adb_daemon_button,
            self.scan_button,
            self.scan_quick_button,
            self.demo_button,
            self.open_settings_button,
            self.uninstall_button,
            self.report_button,
            self.csv_button,
            self.copy_diagnostic_button,
            self.export_diagnostic_button,
            self.history_button,
            self.reload_button,
            self.action_plan_button,
            self.copy_plan_button,
            self.open_reports_button,
            self.save_settings_button,
            self.open_data_button,
            self.open_logs_button,
            self.ai_provider_combo,
            self.openai_model_input,
            self.openai_base_url_input,
            self.minimax_model_input,
            self.minimax_base_url_input,
            self.ai_api_key_input,
            self.select_high_button,
            self.select_review_button,
            self.clear_checks_button,
            self.note_button,
            self.device_combo,
        ):
            widget.setEnabled(not busy)
        self.cancel_scan_button.setEnabled(bool(self.scan_worker and self.scan_worker.isRunning()))
        self.copy_diagnostic_button.setEnabled((not busy) and bool(self.last_diagnostic_text))
        self.export_diagnostic_button.setEnabled((not busy) and bool(self.last_diagnostic_text))
        self._apply_ai_button_state()
        if busy:
            self.ai_button.setEnabled(False)
        if message:
            self.status_label.setText(message)

    def update_workflow_state(self, active: str) -> None:
        order = ["connect", "scan", "results", "validate", "export"]
        active_index = order.index(active) if active in order else 0
        for label in self.workflow_step_labels:
            key = str(label.property("step_key") or "")
            index = order.index(key) if key in order else 0
            if index < active_index:
                object_name = "WorkflowStepDone"
            elif index == active_index:
                object_name = "WorkflowStepActive"
            else:
                object_name = "WorkflowStep"
            label.setObjectName(object_name)
            self._refresh_style(label)

    def _refresh_style(self, widget: QWidget) -> None:
        widget.style().unpolish(widget)
        widget.style().polish(widget)
        widget.update()

    def start_quick_diagnostic(self) -> None:
        self.quick_scan_pending = True
        if self.device.state == "device" and self.device.serial:
            self.scan_apps()
            return
        self.tabs.setCurrentIndex(self.connection_tab_index)
        self.detect_phone()

    def detect_phone(self) -> None:
        self.update_workflow_state("connect")
        self.set_busy(True, "Détection du téléphone...")
        worker = DetectWorker(self.selected_device_serial())
        worker.succeeded.connect(self.on_device_detected)
        worker.failed.connect(self.on_worker_failed)
        worker.finished.connect(self.on_detect_worker_finished)
        self.current_worker = worker
        worker.start()

    def on_detect_worker_finished(self) -> None:
        if self.quick_scan_pending and self.device.state == "device" and self.device.serial:
            self.set_busy(False)
            self.scan_apps()
            return
        self.set_busy(False)

    def run_adb_diagnostic(self, repair: bool = False) -> None:
        message = "Réparation de la connexion ADB..." if repair else "Diagnostic ADB en cours..."
        self.set_busy(True, message)
        worker = ADBDiagnosticWorker(repair=repair, serial=self.selected_device_serial())
        worker.succeeded.connect(self.on_adb_diagnostic_finished)
        worker.failed.connect(self.on_worker_failed)
        worker.finished.connect(lambda: self.set_busy(False))
        self.current_worker = worker
        worker.start()

    def open_adb_daemon_menu(self, position: Any) -> None:
        menu = QMenu(self)
        start_action = QAction("Démarrer daemon ADB", self)
        restart_action = QAction("Redémarrer daemon ADB", self)
        kill_action = QAction("Arrêter daemon ADB", self)
        menu.addAction(start_action)
        menu.addAction(restart_action)
        menu.addAction(kill_action)
        start_action.triggered.connect(lambda: self.run_adb_daemon_action("start"))
        restart_action.triggered.connect(lambda: self.run_adb_daemon_action("restart"))
        kill_action.triggered.connect(lambda: self.run_adb_daemon_action("kill"))
        menu.exec(self.adb_daemon_button.mapToGlobal(position))

    def run_adb_daemon_action(self, action: str) -> None:
        labels = {
            "start": "Démarrage du daemon ADB...",
            "kill": "Arrêt du daemon ADB...",
            "restart": "Redémarrage du daemon ADB...",
        }
        self.set_busy(True, labels.get(action, "Action daemon ADB..."))
        worker = ADBDaemonWorker(action)
        worker.succeeded.connect(lambda output: self.on_adb_daemon_finished(action, output))
        worker.failed.connect(self.on_worker_failed)
        worker.finished.connect(lambda: self.set_busy(False))
        self.current_worker = worker
        worker.start()

    def on_adb_daemon_finished(self, action: str, output: str) -> None:
        labels = {
            "start": "Daemon ADB démarré",
            "kill": "Daemon ADB arrêté",
            "restart": "Daemon ADB redémarré",
        }
        self.status_label.setText(labels.get(action, "Action daemon ADB terminée"))
        logging.info("ADB daemon %s: %s", action, output)

    def on_device_detected(self, payload: dict[str, Any]) -> None:
        device: DeviceInfo = payload["device"]
        self.update_device_combo(payload.get("devices", []), device.serial)
        self.device = device
        self.status_label.setText(device.message)
        self.model_label.setText(f"{device.manufacturer} {device.model}".strip() or "-")
        self.android_label.setText(device.android_version or "-")
        self.serial_label.setText(device.serial or "-")
        if device.state == "device":
            self.update_workflow_state("scan")
        else:
            self.quick_scan_pending = False

    def on_adb_diagnostic_finished(self, report: dict[str, Any]) -> None:
        device: DeviceInfo = report.get("device", DeviceInfo())
        self.update_device_combo(report.get("devices", []), device.serial)
        self.device = device
        self.status_label.setText("Réparation ADB terminée" if report.get("repair") else "Diagnostic ADB terminé")
        self.model_label.setText(f"{device.manufacturer} {device.model}".strip() or "-")
        self.android_label.setText(device.android_version or "-")
        self.serial_label.setText(device.serial or "-")
        self.show_diagnostic_report(report)

    def selected_device_serial(self) -> str:
        value = self.device_combo.currentData()
        return str(value or "")

    def update_device_combo(self, devices: list[ADBDevice], selected_serial: str = "") -> None:
        current = selected_serial or self.selected_device_serial()
        self.device_combo.blockSignals(True)
        self.device_combo.clear()
        self.device_combo.addItem("Auto", "")
        for device in devices:
            label = f"{device.serial} ({device.state})"
            if device.details:
                label = f"{label} - {device.details}"
            self.device_combo.addItem(label, device.serial)
        if current:
            index = self.device_combo.findData(current)
            if index >= 0:
                self.device_combo.setCurrentIndex(index)
        self.device_combo.blockSignals(False)

    def refresh_devices_if_idle(self) -> None:
        if self.is_busy or (self.refresh_worker and self.refresh_worker.isRunning()):
            return
        worker = DevicesRefreshWorker()
        worker.succeeded.connect(self.on_devices_refreshed)
        worker.finished.connect(lambda: setattr(self, "refresh_worker", None))
        self.refresh_worker = worker
        worker.start()

    def on_devices_refreshed(self, devices: list[ADBDevice]) -> None:
        signature = "|".join(f"{device.serial}:{device.state}:{device.details}" for device in devices)
        if signature == self.last_devices_signature:
            return
        previous_signature = self.last_devices_signature
        self.last_devices_signature = signature
        self.update_device_combo(devices)
        ready = [device for device in devices if device.state == "device"]
        if ready and self.device.state != "device":
            self.status_label.setText("Téléphone ADB détecté. Cliquez sur Détecter téléphone.")
        elif previous_signature and not devices:
            self.status_label.setText("Aucun appareil ADB détecté.")

    def show_diagnostic_report(self, report: dict[str, Any]) -> None:
        device: DeviceInfo = report.get("device", DeviceInfo())
        devices: list[ADBDevice] = report.get("devices", [])
        summary = device.message if devices else "Aucun appareil ADB détecté."
        if report.get("adb_error"):
            summary = f"ADB indisponible : {report['adb_error']}"
        if report.get("repair"):
            summary = f"Réparation ADB terminée.\n{summary}"

        details = format_diagnostic_report(report)
        self.last_diagnostic_text = details
        self.copy_diagnostic_button.setEnabled(True)
        self.export_diagnostic_button.setEnabled(True)
        message_box = QMessageBox(self)
        message_box.setWindowTitle("Diagnostic ADB")
        message_box.setIcon(QMessageBox.Information)
        message_box.setText(summary)
        message_box.setDetailedText(details)
        message_box.exec()

    def copy_diagnostic(self) -> None:
        if not self.last_diagnostic_text:
            QMessageBox.information(self, "Diagnostic absent", "Lancez d'abord Diagnostic ADB.")
            return
        QApplication.clipboard().setText(self.last_diagnostic_text)
        self.status_label.setText("Diagnostic copié dans le presse-papiers.")

    def export_diagnostic(self) -> None:
        if not self.last_diagnostic_text:
            QMessageBox.information(self, "Diagnostic absent", "Lancez d'abord Diagnostic ADB.")
            return
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        path = REPORTS_DIR / f"diagnostic_adb_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.txt"
        path.write_text(self.last_diagnostic_text, encoding="utf-8")
        QMessageBox.information(self, "Diagnostic exporté", f"Diagnostic créé :\n{path}")

    def scan_apps(self) -> None:
        self.quick_scan_pending = False
        if self.device.state != "device" or not self.device.serial:
            self.update_workflow_state("connect")
            QMessageBox.warning(self, "Téléphone requis", "Détectez d'abord un téléphone autorisé en USB.")
            return
        self.tabs.setCurrentIndex(self.scan_tab_index)
        self.update_workflow_state("scan")
        self.set_busy(True, "Scan des applications en cours...")
        self.scan_progress.setValue(0)
        self.progress_label.setText("Préparation du scan...")
        worker = ScanWorker(self.device.serial, self.include_system_checkbox.isChecked(), self.device)
        worker.succeeded.connect(self.on_scan_finished)
        worker.progress.connect(self.on_scan_progress)
        worker.failed.connect(self.on_worker_failed)
        worker.finished.connect(self.on_scan_worker_finished)
        self.scan_worker = worker
        self.current_worker = worker
        self.cancel_scan_button.setEnabled(True)
        worker.start()

    def cancel_scan(self) -> None:
        if self.scan_worker and self.scan_worker.isRunning():
            self.scan_worker.cancel()
            self.cancel_scan_button.setEnabled(False)
            self.progress_label.setText("Annulation demandée...")
            self.status_label.setText("Annulation du scan...")

    def on_scan_progress(self, current: int, total: int, package: str) -> None:
        percent = int((current / total) * 100) if total else 0
        self.scan_progress.setValue(percent)
        self.progress_label.setText(f"{current}/{total} {package}")
        self.status_label.setText(f"Scan en cours : {current}/{total}")

    def on_scan_finished(self, payload: dict[str, Any]) -> None:
        rows: list[dict[str, Any]] = payload.get("rows", [])
        errors: list[str] = payload.get("errors", [])
        cancelled = bool(payload.get("cancelled"))
        self.rows = rows
        self.populate_table()
        suspicious = len([r for r in rows if r["risk"].score >= 60 and r["risk"].recommended_action != "do_not_touch"])
        self.scan_progress.setValue(100 if rows else 0)
        if cancelled:
            self.status_label.setText(f"Scan annulé : {len(rows)} apps traitées, {len(errors)} erreur(s).")
            self.progress_label.setText("Scan annulé")
        elif errors:
            self.status_label.setText(f"Scan partiel : {len(rows)} apps, {suspicious} suspectes, {len(errors)} erreur(s).")
            self.progress_label.setText(f"Scan partiel : {len(errors)} erreur(s)")
            QMessageBox.warning(
                self,
                "Scan partiel",
                f"{len(errors)} application(s) n'ont pas livré toutes leurs métadonnées.\n\n"
                + "\n".join(errors[:20]),
            )
        else:
            self.status_label.setText(f"Scan terminé : {len(rows)} apps, {suspicious} suspectes.")
            self.progress_label.setText("Scan terminé")
        if rows:
            self.tabs.setCurrentIndex(self.results_tab_index)
            self.update_workflow_state("results")

    def on_scan_worker_finished(self) -> None:
        self.scan_worker = None
        self.cancel_scan_button.setEnabled(False)
        self.set_busy(False)

    def populate_table(self) -> None:
        self.table.setSortingEnabled(False)
        self.table.blockSignals(True)
        self.table.setRowCount(0)
        for row_data in self.rows:
            row = self.table.rowCount()
            self.table.insertRow(row)
            self._set_row_items(row, row_data)
        self.table.blockSignals(False)
        self.table.setSortingEnabled(True)
        self.table.sortItems(self.COL_SCORE, Qt.DescendingOrder)
        self.apply_filters()
        if self.table.rowCount() > 0:
            self.table.selectRow(0)
            self.update_details_from_selection()
        else:
            self.details_text.clear()
            self.details_title_label.setText("Détails sélection")
        self.update_summary()

    def _set_row_items(self, row: int, row_data: dict[str, Any]) -> None:
        app: AppInfo = row_data["app"]
        risk = row_data["risk"]
        values = [
            "",
            priority_text(row_data),
            str(risk.score),
            display_category(risk.category),
            display_action(risk.recommended_action),
            app.display_name(),
            app.package_name,
            app.installer or "inconnu",
            hidden_summary(app),
            notification_summary(app),
            row_data.get("note", ""),
            "; ".join(risk.reasons),
            row_data.get("ai_text", ""),
        ]
        color = self._row_color(risk.score, risk.category)
        for col, value in enumerate(values):
            item = QTableWidgetItem(value)
            item.setData(Qt.UserRole, app.package_name)
            if col == self.COL_CHECK:
                item.setFlags(Qt.ItemIsEnabled | Qt.ItemIsUserCheckable | Qt.ItemIsSelectable)
                item.setCheckState(Qt.Unchecked)
                item.setText("")
                if app.icon_path and Path(app.icon_path).exists():
                    item.setIcon(QIcon(app.icon_path))
            elif col == self.COL_SCORE:
                item.setData(Qt.DisplayRole, risk.score)
            item.setBackground(color)
            self.table.setItem(row, col, item)
        self.table.setRowHeight(row, 42)

    def _row_color(self, score: int, category: str) -> QColor:
        if category == "do_not_touch_system":
            return QColor("#edf0f3")
        if score >= 60:
            return QColor("#fde7e9")
        if score >= 30:
            return QColor("#fff3d6")
        return QColor("#e7f6ec")

    def apply_filters(self) -> None:
        query = self.search_input.text().strip().lower()
        hide_safe = self.hide_safe_checkbox.isChecked()
        only_hidden = self.hidden_apps_checkbox.isChecked()
        only_notifications = self.notification_audit_checkbox.isChecked()
        only_sideload = self.sideload_checkbox.isChecked()
        min_score = int(self.score_filter.currentData() or 0)
        permission_query = str(self.permission_filter.currentData() or "")
        for row in range(self.table.rowCount()):
            package_item = self.table.item(row, self.COL_PACKAGE)
            if not package_item:
                continue
            package = package_item.text()
            row_data = self.row_by_package(package)
            if not row_data:
                continue
            haystack = " ".join(
                [
                    row_data["app"].display_name(),
                    row_data["app"].package_name,
                    row_data["app"].installer,
                    row_data["risk"].category,
                    " ".join(row_data["app"].hidden_audit),
                    " ".join(row_data["app"].notification_audit),
                ]
            ).lower()
            is_safe = row_data["risk"].score < 30 or row_data["risk"].recommended_action == "keep"
            is_hidden = is_hidden_or_low_visibility(row_data["app"])
            has_notification_audit = bool(row_data["app"].notification_audit)
            is_sideload = is_sideloaded(row_data["app"])
            self.table.setRowHidden(
                row,
                bool(query and query not in haystack)
                or (row_data["risk"].score < min_score)
                or (hide_safe and is_safe)
                or (only_hidden and not is_hidden)
                or (only_notifications and not has_notification_audit)
                or (only_sideload and not is_sideload)
                or (bool(permission_query) and not permission_matches(row_data["app"], permission_query)),
            )
        self.update_summary()

    def on_table_item_changed(self, item: QTableWidgetItem) -> None:
        if item.column() == self.COL_CHECK:
            self.update_summary()

    def update_summary(self) -> None:
        summary = scan_summary(self.rows)
        checked = len(self.selected_rows())
        visible = len([row for row in range(self.table.rowCount()) if not self.table.isRowHidden(row)])
        self.summary_total_label.setText(f"Apps: {summary['total']} ({visible} visibles)")
        self.summary_high_label.setText(f"À traiter: {summary['high']}")
        self.summary_review_label.setText(f"À vérifier: {summary['review']}")
        self.summary_hidden_label.setText(f"Cachées: {summary['hidden']}")
        self.summary_sideload_label.setText(f"Sideload: {summary['sideload']}")
        self.summary_selected_label.setText(f"Cochées: {checked}")
        self.update_results_action_banner(summary, checked)
        if checked:
            self.update_workflow_state("validate")
        elif self.rows:
            self.update_workflow_state("results")

    def update_results_action_banner(self, summary: dict[str, int], checked: int) -> None:
        if not self.rows:
            state = "neutral"
            title = "Lancez un scan pour obtenir une synthèse."
            body = "Diagnostic rapide détecte le téléphone, scanne les apps utilisateur et ouvre cette vue."
        elif summary["high"]:
            state = "risk"
            title = f"{summary['high']} app(s) à traiter en priorité"
            body = (
                "Commencez par Cocher à traiter, ouvrez les détails des apps sélectionnées, "
                "puis désinstallez uniquement après validation humaine."
            )
        elif summary["review"]:
            state = "review"
            title = f"{summary['review']} app(s) à vérifier manuellement"
            body = "Aucune urgence forte détectée. Vérifiez les permissions, l'installateur et la note client avant action."
        else:
            state = "ok"
            title = "Aucune app utilisateur à traiter"
            body = "Vous pouvez exporter un rapport client ou conserver le scan dans l'historique local."
        if checked:
            body = f"{body} {checked} ligne(s) cochée(s)."

        self.results_action_title_label.setText(title)
        self.results_action_body_label.setText(body)
        self.results_action_banner.setProperty("state", state)
        self._refresh_style(self.results_action_banner)

    def check_rows(self, mode: str) -> None:
        self.table.blockSignals(True)
        try:
            for row in range(self.table.rowCount()):
                item = self.table.item(row, self.COL_CHECK)
                package_item = self.table.item(row, self.COL_PACKAGE)
                if not item or not package_item:
                    continue
                row_data = self.row_by_package(package_item.text())
                if not row_data:
                    continue
                should_check = False
                if mode == "high":
                    should_check = (
                        row_data["risk"].score >= 60
                        and row_data["risk"].recommended_action != "do_not_touch"
                        and not row_data["app"].is_system_app
                    )
                elif mode == "review":
                    should_check = row_data["risk"].recommended_action == "review" and not row_data["app"].is_system_app
                elif mode == "clear":
                    should_check = False
                item.setCheckState(Qt.Checked if should_check else Qt.Unchecked)
        finally:
            self.table.blockSignals(False)
        self.update_summary()

    def edit_note_for_selected(self) -> None:
        row_data = self.current_or_checked_row()
        if not row_data:
            QMessageBox.information(self, "Application requise", "Sélectionnez une application pour ajouter une note.")
            return
        self.edit_note(row_data)

    def analyze_with_ai(self) -> None:
        if not self.rows:
            QMessageBox.information(self, "Scan requis", "Scannez les applications avant de lancer l'analyse IA.")
            return
        self.set_busy(True, "Analyse IA des apps suspectes...")
        worker = AIWorker(self.rows)
        worker.succeeded.connect(self.on_ai_finished)
        worker.failed.connect(self.on_worker_failed)
        worker.finished.connect(lambda: self.set_busy(False))
        self.current_worker = worker
        worker.start()

    def on_ai_finished(self, results: dict[str, AIResult]) -> None:
        for row in self.rows:
            app = row["app"]
            ai_result = results.get(app.package_name)
            if ai_result:
                row["ai"] = ai_result
                row["ai_text"] = (
                    f"{ai_result.risk_score}/100 {ai_result.category} "
                    f"({ai_result.confidence}) - {ai_result.reason_fr}"
                )
        self.populate_table()
        self.status_label.setText(f"Analyse IA terminée : {len(results)} résultat(s).")
        self.tabs.setCurrentIndex(self.results_tab_index)

    def open_selected_app_settings(self) -> None:
        row_data = self.current_or_checked_row()
        if not row_data:
            QMessageBox.information(
                self,
                "Application requise",
                "Sélectionnez une ligne ou cochez une seule application pour ouvrir ses paramètres.",
            )
            return
        self.open_app_settings(row_data)

    def open_app_settings(self, row_data: dict[str, Any]) -> None:
        if self.device.state != "device" or not self.device.serial:
            QMessageBox.warning(self, "Téléphone requis", "Détectez d'abord un téléphone autorisé en USB.")
            return

        app = row_data["app"]
        self.set_busy(True, f"Ouverture des paramètres de {app.display_name()}...")
        worker = OpenAppSettingsWorker(self.device.serial, app.package_name)
        worker.succeeded.connect(lambda message: self.on_open_settings_finished(app.package_name, message))
        worker.failed.connect(self.on_worker_failed)
        worker.finished.connect(lambda: self.set_busy(False))
        self.current_worker = worker
        worker.start()

    def on_open_settings_finished(self, package: str, message: str) -> None:
        self.status_label.setText(f"Paramètres ouverts : {package}")
        logging.info("Open settings result for %s: %s", package, message)

    def uninstall_selected(self) -> None:
        selected = self.selected_rows()
        allowed = [r for r in selected if not r["app"].is_system_app and r["risk"].recommended_action != "do_not_touch"]
        blocked = [r for r in selected if r not in allowed]
        if not selected:
            QMessageBox.information(self, "Sélection vide", "Cochez au moins une application utilisateur à désinstaller.")
            return
        if blocked:
            QMessageBox.warning(
                self,
                "Apps protégées ignorées",
                "Les applications système ou marquées do_not_touch ne seront pas désinstallées.",
            )
        if not allowed:
            return

        packages = "\n".join(f"- {r['app'].display_name()} ({r['app'].package_name})" for r in allowed)
        answer = QMessageBox.question(
            self,
            "Validation humaine obligatoire",
            "Confirmez-vous la désinstallation pour l'utilisateur 0 des applications suivantes ?\n\n"
            f"{packages}\n\nAucune suppression automatique ne sera lancée sans cette validation.",
        )
        if answer != QMessageBox.Yes:
            return

        self.set_busy(True, "Désinstallation en cours...")
        worker = UninstallWorker(self.device.serial, [r["app"] for r in allowed])
        worker.succeeded.connect(self.on_uninstall_finished)
        worker.failed.connect(self.on_worker_failed)
        worker.finished.connect(lambda: self.set_busy(False))
        self.current_worker = worker
        worker.start()

    def on_uninstall_finished(self, results: list[dict[str, str]]) -> None:
        self.uninstalled.extend(results)
        message = "\n".join(f"{item['package']}: {item['result']}" for item in results)
        QMessageBox.information(self, "Résultat désinstallation", message or "Aucun résultat.")
        self.status_label.setText("Désinstallation terminée.")
        answer = QMessageBox.question(self, "Rescanner", "Voulez-vous relancer un scan maintenant ?")
        if answer == QMessageBox.Yes:
            self.scan_apps()

    def export_report(self) -> None:
        if not self.rows:
            QMessageBox.information(self, "Rapport impossible", "Scannez les applications avant d'exporter un rapport.")
            return
        try:
            path = export_html_report(self.device, self.rows, self.uninstalled)
        except Exception as exc:  # noqa: BLE001
            logging.exception("Report export failed")
            QMessageBox.critical(self, "Erreur rapport", f"Export impossible : {exc}")
            return
        QMessageBox.information(self, "Rapport exporté", f"Rapport créé :\n{path}")
        self.update_workflow_state("export")

    def export_csv(self) -> None:
        if not self.rows:
            QMessageBox.information(self, "CSV impossible", "Scannez les applications avant d'exporter un CSV.")
            return
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
                    "app_name",
                    "package",
                    "installer",
                    "system",
                    "launcher_visible",
                    "permissions",
                    "risk_reasons",
                    "technician_note",
                    "metadata_error",
                ]
            )
            for row in self.rows:
                app: AppInfo = row["app"]
                risk = row["risk"]
                writer.writerow(
                    [
                        risk.score,
                        priority_text(row),
                        risk.category,
                        risk.recommended_action,
                        app.display_name(),
                        app.package_name,
                        app.installer or "inconnu",
                        "oui" if app.is_system_app else "non",
                        launcher_text(app),
                        "; ".join(app.sensitive_permissions),
                        "; ".join(risk.reasons),
                        row.get("note", ""),
                        app.dumpsys_error,
                    ]
                )
        QMessageBox.information(self, "CSV exporté", f"CSV créé :\n{path}")
        self.update_workflow_state("export")

    def export_action_plan(self) -> None:
        if not self.rows:
            QMessageBox.information(self, "Plan impossible", "Scannez les applications avant d'exporter un plan.")
            return
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        path = REPORTS_DIR / f"plan_action_android_cleaner_{datetime.now().strftime('%Y-%m-%d_%H-%M')}.txt"
        path.write_text(build_action_plan(self.device, self.rows, self.selected_rows()), encoding="utf-8")
        QMessageBox.information(self, "Plan action exporté", f"Plan créé :\n{path}")
        self.update_workflow_state("export")

    def copy_action_plan(self) -> None:
        if not self.rows:
            QMessageBox.information(self, "Plan impossible", "Scannez les applications avant de copier un plan.")
            return
        QApplication.clipboard().setText(build_action_plan(self.device, self.rows, self.selected_rows()))
        self.status_label.setText("Plan d'action copié dans le presse-papiers.")

    def open_reports_folder(self) -> None:
        self.open_folder(REPORTS_DIR)

    def open_folder(self, path: Path) -> None:
        path.mkdir(parents=True, exist_ok=True)
        try:
            if sys.platform == "win32":
                os.startfile(path)  # type: ignore[attr-defined]
            elif sys.platform == "darwin":
                subprocess.run(["open", str(path)], check=False)
            else:
                subprocess.run(["xdg-open", str(path)], check=False)
        except Exception as exc:  # noqa: BLE001
            QMessageBox.warning(self, "Dossier", f"Ouverture impossible : {exc}")

    def show_scan_history(self) -> None:
        scans = self.db.recent_scans(limit=20)
        if not scans:
            QMessageBox.information(self, "Historique", "Aucun scan enregistré.")
            return
        lines = []
        for scan in scans:
            lines.append(
                f"{scan['date']} - {scan['device_model'] or '-'} Android {scan['android_version'] or '-'} "
                f"- {scan['scanned_count']} apps - {scan['suspicious_count']} suspectes"
            )
        QMessageBox.information(self, "Historique des scans", "\n".join(lines))

    def load_demo_data(self) -> None:
        self.device = DeviceInfo(
            serial="DEMO-ANDROID",
            state="device",
            manufacturer="Microwest",
            model="Demo Phone",
            android_version="14",
            message="Mode démo chargé",
        )
        demo_apps = [
            AppInfo(
                package_name="com.fast.cleaner.booster",
                app_label="Fast Cleaner",
                installer="inconnu",
                sensitive_permissions=[
                    "android.permission.SYSTEM_ALERT_WINDOW",
                    "android.permission.POST_NOTIFICATIONS",
                    "android.permission.RECEIVE_BOOT_COMPLETED",
                ],
                has_overlay=True,
                requests_post_notifications=True,
                runs_at_boot=True,
                has_launcher_entry=False,
                hidden_audit=["Aucune icône launcher visible", "Icône non récupérée ou adaptive XML"],
                notification_audit=["Demande POST_NOTIFICATIONS", "Démarrage automatique"],
            ),
            AppInfo(
                package_name="com.whatsapp",
                app_label="WhatsApp",
                installer="com.android.vending",
                sensitive_permissions=["android.permission.READ_CONTACTS"],
                has_launcher_entry=True,
            ),
            AppInfo(
                package_name="com.android.fake.update",
                app_label="System Update",
                installer="inconnu",
                sensitive_permissions=["android.permission.BIND_ACCESSIBILITY_SERVICE"],
                has_accessibility=True,
                has_launcher_entry=False,
                hidden_audit=["Aucune icône launcher visible", "Nom très générique"],
            ),
        ]
        self.rows = [
            {
                "app": app,
                "risk": evaluate_app(app, self.db.reputation_for(app.package_name)),
                "ai": None,
                "ai_text": "",
                "note": "Exemple de triage" if app.package_name == "com.fast.cleaner.booster" else "",
            }
            for app in demo_apps
        ]
        self.rows.sort(key=lambda item: item["risk"].score, reverse=True)
        self.uninstalled = []
        self.on_device_detected({"device": self.device, "devices": [ADBDevice("DEMO-ANDROID", "device", "mode:demo")]})
        self.populate_table()
        self.scan_progress.setValue(100)
        self.progress_label.setText("Mode démo")
        self.status_label.setText("Mode démo chargé : données fictives.")
        self.tabs.setCurrentIndex(self.results_tab_index)
        self.update_workflow_state("results")

    def reload_reputation(self) -> None:
        self.db = ReputationDatabase()
        for row in self.rows:
            row["risk"] = evaluate_app(row["app"], self.db.reputation_for(row["app"].package_name))
        self.populate_table()
        self.status_label.setText("Blacklist/whitelist rechargées.")

    def open_context_menu(self, position: Any) -> None:
        item = self.table.itemAt(position)
        if not item:
            return
        package = self.table.item(item.row(), self.COL_PACKAGE).text()
        row_data = self.row_by_package(package)
        if not row_data:
            return

        menu = QMenu(self)
        whitelist = QAction("Ajouter à la whitelist", self)
        blacklist = QAction("Ajouter à la blacklist", self)
        note = QAction("Note technicien", self)
        open_settings = QAction("Ouvrir paramètres app sur téléphone", self)
        copy_package = QAction("Copier package", self)
        details = QAction("Voir détails", self)
        menu.addAction(whitelist)
        menu.addAction(blacklist)
        menu.addAction(note)
        menu.addSeparator()
        menu.addAction(open_settings)
        menu.addAction(copy_package)
        menu.addAction(details)
        whitelist.triggered.connect(lambda: self.add_reputation(row_data, whitelist=True))
        blacklist.triggered.connect(lambda: self.add_reputation(row_data, whitelist=False))
        note.triggered.connect(lambda: self.edit_note(row_data))
        open_settings.triggered.connect(lambda: self.open_app_settings(row_data))
        copy_package.triggered.connect(lambda: QApplication.clipboard().setText(package))
        details.triggered.connect(lambda: self.open_details(row_data))
        menu.exec(self.table.viewport().mapToGlobal(position))

    def add_reputation(self, row_data: dict[str, Any], whitelist: bool) -> None:
        app = row_data["app"]
        title = "Whitelist" if whitelist else "Blacklist"
        reason, ok = QInputDialog.getText(self, title, "Raison interne :")
        if not ok:
            return
        if whitelist:
            self.db.add_to_whitelist(app.package_name, app.display_name(), reason)
        else:
            self.db.add_to_blacklist(app.package_name, app.display_name(), reason, severity=80)
        self.reload_reputation()

    def edit_note(self, row_data: dict[str, Any]) -> None:
        app = row_data["app"]
        note, ok = QInputDialog.getMultiLineText(
            self,
            "Note technicien",
            f"Note locale pour {app.display_name()} ({app.package_name}) :",
            row_data.get("note", ""),
        )
        if not ok:
            return
        self.db.set_note(app.package_name, note, datetime.now().isoformat(timespec="seconds"))
        row_data["note"] = note.strip()
        self.populate_table()
        self.status_label.setText(f"Note mise à jour : {app.package_name}")

    def open_details_for_cell(self, row: int, _column: int) -> None:
        package_item = self.table.item(row, self.COL_PACKAGE)
        if not package_item:
            return
        row_data = self.row_by_package(package_item.text())
        if row_data:
            self.table.selectRow(row)
            self.open_details(row_data)

    def open_details(self, row_data: dict[str, Any]) -> None:
        self.details_title_label.setText(f"{row_data['app'].display_name()} - {row_data['app'].package_name}")
        self.details_text.setPlainText(build_app_details_text(row_data))
        self.status_label.setText(f"Détails affichés : {row_data['app'].package_name}")
        self.tabs.setCurrentIndex(self.details_tab_index)

    def update_details_from_selection(self) -> None:
        current_items = self.table.selectedItems()
        if not current_items:
            return
        package_item = self.table.item(current_items[0].row(), self.COL_PACKAGE)
        if not package_item:
            return
        row_data = self.row_by_package(package_item.text())
        if row_data:
            self.details_title_label.setText(f"{row_data['app'].display_name()} - {row_data['app'].package_name}")
            self.details_text.setPlainText(build_app_details_text(row_data))

    def row_by_package(self, package: str) -> dict[str, Any] | None:
        return next((row for row in self.rows if row["app"].package_name == package), None)

    def selected_rows(self) -> list[dict[str, Any]]:
        selected: list[dict[str, Any]] = []
        for row in range(self.table.rowCount()):
            item = self.table.item(row, self.COL_CHECK)
            if item and item.checkState() == Qt.Checked:
                package_item = self.table.item(row, self.COL_PACKAGE)
                if not package_item:
                    continue
                package = package_item.text()
                row_data = self.row_by_package(package)
                if row_data:
                    selected.append(row_data)
        return selected

    def current_or_checked_row(self) -> dict[str, Any] | None:
        current_items = self.table.selectedItems()
        if current_items:
            package_item = self.table.item(current_items[0].row(), self.COL_PACKAGE)
            if package_item:
                row_data = self.row_by_package(package_item.text())
                if row_data:
                    return row_data

        checked = self.selected_rows()
        if len(checked) == 1:
            return checked[0]
        return None

    def on_worker_failed(self, message: str) -> None:
        self.quick_scan_pending = False
        self.status_label.setText("Erreur")
        QMessageBox.critical(self, "Erreur", message)


def format_diagnostic_report(report: dict[str, Any]) -> str:
    lines = [
        "Environnement",
        f"- OS : {platform.platform()}",
        f"- Python : {sys.version.split()[0]}",
        f"- Qt : {qVersion()}",
        f"- Dossier app : {PROJECT_DIR}",
        "",
        "Stockage portable",
    ]
    for label, path, status in report.get("portable", []):
        lines.append(f"- {label} : {status} ({path})")

    lines.extend(
        [
            "",
            "ADB",
            f"- Chemin : {report.get('adb_path') or 'introuvable'}",
            f"- Version : {first_line(report.get('adb_version', '')) or 'non disponible'}",
        ]
    )
    if report.get("adb_error"):
        lines.append(f"- Erreur : {report['adb_error']}")
    if report.get("adb_restart"):
        lines.append(f"- Réparation : {report['adb_restart']}")

    lines.extend(
        [
            "",
            "aapt2",
            f"- Chemin : {report.get('aapt2_path') or 'introuvable'}",
            f"- Disponible : {'oui' if report.get('aapt2_available') else 'non'}",
            "",
            "Téléphones",
        ]
    )
    devices: list[ADBDevice] = report.get("devices", [])
    if devices:
        for device in devices:
            detail = f" - {device.details}" if device.details else ""
            lines.append(f"- {device.serial} : {device.state}{detail}")
    else:
        lines.append("- Aucun appareil listé par ADB")

    device_info: DeviceInfo = report.get("device", DeviceInfo())
    lines.extend(
        [
            "",
            "Sélection",
            f"- Serial : {device_info.serial or '-'}",
            f"- État : {device_info.state}",
            f"- Modèle : {f'{device_info.manufacturer} {device_info.model}'.strip() or '-'}",
            f"- Android : {device_info.android_version or '-'}",
            f"- Message : {device_info.message}",
            "",
            "Sortie adb devices -l",
            report.get("devices_output") or "(vide)",
            "",
            "Conseils",
            adb_state_advice(device_info.state, bool(devices)),
        ]
    )
    return "\n".join(lines)


def first_line(value: str) -> str:
    return next((line.strip() for line in value.splitlines() if line.strip()), "")


def adb_state_advice(state: str, has_devices: bool) -> str:
    if not has_devices:
        return (
            "- Branchez le téléphone en USB.\n"
            "- Déverrouillez l'écran.\n"
            "- Activez le débogage USB dans les options développeur.\n"
            "- Essayez un autre câble USB si rien n'apparaît."
        )
    if state == "unauthorized":
        return "- Acceptez la demande d'autorisation RSA sur l'écran du téléphone, puis relancez la détection."
    if state == "offline":
        return "- Débranchez/rebranchez le câble, puis utilisez Réparer connexion."
    if state == "device":
        return "- Connexion ADB opérationnelle."
    return "- Utilisez Réparer connexion, puis vérifiez l'écran du téléphone."


def main() -> int:
    setup_logging()
    app = QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(True)

    lock_file = QLockFile(str(Path(tempfile.gettempdir()) / "microwest_android_cleaner.lock"))
    if not lock_file.tryLock(100):
        logging.info("Microwest Android Cleaner is already running; exiting duplicate instance.")
        return 0

    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
