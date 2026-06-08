from __future__ import annotations

import logging
import platform
import csv
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from PySide6.QtCore import QLockFile, QSize, Qt, QThread, QTimer, Signal, qVersion
from PySide6.QtGui import QAction, QColor, QIcon
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenu,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from adb_client import ADBClient, ADBError, ADBDevice, ADBNotFoundError, DeviceInfo, parse_devices_l
from ai_analyzer import AIAnalyzer, AIResult, ai_payload_from_row
from apk_metadata import ApkMetadataExtractor
from database import ReputationDatabase
from report_generator import export_html_report
from risk_rules import evaluate_app
from scanner import AppInfo, AppScanner


PROJECT_DIR = Path(__file__).resolve().parent
LOG_DIR = PROJECT_DIR / "logs"
REPORTS_DIR = PROJECT_DIR / "reports"


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
            adb = ADBClient()
            db = ReputationDatabase()
            scanner = AppScanner(adb)
            packages = adb.list_packages(self.serial, include_system=self.include_system)
            launcher_packages = adb.list_launcher_packages(self.serial)
            rows: list[dict[str, Any]] = []
            errors: list[str] = []
            total = len(packages)
            for index, (package, installer) in enumerate(packages.items(), start=1):
                if self.cancel_requested or self.isInterruptionRequested():
                    break
                self.progress.emit(index, total, package)
                app = AppInfo(package_name=package, installer=installer, is_system_app=self.include_system)
                try:
                    if launcher_packages is not None:
                        app.has_launcher_entry = package in launcher_packages
                    dumpsys = adb.dumpsys_package(self.serial, package)
                    scanner._enrich_from_dumpsys(app, dumpsys)
                    scanner._enrich_from_apk(self.serial, app)
                    scanner._finalize_audits(app)
                except Exception as exc:  # noqa: BLE001 - partial scan should continue.
                    logging.exception("Metadata enrichment failed for %s", package)
                    app.dumpsys_error = str(exc)
                    errors.append(f"{package}: {exc}")
                risk = evaluate_app(app, db.reputation_for(app.package_name))
                rows.append({"app": app, "risk": risk, "ai": None, "ai_text": ""})
            rows.sort(key=lambda item: item["risk"].score, reverse=True)
            suspicious_count = len([r for r in rows if r["risk"].score >= 60 and r["risk"].recommended_action != "do_not_touch"])
            if rows:
                db.record_scan(
                    datetime.now().isoformat(timespec="seconds"),
                    self.device.model,
                    self.device.android_version,
                    len(rows),
                    suspicious_count,
                )
            self.succeeded.emit({"rows": rows, "errors": errors, "cancelled": self.cancel_requested, "total": total})
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
        f"Permissions sensibles :\n- "
        + ("\n- ".join(app.sensitive_permissions) if app.sensitive_permissions else "Aucune détectée")
        + f"\n\nCommande ADB prévue :\n{command}\n\n"
        f"Commande paramètres app :\n{settings_command}\n\n"
        f"Analyse IA :\n{row.get('ai_text') or 'Non effectuée'}"
    )


class MainWindow(QMainWindow):
    COLUMNS = [
        "",
        "Score",
        "Catégorie",
        "Action",
        "Nom app",
        "Package",
        "Installer",
        "Cachée",
        "Notifications",
        "Raisons",
        "IA",
    ]

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Microwest Android Cleaner")
        self.resize(1320, 780)
        self.db = ReputationDatabase()
        self.ai_analyzer = AIAnalyzer()
        self.device = DeviceInfo()
        self.rows: list[dict[str, Any]] = []
        self.uninstalled: list[dict[str, str]] = []
        self.current_worker: QThread | None = None
        self.scan_worker: ScanWorker | None = None
        self.refresh_worker: DevicesRefreshWorker | None = None
        self.last_diagnostic_text = ""
        self.last_devices_signature = ""
        self.is_busy = False
        self._build_ui()
        self._apply_ai_button_state()
        self.device_refresh_timer = QTimer(self)
        self.device_refresh_timer.setInterval(8000)
        self.device_refresh_timer.timeout.connect(self.refresh_devices_if_idle)
        self.device_refresh_timer.start()

    def _build_ui(self) -> None:
        root = QWidget()
        main_layout = QVBoxLayout(root)
        main_layout.setContentsMargins(18, 16, 18, 18)
        main_layout.setSpacing(12)

        title = QLabel("Microwest Android Cleaner")
        title.setObjectName("Title")
        subtitle = QLabel("Diagnostic Android / Samsung")
        subtitle.setObjectName("Subtitle")
        main_layout.addWidget(title)
        main_layout.addWidget(subtitle)

        state_box = QGroupBox("État téléphone")
        state_layout = QGridLayout(state_box)
        self.status_label = QLabel("Aucun appareil détecté")
        self.model_label = QLabel("-")
        self.android_label = QLabel("-")
        self.serial_label = QLabel("-")
        self.device_combo = QComboBox()
        self.device_combo.addItem("Auto", "")
        state_layout.addWidget(QLabel("Statut"), 0, 0)
        state_layout.addWidget(self.status_label, 0, 1)
        state_layout.addWidget(QLabel("Modèle"), 1, 0)
        state_layout.addWidget(self.model_label, 1, 1)
        state_layout.addWidget(QLabel("Android"), 1, 2)
        state_layout.addWidget(self.android_label, 1, 3)
        state_layout.addWidget(QLabel("Numéro ADB"), 0, 2)
        state_layout.addWidget(self.serial_label, 0, 3)
        state_layout.addWidget(QLabel("Appareil"), 2, 0)
        state_layout.addWidget(self.device_combo, 2, 1, 1, 3)
        main_layout.addWidget(state_box)

        toolbar = QHBoxLayout()
        self.detect_button = QPushButton("Détecter téléphone")
        self.adb_diagnostic_button = QPushButton("Diagnostic ADB")
        self.adb_repair_button = QPushButton("Réparer connexion")
        self.adb_daemon_button = QPushButton("Redémarrer ADB")
        self.adb_daemon_button.setContextMenuPolicy(Qt.CustomContextMenu)
        self.scan_button = QPushButton("Scanner les apps")
        self.cancel_scan_button = QPushButton("Annuler scan")
        self.ai_button = QPushButton("Analyser avec IA")
        self.open_settings_button = QPushButton("Paramètres app")
        self.uninstall_button = QPushButton("Désinstaller sélection")
        self.report_button = QPushButton("Exporter rapport")
        self.csv_button = QPushButton("Exporter CSV")
        self.copy_diagnostic_button = QPushButton("Copier diagnostic")
        self.export_diagnostic_button = QPushButton("Exporter diagnostic")
        self.history_button = QPushButton("Historique")
        self.demo_button = QPushButton("Mode démo")
        self.reload_button = QPushButton("Recharger blacklist/whitelist")
        for button in (
            self.detect_button,
            self.adb_diagnostic_button,
            self.adb_repair_button,
            self.adb_daemon_button,
            self.scan_button,
            self.cancel_scan_button,
            self.ai_button,
            self.open_settings_button,
            self.uninstall_button,
        ):
            toolbar.addWidget(button)
        toolbar.addStretch(1)
        main_layout.addLayout(toolbar)

        export_toolbar = QHBoxLayout()
        for button in (
            self.report_button,
            self.csv_button,
            self.copy_diagnostic_button,
            self.export_diagnostic_button,
            self.history_button,
            self.demo_button,
            self.reload_button,
        ):
            export_toolbar.addWidget(button)
        export_toolbar.addStretch(1)
        main_layout.addLayout(export_toolbar)

        self.cancel_scan_button.setEnabled(False)
        self.copy_diagnostic_button.setEnabled(False)
        self.export_diagnostic_button.setEnabled(False)

        progress_layout = QHBoxLayout()
        self.scan_progress = QProgressBar()
        self.scan_progress.setRange(0, 100)
        self.scan_progress.setValue(0)
        self.scan_progress.setTextVisible(True)
        self.progress_label = QLabel("Prêt")
        progress_layout.addWidget(self.scan_progress, 1)
        progress_layout.addWidget(self.progress_label)
        main_layout.addLayout(progress_layout)

        filters = QHBoxLayout()
        self.include_system_checkbox = QCheckBox("Afficher apps système")
        self.hide_safe_checkbox = QCheckBox("Masquer apps sûres")
        self.hidden_apps_checkbox = QCheckBox("Apps cachées")
        self.notification_audit_checkbox = QCheckBox("Audit notifications")
        self.sideload_checkbox = QCheckBox("Sideload")
        self.score_filter = QComboBox()
        self.score_filter.addItem("Score min: 0", 0)
        self.score_filter.addItem("Score min: 30", 30)
        self.score_filter.addItem("Score min: 60", 60)
        self.permission_filter = QComboBox()
        self.permission_filter.addItem("Toutes permissions", "")
        for permission in ("SMS", "CONTACTS", "CALL", "ACCESSIBILITY", "NOTIFICATION", "OVERLAY", "DEVICE_ADMIN", "VPN"):
            self.permission_filter.addItem(permission, permission)
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Rechercher nom, package, installateur...")
        filters.addWidget(self.include_system_checkbox)
        filters.addWidget(self.hide_safe_checkbox)
        filters.addWidget(self.hidden_apps_checkbox)
        filters.addWidget(self.notification_audit_checkbox)
        filters.addWidget(self.sideload_checkbox)
        filters.addWidget(self.score_filter)
        filters.addWidget(self.permission_filter)
        filters.addWidget(self.search_input, 1)
        main_layout.addLayout(filters)

        self.table = QTableWidget(0, len(self.COLUMNS))
        self.table.setHorizontalHeaderLabels(self.COLUMNS)
        self.table.setSortingEnabled(True)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.setIconSize(QSize(28, 28))
        self.table.verticalHeader().setVisible(False)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Interactive)
        header.setSectionResizeMode(9, QHeaderView.Stretch)
        self.table.setColumnWidth(0, 42)
        self.table.setColumnWidth(1, 70)
        self.table.setColumnWidth(2, 170)
        self.table.setColumnWidth(3, 150)
        self.table.setColumnWidth(4, 180)
        self.table.setColumnWidth(5, 280)
        self.table.setColumnWidth(6, 220)
        self.table.setColumnWidth(7, 120)
        self.table.setColumnWidth(8, 160)
        self.table.setColumnWidth(10, 220)

        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        self.details_text.setPlaceholderText("Sélectionnez une application pour afficher ses détails.")
        self.details_text.setMinimumWidth(330)

        details_box = QGroupBox("Détails sélection")
        details_layout = QVBoxLayout(details_box)
        details_layout.addWidget(self.details_text)

        content_splitter = QSplitter(Qt.Horizontal)
        content_splitter.addWidget(self.table)
        content_splitter.addWidget(details_box)
        content_splitter.setStretchFactor(0, 4)
        content_splitter.setStretchFactor(1, 1)
        content_splitter.setSizes([940, 360])
        main_layout.addWidget(content_splitter, 1)
        self.setCentralWidget(root)

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
        self.reload_button.clicked.connect(self.reload_reputation)
        self.search_input.textChanged.connect(self.apply_filters)
        self.hide_safe_checkbox.stateChanged.connect(self.apply_filters)
        self.hidden_apps_checkbox.stateChanged.connect(self.apply_filters)
        self.notification_audit_checkbox.stateChanged.connect(self.apply_filters)
        self.sideload_checkbox.stateChanged.connect(self.apply_filters)
        self.score_filter.currentIndexChanged.connect(self.apply_filters)
        self.permission_filter.currentIndexChanged.connect(self.apply_filters)
        self.table.customContextMenuRequested.connect(self.open_context_menu)
        self.table.itemSelectionChanged.connect(self.update_details_from_selection)
        self.table.cellDoubleClicked.connect(self.open_details_for_cell)

        self.setStyleSheet(
            """
            QMainWindow { background: #f5f7fa; }
            QLabel#Title { font-size: 26px; font-weight: 700; color: #172033; }
            QLabel#Subtitle { font-size: 14px; color: #5f6b7a; }
            QGroupBox { border: 1px solid #d8dee8; border-radius: 6px; margin-top: 10px; padding: 12px; background: white; }
            QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 4px; }
            QPushButton { padding: 8px 12px; border: 1px solid #b9c2cf; border-radius: 6px; background: white; }
            QPushButton:hover { background: #eef4ff; }
            QPushButton:disabled { color: #8492a6; background: #eef2f7; }
            QLineEdit { padding: 8px; border: 1px solid #b9c2cf; border-radius: 6px; background: white; }
            QTableWidget { background: white; border: 1px solid #d8dee8; gridline-color: #edf1f5; }
            QTextEdit { background: white; border: 1px solid #d8dee8; border-radius: 6px; padding: 8px; }
            QHeaderView::section { background: #e9eef5; padding: 7px; border: 0; border-right: 1px solid #d8dee8; font-weight: 600; }
            """
        )

    def _apply_ai_button_state(self) -> None:
        if self.ai_analyzer.enabled:
            self.ai_button.setEnabled(True)
            self.ai_button.setToolTip("Analyse les apps déjà suspectes avec l'API OpenAI.")
        else:
            self.ai_button.setEnabled(False)
            self.ai_button.setText("Analyser avec IA (clé .env absente)")
            self.ai_button.setToolTip("Ajoutez OPENAI_API_KEY dans .env pour activer cette option.")

    def set_busy(self, busy: bool, message: str = "") -> None:
        self.is_busy = busy
        for widget in (
            self.detect_button,
            self.adb_diagnostic_button,
            self.adb_repair_button,
            self.adb_daemon_button,
            self.scan_button,
            self.demo_button,
            self.open_settings_button,
            self.uninstall_button,
            self.report_button,
            self.csv_button,
            self.copy_diagnostic_button,
            self.export_diagnostic_button,
            self.history_button,
            self.reload_button,
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

    def detect_phone(self) -> None:
        self.set_busy(True, "Détection du téléphone...")
        worker = DetectWorker(self.selected_device_serial())
        worker.succeeded.connect(self.on_device_detected)
        worker.failed.connect(self.on_worker_failed)
        worker.finished.connect(lambda: self.set_busy(False))
        self.current_worker = worker
        worker.start()

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
        if self.device.state != "device" or not self.device.serial:
            QMessageBox.warning(self, "Téléphone requis", "Détectez d'abord un téléphone autorisé en USB.")
            return
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

    def on_scan_worker_finished(self) -> None:
        self.scan_worker = None
        self.cancel_scan_button.setEnabled(False)
        self.set_busy(False)

    def populate_table(self) -> None:
        self.table.setSortingEnabled(False)
        self.table.setRowCount(0)
        for row_data in self.rows:
            row = self.table.rowCount()
            self.table.insertRow(row)
            self._set_row_items(row, row_data)
        self.table.setSortingEnabled(True)
        self.table.sortItems(1, Qt.DescendingOrder)
        self.apply_filters()
        if self.table.rowCount() > 0:
            self.table.selectRow(0)
            self.update_details_from_selection()
        else:
            self.details_text.clear()

    def _set_row_items(self, row: int, row_data: dict[str, Any]) -> None:
        app: AppInfo = row_data["app"]
        risk = row_data["risk"]
        values = [
            "",
            str(risk.score),
            risk.category,
            risk.recommended_action,
            app.display_name(),
            app.package_name,
            app.installer or "inconnu",
            hidden_summary(app),
            notification_summary(app),
            "; ".join(risk.reasons),
            row_data.get("ai_text", ""),
        ]
        color = self._row_color(risk.score, risk.category)
        for col, value in enumerate(values):
            item = QTableWidgetItem(value)
            item.setData(Qt.UserRole, app.package_name)
            if col == 0:
                item.setFlags(Qt.ItemIsEnabled | Qt.ItemIsUserCheckable | Qt.ItemIsSelectable)
                item.setCheckState(Qt.Unchecked)
                item.setText("")
                if app.icon_path and Path(app.icon_path).exists():
                    item.setIcon(QIcon(app.icon_path))
            elif col == 1:
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
            package_item = self.table.item(row, 5)
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
            is_sideload = not row_data["app"].installer or row_data["app"].installer not in {
                "com.android.vending",
                "com.sec.android.app.samsungapps",
            }
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
                    "category",
                    "recommended_action",
                    "app_name",
                    "package",
                    "installer",
                    "system",
                    "launcher_visible",
                    "permissions",
                    "risk_reasons",
                    "metadata_error",
                ]
            )
            for row in self.rows:
                app: AppInfo = row["app"]
                risk = row["risk"]
                writer.writerow(
                    [
                        risk.score,
                        risk.category,
                        risk.recommended_action,
                        app.display_name(),
                        app.package_name,
                        app.installer or "inconnu",
                        "oui" if app.is_system_app else "non",
                        launcher_text(app),
                        "; ".join(app.sensitive_permissions),
                        "; ".join(risk.reasons),
                        app.dumpsys_error,
                    ]
                )
        QMessageBox.information(self, "CSV exporté", f"CSV créé :\n{path}")

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
            {"app": app, "risk": evaluate_app(app, self.db.reputation_for(app.package_name)), "ai": None, "ai_text": ""}
            for app in demo_apps
        ]
        self.rows.sort(key=lambda item: item["risk"].score, reverse=True)
        self.uninstalled = []
        self.on_device_detected({"device": self.device, "devices": [ADBDevice("DEMO-ANDROID", "device", "mode:demo")]})
        self.populate_table()
        self.scan_progress.setValue(100)
        self.progress_label.setText("Mode démo")
        self.status_label.setText("Mode démo chargé : données fictives.")

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
        package = self.table.item(item.row(), 5).text()
        row_data = self.row_by_package(package)
        if not row_data:
            return

        menu = QMenu(self)
        whitelist = QAction("Ajouter à la whitelist", self)
        blacklist = QAction("Ajouter à la blacklist", self)
        open_settings = QAction("Ouvrir paramètres app sur téléphone", self)
        copy_package = QAction("Copier package", self)
        details = QAction("Voir détails", self)
        menu.addAction(whitelist)
        menu.addAction(blacklist)
        menu.addSeparator()
        menu.addAction(open_settings)
        menu.addAction(copy_package)
        menu.addAction(details)
        whitelist.triggered.connect(lambda: self.add_reputation(row_data, whitelist=True))
        blacklist.triggered.connect(lambda: self.add_reputation(row_data, whitelist=False))
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

    def open_details_for_cell(self, row: int, _column: int) -> None:
        package_item = self.table.item(row, 5)
        if not package_item:
            return
        row_data = self.row_by_package(package_item.text())
        if row_data:
            self.table.selectRow(row)
            self.open_details(row_data)

    def open_details(self, row_data: dict[str, Any]) -> None:
        self.details_text.setPlainText(build_app_details_text(row_data))
        self.status_label.setText(f"Détails affichés : {row_data['app'].package_name}")

    def update_details_from_selection(self) -> None:
        current_items = self.table.selectedItems()
        if not current_items:
            return
        package_item = self.table.item(current_items[0].row(), 5)
        if not package_item:
            return
        row_data = self.row_by_package(package_item.text())
        if row_data:
            self.details_text.setPlainText(build_app_details_text(row_data))

    def row_by_package(self, package: str) -> dict[str, Any] | None:
        return next((row for row in self.rows if row["app"].package_name == package), None)

    def selected_rows(self) -> list[dict[str, Any]]:
        selected: list[dict[str, Any]] = []
        for row in range(self.table.rowCount()):
            item = self.table.item(row, 0)
            if item and item.checkState() == Qt.Checked:
                package = self.table.item(row, 5).text()
                row_data = self.row_by_package(package)
                if row_data:
                    selected.append(row_data)
        return selected

    def current_or_checked_row(self) -> dict[str, Any] | None:
        current_items = self.table.selectedItems()
        if current_items:
            package_item = self.table.item(current_items[0].row(), 5)
            if package_item:
                row_data = self.row_by_package(package_item.text())
                if row_data:
                    return row_data

        checked = self.selected_rows()
        if len(checked) == 1:
            return checked[0]
        return None

    def on_worker_failed(self, message: str) -> None:
        self.status_label.setText("Erreur")
        QMessageBox.critical(self, "Erreur", message)


def launcher_text(app: AppInfo) -> str:
    if app.has_launcher_entry is True:
        return "oui"
    if app.has_launcher_entry is False:
        return "non"
    return "non vérifié"


def is_hidden_or_low_visibility(app: AppInfo) -> bool:
    return app.has_launcher_entry is False or "Nom très générique" in app.hidden_audit


def permission_matches(app: AppInfo, query: str) -> bool:
    haystack = " ".join(app.sensitive_permissions + app.notification_audit + app.hidden_audit).upper()
    flags = {
        "ACCESSIBILITY": app.has_accessibility,
        "NOTIFICATION": app.has_notification_listener or app.requests_post_notifications,
        "OVERLAY": app.has_overlay,
        "DEVICE_ADMIN": app.has_device_admin,
        "VPN": app.has_vpn_service,
    }
    if query in flags:
        return flags[query] or query in haystack
    return query in haystack


def hidden_summary(app: AppInfo) -> str:
    if app.has_launcher_entry is False:
        return "Sans launcher"
    if "Nom très générique" in app.hidden_audit:
        return "Nom générique"
    if app.hidden_audit:
        return "À vérifier"
    return "-"


def notification_summary(app: AppInfo) -> str:
    if not app.notification_audit:
        return "-"
    return ", ".join(app.notification_audit[:2])


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
