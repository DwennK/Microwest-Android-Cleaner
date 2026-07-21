from __future__ import annotations

import shutil
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256
from pathlib import Path
from typing import Any

from risk_rules import ReputationLookup

PROJECT_DIR = Path(__file__).resolve().parent
DEFAULT_DB_PATH = PROJECT_DIR / "data" / "app_reputation.sqlite"
CURRENT_SCHEMA_VERSION = 3
VALIDATION_STATUSES = {"unreviewed", "keep", "review", "remove", "removed"}


@dataclass(frozen=True, slots=True)
class ScanAppSnapshot:
    package: str
    app_label: str
    score: int
    category: str
    action: str
    validation_status: str


@dataclass(frozen=True, slots=True)
class RiskChange:
    package: str
    app_label: str
    previous_score: int
    current_score: int
    previous_action: str
    current_action: str


@dataclass(frozen=True, slots=True)
class ScanComparison:
    current_scan_id: int
    previous_scan_id: int | None
    new_apps: tuple[ScanAppSnapshot, ...] = ()
    removed_apps: tuple[ScanAppSnapshot, ...] = ()
    unchanged_count: int = 0
    risk_changes: tuple[RiskChange, ...] = ()

DEFAULT_WHITELIST = [
    ("com.whatsapp", "WhatsApp", "Application courante connue"),
    ("com.facebook.katana", "Facebook", "Application courante connue"),
    ("com.instagram.android", "Instagram", "Application courante connue"),
    ("com.google.android.youtube", "YouTube", "Application Google"),
    ("com.google.android.apps.youtube.music", "YouTube Music", "Application Google"),
    ("com.google.android.videos", "Google TV", "Application Google"),
    ("com.google.android.keep", "Google Keep", "Application Google"),
    ("com.google.android.safetycore", "Android SafetyCore", "Application Google"),
    ("com.google.android.gm", "Gmail", "Application Google"),
    ("com.google.android.apps.maps", "Google Maps", "Application Google"),
    ("com.google.android.apps.photos", "Google Photos", "Application Google"),
    ("com.google.android.calendar", "Google Calendar", "Application Google"),
    ("com.google.android.contacts", "Google Contacts", "Application Google"),
    ("com.google.android.dialer", "Google Phone", "Application Google"),
    ("com.google.android.apps.messaging", "Google Messages", "Application Google"),
    ("com.sec.android.app.sbrowser", "Samsung Internet", "Application Samsung"),
    ("com.sec.android.app.samsungapps", "Galaxy Store", "Application Samsung"),
    ("com.sec.android.app.voicenote", "Samsung Voice Recorder", "Application Samsung"),
    ("com.sec.android.app.music", "Samsung Music", "Application Samsung"),
    ("com.sec.android.app.popupcalculator", "Samsung Calculator", "Application Samsung"),
    ("com.sec.android.easyMover", "Samsung Smart Switch", "Application Samsung"),
    ("com.samsung.android.app.notes", "Samsung Notes", "Application Samsung"),
    ("com.samsung.android.app.watchmanager", "Galaxy Wearable", "Application Samsung"),
    ("com.samsung.android.kidsinstaller", "Samsung Kids Installer", "Application Samsung"),
    ("com.sec.android.app.kidshome", "Samsung Kids", "Application Samsung"),
    ("com.samsung.android.service.health", "Samsung Health Service", "Application Samsung"),
    ("com.samsung.android.oneconnect", "SmartThings", "Application Samsung"),
    ("com.samsung.android.voc", "Samsung Members", "Application Samsung"),
    ("com.microsoft.office.outlook", "Outlook", "Application Microsoft"),
    ("com.spotify.music", "Spotify", "Application courante connue"),
    ("com.netflix.mediaclient", "Netflix", "Application courante connue"),
]


class ReputationDatabase:
    def __init__(self, db_path: Path | None = None) -> None:
        self.db_path = db_path or DEFAULT_DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.initialize()

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def initialize(self) -> None:
        with self.connect() as con:
            current_version = int(con.execute("PRAGMA user_version").fetchone()[0])
            if current_version < CURRENT_SCHEMA_VERSION:
                self._backup_existing_database(con, current_version)
            con.execute(
                """
                CREATE TABLE IF NOT EXISTS whitelist(
                    package TEXT PRIMARY KEY,
                    label TEXT,
                    reason TEXT
                )
                """
            )
            con.execute(
                """
                CREATE TABLE IF NOT EXISTS blacklist(
                    package TEXT PRIMARY KEY,
                    label TEXT,
                    reason TEXT,
                    severity INTEGER
                )
                """
            )
            con.execute(
                """
                CREATE TABLE IF NOT EXISTS scan_history(
                    id INTEGER PRIMARY KEY,
                    date TEXT,
                    device_model TEXT,
                    android_version TEXT,
                    scanned_count INTEGER,
                    suspicious_count INTEGER,
                    device_key TEXT NOT NULL DEFAULT ''
                )
                """
            )
            con.execute(
                """
                CREATE TABLE IF NOT EXISTS uninstall_history(
                    id INTEGER PRIMARY KEY,
                    date TEXT,
                    package TEXT,
                    app_label TEXT,
                    result TEXT
                )
                """
            )
            con.execute(
                """
                CREATE TABLE IF NOT EXISTS app_notes(
                    package TEXT PRIMARY KEY,
                    note TEXT,
                    updated_at TEXT
                )
                """
            )
            self._ensure_column(con, "scan_history", "device_key", "TEXT NOT NULL DEFAULT ''")
            con.execute(
                """
                CREATE TABLE IF NOT EXISTS scan_apps(
                    scan_id INTEGER NOT NULL,
                    package TEXT NOT NULL,
                    app_label TEXT,
                    score INTEGER NOT NULL,
                    category TEXT,
                    action TEXT,
                    validation_status TEXT NOT NULL DEFAULT 'unreviewed',
                    PRIMARY KEY(scan_id, package),
                    FOREIGN KEY(scan_id) REFERENCES scan_history(id) ON DELETE CASCADE
                )
                """
            )
            self._migrate_app_validations(con)
            con.execute("CREATE INDEX IF NOT EXISTS idx_scan_history_device ON scan_history(device_key, id DESC)")
            con.executemany(
                "INSERT OR IGNORE INTO whitelist(package, label, reason) VALUES(?, ?, ?)",
                DEFAULT_WHITELIST,
            )
            con.execute(f"PRAGMA user_version = {CURRENT_SCHEMA_VERSION}")

    def _migrate_app_validations(self, con: sqlite3.Connection) -> None:
        columns = {str(row[1]) for row in con.execute("PRAGMA table_info(app_validations)")}
        if columns and "scan_id" not in columns:
            con.execute("ALTER TABLE app_validations RENAME TO app_validations_v2")

        con.execute(
            """
            CREATE TABLE IF NOT EXISTS app_validations(
                scan_id INTEGER NOT NULL,
                package TEXT NOT NULL,
                status TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY(scan_id, package),
                FOREIGN KEY(scan_id, package) REFERENCES scan_apps(scan_id, package) ON DELETE CASCADE
            )
            """
        )

        legacy_exists = con.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'app_validations_v2'"
        ).fetchone()
        if not legacy_exists:
            return

        con.execute(
            """
            INSERT OR REPLACE INTO app_validations(scan_id, package, status, updated_at)
            SELECT
                scan_apps.scan_id,
                scan_apps.package,
                scan_apps.validation_status,
                COALESCE(app_validations_v2.updated_at, scan_history.date, '')
            FROM scan_apps
            JOIN scan_history ON scan_history.id = scan_apps.scan_id
            LEFT JOIN app_validations_v2 ON app_validations_v2.package = scan_apps.package
            WHERE scan_apps.validation_status IN ('keep', 'review', 'remove', 'removed')
            """
        )
        con.execute("DROP TABLE app_validations_v2")

    def _ensure_column(self, con: sqlite3.Connection, table: str, column: str, definition: str) -> None:
        columns = {str(row[1]) for row in con.execute(f"PRAGMA table_info({table})")}
        if column not in columns:
            con.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

    def _backup_existing_database(self, con: sqlite3.Connection, current_version: int) -> None:
        if current_version >= CURRENT_SCHEMA_VERSION or not self.db_path.exists():
            return
        table_count = con.execute("SELECT COUNT(*) FROM sqlite_master WHERE type = 'table'").fetchone()[0]
        if not table_count:
            return
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = self.db_path.with_name(f"{self.db_path.stem}.schema{current_version}_backup_{timestamp}.sqlite")
        shutil.copy2(self.db_path, backup_path)

    def is_whitelisted(self, package: str) -> bool:
        with self.connect() as con:
            row = con.execute("SELECT 1 FROM whitelist WHERE package = ?", (package,)).fetchone()
            return row is not None

    def is_blacklisted(self, package: str) -> bool:
        with self.connect() as con:
            row = con.execute("SELECT 1 FROM blacklist WHERE package = ?", (package,)).fetchone()
            return row is not None

    def reputation_for(self, package: str) -> ReputationLookup:
        with self.connect() as con:
            whitelist = con.execute("SELECT reason FROM whitelist WHERE package = ?", (package,)).fetchone()
            blacklist = con.execute(
                "SELECT reason, severity FROM blacklist WHERE package = ?",
                (package,),
            ).fetchone()
        return ReputationLookup(
            whitelisted=whitelist is not None,
            blacklisted=blacklist is not None,
            blacklist_severity=int(blacklist["severity"]) if blacklist else 50,
            reason=str(blacklist["reason"]) if blacklist else (str(whitelist["reason"]) if whitelist else ""),
        )

    def add_to_whitelist(self, package: str, label: str = "", reason: str = "") -> None:
        with self.connect() as con:
            con.execute(
                "INSERT OR REPLACE INTO whitelist(package, label, reason) VALUES(?, ?, ?)",
                (package, label, reason),
            )

    def add_to_blacklist(self, package: str, label: str = "", reason: str = "", severity: int = 70) -> None:
        severity = max(0, min(100, int(severity)))
        with self.connect() as con:
            con.execute(
                "INSERT OR REPLACE INTO blacklist(package, label, reason, severity) VALUES(?, ?, ?, ?)",
                (package, label, reason, severity),
            )

    def record_scan(
        self,
        date: str,
        device_model: str,
        android_version: str,
        scanned_count: int,
        suspicious_count: int,
        *,
        device_serial: str = "",
    ) -> int:
        with self.connect() as con:
            cursor = con.execute(
                """
                INSERT INTO scan_history(
                    date, device_model, android_version, scanned_count, suspicious_count, device_key
                ) VALUES(?, ?, ?, ?, ?, ?)
                """,
                (
                    date,
                    device_model,
                    android_version,
                    scanned_count,
                    suspicious_count,
                    self._device_key(device_serial, device_model),
                ),
            )
            return int(cursor.lastrowid)

    def record_scan_apps(self, scan_id: int, rows: list[dict[str, Any]]) -> None:
        values = []
        for row in rows:
            app = row["app"]
            risk = row["risk"]
            values.append(
                (
                    scan_id,
                    app.package_name,
                    app.display_name(),
                    int(risk.score),
                    str(risk.category),
                    str(risk.recommended_action),
                    normalize_validation(row.get("validation", "unreviewed")),
                )
            )
        with self.connect() as con:
            con.executemany(
                """
                INSERT OR REPLACE INTO scan_apps(
                    scan_id, package, app_label, score, category, action, validation_status
                ) VALUES(?, ?, ?, ?, ?, ?, ?)
                """,
                values,
            )

    def comparison_for_scan(self, scan_id: int) -> ScanComparison:
        with self.connect() as con:
            current_history = con.execute(
                "SELECT id, device_key FROM scan_history WHERE id = ?",
                (scan_id,),
            ).fetchone()
            if not current_history:
                return ScanComparison(scan_id, None)
            previous = con.execute(
                """
                SELECT id FROM scan_history
                WHERE device_key = ? AND id < ?
                ORDER BY id DESC LIMIT 1
                """,
                (current_history["device_key"], scan_id),
            ).fetchone()
            current_apps = self._snapshots_for_scan(con, scan_id)
            if not previous:
                return ScanComparison(scan_id, None, new_apps=tuple(current_apps.values()))
            previous_id = int(previous["id"])
            previous_apps = self._snapshots_for_scan(con, previous_id)

        current_packages = set(current_apps)
        previous_packages = set(previous_apps)
        new_apps = tuple(current_apps[package] for package in sorted(current_packages - previous_packages))
        removed_apps = tuple(previous_apps[package] for package in sorted(previous_packages - current_packages))
        shared = sorted(current_packages & previous_packages)
        changes = []
        for package in shared:
            old = previous_apps[package]
            new = current_apps[package]
            if old.score != new.score or old.action != new.action:
                changes.append(
                    RiskChange(
                        package=package,
                        app_label=new.app_label,
                        previous_score=old.score,
                        current_score=new.score,
                        previous_action=old.action,
                        current_action=new.action,
                    )
                )
        return ScanComparison(
            current_scan_id=scan_id,
            previous_scan_id=previous_id,
            new_apps=new_apps,
            removed_apps=removed_apps,
            unchanged_count=len(shared) - len(changes),
            risk_changes=tuple(changes),
        )

    def _snapshots_for_scan(self, con: sqlite3.Connection, scan_id: int) -> dict[str, ScanAppSnapshot]:
        rows = con.execute(
            """
            SELECT package, app_label, score, category, action, validation_status
            FROM scan_apps WHERE scan_id = ?
            """,
            (scan_id,),
        )
        return {
            str(row["package"]): ScanAppSnapshot(
                package=str(row["package"]),
                app_label=str(row["app_label"] or row["package"]),
                score=int(row["score"]),
                category=str(row["category"] or ""),
                action=str(row["action"] or ""),
                validation_status=normalize_validation(row["validation_status"]),
            )
            for row in rows
        }

    def _device_key(self, serial: str, model: str) -> str:
        identity = serial.strip() or f"model:{model.strip().lower()}"
        return sha256(identity.encode("utf-8")).hexdigest()[:24]

    def recent_scans(self, limit: int = 20) -> list[sqlite3.Row]:
        with self.connect() as con:
            return list(
                con.execute(
                    """
                    SELECT date, device_model, android_version, scanned_count, suspicious_count
                    FROM scan_history
                    ORDER BY id DESC
                    LIMIT ?
                    """,
                    (limit,),
                )
            )

    def record_uninstall(self, date: str, package: str, app_label: str, result: str) -> None:
        with self.connect() as con:
            con.execute(
                "INSERT INTO uninstall_history(date, package, app_label, result) VALUES(?, ?, ?, ?)",
                (date, package, app_label, result),
            )

    def note_for(self, package: str) -> str:
        with self.connect() as con:
            row = con.execute("SELECT note FROM app_notes WHERE package = ?", (package,)).fetchone()
            return str(row["note"]) if row and row["note"] else ""

    def set_note(self, package: str, note: str, updated_at: str) -> None:
        with self.connect() as con:
            if note.strip():
                con.execute(
                    "INSERT OR REPLACE INTO app_notes(package, note, updated_at) VALUES(?, ?, ?)",
                    (package, note.strip(), updated_at),
                )
            else:
                con.execute("DELETE FROM app_notes WHERE package = ?", (package,))

    def validation_for(self, scan_id: int, package: str) -> str:
        with self.connect() as con:
            row = con.execute(
                "SELECT status FROM app_validations WHERE scan_id = ? AND package = ?",
                (scan_id, package),
            ).fetchone()
        return normalize_validation(row["status"] if row else "unreviewed")

    def set_validation(self, scan_id: int, package: str, status: str, updated_at: str) -> None:
        normalized = normalize_validation(status)
        with self.connect() as con:
            if normalized == "unreviewed":
                con.execute(
                    "DELETE FROM app_validations WHERE scan_id = ? AND package = ?",
                    (scan_id, package),
                )
            else:
                con.execute(
                    """
                    INSERT OR REPLACE INTO app_validations(scan_id, package, status, updated_at)
                    VALUES(?, ?, ?, ?)
                    """,
                    (scan_id, package, normalized, updated_at),
                )
            con.execute(
                """
                UPDATE scan_apps SET validation_status = ?
                WHERE scan_id = ? AND package = ?
                """,
                (normalized, scan_id, package),
            )


def normalize_validation(value: Any) -> str:
    normalized = str(value or "").strip().lower()
    return normalized if normalized in VALIDATION_STATUSES else "unreviewed"
