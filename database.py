from __future__ import annotations

import shutil
import sqlite3
from datetime import datetime
from pathlib import Path

from risk_rules import ReputationLookup

PROJECT_DIR = Path(__file__).resolve().parent
DEFAULT_DB_PATH = PROJECT_DIR / "data" / "app_reputation.sqlite"
CURRENT_SCHEMA_VERSION = 1

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
                    suspicious_count INTEGER
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
            con.executemany(
                "INSERT OR IGNORE INTO whitelist(package, label, reason) VALUES(?, ?, ?)",
                DEFAULT_WHITELIST,
            )
            con.execute(f"PRAGMA user_version = {CURRENT_SCHEMA_VERSION}")

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

    def record_scan(self, date: str, device_model: str, android_version: str, scanned_count: int, suspicious_count: int) -> None:
        with self.connect() as con:
            con.execute(
                """
                INSERT INTO scan_history(date, device_model, android_version, scanned_count, suspicious_count)
                VALUES(?, ?, ?, ?, ?)
                """,
                (date, device_model, android_version, scanned_count, suspicious_count),
            )

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
