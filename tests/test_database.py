from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from database import CURRENT_SCHEMA_VERSION, ReputationDatabase
from risk_rules import RiskResult
from scanner import AppInfo


def scan_row(package: str, score: int, action: str = "keep", validation: str = "unreviewed") -> dict:
    return {
        "app": AppInfo(package_name=package, app_label=package.rsplit(".", 1)[-1]),
        "risk": RiskResult(score=score, category="test", recommended_action=action),
        "validation": validation,
    }


class ReputationDatabaseTests(unittest.TestCase):
    def test_initialize_sets_schema_version_and_default_whitelist(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            db = ReputationDatabase(Path(temp_dir) / "reputation.sqlite")

            with db.connect() as con:
                version = con.execute("PRAGMA user_version").fetchone()[0]

            self.assertEqual(version, CURRENT_SCHEMA_VERSION)
            self.assertTrue(db.is_whitelisted("com.whatsapp"))

    def test_validation_is_persisted_and_can_be_cleared(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            db = ReputationDatabase(Path(temp_dir) / "reputation.sqlite")
            scan_id = db.record_scan("2026-07-14T11:00:00", "Phone", "14", 1, 0, device_serial="SERIAL")
            db.record_scan_apps(scan_id, [scan_row("com.example.app", 10)])

            db.set_validation(scan_id, "com.example.app", "keep", "2026-07-14T12:00:00")
            self.assertEqual(db.validation_for(scan_id, "com.example.app"), "keep")
            db.set_validation(scan_id, "com.example.app", "unreviewed", "2026-07-14T12:01:00")
            self.assertEqual(db.validation_for(scan_id, "com.example.app"), "unreviewed")

    def test_validation_does_not_leak_between_scans_or_devices(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            db = ReputationDatabase(Path(temp_dir) / "reputation.sqlite")
            first_scan = db.record_scan("2026-07-14T10:00:00", "Phone A", "14", 1, 1, device_serial="A")
            second_scan = db.record_scan("2026-07-14T11:00:00", "Phone A", "14", 1, 1, device_serial="A")
            other_device_scan = db.record_scan(
                "2026-07-14T12:00:00",
                "Phone B",
                "14",
                1,
                1,
                device_serial="B",
            )
            for scan_id in (first_scan, second_scan, other_device_scan):
                db.record_scan_apps(scan_id, [scan_row("com.example.app", 70, "suggest_uninstall")])

            db.set_validation(first_scan, "com.example.app", "remove", "2026-07-14T10:30:00")

            self.assertEqual(db.validation_for(first_scan, "com.example.app"), "remove")
            self.assertEqual(db.validation_for(second_scan, "com.example.app"), "unreviewed")
            self.assertEqual(db.validation_for(other_device_scan, "com.example.app"), "unreviewed")
            with db.connect() as con:
                snapshot_statuses = {
                    row["scan_id"]: row["validation_status"]
                    for row in con.execute(
                        "SELECT scan_id, validation_status FROM scan_apps WHERE package = ? ORDER BY scan_id",
                        ("com.example.app",),
                    )
                }
            self.assertEqual(
                snapshot_statuses,
                {first_scan: "remove", second_scan: "unreviewed", other_device_scan: "unreviewed"},
            )

    def test_migrates_v2_global_validations_to_historical_scan_snapshots(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "reputation.sqlite"
            with sqlite3.connect(db_path) as con:
                con.executescript(
                    """
                    PRAGMA user_version = 2;
                    CREATE TABLE scan_history(
                        id INTEGER PRIMARY KEY,
                        date TEXT,
                        device_model TEXT,
                        android_version TEXT,
                        scanned_count INTEGER,
                        suspicious_count INTEGER,
                        device_key TEXT NOT NULL DEFAULT ''
                    );
                    CREATE TABLE scan_apps(
                        scan_id INTEGER NOT NULL,
                        package TEXT NOT NULL,
                        app_label TEXT,
                        score INTEGER NOT NULL,
                        category TEXT,
                        action TEXT,
                        validation_status TEXT NOT NULL DEFAULT 'unreviewed',
                        PRIMARY KEY(scan_id, package)
                    );
                    CREATE TABLE app_validations(
                        package TEXT PRIMARY KEY,
                        status TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    );
                    INSERT INTO scan_history VALUES(1, '2026-07-14T10:00:00', 'Phone A', '14', 1, 1, 'device-a');
                    INSERT INTO scan_history VALUES(2, '2026-07-14T11:00:00', 'Phone B', '14', 1, 1, 'device-b');
                    INSERT INTO scan_apps VALUES(
                        1, 'com.example.app', 'Example', 70, 'test', 'suggest_uninstall', 'remove'
                    );
                    INSERT INTO scan_apps VALUES(
                        2, 'com.example.app', 'Example', 70, 'test', 'suggest_uninstall', 'unreviewed'
                    );
                    INSERT INTO app_validations VALUES('com.example.app', 'remove', '2026-07-14T10:30:00');
                    """
                )

            db = ReputationDatabase(db_path)

            self.assertEqual(db.validation_for(1, "com.example.app"), "remove")
            self.assertEqual(db.validation_for(2, "com.example.app"), "unreviewed")
            with db.connect() as con:
                columns = {row[1] for row in con.execute("PRAGMA table_info(app_validations)")}
                legacy_table = con.execute(
                    "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'app_validations_v2'"
                ).fetchone()
            self.assertIn("scan_id", columns)
            self.assertIsNone(legacy_table)

    def test_scan_comparison_tracks_new_removed_and_risk_changes(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            db = ReputationDatabase(Path(temp_dir) / "reputation.sqlite")
            first_id = db.record_scan("2026-07-14T10:00:00", "Phone", "14", 2, 1, device_serial="SERIAL")
            db.record_scan_apps(
                first_id,
                [scan_row("com.example.removed", 70, "suggest_uninstall"), scan_row("com.example.same", 10)],
            )
            db.set_validation(first_id, "com.example.removed", "remove", "2026-07-14T10:30:00")
            second_id = db.record_scan("2026-07-14T11:00:00", "Phone", "14", 2, 1, device_serial="SERIAL")
            db.record_scan_apps(second_id, [scan_row("com.example.same", 40, "review"), scan_row("com.example.new", 5)])

            comparison = db.comparison_for_scan(second_id)

            self.assertEqual([app.package for app in comparison.new_apps], ["com.example.new"])
            self.assertEqual([app.package for app in comparison.removed_apps], ["com.example.removed"])
            self.assertEqual([change.package for change in comparison.risk_changes], ["com.example.same"])
            self.assertEqual(comparison.removed_apps[0].validation_status, "remove")


if __name__ == "__main__":
    unittest.main()
