from __future__ import annotations

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

            db.set_validation("com.example.app", "keep", "2026-07-14T12:00:00")
            self.assertEqual(db.validation_for("com.example.app"), "keep")
            db.set_validation("com.example.app", "unreviewed", "2026-07-14T12:01:00")
            self.assertEqual(db.validation_for("com.example.app"), "unreviewed")

    def test_scan_comparison_tracks_new_removed_and_risk_changes(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            db = ReputationDatabase(Path(temp_dir) / "reputation.sqlite")
            first_id = db.record_scan("2026-07-14T10:00:00", "Phone", "14", 2, 1, device_serial="SERIAL")
            db.record_scan_apps(
                first_id,
                [scan_row("com.example.removed", 70, "suggest_uninstall"), scan_row("com.example.same", 10)],
            )
            db.set_validation("com.example.removed", "remove", "2026-07-14T10:30:00")
            second_id = db.record_scan("2026-07-14T11:00:00", "Phone", "14", 2, 1, device_serial="SERIAL")
            db.record_scan_apps(second_id, [scan_row("com.example.same", 40, "review"), scan_row("com.example.new", 5)])

            comparison = db.comparison_for_scan(second_id)

            self.assertEqual([app.package for app in comparison.new_apps], ["com.example.new"])
            self.assertEqual([app.package for app in comparison.removed_apps], ["com.example.removed"])
            self.assertEqual([change.package for change in comparison.risk_changes], ["com.example.same"])
            self.assertEqual(comparison.removed_apps[0].validation_status, "remove")


if __name__ == "__main__":
    unittest.main()
