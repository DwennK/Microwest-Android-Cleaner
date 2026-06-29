from __future__ import annotations

import unittest

from adb_client import DeviceInfo
from risk_rules import ReputationLookup
from scan_workflow import run_scan


class FakeADB:
    def list_packages(self, serial: str, include_system: bool = False) -> dict[str, str]:
        return {"com.fast.cleaner": ""}

    def list_launcher_packages(self, serial: str) -> set[str]:
        return set()

    def dumpsys_package(self, serial: str, package: str) -> str:
        return """
        Package [com.fast.cleaner]
          versionName=1.0
          targetSdk=23
          firstInstallTime=2026-06-01T10:00:00Z
          android.permission.SYSTEM_ALERT_WINDOW
          android.permission.POST_NOTIFICATIONS
        """


class FakeDB:
    def __init__(self) -> None:
        self.recorded = False

    def reputation_for(self, package: str) -> ReputationLookup:
        return ReputationLookup()

    def note_for(self, package: str) -> str:
        return ""

    def record_scan(
        self,
        date: str,
        device_model: str,
        android_version: str,
        scanned_count: int,
        suspicious_count: int,
    ) -> None:
        self.recorded = True


class ScanWorkflowTests(unittest.TestCase):
    def test_run_scan_builds_rows_and_records_history(self) -> None:
        db = FakeDB()
        progress_events = []

        result = run_scan(
            "SERIAL",
            False,
            DeviceInfo(model="Demo", android_version="14"),
            adb=FakeADB(),
            db=db,
            progress=lambda current, total, package: progress_events.append((current, total, package)),
        )

        self.assertFalse(result.cancelled)
        self.assertEqual(result.total, 1)
        self.assertEqual(result.rows[0]["app"].package_name, "com.fast.cleaner")
        self.assertTrue(db.recorded)
        self.assertEqual(progress_events, [(1, 1, "com.fast.cleaner")])


if __name__ == "__main__":
    unittest.main()
