from __future__ import annotations

import unittest

from adb_client import DeviceInfo
from risk_rules import RiskResult
from scanner import AppInfo
from workflow_helpers import build_action_plan, priority_text, scan_summary


def row(package: str, score: int, action: str, *, installer: str = "", hidden: bool = False) -> dict:
    app = AppInfo(
        package_name=package,
        app_label=package.rsplit(".", 1)[-1],
        installer=installer,
        has_launcher_entry=not hidden,
    )
    if hidden:
        app.hidden_audit = ["Aucune icône launcher visible"]
    return {
        "app": app,
        "risk": RiskResult(score=score, category="test", recommended_action=action, reasons=["raison test"]),
        "note": "",
        "ai": None,
        "ai_text": "",
    }


class WorkflowHelperTests(unittest.TestCase):
    def test_priority_text(self) -> None:
        self.assertEqual(priority_text(row("com.test.bad", 85, "suggest_uninstall")), "Urgent")
        self.assertEqual(priority_text(row("com.test.review", 40, "review")), "À vérifier")
        self.assertEqual(priority_text(row("com.test.safe", 5, "keep", installer="com.android.vending")), "OK")

    def test_scan_summary_counts_operational_signals(self) -> None:
        rows = [
            row("com.test.bad", 70, "suggest_uninstall", hidden=True),
            row("com.test.review", 35, "review", installer="com.android.vending"),
            row("com.test.safe", 5, "keep", installer="com.android.vending"),
        ]

        summary = scan_summary(rows)

        self.assertEqual(summary["total"], 3)
        self.assertEqual(summary["high"], 1)
        self.assertEqual(summary["review"], 1)
        self.assertEqual(summary["hidden"], 1)
        self.assertEqual(summary["sideload"], 1)

    def test_action_plan_includes_safe_uninstall_command_template(self) -> None:
        rows = [row("com.test.bad", 70, "suggest_uninstall")]
        device = DeviceInfo(serial="SERIAL", state="device", manufacturer="Samsung", model="S", android_version="14")

        plan = build_action_plan(device, rows)

        self.assertIn("com.test.bad", plan)
        self.assertIn("adb shell pm uninstall --user 0 com.test.bad", plan)
        self.assertIn("validation humaine", plan)


if __name__ == "__main__":
    unittest.main()
