from __future__ import annotations

import unittest

from scanner import AppInfo, AppScanner


class FakeADB:
    def appop_mode(self, serial: str, package: str, operation: str) -> str:
        return "allow" if operation == "SYSTEM_ALERT_WINDOW" else "deny"


class ScannerPermissionTests(unittest.TestCase):
    def test_requested_granted_and_active_are_distinct(self) -> None:
        scanner = AppScanner(FakeADB())
        app = AppInfo(package_name="com.example.overlay")
        dumpsys = """
          requested permissions:
            android.permission.SYSTEM_ALERT_WINDOW
            android.permission.READ_CONTACTS
          runtime permissions:
            android.permission.READ_CONTACTS: granted=true, flags=[ USER_SENSITIVE_WHEN_GRANTED ]
        """

        scanner._enrich_from_dumpsys(app, dumpsys)
        scanner._enrich_from_appops("SERIAL", app)

        self.assertIn("android.permission.SYSTEM_ALERT_WINDOW", app.requested_permissions)
        self.assertIn("android.permission.READ_CONTACTS", app.granted_permissions)
        self.assertNotIn("android.permission.SYSTEM_ALERT_WINDOW", app.granted_permissions)
        self.assertIn("overlay", app.active_capabilities)


if __name__ == "__main__":
    unittest.main()
