from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from adb_client import (
    ADBClient,
    ADBDevice,
    ADBError,
    ADBNotFoundError,
    parse_appop_mode,
    parse_component_packages,
    parse_default_home,
    parse_device_admin_packages,
    parse_devices_l,
    parse_launcher_packages,
    select_device,
)


class ADBClientDiscoveryTests(unittest.TestCase):
    def test_find_adb_uses_platform_fallback_when_gui_path_is_minimal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project_dir = Path(directory)
            homebrew_adb = project_dir / "homebrew" / "bin" / "adb"
            homebrew_adb.parent.mkdir(parents=True)
            homebrew_adb.write_text("#!/bin/sh\n", encoding="utf-8")
            homebrew_adb.chmod(0o755)

            with (
                patch.dict("os.environ", {}, clear=True),
                patch("adb_client.sys.platform", "darwin"),
                patch("adb_client.shutil.which", return_value=None),
                patch("adb_client.platform_adb_candidates", return_value=(homebrew_adb,)),
            ):
                client = ADBClient(project_dir=project_dir)

            self.assertEqual(client.adb_path, str(homebrew_adb.resolve()))

    def test_bundled_adb_keeps_priority_over_environment_and_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundled = root / "adb" / "adb"
            bundled.parent.mkdir()
            bundled.touch()
            bundled.chmod(0o755)
            alternative = root / "alternative"
            alternative.touch()
            alternative.chmod(0o755)
            with (
                patch.dict("os.environ", {"ADB_PATH": str(alternative)}, clear=True),
                patch("adb_client.sys.platform", "darwin"),
                patch("adb_client.shutil.which", return_value=str(alternative)),
                patch("adb_client.platform_adb_candidates", return_value=()),
            ):
                self.assertEqual(ADBClient(root).adb_path, str(bundled.resolve()))

    def test_environment_locations_work_without_path_on_unix_and_windows(self) -> None:
        for platform in ("darwin", "win32"):
            for variable in ("ADB_PATH", "ANDROID_HOME", "ANDROID_SDK_ROOT"):
                with self.subTest(platform=platform, variable=variable), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    sdk = root / "SDK with spaces"
                    executable = sdk / "platform-tools" / ("adb.exe" if platform == "win32" else "adb")
                    executable.parent.mkdir(parents=True)
                    executable.touch()
                    executable.chmod(0o644 if platform == "win32" else 0o755)
                    value = executable if variable == "ADB_PATH" else sdk
                    with (
                        patch.dict("os.environ", {variable: str(value)}, clear=True),
                        patch("adb_client.sys.platform", platform),
                        patch("adb_client.shutil.which", return_value=None),
                        patch("adb_client.platform_adb_candidates", return_value=()),
                    ):
                        self.assertEqual(ADBClient(root).adb_path, str(executable.resolve()))

    def test_unusable_local_file_falls_back_and_missing_adb_reports_error(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundled = root / "adb" / "adb"
            bundled.parent.mkdir()
            bundled.touch()
            bundled.chmod(0o644)
            fallback = root / "valid-adb"
            fallback.touch()
            fallback.chmod(0o755)
            with (
                patch.dict("os.environ", {"ADB_PATH": str(root / "missing")}, clear=True),
                patch("adb_client.sys.platform", "darwin"),
                patch("adb_client.shutil.which", return_value=str(fallback)),
                patch("adb_client.platform_adb_candidates", return_value=()),
            ):
                self.assertEqual(ADBClient(root).adb_path, str(fallback.resolve()))
                fallback.unlink()
                with self.assertRaises(ADBNotFoundError):
                    ADBClient(root)


class ADBClientParserTests(unittest.TestCase):
    def test_default_home_distinguishes_real_home_resolver_and_missing_output(self) -> None:
        self.assertEqual(parse_default_home("priority=0\ncom.sec.android.app.launcher/.Launcher\n"), "com.sec.android.app.launcher")
        for output in ("android/com.android.internal.app.ResolverActivity", "No activity found", "Error: permission denied", ""):
            self.assertIsNone(parse_default_home(output))

    def test_home_reads_are_for_current_user_and_failures_remain_unknown(self) -> None:
        client = object.__new__(ADBClient)
        with patch.object(client, "shell", side_effect=["example.pdf/.Home", "example.pdf/.Home"]) as shell:
            self.assertEqual(client.home_state("test"), ({"example.pdf"}, "example.pdf"))
            for call in shell.call_args_list:
                self.assertIn("current", call.args[1])
                self.assertIn("android.intent.category.HOME", call.args[1])
        with patch.object(client, "shell", side_effect=ADBError("unavailable")):
            self.assertEqual(client.home_state("test"), (None, None))

    def test_parse_devices_l_with_details(self) -> None:
        output = """List of devices attached
R3CTB058TSV        device usb:336592896X product:r9sxxx model:SM_G960F device:starlte transport_id:1
emulator-5554      offline transport_id:2
ABC123            unauthorized usb:123
"""

        devices = parse_devices_l(output)

        self.assertEqual(
            devices,
            [
                ADBDevice(
                    serial="R3CTB058TSV",
                    state="device",
                    details="usb:336592896X product:r9sxxx model:SM_G960F device:starlte transport_id:1",
                ),
                ADBDevice(serial="emulator-5554", state="offline", details="transport_id:2"),
                ADBDevice(serial="ABC123", state="unauthorized", details="usb:123"),
            ],
        )

    def test_select_device_prefers_authorized_device(self) -> None:
        devices = [
            ADBDevice(serial="offline-one", state="offline"),
            ADBDevice(serial="ready-one", state="device"),
        ]

        self.assertEqual(select_device(devices), devices[1])

    def test_select_device_uses_requested_serial(self) -> None:
        devices = [
            ADBDevice(serial="first", state="device"),
            ADBDevice(serial="second", state="device"),
        ]

        self.assertEqual(select_device(devices, "second"), devices[1])
        self.assertIsNone(select_device(devices, "missing"))

    def test_parse_launcher_packages_ignores_intent_names(self) -> None:
        output = """com.example.cleaner/.MainActivity
packageName=com.vendor.weather
android.intent.action.MAIN
"""

        self.assertEqual(parse_launcher_packages(output), {"com.example.cleaner", "com.vendor.weather"})

    def test_parse_active_capability_sources(self) -> None:
        self.assertEqual(
            parse_component_packages("com.example.one/.Service:com.example.two/.Listener"),
            {"com.example.one", "com.example.two"},
        )
        self.assertEqual(
            parse_device_admin_packages("AdminInfo{com.example.admin/.Receiver}"),
            {"com.example.admin"},
        )
        self.assertEqual(parse_appop_mode("SYSTEM_ALERT_WINDOW: allow; time=+2m", "SYSTEM_ALERT_WINDOW"), "allow")


if __name__ == "__main__":
    unittest.main()
