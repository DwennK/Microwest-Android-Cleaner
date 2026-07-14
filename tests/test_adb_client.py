from __future__ import annotations

import unittest

from adb_client import (
    ADBDevice,
    parse_appop_mode,
    parse_component_packages,
    parse_device_admin_packages,
    parse_devices_l,
    parse_launcher_packages,
    select_device,
)


class ADBClientParserTests(unittest.TestCase):
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
