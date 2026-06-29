from __future__ import annotations

import logging
import re
import tempfile
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from adb_client import ADBClient
from apk_metadata import ApkMetadataExtractor

LOGGER = logging.getLogger(__name__)
PROJECT_DIR = Path(__file__).resolve().parent
ICON_CACHE_DIR = PROJECT_DIR / "cache" / "app_icons"

SENSITIVE_PERMISSION_KEYWORDS = {
    "READ_SMS",
    "SEND_SMS",
    "RECEIVE_SMS",
    "READ_CALL_LOG",
    "WRITE_CALL_LOG",
    "READ_CONTACTS",
    "WRITE_CONTACTS",
    "GET_ACCOUNTS",
    "READ_PHONE_STATE",
    "CALL_PHONE",
    "SYSTEM_ALERT_WINDOW",
    "BIND_ACCESSIBILITY_SERVICE",
    "BIND_NOTIFICATION_LISTENER_SERVICE",
    "BIND_DEVICE_ADMIN",
    "REQUEST_INSTALL_PACKAGES",
    "PACKAGE_USAGE_STATS",
    "POST_NOTIFICATIONS",
    "SCHEDULE_EXACT_ALARM",
    "USE_EXACT_ALARM",
    "VIBRATE",
    "RECEIVE_BOOT_COMPLETED",
    "FOREGROUND_SERVICE",
    "BIND_VPN_SERVICE",
}


@dataclass(slots=True)
class AppInfo:
    package_name: str
    app_label: str = ""
    app_label_source: str = "package"
    icon_path: str = ""
    icon_source: str = ""
    has_launcher_entry: bool | None = None
    hidden_audit: list[str] = field(default_factory=list)
    notification_audit: list[str] = field(default_factory=list)
    installer: str = ""
    is_system_app: bool = False
    sensitive_permissions: list[str] = field(default_factory=list)
    enabled: str = ""
    install_date: str = ""
    version_name: str = ""
    target_sdk: str = ""
    has_accessibility: bool = False
    has_overlay: bool = False
    has_device_admin: bool = False
    has_notification_listener: bool = False
    requests_post_notifications: bool = False
    uses_exact_alarm: bool = False
    uses_vibration: bool = False
    can_install_unknown_apps: bool = False
    has_usage_stats: bool = False
    runs_at_boot: bool = False
    has_vpn_service: bool = False
    dumpsys_error: str = ""

    def display_name(self) -> str:
        return self.app_label or package_to_label(self.package_name)


def package_to_label(package_name: str) -> str:
    tail = package_name.split(".")[-1] if package_name else ""
    return tail.replace("_", " ").replace("-", " ").title() or package_name


class AppScanner:
    def __init__(self, adb_client: ADBClient) -> None:
        self.adb_client = adb_client
        self.apk_metadata = ApkMetadataExtractor()

    def scan(self, serial: str, include_system: bool = False) -> list[AppInfo]:
        packages = self.adb_client.list_packages(serial, include_system=include_system)
        launcher_packages = self.adb_client.list_launcher_packages(serial)
        apps: list[AppInfo] = []

        for package, installer in packages.items():
            app = self.scan_package(
                serial=serial,
                package=package,
                installer=installer,
                include_system=include_system,
                launcher_packages=launcher_packages,
            )
            apps.append(app)
        return apps

    def scan_package(
        self,
        serial: str,
        package: str,
        installer: str = "",
        include_system: bool = False,
        launcher_packages: set[str] | None = None,
    ) -> AppInfo:
        app = AppInfo(package_name=package, installer=installer, is_system_app=include_system)
        try:
            if launcher_packages is not None:
                app.has_launcher_entry = package in launcher_packages
            dumpsys = self.adb_client.dumpsys_package(serial, package)
            self._enrich_from_dumpsys(app, dumpsys)
            self._enrich_from_apk(serial, app)
            self._finalize_audits(app)
        except Exception as exc:  # noqa: BLE001 - UI should show partial scan, not abort all.
            LOGGER.exception("Metadata enrichment failed for %s", package)
            app.dumpsys_error = str(exc)
        return app

    def _enrich_from_dumpsys(self, app: AppInfo, dumpsys: str) -> None:
        app.app_label = self._extract_label(app.package_name, dumpsys)
        app.version_name = self._extract_value(dumpsys, r"versionName=([^\s]+)")
        app.target_sdk = self._extract_value(dumpsys, r"targetSdk=([0-9]+)")
        app.install_date = self._extract_value(dumpsys, r"firstInstallTime=([^\n\r]+)")
        app.enabled = self._extract_enabled(dumpsys)
        app.is_system_app = self._is_system_app(dumpsys)
        app.sensitive_permissions = self._extract_sensitive_permissions(dumpsys)
        app.has_accessibility = "BIND_ACCESSIBILITY_SERVICE" in dumpsys or "AccessibilityService" in dumpsys
        app.has_overlay = "SYSTEM_ALERT_WINDOW" in dumpsys
        app.has_device_admin = "BIND_DEVICE_ADMIN" in dumpsys or "android.app.device_admin" in dumpsys
        app.has_notification_listener = "BIND_NOTIFICATION_LISTENER_SERVICE" in dumpsys
        app.requests_post_notifications = "POST_NOTIFICATIONS" in dumpsys
        app.uses_exact_alarm = "SCHEDULE_EXACT_ALARM" in dumpsys or "USE_EXACT_ALARM" in dumpsys
        app.uses_vibration = "VIBRATE" in dumpsys
        app.can_install_unknown_apps = "REQUEST_INSTALL_PACKAGES" in dumpsys
        app.has_usage_stats = "PACKAGE_USAGE_STATS" in dumpsys
        app.runs_at_boot = "RECEIVE_BOOT_COMPLETED" in dumpsys
        app.has_vpn_service = "BIND_VPN_SERVICE" in dumpsys or "VpnService" in dumpsys

    def _extract_label(self, package_name: str, dumpsys: str) -> str:
        # dumpsys generally does not expose the localized label. The APK label
        # extractor can replace this fallback when aapt2 is available.
        return package_to_label(package_name)

    def _enrich_from_apk(self, serial: str, app: AppInfo) -> None:
        if not self.apk_metadata.available:
            return

        try:
            apk_paths = self.adb_client.package_paths(serial, app.package_name)
        except Exception as exc:  # noqa: BLE001
            LOGGER.debug("Unable to read APK path for %s: %s", app.package_name, exc)
            return

        base_apk = next((path for path in apk_paths if path.endswith("/base.apk")), apk_paths[0] if apk_paths else "")
        if not base_apk:
            return

        with tempfile.TemporaryDirectory(prefix="mw_apk_") as temp_dir:
            local_apk = Path(temp_dir) / f"{safe_filename(app.package_name)}.apk"
            try:
                self.adb_client.pull_file(serial, base_apk, local_apk)
                metadata = self.apk_metadata.extract(local_apk)
                icon_path = self.apk_metadata.extract_icon(local_apk, metadata, app.package_name, ICON_CACHE_DIR)
            except Exception as exc:  # noqa: BLE001
                LOGGER.debug("Unable to extract APK metadata for %s: %s", app.package_name, exc)
                return

        if metadata.label:
            app.app_label = metadata.label
            app.app_label_source = "apk"
        if icon_path:
            app.icon_path = str(icon_path)
            app.icon_source = "apk"
        if metadata.version_name and not app.version_name:
            app.version_name = metadata.version_name
        if metadata.target_sdk and not app.target_sdk:
            app.target_sdk = metadata.target_sdk

    def _finalize_audits(self, app: AppInfo) -> None:
        app.hidden_audit = []
        if app.has_launcher_entry is False and not app.is_system_app:
            app.hidden_audit.append("Aucune icône launcher visible")
        if app.app_label_source != "apk":
            app.hidden_audit.append("Nom affiché réel non récupéré")
        if not app.icon_path:
            app.hidden_audit.append("Icône non récupérée ou adaptive XML")
        if is_generic_display_name(app.display_name(), app.package_name):
            app.hidden_audit.append("Nom très générique")

        app.notification_audit = []
        if app.has_notification_listener:
            app.notification_audit.append("Accès aux notifications")
        if app.requests_post_notifications:
            app.notification_audit.append("Demande POST_NOTIFICATIONS")
        if app.runs_at_boot:
            app.notification_audit.append("Démarrage automatique")
        if app.uses_exact_alarm:
            app.notification_audit.append("Alarmes exactes")
        if app.uses_vibration:
            app.notification_audit.append("Vibration")

    def _extract_value(self, text: str, pattern: str) -> str:
        match = re.search(pattern, text)
        return match.group(1).strip() if match else ""

    def _extract_enabled(self, dumpsys: str) -> str:
        for pattern in (r"enabled=([^\s]+)", r"enabledComponents:([^\n\r]+)"):
            value = self._extract_value(dumpsys, pattern)
            if value:
                return value
        return ""

    def _is_system_app(self, dumpsys: str) -> bool:
        flag_lines = [line for line in dumpsys.splitlines() if "flags=[" in line or "pkgFlags=[" in line]
        return any(" SYSTEM" in f" {line} " or " PRIVILEGED" in f" {line} " for line in flag_lines)

    def _extract_sensitive_permissions(self, dumpsys: str) -> list[str]:
        found: set[str] = set()
        for keyword in SENSITIVE_PERMISSION_KEYWORDS:
            if keyword in dumpsys:
                found.add(f"android.permission.{keyword}" if not keyword.startswith("BIND_") else keyword)

        for match in re.finditer(r"android\.permission\.([A-Z0-9_]+)", dumpsys):
            name = match.group(0)
            if any(keyword in name for keyword in SENSITIVE_PERMISSION_KEYWORDS):
                found.add(name)
        return sorted(found)


def installed_recently(install_date: str, days: int = 10) -> bool:
    if not install_date:
        return False
    cleaned = install_date.strip().split()[0]
    candidates = [
        install_date.strip(),
        cleaned,
    ]
    for value in candidates:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=UTC)
            return (datetime.now(UTC) - parsed).days <= days
        except ValueError:
            continue
    return False


def safe_filename(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", value)[:120] or "app"


def is_generic_display_name(label: str, package_name: str) -> bool:
    normalized = label.strip().lower()
    package_tail = package_to_label(package_name).strip().lower()
    generic_names = {
        "app",
        "service",
        "system",
        "update",
        "android",
        "tools",
        "manager",
        "phone",
        "contacts",
        "security",
        "cleaner",
        "weather",
    }
    return normalized in generic_names or normalized == package_tail
