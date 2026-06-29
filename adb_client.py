from __future__ import annotations

import logging
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

LOGGER = logging.getLogger(__name__)
PROJECT_DIR = Path(__file__).resolve().parent


class ADBError(RuntimeError):
    """Base exception for ADB failures."""


class ADBNotFoundError(ADBError):
    """Raised when adb cannot be found."""


class ADBTimeoutError(ADBError):
    """Raised when an ADB command times out."""


@dataclass(slots=True)
class DeviceInfo:
    serial: str = ""
    state: str = "none"
    manufacturer: str = ""
    model: str = ""
    android_version: str = ""
    message: str = "Aucun appareil détecté"


@dataclass(slots=True)
class ADBDevice:
    serial: str
    state: str
    details: str = ""


class ADBClient:
    """Small, conservative ADB wrapper used by the GUI.

    The application intentionally exposes only metadata collection commands and
    the allowed uninstall command: pm uninstall --user 0 PACKAGE.
    """

    def __init__(self, project_dir: Path | None = None, timeout: int = 15) -> None:
        self.project_dir = project_dir or PROJECT_DIR
        self.timeout = timeout
        self.adb_path = self._find_adb()

    def _find_adb(self) -> str:
        bundled_name = "adb.exe" if sys.platform == "win32" else "adb"
        bundled = self.project_dir / "adb" / bundled_name
        if bundled.exists():
            return str(bundled)

        from_path = shutil.which("adb")
        if from_path:
            return from_path

        raise ADBNotFoundError(
            "ADB introuvable. Installez Android Platform Tools et ajoutez adb au PATH, "
            "ou placez le binaire adb compatible avec votre système dans le dossier adb/."
        )

    def _run(self, args: list[str], timeout: int | None = None) -> subprocess.CompletedProcess[str]:
        command = [self.adb_path, *args]
        LOGGER.debug("ADB command: %s", " ".join(command))
        creationflags = 0
        if sys.platform == "win32" and hasattr(subprocess, "CREATE_NO_WINDOW"):
            creationflags = subprocess.CREATE_NO_WINDOW
        try:
            return subprocess.run(
                command,
                text=True,
                capture_output=True,
                timeout=timeout or self.timeout,
                creationflags=creationflags,
                check=False,
            )
        except OSError as exc:
            raise ADBError(f"Impossible d'exécuter ADB: {exc}") from exc
        except subprocess.TimeoutExpired as exc:
            raise ADBTimeoutError("La commande ADB a expiré.") from exc

    def start_server(self) -> str:
        result = self._run(["start-server"], timeout=15)
        if result.returncode != 0:
            raise ADBError(result.stderr.strip() or result.stdout.strip() or "Impossible de démarrer le daemon ADB.")
        return (result.stdout + result.stderr).strip() or "Daemon ADB démarré."

    def kill_server(self) -> str:
        result = self._run(["kill-server"], timeout=15)
        if result.returncode != 0:
            raise ADBError(result.stderr.strip() or result.stdout.strip() or "Impossible d'arrêter le daemon ADB.")
        return (result.stdout + result.stderr).strip() or "Daemon ADB arrêté."

    def restart_server(self) -> str:
        kill_message = self.kill_server()
        start_message = self.start_server()
        return f"{kill_message}\n{start_message}".strip()

    def version(self) -> str:
        result = self._run(["version"], timeout=10)
        if result.returncode != 0:
            raise ADBError(result.stderr.strip() or result.stdout.strip() or "Impossible d'exécuter adb version.")
        return result.stdout.strip()

    def devices_output(self) -> str:
        result = self._run(["devices", "-l"], timeout=10)
        if result.returncode != 0:
            raise ADBError(result.stderr.strip() or result.stdout.strip() or "Impossible d'exécuter adb devices -l.")
        return result.stdout.strip()

    def detailed_devices(self) -> list[ADBDevice]:
        return parse_devices_l(self.devices_output())

    def devices(self) -> list[tuple[str, str]]:
        return [(device.serial, device.state) for device in self.detailed_devices()]

    def detect_device(self, serial: str = "") -> DeviceInfo:
        devices = self.detailed_devices()
        if not devices:
            return DeviceInfo(
                message=(
                    "Aucun appareil ADB détecté. Vérifiez que le téléphone est déverrouillé, "
                    "que le débogage USB est activé et que la demande d'autorisation RSA a été acceptée."
                )
            )

        selected = select_device(devices, serial)
        if selected is None:
            return DeviceInfo(
                state="none",
                message=f"Appareil ADB introuvable pour le numéro sélectionné : {serial}",
            )

        if selected.state == "unauthorized":
            return DeviceInfo(
                serial=selected.serial,
                state=selected.state,
                message="Téléphone non autorisé : acceptez le débogage USB sur l'écran du téléphone.",
            )
        if selected.state != "device":
            return DeviceInfo(
                serial=selected.serial,
                state=selected.state,
                message=f"Téléphone détecté mais état ADB: {selected.state}",
            )

        info = DeviceInfo(serial=selected.serial, state="device", message="Téléphone connecté")
        info.manufacturer = self.getprop(selected.serial, "ro.product.manufacturer")
        info.model = self.getprop(selected.serial, "ro.product.model")
        info.android_version = self.getprop(selected.serial, "ro.build.version.release")
        if not serial and len(devices) > 1:
            info.message = "Téléphone connecté. Plusieurs appareils détectés : vérifiez la sélection."
        return info

    def shell(self, serial: str, shell_args: list[str], timeout: int | None = None) -> str:
        result = self._run(["-s", serial, "shell", *shell_args], timeout=timeout)
        if result.returncode != 0:
            raise ADBError(result.stderr.strip() or result.stdout.strip() or "Commande ADB échouée.")
        return result.stdout.strip()

    def getprop(self, serial: str, prop: str) -> str:
        try:
            return self.shell(serial, ["getprop", prop], timeout=8).strip()
        except ADBError:
            LOGGER.exception("Unable to read property %s", prop)
            return ""

    def list_packages(self, serial: str, include_system: bool = False) -> dict[str, str]:
        args = ["pm", "list", "packages", "-i"]
        if not include_system:
            args.append("-3")
        output = self.shell(serial, args, timeout=45)

        packages: dict[str, str] = {}
        for raw_line in output.splitlines():
            line = raw_line.strip()
            if not line.startswith("package:"):
                continue
            without_prefix = line.removeprefix("package:")
            package = without_prefix.split()[0]
            installer = ""
            match = re.search(r"installer=([^\s]+)", line)
            if match:
                installer = match.group(1).strip()
            packages[package] = "" if installer in {"null", "None"} else installer
        return packages

    def list_launcher_packages(self, serial: str) -> set[str] | None:
        commands = [
            [
                "cmd",
                "package",
                "query-activities",
                "--brief",
                "-a",
                "android.intent.action.MAIN",
                "-c",
                "android.intent.category.LAUNCHER",
            ],
            [
                "cmd",
                "package",
                "query-activities",
                "-a",
                "android.intent.action.MAIN",
                "-c",
                "android.intent.category.LAUNCHER",
            ],
        ]
        last_error = ""
        for command in commands:
            try:
                output = self.shell(serial, command, timeout=20)
            except ADBError as exc:
                last_error = str(exc)
                continue
            packages = parse_launcher_packages(output)
            if packages:
                return packages
        LOGGER.info("Unable to list launcher packages: %s", last_error)
        return None

    def dumpsys_package(self, serial: str, package: str) -> str:
        return self.shell(serial, ["dumpsys", "package", package], timeout=15)

    def package_paths(self, serial: str, package: str) -> list[str]:
        output = self.shell(serial, ["pm", "path", package], timeout=10)
        paths: list[str] = []
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("package:"):
                paths.append(line.removeprefix("package:").strip())
        return paths

    def pull_file(self, serial: str, remote_path: str, local_path: Path, timeout: int = 45) -> None:
        # Pulling the installed APK reads only the application package file, not
        # customer contacts, SMS, photos, accounts, or app-private data.
        result = self._run(["-s", serial, "pull", remote_path, str(local_path)], timeout=timeout)
        if result.returncode != 0:
            raise ADBError(result.stderr.strip() or result.stdout.strip() or "Impossible de copier l'APK.")

    def open_app_settings(self, serial: str, package: str) -> str:
        if not re.fullmatch(r"[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+", package):
            raise ADBError("Package invalide")
        return self.shell(
            serial,
            [
                "am",
                "start",
                "-a",
                "android.settings.APPLICATION_DETAILS_SETTINGS",
                "-d",
                f"package:{package}",
            ],
            timeout=10,
        )

    def uninstall_user_package(self, serial: str, package: str) -> tuple[bool, str]:
        if not re.fullmatch(r"[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+", package):
            return False, "Package invalide"
        try:
            output = self.shell(serial, ["pm", "uninstall", "--user", "0", package], timeout=60)
        except ADBError as exc:
            return False, str(exc)
        success = "Success" in output
        return success, output or ("Success" if success else "Failure")


def parse_launcher_packages(output: str) -> set[str]:
    packages: set[str] = set()
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith(("No activities", "Activities:")):
            continue
        for pattern in (r"(?:^|\s)([A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+)/", r"packageName=([A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+)"):
            match = re.search(pattern, line)
            if match and not match.group(1).startswith("android.intent."):
                packages.add(match.group(1))
                break
    return packages


def parse_devices_l(output: str) -> list[ADBDevice]:
    devices: list[ADBDevice] = []
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("List of devices"):
            continue
        parts = re.split(r"\s+", line, maxsplit=2)
        if len(parts) < 2:
            continue
        details = parts[2] if len(parts) > 2 else ""
        devices.append(ADBDevice(serial=parts[0], state=parts[1], details=details))
    return devices


def select_device(devices: list[ADBDevice], serial: str = "") -> ADBDevice | None:
    if serial:
        return next((device for device in devices if device.serial == serial), None)
    return next((device for device in devices if device.state == "device"), devices[0] if devices else None)
