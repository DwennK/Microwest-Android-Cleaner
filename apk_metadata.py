from __future__ import annotations

import logging
import re
import shutil
import subprocess
import sys
import zipfile
from dataclasses import dataclass
from pathlib import Path


LOGGER = logging.getLogger(__name__)
PROJECT_DIR = Path(__file__).resolve().parent


@dataclass(slots=True)
class ApkMetadata:
    label: str = ""
    package_name: str = ""
    version_name: str = ""
    sdk_version: str = ""
    target_sdk: str = ""
    icon_paths: list[str] | None = None


class ApkMetadataExtractor:
    def __init__(self, project_dir: Path | None = None) -> None:
        self.project_dir = project_dir or PROJECT_DIR
        self.aapt2_path = self._find_aapt2()

    @property
    def available(self) -> bool:
        return bool(self.aapt2_path)

    def _find_aapt2(self) -> str:
        executable_name = "aapt2.exe" if sys.platform == "win32" else "aapt2"
        candidates = [
            self.project_dir / "tools" / executable_name,
            self.project_dir / "adb" / executable_name,
        ]
        for candidate in candidates:
            if candidate.exists():
                return str(candidate)
        return shutil.which("aapt2") or ""

    def extract(self, apk_path: Path) -> ApkMetadata:
        if not self.aapt2_path:
            return ApkMetadata()

        creationflags = 0
        if sys.platform == "win32" and hasattr(subprocess, "CREATE_NO_WINDOW"):
            creationflags = subprocess.CREATE_NO_WINDOW

        try:
            result = subprocess.run(
                [self.aapt2_path, "dump", "badging", str(apk_path)],
                text=True,
                capture_output=True,
                timeout=20,
                creationflags=creationflags,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            LOGGER.exception("aapt2 dump failed for %s", apk_path)
            return ApkMetadata()

        if result.returncode != 0:
            LOGGER.debug("aapt2 returned %s: %s", result.returncode, result.stderr.strip())
            return ApkMetadata()
        return parse_aapt2_badging(result.stdout)

    def extract_icon(self, apk_path: Path, metadata: ApkMetadata, package_name: str, cache_dir: Path) -> Path | None:
        icon_path = best_icon_path(metadata.icon_paths or [])
        if not icon_path:
            return None

        cache_dir.mkdir(parents=True, exist_ok=True)
        suffix = Path(icon_path).suffix.lower()
        if suffix not in {".png", ".webp", ".jpg", ".jpeg"}:
            return None

        output_path = cache_dir / f"{safe_filename(package_name)}{suffix}"
        try:
            with zipfile.ZipFile(apk_path) as archive:
                with archive.open(icon_path) as source:
                    output_path.write_bytes(source.read())
        except (KeyError, OSError, zipfile.BadZipFile):
            LOGGER.debug("Unable to extract icon %s from %s", icon_path, apk_path)
            return None
        return output_path


def parse_aapt2_badging(output: str) -> ApkMetadata:
    metadata = ApkMetadata()
    metadata.package_name = _extract_quoted(output, r"package: name='([^']+)'")
    metadata.version_name = _extract_quoted(output, r"versionName='([^']+)'")
    metadata.sdk_version = _extract_quoted(output, r"sdkVersion:'([^']+)'")
    metadata.target_sdk = _extract_quoted(output, r"targetSdkVersion:'([^']+)'")
    metadata.icon_paths = extract_icon_paths(output)

    label = _extract_quoted(output, r"application-label-fr:'([^']+)'")
    if not label:
        label = _extract_quoted(output, r"application-label-fr-CA:'([^']+)'")
    if not label:
        label = _extract_quoted(output, r"application-label-fr-FR:'([^']+)'")
    if not label:
        label = _extract_quoted(output, r"application-label:'([^']+)'")
    metadata.label = label.strip()
    return metadata


def _extract_quoted(text: str, pattern: str) -> str:
    match = re.search(pattern, text)
    return match.group(1).strip() if match else ""


def extract_icon_paths(output: str) -> list[str]:
    paths: list[str] = []
    for line in output.splitlines():
        if line.startswith("application-icon"):
            match = re.search(r":'([^']+)'", line)
            if match:
                paths.append(match.group(1).strip())
    return paths


def best_icon_path(paths: list[str]) -> str:
    raster_paths = [path for path in paths if Path(path).suffix.lower() in {".png", ".webp", ".jpg", ".jpeg"}]
    if not raster_paths:
        return ""

    def density(path: str) -> int:
        match = re.search(r"application-icon-(\d+)", path)
        if match:
            return int(match.group(1))
        match = re.search(r"(mdpi|hdpi|xhdpi|xxhdpi|xxxhdpi)", path)
        if not match:
            return 0
        return {"mdpi": 160, "hdpi": 240, "xhdpi": 320, "xxhdpi": 480, "xxxhdpi": 640}[match.group(1)]

    return max(raster_paths, key=density)


def safe_filename(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", value)[:120] or "app"
