"""Install Google's standalone AAPT2 for APK labels/icons without a full Android SDK."""
from __future__ import annotations

import hashlib
import io
import subprocess
import sys
import tempfile
import urllib.request
import zipfile
from pathlib import Path

VERSION = "9.4.1-15978811"
SHA256 = {
    "osx": "eb93ce9d0fa121333f12395b3ab30822c5cdb9155737f20d342fe71809757059",
    "linux": "f5bebd466ecf14d341fd465f2756a16d86052f29eb4532003d5ff7bcffd08de5",
    "windows": "5fe3c8ee5c6b3f47efd1fced1d6418084037f54f13290816c5db717e6b5c92aa",
}


def install(destination: Path) -> Path:
    platform = {"darwin": "osx", "win32": "windows", "linux": "linux"}.get(sys.platform)
    if platform is None:
        raise RuntimeError(f"Plateforme non prise en charge : {sys.platform}")
    name = "aapt2.exe" if platform == "windows" else "aapt2"
    output = destination / name
    if output.exists():
        subprocess.run([str(output.resolve()), "version"], check=True, timeout=15)
        return output
    url = f"https://dl.google.com/dl/android/maven2/com/android/tools/build/aapt2/{VERSION}/aapt2-{VERSION}-{platform}.jar"
    with urllib.request.urlopen(url, timeout=60) as response:
        data = response.read()
    if hashlib.sha256(data).hexdigest() != SHA256[platform]:
        raise RuntimeError("Archive AAPT2 inattendue : vérification SHA-256 échouée.")
    destination.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(data)) as archive, tempfile.TemporaryDirectory(dir=destination) as temporary:
        binary = Path(temporary) / name
        binary.write_bytes(archive.read(name))
        binary.chmod(0o755)
        subprocess.run([str(binary.resolve()), "version"], check=True, timeout=15)
        if "NOTICE" in archive.namelist():
            (destination / "aapt2-NOTICE.txt").write_bytes(archive.read("NOTICE"))
        binary.replace(output)
    return output


if __name__ == "__main__":
    print(f"AAPT2 disponible : {install(Path(__file__).resolve().parents[1] / 'tools')}")
