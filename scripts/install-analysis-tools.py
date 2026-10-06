"""Install pinned Android signature verifier + portable JRE for Windows development.

Archives originate from Google and Eclipse Adoptium. Existing installations are
preserved. Nothing is added to PATH or installed system-wide.
"""
from pathlib import Path
from io import BytesIO
from urllib.request import urlopen
from zipfile import ZipFile
import hashlib
import shutil
import tempfile

root = Path(__file__).resolve().parents[1] / "tools"


def archive(url, algorithm, expected):
    with urlopen(url, timeout=90) as response:
        data = response.read(256 * 1024 * 1024 + 1)
    if len(data) > 256 * 1024 * 1024:
        raise RuntimeError("Archive exceeds size limit")
    if hashlib.new(algorithm, data).hexdigest() != expected:
        raise RuntimeError("Archive checksum mismatch")
    return ZipFile(BytesIO(data))


root.mkdir(exist_ok=True)
if not (root / "apksigner.jar").exists():
    with archive("https://dl.google.com/android/repository/build-tools_r36_windows.zip", "sha1",
                 "f16ccffd34de8790dede813a6c7d8e2c11a27b50") as z:
        name = next(n for n in z.namelist() if n.endswith("/lib/apksigner.jar"))
        (root / "apksigner.jar").write_bytes(z.read(name))
        notice = next((n for n in z.namelist() if n.endswith("/NOTICE.txt")), None)
        if notice:
            (root / "apksigner-NOTICE.txt").write_bytes(z.read(notice))

if not (root / "jre" / "bin" / "java.exe").exists():
    with archive("https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.12.1%2B1/OpenJDK21U-jre_x64_windows_hotspot_21.0.12.1_1.zip",
                 "sha256", "d35f31e712f0fcf6ac5a093edc90204fbff22f720ba3950bd09d331d5e621636") as z:
        with tempfile.TemporaryDirectory(dir=root) as staging:
            target = Path(staging).resolve()
            for entry in z.infolist():
                if not (target / entry.filename).resolve().is_relative_to(target):
                    raise RuntimeError("Unsafe archive path")
            z.extractall(target)
            extracted = next(p for p in target.iterdir() if p.is_dir())
            shutil.move(str(extracted), str(root / "jre"))
print("Signature verifier and portable Java ready.")
