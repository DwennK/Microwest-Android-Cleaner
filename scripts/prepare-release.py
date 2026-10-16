"""Package one signed EXE and its GitHub updater manifest; never read signing keys."""
import hashlib
import json
import os
from pathlib import Path
import shutil
from datetime import datetime, timezone


def manifest(version, name, signature):
    if not signature.strip():
        raise ValueError("Updater signature is missing")
    return {
        "version": version,
        "notes": f"Microwest Android Cleaner {version}",
        "pub_date": datetime.now(timezone.utc).isoformat(),
        "platforms": {
            "windows-x86_64": {
                "signature": signature.strip(),
                "url": f"https://github.com/DwennK/Microwest-Android-Cleaner/releases/download/v{version}/{name}",
            }
        },
    }


def prepare(root):
    version = json.loads((root / "package.json").read_text(encoding="utf-8"))["version"]
    ref = os.environ.get("GITHUB_REF", "")
    if ref.startswith("refs/tags/") and ref != f"refs/tags/v{version}":
        raise ValueError("Release tag does not match application version")
    installers = list((root / "src-tauri/target/release/bundle/nsis").glob("*-setup.exe"))
    if len(installers) != 1:
        raise ValueError("Expected exactly one EXE installer")
    installer = installers[0]
    signature = Path(str(installer) + ".sig").read_text(encoding="utf-8").strip()
    name = f"Microwest.Android.Cleaner_{version}_x64-setup.exe"
    data = manifest(version, name, signature)
    output = root / "release-output"
    output.mkdir(exist_ok=True)
    if any(output.iterdir()):
        raise ValueError("Release output directory must be empty")
    shutil.copy2(installer, output / name)
    (output / f"{name}.sig").write_text(signature + "\n", encoding="utf-8")
    (output / "latest.json").write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    sums = []
    for path in sorted(output.iterdir()):
        sums.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}")
    (output / "SHA256SUMS.txt").write_text("\n".join(sums) + "\n", encoding="ascii")


if __name__ == "__main__":
    prepare(Path(__file__).resolve().parents[1])
