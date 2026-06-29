from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parents[1]


def add_data_arg(source: Path, destination: str) -> str:
    return f"{source}{os.pathsep}{destination}"


def existing_files(directory: Path) -> list[Path]:
    if not directory.exists():
        return []
    return [path for path in directory.rglob("*") if path.is_file() and path.name != ".gitkeep"]


def bundle_destination(root_name: str, path: Path, source_root: Path) -> str:
    parent = path.relative_to(source_root).parent
    return root_name if str(parent) == "." else f"{root_name}/{parent}"


def build_command(args: argparse.Namespace) -> list[str]:
    command = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        "--onedir",
        "--windowed",
        "--name",
        args.name,
        "--specpath",
        str(PROJECT_DIR / "packaging" / "generated"),
        "--workpath",
        str(PROJECT_DIR / "build" / "pyinstaller"),
        "--distpath",
        str(PROJECT_DIR / "dist"),
    ]

    if args.icon:
        command.extend(["--icon", str(Path(args.icon).resolve())])

    if args.include_adb:
        for path in existing_files(PROJECT_DIR / "adb"):
            command.extend(["--add-binary", add_data_arg(path, bundle_destination("adb", path, PROJECT_DIR / "adb"))])

    if args.include_aapt2:
        for path in existing_files(PROJECT_DIR / "tools"):
            command.extend(["--add-binary", add_data_arg(path, bundle_destination("tools", path, PROJECT_DIR / "tools"))])

    for directory in ("data", "logs", "reports", "cache"):
        placeholder = PROJECT_DIR / directory / ".gitkeep"
        if placeholder.exists():
            command.extend(["--add-data", add_data_arg(placeholder, directory)])

    command.append(str(PROJECT_DIR / "main.py"))
    return command


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build a Microwest Android Cleaner desktop bundle with PyInstaller.")
    parser.add_argument("--name", default="Microwest Android Cleaner", help="Application bundle name.")
    parser.add_argument("--icon", help="Optional .ico/.icns icon path.")
    parser.add_argument("--include-adb", action="store_true", help="Bundle files from adb/.")
    parser.add_argument("--include-aapt2", action="store_true", help="Bundle files from tools/.")
    parser.add_argument("--print-command", action="store_true", help="Print the PyInstaller command without running it.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    command = build_command(args)
    if args.print_command:
        print(" ".join(command))
        return 0
    try:
        subprocess.run(command, cwd=PROJECT_DIR, check=True)
    except subprocess.CalledProcessError as exc:
        return exc.returncode
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
