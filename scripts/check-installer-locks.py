"""Exercise the shipping NSIS hooks against real Windows DLL locks.

Run after tauri build (the harness uses its generated utils.nsh and NSIS cache).
All processes and resources belong to temporary directories; ADB servers use
private ports, so the workstation's normal ADB server is not affected.
"""

import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time


ROOT = Path(__file__).resolve().parents[1]
FILES = ("adb.exe", "AdbWinApi.dll", "AdbWinUsbApi.dll")


def run(*args, **kwargs):
    command = [str(arg) for arg in args]
    # NSIS parses its final directory switch itself; it must not be quoted.
    # This is a raw CreateProcess command line, never passed through a shell.
    if command[-1].startswith(("/D=", "_?=")):
        command = subprocess.list2cmdline(command[:-1]) + " " + command[-1]
    return subprocess.run(
        command, check=True, timeout=60,
        capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW, **kwargs
    )


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def server_alive(port):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1):
            return True
    except OSError:
        return False


def copy_adb(directory):
    target = directory / "adb"
    target.mkdir(parents=True)
    for name in FILES:
        shutil.copy2(ROOT / "adb" / name, target / name)
    return target / "adb.exe"


def assert_locked(path):
    try:
        with path.open("r+b"):
            pass
    except PermissionError:
        return
    raise AssertionError(f"Test precondition failed: {path} is not locked")


def wait_unlocked(directory):
    # kill-server acknowledges before Windows has necessarily unmapped the DLLs.
    deadline = time.monotonic() + 10
    while True:
        try:
            for name in FILES:
                path = directory / "adb" / name
                if path.exists():
                    with path.open("r+b"):
                        pass
            return
        except PermissionError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.05)


def compile_harness(work):
    nsis = Path(os.environ["LOCALAPPDATA"]) / "tauri/NSIS"
    generated = ROOT / "src-tauri/target/release/nsis/x64"
    source = work / "harness.nsi"
    installer = work / "harness.exe"
    # The actual shipping macros, including Tauri's Restart Manager helper.
    source.write_text(r'''
Unicode true
RequestExecutionLevel user
SilentInstall silent
SilentUnInstall silent
!include "LogicLib.nsh"
!include "Win\RestartManager.nsh"
!include "@GENERATED@\utils.nsh"
!include "@ROOT@\src-tauri\windows\hooks.nsh"
!addplugindir "@NSIS@\Plugins\x86-unicode\additional"
!define MAINBINARYNAME "microwest-lock-test"
!define PRODUCTNAME "Microwest lock test"
Var PassiveMode
LangString appRunning 1033 "{{product_name}} is running"
LangString appRunningOkKill 1033 "Close {{product_name}}?"
LangString failedToKillApp 1033 "Cannot close {{product_name}}"
Name "Microwest installer lock regression test"
OutFile "@INSTALLER@"
Section
  StrCpy $PassiveMode 1
  !insertmacro NSIS_HOOK_PREINSTALL
  SetOutPath "$INSTDIR\adb"
  File "@ROOT@\adb\adb.exe"
  File "@ROOT@\adb\AdbWinApi.dll"
  File "@ROOT@\adb\AdbWinUsbApi.dll"
  WriteUninstaller "$INSTDIR\uninstall.exe"
  FileOpen $0 "$INSTDIR\installed.txt" w
  FileWrite $0 "installed"
  FileClose $0
SectionEnd
Section Uninstall
  !insertmacro NSIS_HOOK_PREUNINSTALL
  Delete "$INSTDIR\adb\adb.exe"
  Delete "$INSTDIR\adb\AdbWinApi.dll"
  Delete "$INSTDIR\adb\AdbWinUsbApi.dll"
  FileOpen $0 "$INSTDIR\uninstalled.txt" w
  FileWrite $0 "uninstalled"
  FileClose $0
SectionEnd
'''.replace("@GENERATED@", str(generated)).replace("@ROOT@", str(ROOT))
        .replace("@NSIS@", str(nsis)).replace("@INSTALLER@", str(installer)),
        encoding="utf-8")
    result = run(nsis / "makensis.exe", "/V2", source)
    if result.stdout:
        print(result.stdout.decode(errors="replace"))
    # A 32-bit NSIS process can load the bundled 32-bit ADB DLL even when the
    # Python test runner is 64-bit. It models a surviving DLL mapping without
    # relying on the old adb.exe being present or runnable.
    holder = work / "dll-holder.exe"
    holder_source = work / "dll-holder.nsi"
    holder_source.write_text(r'''
Unicode true
RequestExecutionLevel user
SilentInstall silent
Name "Microwest DLL lock fixture"
OutFile "@HOLDER@"
Section
  System::Call 'kernel32::LoadLibraryW(w "$INSTDIR\adb\AdbWinApi.dll") p.r0'
  IntCmp $0 0 failed loaded loaded
  failed:
    SetErrorLevel 2
    Quit
  loaded:
    FileOpen $1 "$INSTDIR\ready" w
    FileWrite $1 "ready"
    FileClose $1
    Sleep 60000
SectionEnd
'''.replace("@HOLDER@", str(holder)), encoding="utf-8")
    run(nsis / "makensis.exe", "/V2", holder_source)
    return installer, holder


def main():
    if sys.platform != "win32":
        raise SystemExit("This regression check requires Windows")
    with tempfile.TemporaryDirectory(prefix="microwest installer locks ") as temp:
        work = Path(temp)
        installer, holder = compile_harness(work)
        other = copy_adb(work / "other installation")
        other_port = free_port()
        run(other, "-P", other_port, "start-server")
        try:
            # Fresh install and reinstall with no running ADB must both succeed.
            target = work / "installation with spaces"
            run(installer, "/S", f"/D={target}")
            assert (target / "installed.txt").is_file()
            run(installer, "/S", f"/D={target}")
            print("PASS: fresh install and idle reinstall")

            adb = target / "adb/adb.exe"
            port = free_port()
            run(adb, "-P", port, "start-server")
            try:
                assert_locked(target / "adb/AdbWinApi.dll")
                (target / "installed.txt").unlink()
                run(installer, "/S", f"/D={target}")
                assert (target / "installed.txt").is_file()
                assert not server_alive(port), "Bundled ADB survived the update"
                assert server_alive(other_port), "An unrelated ADB server was stopped"
                for name in FILES:
                    assert (target / "adb" / name).read_bytes() == (ROOT / "adb" / name).read_bytes()
                print("PASS: update replaces locked DLLs and preserves unrelated ADB")

                run(adb, "-P", port, "start-server")
                assert_locked(target / "adb/AdbWinApi.dll")
                run(target / "uninstall.exe", "/S", f"_?={target}")
                assert (target / "uninstalled.txt").is_file()
                assert not any((target / "adb" / name).exists() for name in FILES)
                assert not server_alive(port)
                assert server_alive(other_port)
                print("PASS: uninstall removes resources while ADB is running")
            finally:
                if server_alive(port):
                    run(other, "-P", port, "kill-server")
                wait_unlocked(target)

            # Reproduce a partial old uninstall: DLL loaded but adb.exe absent.
            orphan = work / "partial installation"
            orphan_adb = copy_adb(orphan)
            orphan_adb.unlink()
            ready = orphan / "ready"
            helper = subprocess.Popen(
                subprocess.list2cmdline([str(holder), "/S"]) + f" /D={orphan}",
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            try:
                deadline = time.monotonic() + 10
                while not ready.exists() and helper.poll() is None and time.monotonic() < deadline:
                    time.sleep(0.05)
                assert ready.exists(), "DLL holder did not start"
                assert_locked(orphan / "adb/AdbWinApi.dll")
                run(installer, "/S", f"/D={orphan}")
                assert (orphan / "installed.txt").is_file()
                helper.wait(timeout=5)
                assert server_alive(other_port)
                print("PASS: partial installation with an orphan DLL lock is repaired")
            finally:
                if helper.poll() is None:
                    helper.terminate()
                helper.wait(timeout=5)
        finally:
            run(other, "-P", other_port, "kill-server")
            wait_unlocked(other.parent.parent)


if __name__ == "__main__":
    main()
