; Tauri's Restart Manager helper targets the exact registered file, so an ADB
; server from another installation is left alone. Close the UI first to prevent
; it from starting ADB again while its resources are being replaced.
!macro MicrowestReleaseAndroidTools
  !insertmacro CheckIfAppIsRunning "$INSTDIR\${MAINBINARYNAME}.exe" "${PRODUCTNAME}"
  !insertmacro CheckIfAppIsRunning "$INSTDIR\adb\adb.exe" "ADB - Microwest Android Cleaner"
  ; An older uninstaller may already have removed adb.exe while its loaded DLLs
  ; remain locked. Register those paths too, even in a partially removed install.
  !insertmacro CheckIfAppIsRunning "$INSTDIR\adb\AdbWinApi.dll" "ADB - Microwest Android Cleaner"
  !insertmacro CheckIfAppIsRunning "$INSTDIR\adb\AdbWinUsbApi.dll" "ADB - Microwest Android Cleaner"
!macroend

!macro NSIS_HOOK_PREINSTALL
  !insertmacro MicrowestReleaseAndroidTools
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  !insertmacro MicrowestReleaseAndroidTools
!macroend
