@echo off
setlocal
cd /d "%~dp0"
echo ======================================================
echo PRIVPASS SECRETGUARD - DEMO SCAN
echo ======================================================
echo.
set "PY="
if exist ".venv\Scripts\python.exe" set "PY=.venv\Scripts\python.exe"
if not defined PY set "PY=py"
"%PY%" "tools\secret_scan.py" "data\demo-repo" --fail-on high --min-confidence 0.80
set "RC=%ERRORLEVEL%"
echo.
echo ======================================================
echo GIT HISTORY DEMO - HEAD is clean, history is not
echo ======================================================
"%PY%" "tools\secret_scan.py" "demo-assets\PrivPass-History-Leak-Repo.zip"
echo.
if "%RC%"=="1" (
  echo SUCCESS: blocking findings were detected as expected.
  echo This is the intended SecretGuard security-gate result.
) else if "%RC%"=="0" (
  echo SUCCESS: no blocking findings were detected.
) else (
  echo ERROR: SecretGuard could not run. Use DOCTOR-PRIVPASS.bat for diagnostics.
)
echo.
pause
exit /b 0
