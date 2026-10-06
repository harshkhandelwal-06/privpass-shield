@echo off
setlocal
cd /d "%~dp0"

echo ======================================================
echo PRIVPASS SECRETGUARD - INSTALL PRE-COMMIT DEMO
echo ======================================================
echo.
set "PY="
if exist ".venv\Scripts\python.exe" set "PY=.venv\Scripts\python.exe"
if not defined PY set "PY=py"

"%PY%" "tools\install_precommit.py" --demo
set "RC=%ERRORLEVEL%"
echo.
if "%RC%"=="0" (
  echo SUCCESS: a dedicated Git test repository was prepared.
  echo Run RUN-SECRETGUARD-HOOK-DEMO.bat to test commit blocking.
) else (
  echo ERROR: could not prepare the demo Git repository.
  echo Make sure Git is installed and available from Command Prompt.
)
echo.
pause
exit /b %RC%
