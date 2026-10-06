@echo off
setlocal
cd /d "%~dp0.."
if exist ".venv\Scripts\python.exe" (
  ".venv\Scripts\python.exe" "%~dp0..\tools\ui_check.py"
  if errorlevel 1 goto :fail
  ".venv\Scripts\python.exe" -m pytest -q
  if errorlevel 1 goto :fail
  ".venv\Scripts\python.exe" -m compileall app tools
  if errorlevel 1 goto :fail
  echo.
  echo VERIFY PASSED
  pause
  endlocal
  exit /b 0
)
echo Local venv not found. Run START-PRIVPASS.bat once first.
:fail
pause
endlocal
exit /b 1
