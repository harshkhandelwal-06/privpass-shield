@echo off
setlocal
cd /d "%~dp0.."
if exist ".venv\Scripts\python.exe" (
  ".venv\Scripts\python.exe" "%~dp0..\tools\doctor.py"
) else (
  where py >nul 2>nul
  if errorlevel 1 (echo Python launcher not found.&pause&exit /b 1)
  py -3 "%~dp0..\tools\doctor.py"
)
pause
endlocal
