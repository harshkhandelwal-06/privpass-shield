@echo off
setlocal
cd /d "%~dp0.."
set "PY="
if exist ".venv\Scripts\python.exe" set "PY=.venv\Scripts\python.exe"
if not defined PY set "PY=py"
"%PY%" "tools\prove_hibp_privacy.py"
echo.
pause
