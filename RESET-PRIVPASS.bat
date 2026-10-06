@echo off
setlocal
cd /d "%~dp0"
if exist runtime rmdir /s /q runtime
if exist .venv rmdir /s /q .venv
echo Runtime reset complete.
pause
endlocal
