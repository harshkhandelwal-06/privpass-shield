@echo off
setlocal
for /f "tokens=5" %%p in ('netstat -ano ^| findstr ":8000"') do taskkill /PID %%p /F >nul 2>nul
echo PrivPass local server stopped if it was running on port 8000.
pause
endlocal
