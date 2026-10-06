@echo off
setlocal
cd /d "%~dp0"
echo.
echo ============================================================
echo   PRIVPASS SHIELD - ONE CLICK START
echo ============================================================
set "PYCMD="
where py >nul 2>nul
if not errorlevel 1 set "PYCMD=py -3"
if not defined PYCMD (
  where python >nul 2>nul
  if not errorlevel 1 set "PYCMD=python"
)
if not defined PYCMD goto :nopython
%PYCMD% "%~dp0tools\launcher.py"
if errorlevel 1 goto :fail
goto :done
:nopython
echo.
echo Python 3.10 or newer was not found. Install it from python.org
echo (tick "Add python.exe to PATH"), then run this file again.
pause
exit /b 1
:fail
echo.
echo PrivPass Shield could not start - see the message above.
echo Tip: run scripts\RESET-PRIVPASS.bat to rebuild the environment, then try again.
pause
exit /b 1
:done
endlocal
