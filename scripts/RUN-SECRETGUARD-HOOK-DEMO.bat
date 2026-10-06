@echo off
setlocal
cd /d "%~dp0.."
echo ======================================================
echo PRIVPASS SECRETGUARD - PRE-COMMIT BLOCK/PASS DEMO
echo ======================================================
set "PY="
if exist ".venv\Scripts\python.exe" set "PY=.venv\Scripts\python.exe"
if not defined PY set "PY=py"

"%PY%" "tools\install_precommit.py" --demo
if errorlevel 1 (
  echo.
  echo Could not prepare the Git test repository.
  pause
  exit /b 1
)

set "DEMO=%~dp0..\data\precommit-demo-repo"
cd /d "%DEMO%"
if not exist "leak-demo.py" (
  >"leak-demo.py" echo AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
  >>"leak-demo.py" echo AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
)
git add leak-demo.py

echo.
echo TEST 1: commit with a synthetic secret (should BLOCK)
git commit -m "secretguard blocked test"
set "BLOCK_RC=%ERRORLEVEL%"
if "%BLOCK_RC%"=="1" (
  echo PASS: commit was blocked by SecretGuard.
) else (
  echo FAIL: expected the secret commit to be blocked. Exit=%BLOCK_RC%
)

git reset -- leak-demo.py >nul 2>&1
del /q leak-demo.py >nul 2>&1
if exist clean-demo.py del /q clean-demo.py >nul 2>&1
>clean-demo.py echo print("hello from a clean demo")
git add clean-demo.py

echo.
echo TEST 2: clean commit (should PASS)
git commit -m "clean secretguard test"
set "PASS_RC=%ERRORLEVEL%"
if "%PASS_RC%"=="0" (
  echo PASS: clean commit was accepted.
) else (
  echo FAIL: expected clean commit to pass. Exit=%PASS_RC%
)

echo.
cd /d "%~dp0.."
echo Finished SecretGuard pre-commit demonstration.
pause
exit /b 0
