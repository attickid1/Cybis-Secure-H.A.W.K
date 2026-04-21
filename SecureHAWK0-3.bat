@echo off
REM ====================================================================
REM  SecureHAWK - Build Script
REM  This script builds file_monitor_enhanced.py into a single .exe file
REM ====================================================================

echo.
echo ====================================================================
echo   SecureHAWK - Build Script
echo ====================================================================
echo.

REM Check that Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH.
    echo Install Python from python.org and check "Add Python to PATH".
    pause
    exit /b 1
)

echo [1/4] Verifying required packages...
python -m pip install --quiet --upgrade pip
python -m pip install --quiet watchdog flask flask-cors psutil pyinstaller
if errorlevel 1 (
    echo ERROR: Failed to install required packages.
    pause
    exit /b 1
)

echo [2/4] Cleaning previous build artifacts...
if exist build rmdir /s /q build
if exist dist rmdir /s /q dist
if exist SecureHAWK.spec del SecureHAWK.spec

echo [3/4] Building executable (this takes 1-3 minutes)...
python -m PyInstaller ^
    --onefile ^
    --name SecureHAWK ^
    --console ^
    --clean ^
    --noconfirm ^
    --collect-all flask ^
    --collect-all watchdog ^
    --collect-all psutil ^
    --collect-all flask_cors ^
    --collect-all werkzeug ^
    --collect-all jinja2 ^
    file_monitor_enhanced.py

if errorlevel 1 (
    echo.
    echo ERROR: Build failed. Check the output above for details.
    pause
    exit /b 1
)

echo [4/4] Build complete!
echo.
echo ====================================================================
echo   SUCCESS
echo ====================================================================
echo.
echo   Executable location: %CD%\dist\SecureHAWK.exe
echo.
echo   You can now:
echo     - Double-click SecureHAWK.exe to run it
echo     - Copy it to any Windows machine (no Python needed)
echo     - Distribute it as a standalone program
echo.
echo   Note: Windows SmartScreen may warn on first run.
echo   Click "More info" then "Run anyway" to proceed.
echo.
pause
