@echo off
REM ====================================================================
REM  SecureHAWK v0.3 - Build Script
REM  Builds SecureHAWK.py into a single windowed .exe (no console)
REM ====================================================================

echo.
echo ====================================================================
echo   SecureHAWK v0.3 - Build Script
echo ====================================================================
echo.

REM Verify Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH.
    echo.
    echo Fix:
    echo   1. Install Python from https://www.python.org/downloads/
    echo   2. During install, CHECK "Add Python to PATH"
    echo   3. Close and reopen this command window
    echo.
    pause
    exit /b 1
)

echo [1/4] Installing required packages...
python -m pip install --quiet --upgrade pip
python -m pip install --quiet watchdog flask flask-cors psutil pyinstaller
if errorlevel 1 (
    echo ERROR: Failed to install required packages.
    echo Check your internet connection and try again.
    pause
    exit /b 1
)

echo [2/4] Cleaning previous build artifacts...
if exist build rmdir /s /q build
if exist dist rmdir /s /q dist
if exist SecureHAWK.spec del SecureHAWK.spec

echo [3/4] Building executable (this takes 1-3 minutes)...
echo.

python -m PyInstaller ^
    --onefile ^
    --windowed ^
    --name SecureHAWK ^
    --clean ^
    --noconfirm ^
    --collect-all flask ^
    --collect-all watchdog ^
    --collect-all psutil ^
    --collect-all flask_cors ^
    --collect-all werkzeug ^
    --collect-all jinja2 ^
    SecureHAWK.py

if errorlevel 1 (
    echo.
    echo ====================================================================
    echo   BUILD FAILED
    echo ====================================================================
    echo   Check the output above for the specific error.
    echo.
    pause
    exit /b 1
)

echo.
echo [4/4] Build complete!
echo.
echo ====================================================================
echo   BUILD SUCCESSFUL
echo ====================================================================
echo.
echo   Executable:  %CD%\dist\SecureHAWK.exe
echo.
echo   You can now:
echo     - Double-click SecureHAWK.exe to launch the GUI
echo     - Copy it to any Windows machine (no Python needed)
echo     - Pin it to your taskbar for quick access
echo.
echo   First-run notes:
echo     - Windows SmartScreen may warn on first launch.
echo       Click "More info" then "Run anyway" to proceed.
echo     - Some antivirus may flag unsigned executables.
echo       Add an exclusion if this happens on your machine.
echo.
pause
