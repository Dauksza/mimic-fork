@echo off
setlocal
cd /d "%~dp0"
title Mimic Installer

echo.
echo  MIMIC - Windows desktop setup
echo  =============================
echo.
echo This installs Mimic's Python dependencies into a private .venv folder.
echo Ghidra, JADX, Apktool and other specialist analyzers are separate optional tools.
echo.

if exist ".venv\Scripts\python.exe" goto CheckPython

where py >nul 2>nul
if not errorlevel 1 (
    py -3 -m venv .venv
    if errorlevel 1 goto SetupFailed
    goto CheckPython
)

where python >nul 2>nul
if errorlevel 1 (
    echo Python was not found. Install Python 3.10 or newer from https://www.python.org/downloads/windows/
    echo Be sure to enable the Python launcher or add Python to PATH.
    goto SetupFailed
)
python -m venv .venv
if errorlevel 1 goto SetupFailed

:CheckPython
".venv\Scripts\python.exe" -c "import sys; raise SystemExit(0 if sys.version_info >= (3,10) else 1)"
if errorlevel 1 (
    echo Mimic requires Python 3.10 or newer. Delete the .venv folder and retry with a newer Python.
    goto SetupFailed
)

:InstallPackages
echo Installing or updating Mimic and its optional Windows analysis dependencies...
".venv\Scripts\python.exe" -m pip install --upgrade pip
if errorlevel 1 goto SetupFailed
".venv\Scripts\python.exe" -m pip install -e ".[windows,analysis,instrumentation]"
if errorlevel 1 goto SetupFailed

echo.
echo Setup completed.
echo.
echo Double-click Mimic.vbs to open the graphical interface without a command prompt.
echo Use the Analyze Any App tab for standalone analysis, or Capture and Rebuild to observe a running Windows app.
echo.
pause
exit /b 0

:SetupFailed
echo.
echo Setup did not complete. Read the messages above, verify Python and internet access, then run this installer again.
echo.
pause
exit /b 1
