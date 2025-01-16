@echo off

:: Check for administrative privileges
NET FILE >nul 2>&1
if '%errorlevel%' NEQ '0' (
    echo Requesting administrative privileges...
    PowerShell -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

:: Administrative privileges confirmed
echo Running with elevated privileges...

REM Run powershell audit script
powershell -ExecutionPolicy ByPass -File audit.ps1

echo "All data has been extracted"