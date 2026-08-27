@echo off
title Register Project Mirage .wraith Icon
echo Registering Project Mirage .wraith icon in Windows Explorer...
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0register-windows-icon.ps1"
if %ERRORLEVEL% EQU 0 (
    echo.
    echo ========================================================
    echo  Icon registered successfully!
    echo  All .wraith encrypted files now display the nobug icon.
    echo ========================================================
) else (
    echo.
    echo An error occurred during registration.
)
pause
