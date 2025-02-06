@echo off
REM ============================================================
REM Remove BitThief startup registry entry and its files
REM ============================================================

echo Removing BitThief startup registry entry...
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v BitThief /f

echo Deleting BitThief working directory...
REM The BitThief folder is located in %APPDATA%
set "TARGETDIR=%APPDATA%\BitThief"
if exist "%TARGETDIR%" (
    rd /s /q "%TARGETDIR%"
    echo Directory %TARGETDIR% has been removed.
) else (
    echo Directory %TARGETDIR% does not exist.
)

echo Cleanup complete.
pause
