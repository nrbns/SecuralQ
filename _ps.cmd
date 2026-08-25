@echo off
setlocal
cd /d "%~dp0"
set "SCRIPT=%~1"
if "%SCRIPT%"=="" (
  echo Usage: _ps.cmd scripts\something.ps1 [args...]
  exit /b 1
)
shift
powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%" %1 %2 %3 %4 %5 %6 %7 %8 %9
exit /b %ERRORLEVEL%