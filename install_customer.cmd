@echo off
REM Customer / other-device mode: bind LAN, then check functions.
cd /d "%~dp0"
echo SecuraIQ customer install — other phones/PCs use the LAN URL, never localhost.
echo.
call "%~dp0_ps.cmd" "%~dp0scripts\start.ps1" -Lan
