@echo off
cd /d "%~dp0"
call "%~dp0_ps.cmd" "%~dp0scripts\build_exe.ps1" %*
