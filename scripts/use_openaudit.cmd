@echo off
cd /d "%~dp0"
call "%~dp0_ps.cmd" use_openaudit.ps1 %*
