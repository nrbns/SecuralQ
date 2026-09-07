# SecuraIQ agent — Windows installer (DEVELOPER FALLBACK).
#
# Prefer the packaged agent from dist/agent-packages/ (or Agents UI download):
#   SecuraIQ-Agent-*-windows-x64.exe  or  *.zip (embeds install.ps1).
# This script remains for labs without a built package.
#
# Registers the agent as a Scheduled Task that starts at boot, runs as
# SYSTEM (no logged-in user needed), and restarts automatically on failure —
# the closest install-free equivalent to a native Windows Service without
# pulling in a third-party service wrapper (NSSM, WinSW) or requiring
# pywin32 to be pre-installed on the target machine.
#
# Usage (run from an elevated/Administrator PowerShell):
#   .\install_agent_windows.ps1 -Server "https://securaiq.example.com" -Token "<agent_id>.<agent_key>"

param(
    [Parameter(Mandatory = $true)][string]$Server,
    [Parameter(Mandatory = $true)][string]$Token,
    [int]$IntervalSec = 60,
    [int]$SentinelIntervalSec = 10,
    [string]$InstallDir = "$env:ProgramData\SecuraIQ\agent",
    [string]$TaskName = "SecuraIQAgent"
)

$ErrorActionPreference = "Stop"

$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This installer needs an elevated (Administrator) PowerShell session. Right-click PowerShell -> Run as administrator, then re-run."
    exit 1
}

$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) { $python = Get-Command python3 -ErrorAction SilentlyContinue }
if (-not $python) {
    Write-Error "python.exe not found on PATH. Install Python 3.8+ (tick 'Add python.exe to PATH') first."
    exit 1
}

$scriptSrc = Join-Path $PSScriptRoot "securaiq_agent.py"
if (-not (Test-Path $scriptSrc)) {
    Write-Error "Could not find securaiq_agent.py next to this installer at $scriptSrc. Download both files together:`n  curl -fsSL <server>/api/agents/install-script -o securaiq_agent.py`n  curl -fsSL <server>/api/agents/install-script/windows -o install_agent_windows.ps1"
    exit 1
}

New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
Copy-Item -Path $scriptSrc -Destination (Join-Path $InstallDir "securaiq_agent.py") -Force

# Store the token in a file readable only by Administrators + SYSTEM, rather
# than embedding it in the scheduled task's command line (visible to any
# user via Task Scheduler / Get-ScheduledTask / process listings).
$tokenFile = Join-Path $InstallDir "agent.token"
Set-Content -Path $tokenFile -Value $Token -NoNewline -Encoding ascii
icacls $tokenFile /inheritance:r | Out-Null
icacls $tokenFile /grant "SYSTEM:(R)" "*S-1-5-32-544:(R)" | Out-Null  # SYSTEM + Administrators only

$agentScript = Join-Path $InstallDir "securaiq_agent.py"
$action = New-ScheduledTaskAction -Execute $python.Source `
    -Argument "`"$agentScript`" --server `"$Server`" --token-file `"$tokenFile`" --interval $IntervalSec --sentinel-interval $SentinelIntervalSec"

$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
    -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit ([TimeSpan]::Zero)

Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings `
    -Description "SecuraIQ native agent — telemetry check-in + Sentinel real-time threat watcher" | Out-Null
Start-ScheduledTask -TaskName $TaskName

Write-Host ""
Write-Host "SecuraIQ agent installed and running as a scheduled task (starts at boot, restarts on failure, runs as SYSTEM)."
Write-Host "  Status:  Get-ScheduledTask -TaskName $TaskName | Get-ScheduledTaskInfo"
Write-Host "  Stop:    Stop-ScheduledTask -TaskName $TaskName"
Write-Host "  Remove:  Unregister-ScheduledTask -TaskName $TaskName -Confirm:`$false; Remove-Item -Recurse -Force '$InstallDir'"
Write-Host ""
Write-Host "Note: this uses Task Scheduler (SYSTEM account, restart-on-failure) rather than a true"
Write-Host "Windows Service, to stay install-free (no NSSM/WinSW/pywin32 dependency). Behavior is"
Write-Host "equivalent for monitoring purposes: starts at boot, unattended, auto-restarts."
