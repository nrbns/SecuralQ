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

if ($Server -match '(?i)localhost|127\.0\.0\.1|\[::1\]') {
    Write-Warning "Server URL is localhost. On another PC that points at THIS machine, not SecuraIQ. Use the SecuraIQ host LAN IP (e.g. http://192.168.x.x:8080) and start SecuraIQ with .\start_lan.cmd."
}

$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This installer needs an elevated (Administrator) PowerShell session. Right-click PowerShell -> Run as administrator, then re-run."
    exit 1
}

$exeSrc = Join-Path $PSScriptRoot "SecuraIQ-Agent.exe"
$scriptSrc = Join-Path $PSScriptRoot "securaiq_agent.py"
$useExe = Test-Path $exeSrc
$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) { $python = Get-Command python3 -ErrorAction SilentlyContinue }

if (-not $useExe -and -not (Test-Path $scriptSrc)) {
    Write-Error "Neither SecuraIQ-Agent.exe nor securaiq_agent.py is next to this installer. On the customer PC copy the Windows package from Agents (or dist/agent-packages), not only this .ps1."
    exit 1
}
if (-not $useExe -and -not $python) {
    Write-Error "This PC has no Python and no SecuraIQ-Agent.exe. Customer devices: download the Windows .exe/.zip from the SecuraIQ Agents page. Do not use http://127.0.0.1 as --server."
    exit 1
}

New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
# Store the token in a file readable only by Administrators + SYSTEM, rather
# than embedding it in the scheduled task's command line (visible to any
# user via Task Scheduler / Get-ScheduledTask / process listings).
$tokenFile = Join-Path $InstallDir "agent.token"
Set-Content -Path $tokenFile -Value $Token -NoNewline -Encoding ascii
icacls $tokenFile /inheritance:r | Out-Null
icacls $tokenFile /grant "SYSTEM:(R)" "*S-1-5-32-544:(R)" | Out-Null  # SYSTEM + Administrators only

if ($useExe) {
    $exeDst = Join-Path $InstallDir "SecuraIQ-Agent.exe"
    Copy-Item -Path $exeSrc -Destination $exeDst -Force
    $action = New-ScheduledTaskAction -Execute $exeDst `
        -Argument "--server `"$Server`" --token-file `"$tokenFile`" --interval $IntervalSec --sentinel-interval $SentinelIntervalSec"
} else {
    Copy-Item -Path $scriptSrc -Destination (Join-Path $InstallDir "securaiq_agent.py") -Force
    $agentScript = Join-Path $InstallDir "securaiq_agent.py"
    $action = New-ScheduledTaskAction -Execute $python.Source `
        -Argument "`"$agentScript`" --server `"$Server`" --token-file `"$tokenFile`" --interval $IntervalSec --sentinel-interval $SentinelIntervalSec"
}

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
