# SecuraIQ Agent — Windows package installer (Scheduled Task).
#
# Prefer a packaged SecuraIQ-Agent.exe in this folder (Rust or PyInstaller);
# fall back to securaiq_agent.py + python on PATH.
# Rust builds accept the same --server/--token-file/--interval/--sentinel-interval/--insecure
# flags (sentinel-interval is installer-parity only; FIM/logs ship on check-in).
#
# Build Rust exe into this folder:
#   powershell -File scripts\packaging\build_rust_windows.ps1
#
# Usage (elevated PowerShell):
#   .\install.ps1 -Server "https://securaiq.example.com" -Token "<agent_id>.<agent_key>"

param(
    [Parameter(Mandatory = $true)][string]$Server,
    [Parameter(Mandatory = $true)][string]$Token,
    [int]$IntervalSec = 60,
    [int]$SentinelIntervalSec = 10,
    [string]$InstallDir = "$env:ProgramData\SecuraIQ\agent",
    [string]$TaskName = "SecuraIQAgent",
    [switch]$Insecure
)

$ErrorActionPreference = "Stop"

$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Run this from an elevated (Administrator) PowerShell session."
    exit 1
}

$here = $PSScriptRoot
$exeSrc = Join-Path $here "SecuraIQ-Agent.exe"
$scriptSrc = Join-Path $here "securaiq_agent.py"
$useExe = Test-Path $exeSrc

if (-not $useExe -and -not (Test-Path $scriptSrc)) {
    Write-Error "Neither SecuraIQ-Agent.exe nor securaiq_agent.py found in $here"
    exit 1
}

New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null

$tokenFile = Join-Path $InstallDir "agent.token"
Set-Content -Path $tokenFile -Value $Token -NoNewline -Encoding ascii
icacls $tokenFile /inheritance:r | Out-Null
icacls $tokenFile /grant "SYSTEM:(R)" "*S-1-5-32-544:(R)" | Out-Null

$extra = ""
if ($Insecure) { $extra = " --insecure" }

if ($useExe) {
    $exeDst = Join-Path $InstallDir "SecuraIQ-Agent.exe"
    Copy-Item -Path $exeSrc -Destination $exeDst -Force
    $action = New-ScheduledTaskAction -Execute $exeDst `
        -Argument "--server `"$Server`" --token-file `"$tokenFile`" --interval $IntervalSec --sentinel-interval $SentinelIntervalSec$extra"
} else {
    $python = Get-Command python -ErrorAction SilentlyContinue
    if (-not $python) { $python = Get-Command python3 -ErrorAction SilentlyContinue }
    if (-not $python) {
        Write-Error "python.exe not found on PATH. Install Python 3.8+ or use the packaged SecuraIQ-Agent.exe."
        exit 1
    }
    Copy-Item -Path $scriptSrc -Destination (Join-Path $InstallDir "securaiq_agent.py") -Force
    $agentScript = Join-Path $InstallDir "securaiq_agent.py"
    $action = New-ScheduledTaskAction -Execute $python.Source `
        -Argument "`"$agentScript`" --server `"$Server`" --token-file `"$tokenFile`" --interval $IntervalSec --sentinel-interval $SentinelIntervalSec$extra"
}

$quick = Join-Path $here "QUICKSTART.md"
if (Test-Path $quick) { Copy-Item $quick (Join-Path $InstallDir "QUICKSTART.md") -Force }
$envEx = Join-Path $here "agent.env.example"
if (Test-Path $envEx) { Copy-Item $envEx (Join-Path $InstallDir "agent.env.example") -Force }

$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
    -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit ([TimeSpan]::Zero)

Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings `
    -Description "SecuraIQ native agent — telemetry + Sentinel + Agent Gateway" | Out-Null
Start-ScheduledTask -TaskName $TaskName

Write-Host ""
Write-Host "SecuraIQ agent installed (Scheduled Task '$TaskName')."
Write-Host "  Status:  Get-ScheduledTask -TaskName $TaskName | Get-ScheduledTaskInfo"
Write-Host "  Stop:    Stop-ScheduledTask -TaskName $TaskName"
Write-Host "  Remove:  Unregister-ScheduledTask -TaskName $TaskName -Confirm:`$false; Remove-Item -Recurse -Force '$InstallDir'"
