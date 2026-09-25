# Start SecuraIQ (Windows) - zero-config: no manual .env. Localhost by default; -Lan for Wi-Fi devices.
param(
    [switch]$Lan,
    [switch]$NoBrowser
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location (Join-Path $root "..")

function Find-Python {
    foreach ($cmd in @("python", "py")) {
        $exe = Get-Command $cmd -ErrorAction SilentlyContinue
        if (-not $exe) { continue }
        try {
            if ($cmd -eq "py") {
                $ver = & py -3 -c "import sys; print('%d.%d' % sys.version_info[:2])" 2>$null
                if ($ver) {
                    $parts = $ver.Split(".")
                    if ([int]$parts[0] -gt 3 -or ([int]$parts[0] -eq 3 -and [int]$parts[1] -ge 11)) {
                        return @{ Exe = "py"; Args = @("-3") }
                    }
                }
            } else {
                $ver = & python -c "import sys; print('%d.%d' % sys.version_info[:2])" 2>$null
                if ($ver) {
                    $parts = $ver.Split(".")
                    if ([int]$parts[0] -gt 3 -or ([int]$parts[0] -eq 3 -and [int]$parts[1] -ge 11)) {
                        return @{ Exe = "python"; Args = @() }
                    }
                }
            }
        } catch { }
    }
    throw "Python 3.11+ not found. Install from https://www.python.org/downloads/ and tick 'Add python.exe to PATH'."
}

function Set-EnvLine {
    param([string[]]$Lines, [string]$Key, [string]$Value)
    $pattern = "^" + [regex]::Escape($Key) + "=.*"
    $replacement = "$Key=$Value"
    $found = $false
    $out = foreach ($line in $Lines) {
        if ($line -match $pattern) {
            $found = $true
            $replacement
        } else {
            $line
        }
    }
    if (-not $found) { $out += $replacement }
    return ,$out
}

function Ensure-EnvFile {
    if (-not (Test-Path ".env.example")) {
        throw "Missing .env.example - clone the full SecuraIQ repo."
    }
    if (-not (Test-Path ".env")) {
        Copy-Item .env.example .env
        Write-Host "Created .env from .env.example (no manual editing needed)"
    }
}

$py = Find-Python
$pyInvoke = {
    param([string[]]$ExtraArgs)
    if ($py.Args.Count) {
        & $py.Exe @($py.Args + $ExtraArgs)
    } else {
        & $py.Exe @ExtraArgs
    }
}

function Ensure-VenvAndDeps {
    if (-not (Test-Path ".venv\Scripts\python.exe")) {
        Write-Host "Creating virtual environment..."
        if ($py.Args.Count) {
            & $py.Exe @($py.Args + @("-m", "venv", ".venv"))
        } else {
            & $py.Exe -m venv .venv
        }
        if (-not (Test-Path ".venv\Scripts\python.exe")) {
            throw "Failed to create .venv - check Python install."
        }
    }

    # Critical: a half-created .venv (folder exists, packages missing) used to skip
    # install forever and crash with ModuleNotFoundError: fastapi.
    & .\.venv\Scripts\python.exe -c "import fastapi, uvicorn" 2>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Installing dependencies (first run or repair - may take a few minutes)..."
        & .\.venv\Scripts\python.exe -m pip install --upgrade pip
        if ($LASTEXITCODE -ne 0) { throw "pip upgrade failed - check network / Python install." }
        & .\.venv\Scripts\python.exe -m pip install -r requirements.txt
        if ($LASTEXITCODE -ne 0) { throw "pip install -r requirements.txt failed." }
        & .\.venv\Scripts\python.exe -c "import fastapi, uvicorn"
        if ($LASTEXITCODE -ne 0) {
            throw "fastapi/uvicorn still missing after install. Delete the .venv folder and run .\run_proper.cmd again."
        }
        Write-Host "Dependencies ready." -ForegroundColor Green
    }
}

Ensure-VenvAndDeps
Ensure-EnvFile

$lines = @(Get-Content ".env" -Encoding UTF8)
if ($Lan) {
    $lines = Set-EnvLine $lines "HOST" "0.0.0.0"
    $lines = Set-EnvLine $lines "CORS_ORIGINS" "*"
    $lines = Set-EnvLine $lines "WORKSPACE_ZERO_START" "false"
    $lines = Set-EnvLine $lines "ALLOW_OPEN_LAN" "true"
    $lines = Set-EnvLine $lines "LAN_AUTO_SCAN" "false"
} else {
    $lines = Set-EnvLine $lines "HOST" "127.0.0.1"
    $lines = Set-EnvLine $lines "CORS_ORIGINS" "http://127.0.0.1:8080,http://localhost:8080"
    $lines = Set-EnvLine $lines "WORKSPACE_ZERO_START" "false"
    $lines = Set-EnvLine $lines "ALLOW_OPEN_LAN" "false"
    $lines = Set-EnvLine $lines "LAN_AUTO_SCAN" "false"
}
if (Get-Command ollama -ErrorAction SilentlyContinue) {
    $lines = Set-EnvLine $lines "MODEL_BACKEND" "ollama"
}
# Sensible zero-config defaults if missing from an old .env
$lines = Set-EnvLine $lines "AUTH_ALLOW_REGISTER" "false"
$utf8Bom = New-Object System.Text.UTF8Encoding $true
[System.IO.File]::WriteAllLines((Join-Path (Get-Location) ".env"), $lines, $utf8Bom)

$portLine = ($lines | Where-Object { $_ -match "^PORT=" } | Select-Object -First 1)
$port = 8080
if ($portLine -match "^PORT=(\d+)") { $port = [int]$Matches[1] }
$appUrl = "http://127.0.0.1:$port"

Write-Host ""
if ($Lan) {
    Write-Host "Starting SecuraIQ (LAN mode - other devices on Wi-Fi can open)" -ForegroundColor Yellow
    Write-Host "  This PC:     $appUrl"
    try {
        Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object { $_.IPAddress -notlike "127.*" -and $_.IPAddress -notlike "169.254.*" } |
            Select-Object -ExpandProperty IPAddress -Unique |
            ForEach-Object { Write-Host "  Phone/other: http://${_}:$port" }
    } catch { }
    # Open Windows Firewall for inbound TCP on the app port (lab LAN only)
    try {
        $ruleName = "SecuraIQ LAN $port"
        $existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
        if (-not $existing) {
            New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Protocol TCP `
                -LocalPort $port -Action Allow -Profile Private -ErrorAction SilentlyContinue | Out-Null
            Write-Host "  Firewall:    allowed inbound TCP $port (Private profile)" -ForegroundColor DarkGray
        }
    } catch {
        Write-Host "  Firewall:    if phones cannot connect, allow TCP $port in Windows Defender Firewall" -ForegroundColor DarkYellow
    }
    Write-Host "  Live share:  same assets/scans on every device. Start a scan from the UI - boot auto-scan is off so phones are not blocked." -ForegroundColor DarkGray
    Write-Host "  Check:       .\.venv\Scripts\python.exe scripts\customer_install_check.py" -ForegroundColor DarkGray
    Write-Host "  Other PC:    open the Phone/other URL above - never http://127.0.0.1 on that device" -ForegroundColor DarkGray
} else {
    Write-Host "Starting SecuraIQ (localhost)" -ForegroundColor Green
    Write-Host "  LAN / phone: .\start_lan.cmd   or   .\start.cmd -Lan"
}
Write-Host "No .env editing required. Optional keys: Settings in the UI."

$rootAbs = (Resolve-Path ".").Path
$pyExe = Join-Path $rootAbs ".venv\Scripts\python.exe"
# Free a leftover python/uvicorn on this port so double-click start.cmd works.
try {
    Get-NetTCPConnection -LocalPort $port -ErrorAction SilentlyContinue |
        Where-Object { $_.State -eq "Listen" } |
        ForEach-Object {
            $procOnPort = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
            if ($procOnPort -and ($procOnPort.ProcessName -match "python|uvicorn")) {
                Write-Host "  Stopping leftover $($procOnPort.ProcessName) on port $port" -ForegroundColor DarkGray
                Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue
            }
        }
} catch { }
$runArgs = @("-u", "run.py")
if ($Lan) { $runArgs += "--lan" }
$proc = Start-Process -FilePath $pyExe -ArgumentList $runArgs -WorkingDirectory $rootAbs -PassThru -NoNewWindow
$waitArgs = @((Join-Path $rootAbs "scripts\wait_open.py"), "--url", $appUrl, "--timeout", "12", "--open-after", "1.5")
if ($NoBrowser) { $waitArgs += "--no-browser" }
& $pyExe @waitArgs
$waitCode = $LASTEXITCODE
if ($waitCode -eq 0) {
    Write-Host "  Ready: $appUrl" -ForegroundColor Green
} else {
    Write-Host "  Opened $appUrl - refresh if the page is still starting" -ForegroundColor Yellow
}
if ($Lan) {
    Write-Host "  Other phones/PCs: use a Phone/other URL above, never localhost." -ForegroundColor DarkGray
}
Wait-Process -Id $proc.Id
