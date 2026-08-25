# Enable secured local mode: auth on, register off, localhost bind, keep workspace data.
# Prints the bootstrap admin password once if it had to be generated.
param(
    [string]$Password = ""
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location (Join-Path $root "..")

if (-not (Test-Path ".env")) {
    Copy-Item .env.example .env
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

if (-not $Password) {
    $Password = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 20 | ForEach-Object { [char]$_ })
    $generated = $true
} else {
    $generated = $false
}

$lines = @(Get-Content ".env" -Encoding UTF8)
$lines = Set-EnvLine $lines "AUTH_ENABLED" "true"
$lines = Set-EnvLine $lines "AUTH_ALLOW_REGISTER" "false"
$lines = Set-EnvLine $lines "BOOTSTRAP_ADMIN_USERNAME" "admin"
$lines = Set-EnvLine $lines "BOOTSTRAP_ADMIN_PASSWORD" $Password
$lines = Set-EnvLine $lines "HOST" "127.0.0.1"
$lines = Set-EnvLine $lines "CORS_ORIGINS" "http://127.0.0.1:8080,http://localhost:8080"
$lines = Set-EnvLine $lines "WORKSPACE_ZERO_START" "false"
$lines = Set-EnvLine $lines "ALLOW_OPEN_LAN" "false"
$lines = Set-EnvLine $lines "LAN_AUTO_SCAN" "false"
$lines = Set-EnvLine $lines "HERMES_SESSION_KEY" ""

$utf8Bom = New-Object System.Text.UTF8Encoding $true
[System.IO.File]::WriteAllLines((Join-Path (Get-Location) ".env"), $lines, $utf8Bom)

Write-Host "Secured mode written to .env" -ForegroundColor Green
Write-Host "  AUTH_ENABLED=true"
Write-Host "  AUTH_ALLOW_REGISTER=false"
Write-Host "  HOST=127.0.0.1 (localhost only)"
Write-Host "  WORKSPACE_ZERO_START=false (data kept across restarts)"
Write-Host "  Username: admin"
if ($generated) {
    Write-Host "  Password: $Password" -ForegroundColor Yellow
    Write-Host "  Save this password now - it is only shown once here."
} else {
    Write-Host "  Password: (from -Password argument)"
}
Write-Host ""
Write-Host "Restart SecuraIQ, then sign in at http://127.0.0.1:8080"
Write-Host "  .\start.cmd"
