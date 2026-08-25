# Install / register HardeningKitty for SecuraIQ (Windows PowerShell 5.1+)
# Source: https://github.com/scipag/HardeningKitty
# CIS Benchmarks (official PDFs / CIS-CAT): https://downloads.cisecurity.org/#/
#
# Usage:
#   .\scripts\use_hardeningkitty.cmd
#   .\scripts\use_hardeningkitty.ps1 -ModulePath "C:\path\to\HardeningKitty"
#   .\scripts\use_hardeningkitty.ps1 -Download

param(
    [string]$ModulePath = "",
    [string]$List = "",
    [switch]$Download
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location (Join-Path $root "..")

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

if (-not (Test-Path ".env")) {
    Copy-Item .env.example .env
}

$resolved = $ModulePath
if ($Download -or -not $resolved) {
    $vendor = Join-Path (Get-Location) "vendor\HardeningKitty"
    if ($Download -or -not (Test-Path (Join-Path $vendor "HardeningKitty.psm1"))) {
        Write-Host "Downloading HardeningKitty from GitHub..."
        New-Item -ItemType Directory -Force -Path $vendor | Out-Null
        $zip = Join-Path $env:TEMP "hardeningkitty-master.zip"
        Invoke-WebRequest -Uri "https://github.com/scipag/HardeningKitty/archive/refs/heads/master.zip" -OutFile $zip -UseBasicParsing
        $extract = Join-Path $env:TEMP "hardeningkitty-extract"
        if (Test-Path $extract) { Remove-Item $extract -Recurse -Force }
        Expand-Archive -Path $zip -DestinationPath $extract -Force
        $inner = Get-ChildItem $extract | Select-Object -First 1
        Copy-Item -Path (Join-Path $inner.FullName "*") -Destination $vendor -Recurse -Force
        Remove-Item $zip -Force -ErrorAction SilentlyContinue
        Remove-Item $extract -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "Extracted to $vendor"
    }
    $resolved = $vendor
}

if (-not (Test-Path (Join-Path $resolved "HardeningKitty.psm1"))) {
    throw "HardeningKitty.psm1 not found under $resolved"
}

$lines = Get-Content ".env" -Encoding UTF8
$lines = Set-EnvLine $lines "HARDENINGKITTY_MODULE_PATH" $resolved
if ($List) {
    $lines = Set-EnvLine $lines "HARDENINGKITTY_LIST" $List
}
$utf8Bom = New-Object System.Text.UTF8Encoding $true
[System.IO.File]::WriteAllLines((Join-Path (Get-Location) ".env"), $lines, $utf8Bom)

Write-Host "Configured HardeningKitty in .env"
Write-Host "  Module: $resolved"
if ($List) { Write-Host "  List:   $List" }
Write-Host ""
Write-Host "Next:"
Write-Host "  1. Restart SecuraIQ"
Write-Host "  2. Frameworks -> Run HardeningKitty audit (Audit mode only)"
Write-Host "  3. Official CIS Benchmarks: https://downloads.cisecurity.org/#/"
Write-Host "HailMary (apply settings) is not exposed via SecuraIQ - use PowerShell on owned hosts after backup."
