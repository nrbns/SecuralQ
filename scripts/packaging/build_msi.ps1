#Requires -Version 5.1
<#
.SYNOPSIS
  Wrap a built SecuraIQ-Agent Windows .exe into an MSI (WiX Toolset).

.DESCRIPTION
  Prerequisites:
    - WiX Toolset v3 (candle.exe / light.exe) on PATH, or WIX env pointing at WiX bin
    - A built exe from: python scripts/build_agent_packages.py --platform windows

  Authenticode signing is intentionally NOT performed here. After MSI build, sign with
  your org's code-signing cert in CI (signtool) — never commit private keys.

.EXAMPLE
  .\scripts\packaging\build_msi.ps1
  .\scripts\packaging\build_msi.ps1 -ExePath dist\agent-packages\SecuraIQ-Agent-1.0.0-windows-x64.exe
#>
param(
  [string]$ExePath = "",
  [string]$OutDir = "",
  [string]$Version = ""
)

$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$PkgDir = Join-Path $Root "dist\agent-packages"
$WixDir = Join-Path $PSScriptRoot "wix"
$Staging = Join-Path $Root "build\msi-staging"

if (-not $OutDir) { $OutDir = $PkgDir }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
New-Item -ItemType Directory -Force -Path $Staging | Out-Null

if (-not $ExePath) {
  $found = Get-ChildItem -Path $PkgDir -Filter "SecuraIQ-Agent-*-windows-x64.exe" -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1
  if (-not $found) {
    throw "No Windows agent exe found under $PkgDir. Run: python scripts/build_agent_packages.py --platform windows"
  }
  $ExePath = $found.FullName
}
if (-not (Test-Path $ExePath)) { throw "Exe not found: $ExePath" }

if (-not $Version) {
  if ($ExePath -match "SecuraIQ-Agent-([0-9.]+)-windows") { $Version = $Matches[1] }
  else { $Version = "0.0.0" }
}
# WiX Product Version is up to 4 numeric parts
$WixVersion = ($Version -split "[^0-9]")[0..3] -join "."
if ($WixVersion -notmatch "^\d") { $WixVersion = "0.0.0" }

$EnvExample = Join-Path $Root "scripts\packaging\agent.env.example"
if (-not (Test-Path $EnvExample)) { throw "Missing $EnvExample" }

$candle = Get-Command candle.exe -ErrorAction SilentlyContinue
$light = Get-Command light.exe -ErrorAction SilentlyContinue
if (-not $candle -and $env:WIX) {
  $candle = Get-Command (Join-Path $env:WIX "bin\candle.exe") -ErrorAction SilentlyContinue
  $light = Get-Command (Join-Path $env:WIX "bin\light.exe") -ErrorAction SilentlyContinue
}
if (-not $candle -or -not $light) {
  Write-Warning "WiX Toolset (candle/light) not found on PATH. MSI scaffold is present but not built."
  Write-Warning "Install WiX 3.x from https://wixtoolset.org/ and re-run this script."
  exit 2
}

$wxs = Join-Path $WixDir "SecuraIQAgent.wxs"
$wixobj = Join-Path $Staging "SecuraIQAgent.wixobj"
$msiName = "SecuraIQ-Agent-$Version-windows-x64.msi"
$msiPath = Join-Path $OutDir $msiName

& $candle.Source -nologo `
  "-dAgentVersion=$WixVersion" `
  "-dAgentExe=$ExePath" `
  "-dAgentEnvExample=$EnvExample" `
  -out $wixobj `
  $wxs
if ($LASTEXITCODE -ne 0) { throw "candle failed" }

& $light.Source -nologo -out $msiPath $wixobj
if ($LASTEXITCODE -ne 0) { throw "light failed" }

Write-Host "Built MSI: $msiPath"
Write-Host "Sign next (CI): signtool sign /fd SHA256 /a `"$msiPath`""
exit 0
