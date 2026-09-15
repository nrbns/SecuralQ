#Requires -Version 5.1
<#
.SYNOPSIS
  Authenticode-sign SecuraIQ Windows agent artifacts (exe/msi) when a cert is available.

.DESCRIPTION
  Does NOT create or embed a code-signing certificate. Requires your org cert via:
    - Windows Certificate Store (thumbprint), or
    - PFX file + password (CI: map secrets to files, never commit them)

  Lab without secrets: exits 0 with "skipped" so CI stays green.
  Production: set SIGN_WINDOWS=1 and provide cert material.

.EXAMPLE
  .\scripts\packaging\sign_windows.ps1 -ArtifactDir dist\agent-packages
  $env:SIGN_WINDOWS='1'; $env:CODE_SIGN_THUMBPRINT='ABC...'; .\scripts\packaging\sign_windows.ps1
#>
param(
  [string]$ArtifactDir = "",
  [string]$Thumbprint = $env:CODE_SIGN_THUMBPRINT,
  [string]$PfxPath = $env:CODE_SIGN_PFX_PATH,
  [string]$PfxPassword = $env:CODE_SIGN_PFX_PASSWORD,
  [string]$TimestampUrl = "http://timestamp.digicert.com"
)

$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..\..")
if (-not $ArtifactDir) { $ArtifactDir = Join-Path $Root "dist\agent-packages" }

if (($env:SIGN_WINDOWS -as [string]).ToLower() -notin @("1", "true", "yes")) {
  Write-Host "sign_windows: SIGN_WINDOWS not set — skipping Authenticode (scaffold only)."
  exit 0
}

$signtool = $null
foreach ($cand in @(
  "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe",
  "${env:ProgramFiles}\Windows Kits\10\bin\*\x64\signtool.exe"
)) {
  $hit = Get-Item $cand -ErrorAction SilentlyContinue | Sort-Object FullName -Descending | Select-Object -First 1
  if ($hit) { $signtool = $hit.FullName; break }
}
if (-not $signtool) {
  throw "signtool.exe not found. Install Windows SDK or run on windows-latest with SDK."
}

$files = @()
$files += Get-ChildItem -Path $ArtifactDir -Filter "*.exe" -ErrorAction SilentlyContinue
$files += Get-ChildItem -Path $ArtifactDir -Filter "*.msi" -ErrorAction SilentlyContinue
if (-not $files) {
  Write-Host "sign_windows: no exe/msi under $ArtifactDir"
  exit 0
}

$signArgsBase = @("sign", "/fd", "SHA256", "/tr", $TimestampUrl, "/td", "SHA256")
if ($Thumbprint) {
  $signArgsBase += @("/sha1", $Thumbprint)
} elseif ($PfxPath) {
  if (-not (Test-Path $PfxPath)) { throw "PFX not found: $PfxPath" }
  $signArgsBase += @("/f", $PfxPath)
  if ($PfxPassword) { $signArgsBase += @("/p", $PfxPassword) }
} else {
  throw "SIGN_WINDOWS=1 but neither CODE_SIGN_THUMBPRINT nor CODE_SIGN_PFX_PATH set"
}

foreach ($f in $files) {
  Write-Host "Authenticode: $($f.Name)"
  & $signtool @signArgsBase $f.FullName
  if ($LASTEXITCODE -ne 0) { throw "signtool failed for $($f.Name)" }
}
Write-Host "sign_windows: signed $($files.Count) artifact(s)"
