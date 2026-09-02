# Build SecuraIQ.exe (Windows). Requires the project venv from run_proper.cmd / start.cmd.
param(
    [switch]$OneFile
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $root

$py = Join-Path $root ".venv\Scripts\python.exe"
if (-not (Test-Path $py)) {
    throw "Missing .venv. Run .\run_proper.cmd once, then re-run this script."
}

Write-Host "Installing PyInstaller..."
& $py -m pip install -q "pyinstaller>=6.3"
if ($LASTEXITCODE -ne 0) { throw "pip install pyinstaller failed" }

$spec = Join-Path $root "packaging\securaiq.spec"
Write-Host "Building from $spec (this can take several minutes)..."
$args = @("--noconfirm", "--clean", $spec)
if ($OneFile) {
    Write-Host "Note: -OneFile is not used; the spec is onedir so RAG/torch start in seconds, not minutes."
}
& $py -m PyInstaller @args
if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed" }

$exe = Join-Path $root "dist\SecuraIQ\SecuraIQ.exe"
if (-not (Test-Path $exe)) { throw "Build finished but $exe was not created." }

Write-Host ""
Write-Host "Built: $exe"
Write-Host "Double-click SecuraIQ.exe (keep the whole dist\SecuraIQ folder together)."
Write-Host "UI: http://127.0.0.1:8080  — data and .env are created next to the EXE."
