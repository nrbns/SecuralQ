# Build SecuraIQ.exe (Windows) - single-file build, one exe in dist\, nothing else.
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
Write-Host "Building from $spec (single-file - this can take several minutes)..."
& $py -m PyInstaller --noconfirm --clean $spec
if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed" }

$exe = Join-Path $root "dist\SecuraIQ.exe"
if (-not (Test-Path $exe)) { throw "Build finished but $exe was not created." }

Write-Host ""
Write-Host "Built: $exe"
Write-Host "Double-click SecuraIQ.exe - it's the only file you need, nothing else to keep alongside it."
Write-Host "First launch is slower than later ones: PyInstaller unpacks the whole bundle to a temp"
Write-Host "folder every run before uvicorn can start (that's the real cost of a single-file exe)."
Write-Host "UI: http://127.0.0.1:8080 - data and .env are created next to wherever you put the EXE."
