# Build Rust SecuraIQ-Agent.exe and stage Windows zip under dist/agent-packages.
# Usage (repo root):
#   powershell -ExecutionPolicy Bypass -File scripts\packaging\build_rust_windows.ps1

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Set-Location $Root

$env:CARGO_TARGET_DIR = Join-Path $Root "securaiq-agent\target"
python scripts/build_agent_packages.py --platform windows --rust

Write-Host ""
Write-Host "Install on a lab host (elevated):"
Write-Host "  cd scripts\packaging"
Write-Host "  .\install.ps1 -Server https://your-host:8080 -Token '<agent_id>.<agent_key>'"
