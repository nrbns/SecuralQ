#Requires -Version 5.1
<#
.SYNOPSIS
  Ops-host one-shot for remaining commercial realtime proofs (Docker + optional signing).

.DESCRIPTION
  Run on a machine with Docker Desktop installed. Performs:
    1) redis-ha compose up
    2) Sentinel inject-stop measure (--record)
    3) Multiworker smoke document + phase1 simulate
    4) Optional Authenticode if SIGN_WINDOWS=1

  Never invents HA numbers — records only what this run measures.
#>
param(
  [switch]$SkipSign,
  [switch]$SkipCompose
)

$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $Root

function Require-Docker {
  $d = Get-Command docker -ErrorAction SilentlyContinue
  if (-not $d) {
    throw "Docker not found. Install Docker Desktop, then re-run this script."
  }
  docker info 2>$null | Out-Null
  if ($LASTEXITCODE -ne 0) {
    throw "Docker daemon not running. Start Docker Desktop and retry."
  }
}

Write-Host "=== SecuraIQ remaining ops (live host) ==="
Require-Docker

if (-not $SkipCompose) {
  Write-Host "[1] docker compose --profile redis-ha up -d"
  docker compose --profile redis-ha up -d
  Start-Sleep -Seconds 5
}

Write-Host "[2] Sentinel check"
python scripts/realtime_phase1_proof.py --check-sentinel
if ($LASTEXITCODE -ne 0) { Write-Warning "check-sentinel failed — continue to measure anyway" }

Write-Host "[3] Measured failover inject-stop + record"
python scripts/sentinel_failover_measure.py --inject-stop --record
$measureExit = $LASTEXITCODE

Write-Host "[4] Multiworker / once-only"
python scripts/realtime_multiworker_smoke.py --simulate
python scripts/realtime_ops_remaining_proof.py

if (-not $SkipSign -and ($env:SIGN_WINDOWS -as [string]).ToLower() -in @("1","true","yes")) {
  Write-Host "[5] Authenticode sign_windows.ps1"
  & "$Root\scripts\packaging\sign_windows.ps1"
} else {
  Write-Host "[5] Signing skipped (set SIGN_WINDOWS=1 + cert to enable)"
}

Write-Host ""
Write-Host "Measurements: data/ops/sentinel_failover_measurements.jsonl"
Write-Host "Lab note: docs/ops/SENTINEL-FAILOVER-LAB.md"
if ($measureExit -ne 0) {
  Write-Host "RESULT: PARTIAL — measure exited $measureExit"
  exit $measureExit
}
Write-Host "RESULT: OPS HOST REMAINING COMPLETE (fill table in SENTINEL-FAILOVER-LAB.md)"
exit 0
