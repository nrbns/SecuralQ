# Lab code-signing material (NOT for commercial release)

Self-signed / lab-only. Commercial Windows release requires an EV Authenticode certificate from a public CA (`SIGN_WINDOWS=1` + `CODE_SIGN_THUMBPRINT` or PFX in CI secrets).

Generate / refresh:
  python scripts/realtime_remaining_full_proof.py
Sign (when SIGN_WINDOWS=1 and PFX set):
  .\scripts\packaging\sign_windows.ps1 -ArtifactDir dist\agent-packages
