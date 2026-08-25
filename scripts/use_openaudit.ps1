# Configure .env for network inventory (Windows PowerShell 5.1+ safe)
# Password is prompted as SecureString - never pass plaintext on the command line.
# Usage:
#   .\scripts\use_openaudit.ps1 -BaseUrl http://192.168.56.10 -User admin
# Optional:
#   .\scripts\use_openaudit.ps1 -BaseUrl http://inventory.lab -User admin -ApiPrefix /index.php -VerifySsl

param(
    [Parameter(Mandatory = $true)][string]$BaseUrl,
    [Parameter(Mandatory = $true)][string]$User,
    [SecureString]$Password,
    [string]$ApiPrefix = "/open-audit/index.php",
    [switch]$VerifySsl
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location (Join-Path $root "..")

function ConvertFrom-SecureStringPlain {
    param([SecureString]$Secure)
    if (-not $Secure) { return "" }
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
}

if (-not $Password) {
    $Password = Read-Host "Inventory password" -AsSecureString
}
$plainPassword = ConvertFrom-SecureStringPlain $Password
if (-not $plainPassword) {
    throw "Inventory password is required."
}

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

$lines = Get-Content ".env" -Encoding UTF8
$lines = Set-EnvLine $lines "OPENAUDIT_BASE_URL" $BaseUrl
$lines = Set-EnvLine $lines "OPENAUDIT_USER" $User
$lines = Set-EnvLine $lines "OPENAUDIT_PASSWORD" $plainPassword
$lines = Set-EnvLine $lines "OPENAUDIT_API_PREFIX" $ApiPrefix
$lines = Set-EnvLine $lines "OPENAUDIT_VERIFY_SSL" ($(if ($VerifySsl) { "true" } else { "false" }))

$plainPassword = $null

$utf8Bom = New-Object System.Text.UTF8Encoding $true
[System.IO.File]::WriteAllLines((Join-Path (Get-Location) ".env"), $lines, $utf8Bom)

Write-Host "Configured network inventory in .env (password stored in .env only - not printed)"
Write-Host "  URL:      $BaseUrl"
Write-Host "  User:     $User"
Write-Host "  Prefix:   $ApiPrefix"
Write-Host "  Password: ********"
Write-Host "Restart SecuraIQ, then open Assets -> Sync inventory"
Write-Host "Or: .\scripts\start.ps1"
