$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot

Set-Location $root

Write-Host ""
Write-Host "SecurityGuard Release Gate"
Write-Host ""

dotnet restore

if ($LASTEXITCODE -ne 0) {
    exit 1
}

dotnet build `
    SecurityGuard.slnx `
    --configuration Release `
    --no-restore

if ($LASTEXITCODE -ne 0) {
    exit 1
}

dotnet test `
    SecurityGuard.slnx `
    --configuration Release `
    --no-restore `
    --no-build

if ($LASTEXITCODE -ne 0) {
    exit 1
}

Write-Host ""
Write-Host "RELEASE GATE PASSED"