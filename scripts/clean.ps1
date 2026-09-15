$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot

Set-Location $root

dotnet clean

Get-ChildItem `
    -Path $root `
    -Directory `
    -Recurse `
    -Force |
    Where-Object {
        $_.Name -eq "bin" -or
        $_.Name -eq "obj" -or
        $_.Name -eq "TestResults"
    } |
    Remove-Item `
        -Recurse `
        -Force `
        -ErrorAction SilentlyContinue

Write-Host "SecurityGuard build artifacts removed."