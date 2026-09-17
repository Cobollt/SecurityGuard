param(
    [string]$Version = "0.1.0"
)

$ErrorActionPreference = "Stop"

$root =
    Split-Path -Parent $PSScriptRoot

Set-Location $root

if ([System.Environment]::OSVersion.Platform -ne
    [System.PlatformID]::Win32NT) {
    throw "SecurityGuard MSI must be built on Windows."
}

$publishScript =
    Join-Path $PSScriptRoot "publish-win-x64.ps1"

& $publishScript

if ($LASTEXITCODE -ne 0) {
    throw "SecurityGuard publish failed."
}

$installerProject =
    Join-Path `
        $root `
        "installer\SecurityGuard.Installer\SecurityGuard.Installer.wixproj"

$installerOutput =
    Join-Path `
        $root `
        "artifacts\installer"

if (Test-Path $installerOutput) {
    Remove-Item `
        $installerOutput `
        -Recurse `
        -Force
}

New-Item `
    -ItemType Directory `
    -Path $installerOutput `
    -Force |
    Out-Null

dotnet build `
    $installerProject `
    -c Release `
    -p:ProductVersion=$Version

if ($LASTEXITCODE -ne 0) {
    throw "SecurityGuard installer build failed."
}

$msi =
    Get-ChildItem `
        -Path $installerOutput `
        -Filter "*.msi" `
        -Recurse |
    Select-Object -First 1

if ($null -eq $msi) {
    throw "SecurityGuard MSI was not produced."
}

Write-Host ""
Write-Host "SecurityGuard installer created:"
Write-Host $msi.FullName