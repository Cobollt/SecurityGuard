param(
    [string]$Version = "0.1.0"
)

$ErrorActionPreference = "Stop"

$root =
    Split-Path -Parent $PSScriptRoot

Set-Location $root

if ($env:OS -ne "Windows_NT") {
    throw "SecurityGuard MSI must be built on Windows."
}

$publishScript =
    Join-Path $PSScriptRoot "publish-win-x64.ps1"

& $publishScript

$installerProject =
    Join-Path `
        $root `
        "installer\SecurityGuard.Installer\SecurityGuard.Installer.wixproj"

$installerOutput =
    Join-Path `
        $root `
        "artifacts\installer\$Version"

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

$expectedMsi =
    Join-Path `
        $installerOutput `
        "SecurityGuard-$Version-win-x64.msi"

if (-not (Test-Path $expectedMsi)) {
    throw "SecurityGuard MSI was not produced: $expectedMsi"
}

Write-Host ""
Write-Host "SecurityGuard installer created:"
Write-Host $expectedMsi