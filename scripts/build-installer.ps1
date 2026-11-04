param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^\d+\.\d+\.\d+$')]
    [string]$Version
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

& $publishScript -Version $Version

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

$bootstrapperProject =
    Join-Path `
        $root `
        "installer\SecurityGuard.Bootstrapper\SecurityGuard.Bootstrapper.wixproj"

$bootstrapperDirectory =
    Split-Path -Parent $bootstrapperProject

Remove-Item `
    (Join-Path $bootstrapperDirectory "bin"), `
    (Join-Path $bootstrapperDirectory "obj") `
    -Recurse `
    -Force `
    -ErrorAction SilentlyContinue

dotnet build `
    $bootstrapperProject `
    -c Release `
    -t:Rebuild `
    -p:ProductVersion=$Version

if ($LASTEXITCODE -ne 0) {
    throw "SecurityGuard EXE installer build failed."
}

$expectedExe =
    Join-Path `
        $installerOutput `
        "SecurityGuard-$Version-win-x64-setup.exe"

if (-not (Test-Path $expectedExe)) {
    throw "SecurityGuard EXE installer was not produced: $expectedExe"
}

Write-Host ""
Write-Host "SecurityGuard installers created:"
Write-Host $expectedMsi
Write-Host $expectedExe