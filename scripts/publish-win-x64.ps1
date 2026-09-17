$ErrorActionPreference = "Stop"

$root =
    Split-Path -Parent $PSScriptRoot

Set-Location $root

$artifacts =
    Join-Path $root "artifacts"

$publishRoot =
    Join-Path $artifacts "publish"

$serviceOutput =
    Join-Path $publishRoot "service\win-x64"

$uiOutput =
    Join-Path $publishRoot "ui\win-x64"

if (Test-Path $serviceOutput) {
    Remove-Item `
        $serviceOutput `
        -Recurse `
        -Force
}

if (Test-Path $uiOutput) {
    Remove-Item `
        $uiOutput `
        -Recurse `
        -Force
}

New-Item `
    -ItemType Directory `
    -Path $serviceOutput `
    -Force |
    Out-Null

New-Item `
    -ItemType Directory `
    -Path $uiOutput `
    -Force |
    Out-Null

dotnet publish `
    "src\SecurityGuard.Service\SecurityGuard.Service.csproj" `
    -c Release `
    -r win-x64 `
    --self-contained true `
    -p:PublishSingleFile=false `
    -p:PublishTrimmed=false `
    -p:DebugSymbols=false `
    -p:DebugType=None `
    -o $serviceOutput

if ($LASTEXITCODE -ne 0) {
    throw "SecurityGuard.Service publish failed."
}

dotnet publish `
    "src\SecurityGuard.UI\SecurityGuard.UI.csproj" `
    -c Release `
    -r win-x64 `
    --self-contained true `
    -p:PublishSingleFile=false `
    -p:PublishTrimmed=false `
    -p:DebugSymbols=false `
    -p:DebugType=None `
    -o $uiOutput

if ($LASTEXITCODE -ne 0) {
    throw "SecurityGuard.UI publish failed."
}

$serviceExecutable =
    Join-Path $serviceOutput "SecurityGuard.Service.exe"

$uiExecutable =
    Join-Path $uiOutput "SecurityGuard.UI.exe"

if (-not (Test-Path $serviceExecutable)) {
    throw "SecurityGuard.Service.exe was not produced."
}

if (-not (Test-Path $uiExecutable)) {
    throw "SecurityGuard.UI.exe was not produced."
}

Write-Host ""
Write-Host "SecurityGuard publish completed."
Write-Host ""
Write-Host "Service:"
Write-Host $serviceOutput
Write-Host ""
Write-Host "UI:"
Write-Host $uiOutput