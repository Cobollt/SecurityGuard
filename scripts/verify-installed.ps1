param(
    [Parameter(Mandatory = $true)]
    [string]$ExpectedVersion
)

$ErrorActionPreference = "Stop"

$serviceName =
    "SecurityGuard"

$installRoot =
    "C:\Program Files\SecurityGuard"

$servicePath =
    Join-Path `
        $installRoot `
        "Service\SecurityGuard.Service.exe"

$uiPath =
    Join-Path `
        $installRoot `
        "UI\SecurityGuard.UI.exe"

$programData =
    "C:\ProgramData\SecurityGuard"

$requiredDirectories =
    @(
        "Data",
        "Quarantine",
        "Logs",
        "Temp",
        "Lists",
        "Lists\Exports",
        "Lists\Imports"
    )

if (-not (Test-Path $servicePath)) {
    throw "SecurityGuard.Service.exe is missing."
}

if (-not (Test-Path $uiPath)) {
    throw "SecurityGuard.UI.exe is missing."
}

$service =
    Get-Service `
        -Name $serviceName `
        -ErrorAction Stop

if ($service.Status -ne "Running") {
    throw "SecurityGuard service is not running."
}

$cimService =
    Get-CimInstance `
        Win32_Service `
        -Filter "Name='$serviceName'"

if ($null -eq $cimService) {
    throw "SecurityGuard service was not found through Win32_Service."
}

if ($cimService.StartMode -ne "Auto") {
    throw "SecurityGuard service startup type is not Automatic."
}

$serviceRegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\SecurityGuard"
$serviceObjectName = (Get-ItemProperty -Path $serviceRegistryPath -Name ObjectName -ErrorAction Stop).ObjectName

$serviceAccount = New-Object System.Security.Principal.NTAccount($serviceObjectName)
$serviceAccountSid = $serviceAccount.Translate(
    [System.Security.Principal.SecurityIdentifier]
).Value

if ($serviceAccountSid -ne "S-1-5-18") {
    throw "SecurityGuard service is not running as LocalSystem."
}

if ($cimService.PathName -notlike "*SecurityGuard.Service.exe*") {
    throw "SecurityGuard service executable path is invalid."
}

foreach ($directory in $requiredDirectories) {
    $path =
        Join-Path `
            $programData `
            $directory

    if (-not (Test-Path $path)) {
        throw "Required directory is missing: $path"
    }
}

$uninstallEntries =
    @()

$registryPaths =
    @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

foreach ($registryPath in $registryPaths) {
    $uninstallEntries +=
        Get-ItemProperty `
            $registryPath `
            -ErrorAction SilentlyContinue |
        Where-Object {
            $_.DisplayName -eq "SecurityGuard"
        }
}

if ($uninstallEntries.Count -ne 1) {
    throw "Expected exactly one installed SecurityGuard product."
}

if ($uninstallEntries[0].DisplayVersion -ne $ExpectedVersion) {
    throw "Installed version is '$($uninstallEntries[0].DisplayVersion)', expected '$ExpectedVersion'."
}

$commonPrograms =
    [Environment]::GetFolderPath(
        "CommonPrograms")

$shortcut =
    Join-Path `
        $commonPrograms `
        "SecurityGuard\SecurityGuard.lnk"

if (-not (Test-Path $shortcut)) {
    throw "SecurityGuard Start Menu shortcut is missing."
}

Write-Host ""
Write-Host "SecurityGuard installation verification passed."
Write-Host ""
Write-Host "Version: $ExpectedVersion"
Write-Host "Service: Running"
Write-Host "Startup: Automatic"
Write-Host "Account: LocalSystem"
Write-Host "ProgramData: OK"
Write-Host "Start Menu: OK"