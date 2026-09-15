$ErrorActionPreference = "Continue"

$root = Split-Path -Parent $PSScriptRoot

Set-Location $root

$projects = @(
    @{
        Name = "Core"
        Path = "tests/SecurityGuard.Core.Tests/SecurityGuard.Core.Tests.csproj"
    },
    @{
        Name = "Storage"
        Path = "tests/SecurityGuard.Storage.Tests/SecurityGuard.Storage.Tests.csproj"
    },
    @{
        Name = "Infrastructure"
        Path = "tests/SecurityGuard.Infrastructure.Tests/SecurityGuard.Infrastructure.Tests.csproj"
    },
    @{
        Name = "AlgorithmGuard"
        Path = "tests/SecurityGuard.AlgorithmGuard.Tests/SecurityGuard.AlgorithmGuard.Tests.csproj"
    },
    @{
        Name = "TransferGuard"
        Path = "tests/SecurityGuard.TransferGuard.Tests/SecurityGuard.TransferGuard.Tests.csproj"
    },
    @{
        Name = "ArchiveGuard"
        Path = "tests/SecurityGuard.ArchiveGuard.Tests/SecurityGuard.ArchiveGuard.Tests.csproj"
    },
    @{
        Name = "Service"
        Path = "tests/SecurityGuard.Service.Tests/SecurityGuard.Service.Tests.csproj"
    },
    @{
        Name = "UI"
        Path = "tests/SecurityGuard.UI.Tests/SecurityGuard.UI.Tests.csproj"
    }
)

$results = @()

Write-Host ""
Write-Host "=========================================="
Write-Host " SecurityGuard full test gate"
Write-Host "=========================================="
Write-Host ""

Write-Host "Restore"
dotnet restore

if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "RESTORE FAILED"
    exit 1
}

Write-Host ""
Write-Host "Build"
dotnet build --no-restore

if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "BUILD FAILED"
    exit 1
}

foreach ($project in $projects) {
    Write-Host ""
    Write-Host "------------------------------------------"
    Write-Host "Testing $($project.Name)"
    Write-Host "------------------------------------------"

    if (-not (Test-Path $project.Path)) {
        $results += [PSCustomObject]@{
            Project = $project.Name
            Result = "MISSING"
        }

        continue
    }

    dotnet test $project.Path `
        --no-restore `
        --no-build `
        --verbosity minimal

    if ($LASTEXITCODE -eq 0) {
        $results += [PSCustomObject]@{
            Project = $project.Name
            Result = "PASS"
        }
    }
    else {
        $results += [PSCustomObject]@{
            Project = $project.Name
            Result = "FAIL"
        }
    }
}

Write-Host ""
Write-Host "=========================================="
Write-Host " Results"
Write-Host "=========================================="
Write-Host ""

$results |
    Format-Table -AutoSize

$failed = @(
    $results |
        Where-Object {
            $_.Result -ne "PASS"
        }
)

if ($failed.Count -gt 0) {
    Write-Host ""
    Write-Host "SECURITYGUARD TEST GATE FAILED"
    exit 1
}

Write-Host ""
Write-Host "SECURITYGUARD TEST GATE PASSED"
exit 0