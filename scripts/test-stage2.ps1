$ErrorActionPreference = "Stop"

Write-Host "SecurityGuard Stage 2"

Write-Host "Restore"
dotnet restore SecurityGuard.sln

Write-Host "Build"
dotnet build SecurityGuard.sln --no-restore

Write-Host "Core"
dotnet test tests/SecurityGuard.Core.Tests --no-build

Write-Host "Storage"
dotnet test tests/SecurityGuard.Storage.Tests --no-build

Write-Host "Infrastructure"
dotnet test tests/SecurityGuard.Infrastructure.Tests --no-build

Write-Host "Service"
dotnet test tests/SecurityGuard.Service.Tests --no-build

Write-Host "UI"
dotnet test tests/SecurityGuard.UI.Tests --no-build

Write-Host "AlgorithmGuard"
dotnet test tests/SecurityGuard.AlgorithmGuard.Tests --no-build

Write-Host "Stage 2 current tests passed"