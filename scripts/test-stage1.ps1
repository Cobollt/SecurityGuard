$ErrorActionPreference = "Stop"

Write-Host "SecurityGuard Stage 1"

Write-Host "Restore"
dotnet restore SecurityGuard.sln

Write-Host "Build"
dotnet build SecurityGuard.sln --no-restore

Write-Host "Core tests"
dotnet test tests/SecurityGuard.Core.Tests --no-build

Write-Host "Storage tests"
dotnet test tests/SecurityGuard.Storage.Tests --no-build

Write-Host "Infrastructure tests"
dotnet test tests/SecurityGuard.Infrastructure.Tests --no-build

Write-Host "Service tests"
dotnet test tests/SecurityGuard.Service.Tests --no-build

Write-Host "UI tests"
dotnet test tests/SecurityGuard.UI.Tests --no-build

Write-Host "Stage 1 passed"