$ErrorActionPreference = "Stop"

dotnet test tests/SecurityGuard.Core.Tests
dotnet test tests/SecurityGuard.Storage.Tests
dotnet test tests/SecurityGuard.Infrastructure.Tests
dotnet test tests/SecurityGuard.Service.Tests
dotnet test tests/SecurityGuard.UI.Tests
dotnet test tests/SecurityGuard.AlgorithmGuard.Tests
dotnet test tests/SecurityGuard.TransferGuard.Tests
dotnet test tests/SecurityGuard.ArchiveGuard.Tests