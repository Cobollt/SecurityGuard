using SecurityGuard.Core.Enums;

namespace SecurityGuard.Core.Tests;

public sealed class SecurityModuleContractTests
{
    [Fact]
    public void All_expected_modules_exist()
    {
        var modules =
            Enum.GetValues<
                SecurityModuleKind>();

        Assert.Contains(
            SecurityModuleKind.Core,
            modules);

        Assert.Contains(
            SecurityModuleKind.AlgorithmGuard,
            modules);

        Assert.Contains(
            SecurityModuleKind.TransferGuard,
            modules);

        Assert.Contains(
            SecurityModuleKind.ArchiveGuard,
            modules);

        Assert.Equal(
            4,
            modules.Length);
    }
}