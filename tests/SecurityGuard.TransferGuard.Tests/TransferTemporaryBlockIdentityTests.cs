using SecurityGuard.TransferGuard.Enums;
using SecurityGuard.TransferGuard.Services;

namespace SecurityGuard.TransferGuard.Tests;

public sealed class TransferTemporaryBlockIdentityTests
{
    [Fact]
    public void Same_endpoint_has_same_identity()
    {
        var first =
            TransferTemporaryBlockIdentity.Create(
                @"C:\Apps\client.exe",
                "1.1.1.1",
                443,
                TransferProtocol.Tcp);

        var second =
            TransferTemporaryBlockIdentity.Create(
                @"c:\apps\CLIENT.exe",
                "1.1.1.1",
                443,
                TransferProtocol.Tcp);

        Assert.Equal(
            first,
            second);
    }

    [Fact]
    public void Different_destination_has_different_identity()
    {
        var first =
            TransferTemporaryBlockIdentity.Create(
                @"C:\Apps\client.exe",
                "1.1.1.1",
                443,
                TransferProtocol.Tcp);

        var second =
            TransferTemporaryBlockIdentity.Create(
                @"C:\Apps\client.exe",
                "8.8.8.8",
                443,
                TransferProtocol.Tcp);

        Assert.NotEqual(
            first,
            second);
    }

    [Fact]
    public void Same_rule_and_endpoint_have_same_identity()
    {
        var sourceRuleId =
            Guid.NewGuid();

        var first =
            TransferTemporaryBlockIdentity.Create(
                sourceRuleId,
                @"C:\Apps\client.exe",
                "1.1.1.1",
                443,
                TransferProtocol.Tcp);

        var second =
            TransferTemporaryBlockIdentity.Create(
                sourceRuleId,
                @"c:\apps\CLIENT.exe",
                "1.1.1.1",
                443,
                TransferProtocol.Tcp);

        Assert.Equal(
            first,
            second);
    }

    [Fact]
    public void Different_source_rules_have_different_identity()
    {
        var first =
            TransferTemporaryBlockIdentity.Create(
                Guid.NewGuid(),
                @"C:\Apps\client.exe",
                "1.1.1.1",
                443,
                TransferProtocol.Tcp);

        var second =
            TransferTemporaryBlockIdentity.Create(
                Guid.NewGuid(),
                @"C:\Apps\client.exe",
                "1.1.1.1",
                443,
                TransferProtocol.Tcp);

        Assert.NotEqual(
            first,
            second);
    }
}