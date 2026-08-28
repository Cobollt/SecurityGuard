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
}