using SecurityGuard.Core.Models;
using SecurityGuard.TransferGuard.Enums;
using SecurityGuard.TransferGuard.Models;
using SecurityGuard.TransferGuard.Services;

namespace SecurityGuard.TransferGuard.Tests;

public sealed class TransferConnectionIdentityTests
{
    [Fact]
    public void Different_local_ports_have_same_identity()
    {
        var first =
            Create(
                50000);

        var second =
            Create(
                51000);

        Assert.Equal(
            TransferConnectionIdentity.Create(
                first),
            TransferConnectionIdentity.Create(
                second));
    }

    private static NetworkConnectionObservation Create(
        int localPort)
    {
        return new NetworkConnectionObservation(
            Guid.NewGuid(),
            DateTimeOffset.UtcNow,
            TransferProtocol.Tcp,
            NetworkAddressFamily.IPv4,
            "192.168.1.20",
            localPort,
            "1.1.1.1",
            443,
            new ProcessInfo(
                100,
                null,
                "client.exe",
                @"C:\client.exe",
                null,
                null,
                null),
            @"\device\harddiskvolume3\client.exe");
    }
}