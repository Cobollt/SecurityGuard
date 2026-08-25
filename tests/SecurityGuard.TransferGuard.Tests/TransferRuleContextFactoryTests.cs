using SecurityGuard.Core.Models;
using SecurityGuard.TransferGuard.Enums;
using SecurityGuard.TransferGuard.Models;
using SecurityGuard.TransferGuard.Services;

namespace SecurityGuard.TransferGuard.Tests;

public sealed class TransferRuleContextFactoryTests
{
    [Fact]
    public void Connection_is_mapped_to_rule_context()
    {
        var observation =
            new NetworkConnectionObservation(
                Guid.NewGuid(),
                DateTimeOffset.UtcNow,
                TransferProtocol.Tcp,
                NetworkAddressFamily.IPv4,
                "192.168.1.20",
                50000,
                "1.1.1.1",
                443,
                new ProcessInfo(
                    100,
                    null,
                    "client.exe",
                    @"C:\Apps\client.exe",
                    null,
                    null,
                    null),
                @"\device\harddiskvolume3\apps\client.exe");

        var context =
            new TransferRuleContextFactory()
                .Create(
                    observation);

        Assert.Equal(
            "client.exe",
            context.Process);

        Assert.Equal(
            @"\device\harddiskvolume3\apps\client.exe",
            context.ProcessPath);

        Assert.Equal(
            "1.1.1.1",
            context.RemoteAddress);

        Assert.Equal(
            443,
            context.RemotePort);

        Assert.Equal(
            "Tcp",
            context.Protocol);
    }
}