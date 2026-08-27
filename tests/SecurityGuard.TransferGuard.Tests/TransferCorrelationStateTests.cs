using SecurityGuard.Core.Models;
using SecurityGuard.TransferGuard.Configuration;
using SecurityGuard.TransferGuard.Enums;
using SecurityGuard.TransferGuard.Models;
using SecurityGuard.TransferGuard.Services;

namespace SecurityGuard.TransferGuard.Tests;

public sealed class TransferCorrelationStateTests
{
    [Fact]
    public void File_read_is_found_for_same_process()
    {
        var now =
            DateTimeOffset.UtcNow;

        var state =
            new TransferCorrelationState(
                new TransferGuardOptions
                {
                    FileCorrelationWindow =
                        TimeSpan.FromSeconds(10)
                });

        state.RecordFileRead(
            new FileReadActivity(
                100,
                @"C:\Temp\report.pdf",
                4096,
                now));

        var files =
            state.GetRecentFiles(
                100,
                now +
                TimeSpan.FromSeconds(2));

        var file =
            Assert.Single(
                files);

        Assert.Equal(
            @"C:\Temp\report.pdf",
            file.FilePath);

        Assert.Equal(
            4096,
            file.ObservedReadBytes);
    }

    [Fact]
    public void Different_process_does_not_match()
    {
        var now =
            DateTimeOffset.UtcNow;

        var state =
            new TransferCorrelationState(
                new TransferGuardOptions());

        state.RecordFileRead(
            new FileReadActivity(
                100,
                @"C:\Temp\report.pdf",
                4096,
                now));

        var files =
            state.GetRecentFiles(
                200,
                now);

        Assert.Empty(
            files);
    }

    [Fact]
    public void Expired_file_read_does_not_match()
    {
        var now =
            DateTimeOffset.UtcNow;

        var state =
            new TransferCorrelationState(
                new TransferGuardOptions
                {
                    FileCorrelationWindow =
                        TimeSpan.FromSeconds(5)
                });

        state.RecordFileRead(
            new FileReadActivity(
                100,
                @"C:\Temp\report.pdf",
                4096,
                now));

        var files =
            state.GetRecentFiles(
                100,
                now +
                TimeSpan.FromSeconds(10));

        Assert.Empty(
            files);
    }

    [Fact]
    public void Repeated_reads_are_aggregated()
    {
        var now =
            DateTimeOffset.UtcNow;

        var state =
            new TransferCorrelationState(
                new TransferGuardOptions());

        state.RecordFileRead(
            new FileReadActivity(
                100,
                @"C:\Temp\report.pdf",
                4096,
                now));

        state.RecordFileRead(
            new FileReadActivity(
                100,
                @"C:\Temp\report.pdf",
                8192,
                now +
                TimeSpan.FromMilliseconds(100)));

        var files =
            state.GetRecentFiles(
                100,
                now +
                TimeSpan.FromSeconds(1));

        var file =
            Assert.Single(
                files);

        Assert.Equal(
            12288,
            file.ObservedReadBytes);
    }

    [Fact]
    public void Recent_connection_can_be_found_after_file_read()
    {
        var now =
            DateTimeOffset.UtcNow;

        var state =
            new TransferCorrelationState(
                new TransferGuardOptions
                {
                    FileCorrelationWindow =
                        TimeSpan.FromSeconds(10)
                });

        var observation =
            new NetworkConnectionObservation(
                Guid.NewGuid(),
                now,
                TransferProtocol.Tcp,
                NetworkAddressFamily.IPv4,
                "192.168.1.10",
                52000,
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
                @"C:\Apps\client.exe");

        state.RecordConnection(
            observation);

        var connections =
            state.GetRecentConnections(
                100,
                now +
                TimeSpan.FromSeconds(2));

        var restored =
            Assert.Single(
                connections);

        Assert.Equal(
            observation.Id,
            restored.Id);
    }

    [Fact]
    public void Repeated_network_sends_are_aggregated()
    {
        var now =
            DateTimeOffset.UtcNow;

        var state =
            new TransferCorrelationState(
                new TransferGuardOptions());

        state.RecordNetworkSend(
            new NetworkSendActivity(
                100,
                TransferProtocol.Tcp,
                NetworkAddressFamily.IPv4,
                "192.168.1.10",
                51000,
                "1.1.1.1",
                443,
                4096,
                now));

        state.RecordNetworkSend(
            new NetworkSendActivity(
                100,
                TransferProtocol.Tcp,
                NetworkAddressFamily.IPv4,
                "192.168.1.10",
                51000,
                "1.1.1.1",
                443,
                8192,
                now +
                TimeSpan.FromMilliseconds(50)));

        var sends =
            state.GetRecentNetworkSends(
                100,
                now +
                TimeSpan.FromSeconds(1));

        var send =
            Assert.Single(
                sends);

        Assert.Equal(
            12288,
            send.ObservedSentBytes);
    }

    [Fact]
    public void Different_destinations_are_not_aggregated()
    {
        var now =
            DateTimeOffset.UtcNow;

        var state =
            new TransferCorrelationState(
                new TransferGuardOptions());

        state.RecordNetworkSend(
            new NetworkSendActivity(
                100,
                TransferProtocol.Tcp,
                NetworkAddressFamily.IPv4,
                "192.168.1.10",
                51000,
                "1.1.1.1",
                443,
                4096,
                now));

        state.RecordNetworkSend(
            new NetworkSendActivity(
                100,
                TransferProtocol.Tcp,
                NetworkAddressFamily.IPv4,
                "192.168.1.10",
                51001,
                "8.8.8.8",
                443,
                4096,
                now));

        var sends =
            state.GetRecentNetworkSends(
                100,
                now);

        Assert.Equal(
            2,
            sends.Count);
    }
}