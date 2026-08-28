using SecurityGuard.TransferGuard.Enums;
using SecurityGuard.TransferGuard.Models;
using SecurityGuard.TransferGuard.Services;

namespace SecurityGuard.TransferGuard.Tests;

public sealed class TransferCorrelationConfidenceCalculatorTests
{
    [Fact]
    public void Similar_large_read_and_send_can_be_high_confidence()
    {
        var now =
            DateTimeOffset.UtcNow;

        var file =
            new RecentFileRead(
                100,
                @"C:\Temp\report.bin",
                10L * 1024L * 1024L,
                now,
                now,
                new TransferFileClassification(
                    TransferFileCategory.Document,
                    TransferFilePriority.High,
                    "Test document"));

        var send =
            new RecentNetworkSend(
                100,
                TransferProtocol.Tcp,
                NetworkAddressFamily.IPv4,
                "192.168.1.10",
                51000,
                "1.1.1.1",
                443,
                11L * 1024L * 1024L,
                now,
                now +
                TimeSpan.FromMilliseconds(500));

        var result =
            new TransferCorrelationConfidenceCalculator()
                .Calculate(
                    file,
                    send,
                    10L * 1024L * 1024L);

        Assert.Equal(
            TransferCorrelationConfidence.High,
            result.Confidence);

        Assert.True(
            result.VolumeSimilarity >
            0.90);
    }

    [Fact]
    public void Very_different_volumes_are_not_high_confidence()
    {
        var now =
            DateTimeOffset.UtcNow;

        var file =
            new RecentFileRead(
                100,
                @"C:\Temp\report.bin",
                10L * 1024L * 1024L,
                now,
                now);

        var send =
            new RecentNetworkSend(
                100,
                TransferProtocol.Tcp,
                NetworkAddressFamily.IPv4,
                "192.168.1.10",
                51000,
                "1.1.1.1",
                443,
                128L * 1024L,
                now,
                now +
                TimeSpan.FromMilliseconds(500));

        var result =
            new TransferCorrelationConfidenceCalculator()
                .Calculate(
                    file,
                    send,
                    10L * 1024L * 1024L);

        Assert.NotEqual(
            TransferCorrelationConfidence.High,
            result.Confidence);

        Assert.True(
            result.VolumeSimilarity <
            0.10);
    }

    [Fact]
    public void Expired_network_send_is_not_returned()
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

        var sends =
            state.GetRecentNetworkSends(
                100,
                now +
                TimeSpan.FromSeconds(10));

        Assert.Empty(
            sends);
    }

    [Fact]
    public void Low_priority_file_is_capped_below_high_confidence()
    {
        var now =
            DateTimeOffset.UtcNow;

        var file =
            new RecentFileRead(
                100,
                @"C:\Temp\application.log",
                10L * 1024L * 1024L,
                now,
                now,
                new TransferFileClassification(
                    TransferFileCategory.Log,
                    TransferFilePriority.Low,
                    "Log"));

        var send =
            new RecentNetworkSend(
                100,
                TransferProtocol.Tcp,
                NetworkAddressFamily.IPv4,
                "192.168.1.10",
                51000,
                "1.1.1.1",
                443,
                10L * 1024L * 1024L,
                now,
                now +
                TimeSpan.FromMilliseconds(100));

        var result =
            new TransferCorrelationConfidenceCalculator()
                .Calculate(
                    file,
                    send,
                    10L * 1024L * 1024L);

        Assert.NotEqual(
            TransferCorrelationConfidence.High,
            result.Confidence);
    }
}