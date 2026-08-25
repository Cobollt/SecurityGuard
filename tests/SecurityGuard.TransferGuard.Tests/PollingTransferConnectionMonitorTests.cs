using SecurityGuard.TransferGuard.Configuration;
using SecurityGuard.TransferGuard.Enums;
using SecurityGuard.TransferGuard.Models;
using SecurityGuard.TransferGuard.Monitoring;

namespace SecurityGuard.TransferGuard.Tests;

public sealed class PollingTransferConnectionMonitorTests
{
    [Fact]
    public async Task Existing_connection_is_emitted_only_once()
    {
        var connection =
            new TcpConnectionSnapshot(
                100,
                NetworkAddressFamily.IPv4,
                "192.168.1.10",
                51000,
                "1.1.1.1",
                443,
                TransferTcpState.Established);

        var provider =
            new FakeTcpConnectionSnapshotProvider(
                [connection],
                [connection]);

        var monitor =
            new PollingTransferConnectionMonitor(
                provider,
                new TransferGuardOptions
                {
                    PollInterval =
                        TimeSpan.FromMilliseconds(10)
                });

        using var cancellation =
            new CancellationTokenSource(
                TimeSpan.FromMilliseconds(50));

        var received =
            new List<TcpConnectionSnapshot>();

        try
        {
            await foreach (
                var item in
                monitor.WatchAsync(
                    cancellation.Token))
            {
                received.Add(
                    item);
            }
        }
        catch (OperationCanceledException)
        {
        }

        Assert.Single(
            received);
    }

    [Fact]
    public async Task New_connection_is_emitted()
    {
        var first =
            new TcpConnectionSnapshot(
                100,
                NetworkAddressFamily.IPv4,
                "192.168.1.10",
                50000,
                "1.1.1.1",
                443,
                TransferTcpState.Established);

        var second =
            new TcpConnectionSnapshot(
                200,
                NetworkAddressFamily.IPv4,
                "192.168.1.10",
                50001,
                "8.8.8.8",
                443,
                TransferTcpState.Established);

        var provider =
            new FakeTcpConnectionSnapshotProvider(
                [first],
                [first, second]);

        var monitor =
            new PollingTransferConnectionMonitor(
                provider,
                new TransferGuardOptions
                {
                    PollInterval =
                        TimeSpan.FromMilliseconds(10)
                });

        using var cancellation =
            new CancellationTokenSource(
                TimeSpan.FromMilliseconds(50));

        var received =
            new List<TcpConnectionSnapshot>();

        try
        {
            await foreach (
                var item in
                monitor.WatchAsync(
                    cancellation.Token))
            {
                received.Add(
                    item);
            }
        }
        catch (OperationCanceledException)
        {
        }

        Assert.Equal(
            2,
            received.Count);

        Assert.Contains(
            received,
            item =>
                item.ProcessId == 200);
    }

    [Fact]
    public async Task Loopback_connection_is_ignored()
    {
        var connection =
            new TcpConnectionSnapshot(
                100,
                NetworkAddressFamily.IPv4,
                "127.0.0.1",
                50000,
                "127.0.0.1",
                8000,
                TransferTcpState.Established);

        var provider =
            new FakeTcpConnectionSnapshotProvider(
                [connection]);

        var monitor =
            new PollingTransferConnectionMonitor(
                provider,
                new TransferGuardOptions
                {
                    PollInterval =
                        TimeSpan.FromMilliseconds(10),
                    IgnoreLoopback =
                        true
                });

        using var cancellation =
            new CancellationTokenSource(
                TimeSpan.FromMilliseconds(30));

        var received =
            new List<TcpConnectionSnapshot>();

        try
        {
            await foreach (
                var item in
                monitor.WatchAsync(
                    cancellation.Token))
            {
                received.Add(
                    item);
            }
        }
        catch (OperationCanceledException)
        {
        }

        Assert.Empty(
            received);
    }

    [Fact]
    public async Task Time_wait_connection_is_ignored()
{
    var connection =
        new TcpConnectionSnapshot(
            100,
            NetworkAddressFamily.IPv4,
            "192.168.1.10",
            50000,
            "1.1.1.1",
            443,
            TransferTcpState.TimeWait);

    var provider =
        new FakeTcpConnectionSnapshotProvider(
            [connection]);

    var monitor =
        new PollingTransferConnectionMonitor(
            provider,
            new TransferGuardOptions
            {
                PollInterval =
                    TimeSpan.FromMilliseconds(10)
            });

    using var cancellation =
        new CancellationTokenSource(
            TimeSpan.FromMilliseconds(30));

    var received =
        new List<TcpConnectionSnapshot>();

    try
    {
        await foreach (
            var item in
            monitor.WatchAsync(
                cancellation.Token))
        {
            received.Add(
                item);
        }
    }
    catch (OperationCanceledException)
    {
    }

    Assert.Empty(
        received);
}
}