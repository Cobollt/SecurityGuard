using System.Diagnostics.Eventing.Reader;
using System.Net;
using System.Runtime.CompilerServices;
using System.Runtime.Versioning;
using System.Threading.Channels;
using SecurityGuard.TransferGuard.Configuration;
using SecurityGuard.TransferGuard.Contracts;
using SecurityGuard.TransferGuard.Models;

namespace SecurityGuard.TransferGuard.Monitoring;

public sealed class WindowsOutboundConnectionEventSource
    : IOutboundConnectionEventSource
{
    private readonly FilteringPlatformEventParser _parser;
    private readonly TransferGuardOptions _options;

    public WindowsOutboundConnectionEventSource(
        FilteringPlatformEventParser parser,
        TransferGuardOptions options)
    {
        _parser =
            parser;

        _options =
            options;
    }

    public IAsyncEnumerable<FilteringPlatformConnectionEvent> WatchAsync(
        CancellationToken cancellationToken = default)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException(
                "Windows Filtering Platform event monitoring is available only on Windows.");
        }

        return WatchWindowsAsync(
            cancellationToken);
    }

    [SupportedOSPlatform("windows")]
    private async IAsyncEnumerable<FilteringPlatformConnectionEvent> WatchWindowsAsync(
        [EnumeratorCancellation]
        CancellationToken cancellationToken = default)
    {
        var channel =
            Channel.CreateUnbounded<
                FilteringPlatformConnectionEvent>();

        var query =
            new EventLogQuery(
                "Security",
                PathType.LogName,
                "*[System[(EventID=5156)]]");

        using var watcher =
            new EventLogWatcher(
                query);

        watcher.EventRecordWritten +=
            (_, eventArgs) =>
            {
                if (eventArgs.EventException is not null)
                {
                    channel.Writer.TryComplete(
                        eventArgs.EventException);

                    return;
                }

                if (eventArgs.EventRecord is null)
                {
                    return;
                }

                using var record =
                    eventArgs.EventRecord;

                try
                {
                    var detected =
                        record.TimeCreated is null
                            ? DateTimeOffset.UtcNow
                            : new DateTimeOffset(
                                record.TimeCreated.Value
                                    .ToUniversalTime());

                    var parsed =
                        _parser.Parse(
                            record.ToXml(),
                            detected);

                    if (parsed is null ||
                        !ShouldObserve(
                            parsed))
                    {
                        return;
                    }

                    channel.Writer.TryWrite(
                        parsed);
                }
                catch
                {
                }
            };

        using var registration =
            cancellationToken.Register(
                () =>
                {
                    try
                    {
                        watcher.Enabled =
                            false;
                    }
                    catch
                    {
                    }

                    channel.Writer.TryComplete();
                });

        watcher.Enabled =
            true;

        await foreach (
            var item in
            channel.Reader.ReadAllAsync(
                cancellationToken))
        {
            yield return item;
        }
    }

    private bool ShouldObserve(
        FilteringPlatformConnectionEvent connection)
    {
        if (connection.ProcessId <= 0)
        {
            return false;
        }

        if (!_options.IgnoreLoopback)
        {
            return true;
        }

        if (!IPAddress.TryParse(
                connection.RemoteAddress,
                out var remoteAddress))
        {
            return true;
        }

        return !IPAddress.IsLoopback(
            remoteAddress);
    }
}