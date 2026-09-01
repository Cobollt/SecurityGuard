using System.Diagnostics.Eventing.Reader;
using System.Runtime.CompilerServices;
using System.Threading.Channels;
using SecurityGuard.TransferGuard.Configuration;
using SecurityGuard.TransferGuard.Contracts;
using SecurityGuard.TransferGuard.Models;

namespace SecurityGuard.TransferGuard.Monitoring;

public sealed class WindowsOutboundConnectionEventSource
    : IOutboundConnectionEventSource
{
    private readonly FilteringPlatformEventParser _parser;
    private readonly ITransferTelemetryHealthTracker _healthTracker;
    private readonly TransferGuardOptions _options;

    public WindowsOutboundConnectionEventSource(
        FilteringPlatformEventParser parser,
        ITransferTelemetryHealthTracker healthTracker,
        TransferGuardOptions options)
    {
        _parser =
            parser;

        _healthTracker =
            healthTracker;

        _options =
            options;
    }

    public async IAsyncEnumerable<FilteringPlatformConnectionEvent> WatchAsync(
        [EnumeratorCancellation]
        CancellationToken cancellationToken = default)
    {
        var channel =
            Channel.CreateBounded<FilteringPlatformConnectionEvent>(
                new BoundedChannelOptions(
                    _options.OutboundEventChannelCapacity)
                {
                    SingleReader =
                        true,

                    SingleWriter =
                        false,

                    AllowSynchronousContinuations =
                        false,

                    FullMode =
                        BoundedChannelFullMode.DropOldest
                },
                _ =>
                    _healthTracker.RecordWfpDrop());

        var query =
            new EventLogQuery(
                "Security",
                PathType.LogName,
                "*[System[(EventID=5156)]]");

        using var watcher =
            new EventLogWatcher(
                query);

        void HandleRecord(
            object? sender,
            EventRecordWrittenEventArgs args)
        {
            if (args.EventException is not null)
            {
                _healthTracker.RecordWfpSubscriptionFailure();

                channel.Writer.TryComplete(
                    args.EventException);

                return;
            }

            using var record =
                args.EventRecord;

            if (record is null)
            {
                return;
            }

            try
            {
                var connection =
                    _parser.Parse(
                        record.ToXml());

                if (connection is null)
                {
                    return;
                }

                if (_options.IgnoreLoopback &&
                    IsLoopback(
                        connection))
                {
                    return;
                }

                channel.Writer.TryWrite(
                    connection);
            }
            catch
            {
                _healthTracker.RecordWfpParseFailure();
            }
        }

        watcher.EventRecordWritten +=
            HandleRecord;

        try
        {
            watcher.Enabled =
                true;

            await foreach (
                var connection in
                channel.Reader.ReadAllAsync(
                    cancellationToken))
            {
                yield return connection;
            }
        }
        finally
        {
            watcher.EventRecordWritten -=
                HandleRecord;

            watcher.Enabled =
                false;

            channel.Writer.TryComplete();
        }
    }

    private static bool IsLoopback(
        FilteringPlatformConnectionEvent connection)
    {
        return connection.RemoteAddress ==
                   "127.0.0.1" ||
               connection.RemoteAddress ==
                   "::1";
    }
}