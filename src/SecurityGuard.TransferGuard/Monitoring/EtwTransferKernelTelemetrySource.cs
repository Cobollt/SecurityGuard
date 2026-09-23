using System.Net;
using System.Runtime.CompilerServices;
using System.Threading.Channels;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;
using SecurityGuard.TransferGuard.Configuration;
using SecurityGuard.TransferGuard.Contracts;
using SecurityGuard.TransferGuard.Enums;
using SecurityGuard.TransferGuard.Models;
using System.Collections.Concurrent;

namespace SecurityGuard.TransferGuard.Monitoring;

public sealed class EtwTransferKernelTelemetrySource
    : ITransferKernelTelemetrySource
{
    private const string SessionName =
        "SecurityGuard.TransferGuard.Kernel";

    private readonly ITransferPathNormalizer _pathNormalizer;
    private readonly ITransferFileClassifier _fileClassifier;
    private readonly ITransferProcessInstanceRegistry _processRegistry;
    private readonly ITransferTelemetryHealthTracker _healthTracker;
    private readonly TransferGuardOptions _options;

    public EtwTransferKernelTelemetrySource(
        ITransferPathNormalizer pathNormalizer,
        ITransferFileClassifier fileClassifier,
        ITransferProcessInstanceRegistry processRegistry,
        ITransferTelemetryHealthTracker healthTracker,
        TransferGuardOptions options)
    {
        _pathNormalizer =
            pathNormalizer;

        _fileClassifier =
            fileClassifier;

        _processRegistry =
            processRegistry;

        _healthTracker =
            healthTracker;

        _options =
            options;
    }

    public async IAsyncEnumerable<TransferKernelActivity> WatchAsync(
        [EnumeratorCancellation]
        CancellationToken cancellationToken = default)
    {
        if (TraceEventSession.IsElevated() !=
            true)
        {
            throw new InvalidOperationException(
                "TransferGuard kernel ETW monitoring requires elevated privileges.");
        }

        _processRegistry.Prime();

        var channel =
            Channel.CreateBounded<TransferKernelActivity>(
                new BoundedChannelOptions(
                    _options.KernelTelemetryChannelCapacity)
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
                    _healthTracker.RecordKernelDrop());

        var pendingFileReads =
            new ConcurrentDictionary<
                string,
                PendingFileRead>(
                StringComparer.OrdinalIgnoreCase);

        using var aggregationCancellation =
            CancellationTokenSource.CreateLinkedTokenSource(
                cancellationToken);

        using var session =
            new TraceEventSession(
                SessionName);

        session.StopOnDispose =
            true;

        session.EnableKernelProvider(
            KernelTraceEventParser.Keywords.Process |
            KernelTraceEventParser.Keywords.FileIO |
            KernelTraceEventParser.Keywords.FileIOInit |
            KernelTraceEventParser.Keywords.NetworkTCPIP);

        session.Source.Kernel.ProcessStart +=
            data =>
            {
                var detectedAt =
                    ToUtc(
                        data.TimeStamp);

                var instance =
                    _processRegistry.RegisterStart(
                        data.ProcessID,
                        detectedAt);

                channel.Writer.TryWrite(
                    new ProcessStartedKernelActivity(
                        instance,
                        detectedAt));
            };

        session.Source.Kernel.ProcessStop +=
            data =>
            {
                FlushPendingFileReads(
                    pendingFileReads,
                    channel.Writer,
                    DateTimeOffset.MaxValue,
                    processId:
                        data.ProcessID,
                    force:
                        true);

                var instance =
                    _processRegistry.RegisterStop(
                        data.ProcessID);

                if (instance is null)
                {
                    return;
                }

                channel.Writer.TryWrite(
                    new ProcessStoppedKernelActivity(
                        instance.Value,
                        ToUtc(
                            data.TimeStamp)));
            };

        session.Source.Kernel.FileIORead +=
            data =>
            {
                if (!ShouldObserveProcess(
                    data.ProcessID))

                if (data.IoSize <= 0)
                    {
                        return;
                    }

                var processInstance =
                    _processRegistry.Resolve(
                        data.ProcessID);

                if (processInstance is null)
                {
                    return;
                }

                var path =
                    _pathNormalizer.Normalize(
                        data.FileName);

                if (string.IsNullOrWhiteSpace(
                        path))
                {
                    return;
                }

                TransferFileClassification classification;

                try
                {
                    classification =
                        _fileClassifier.Classify(
                            path);
                }
                catch
                {
                    classification =
                        TransferFileClassification.Default;
                }

                if (classification.Priority ==
                    TransferFilePriority.Ignore)
                {
                    return;
                }

                var readAtUtc =
                    ToUtc(
                        data.TimeStamp);

                var key =
                    BuildFileReadAggregationKey(
                        data.ProcessID,
                        path);

                pendingFileReads.AddOrUpdate(
                    key,
                    _ =>
                        new PendingFileRead(
                            data.ProcessID,
                            path,
                            data.IoSize,
                            readAtUtc,
                            classification,
                            processInstance),
                    (_, existing) =>
                        existing with
                        {
                            BytesRead =
                                existing.BytesRead +
                                data.IoSize,

                            LastReadAtUtc =
                                readAtUtc,

                            Classification =
                                classification,

                            ProcessInstance =
                                processInstance
                        });
            };

        session.Source.Kernel.TcpIpSend +=
            data =>
                WriteNetworkSend(
                    channel.Writer,
                    data.ProcessID,
                    TransferProtocol.Tcp,
                    NetworkAddressFamily.IPv4,
                    data.saddr,
                    data.sport,
                    data.daddr,
                    data.dport,
                    data.size,
                    data.TimeStamp);

        session.Source.Kernel.TcpIpSendIPV6 +=
            data =>
                WriteNetworkSend(
                    channel.Writer,
                    data.ProcessID,
                    TransferProtocol.Tcp,
                    NetworkAddressFamily.IPv6,
                    data.saddr,
                    data.sport,
                    data.daddr,
                    data.dport,
                    data.size,
                    data.TimeStamp);

        session.Source.Kernel.UdpIpSend +=
            data =>
                WriteNetworkSend(
                    channel.Writer,
                    data.ProcessID,
                    TransferProtocol.Udp,
                    NetworkAddressFamily.IPv4,
                    data.saddr,
                    data.sport,
                    data.daddr,
                    data.dport,
                    data.size,
                    data.TimeStamp);

        session.Source.Kernel.UdpIpSendIPV6 +=
            data =>
                WriteNetworkSend(
                    channel.Writer,
                    data.ProcessID,
                    TransferProtocol.Udp,
                    NetworkAddressFamily.IPv6,
                    data.saddr,
                    data.sport,
                    data.daddr,
                    data.dport,
                    data.size,
                    data.TimeStamp);

        var aggregationTask =
            Task.Run(
                async () =>
                {
                    using var timer =
                        new PeriodicTimer(
                            _options.KernelTelemetryAggregationInterval);

                    try
                    {
                        while (await timer.WaitForNextTickAsync(
                                   aggregationCancellation.Token))
                        {
                            FlushPendingFileReads(
                                pendingFileReads,
                                channel.Writer,
                                DateTimeOffset.MaxValue,
                                force:
                                    true);
                        }
                    }
                    catch (OperationCanceledException)
                        when (aggregationCancellation.IsCancellationRequested)
                    {
                    }
                },
        CancellationToken.None);

        var processingTask =
            Task.Run(
                () =>
                {
                    try
                    {
                        session.Source.Process();

                        FlushPendingFileReads(
                            pendingFileReads,
                            channel.Writer,
                            DateTimeOffset.MaxValue,
                            force:
                                true);

                        channel.Writer.TryComplete();
                    }
                    catch (Exception exception)
                    {
                        _healthTracker.RecordKernelSourceFailure();

                        channel.Writer.TryComplete(
                            exception);
                    }
                },
                CancellationToken.None);

        using var cancellationRegistration =
            cancellationToken.Register(
                () =>
                    channel.Writer.TryComplete());

        try
        {
            await foreach (
                var activity in
                channel.Reader.ReadAllAsync(
                    cancellationToken))
            {
                yield return activity;
            }
        }
        finally
        {
            aggregationCancellation.Cancel();
            try
            {
                session.Stop(
                    true);
            }
            catch when (
                cancellationToken.IsCancellationRequested)
            {
            }

            try
            {
                await processingTask;
            }
            catch (OperationCanceledException)
                when (cancellationToken.IsCancellationRequested)
            {
            }
        }
    }

    private static string BuildFileReadAggregationKey(
        int processId,
        string path)
        {
            return $"{processId}|{path}";
        }

    private static void FlushPendingFileReads(
        ConcurrentDictionary<
            string,
            PendingFileRead> pendingFileReads,
        ChannelWriter<TransferKernelActivity> writer,
        DateTimeOffset cutoff,
        int? processId = null,
        bool force = false)
    {
        foreach (var item in pendingFileReads)
        {
            var pending =
                item.Value;

            if (processId is not null &&
                pending.ProcessId !=
                processId.Value)
            {
                continue;
            }

            if (!force &&
                pending.LastReadAtUtc >
                cutoff)
            {
                continue;
            }

            if (!pendingFileReads.TryRemove(
                    item.Key,
                    out var removed))
            {
                continue;
            }

            writer.TryWrite(
                new FileReadKernelActivity(
                    new FileReadActivity(
                        removed.ProcessId,
                        removed.FilePath,
                        removed.BytesRead,
                        removed.LastReadAtUtc,
                        removed.Classification,
                        removed.ProcessInstance)));
        }
    }

    private sealed record PendingFileRead(
        int ProcessId,
        string FilePath,
        long BytesRead,
        DateTimeOffset LastReadAtUtc,
        TransferFileClassification Classification,
        TransferProcessInstanceId? ProcessInstance);

    private void WriteNetworkSend(
        ChannelWriter<TransferKernelActivity> writer,
        int processId,
        TransferProtocol protocol,
        NetworkAddressFamily addressFamily,
        IPAddress localAddress,
        int localPort,
        IPAddress remoteAddress,
        int remotePort,
        int size,
        DateTime timestamp)
    {
        if (!ShouldObserveProcess(
                processId))
        {
            return;
        }

        if (size <= 0 ||
            remotePort <= 0)
        {
            return;
        }

        if (_options.IgnoreLoopback &&
            IPAddress.IsLoopback(
                remoteAddress))
        {
            return;
        }

        var processInstance =
            _processRegistry.Resolve(
                processId);

        if (processInstance is null)
        {
            return;
        }

        writer.TryWrite(
            new NetworkSendKernelActivity(
                new NetworkSendActivity(
                    processId,
                    protocol,
                    addressFamily,
                    localAddress.ToString(),
                    localPort,
                    remoteAddress.ToString(),
                    remotePort,
                    size,
                    ToUtc(
                        timestamp),
                    processInstance)));
    }

    private static bool ShouldObserveProcess(
        int processId)
    {
        return processId > 4 &&
               processId !=
               Environment.ProcessId;
    }

    private static DateTimeOffset ToUtc(
        DateTime value)
    {
        return new DateTimeOffset(
            value.ToUniversalTime());
    }
}