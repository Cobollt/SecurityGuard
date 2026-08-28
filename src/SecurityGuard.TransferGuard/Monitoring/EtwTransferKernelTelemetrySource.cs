using System.Net;
using System.Runtime.CompilerServices;
using System.Threading.Channels;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;
using SecurityGuard.TransferGuard.Configuration;
using SecurityGuard.TransferGuard.Contracts;
using SecurityGuard.TransferGuard.Enums;
using SecurityGuard.TransferGuard.Models;
using SecurityGuard.TransferGuard.Enums;

namespace SecurityGuard.TransferGuard.Monitoring;

public sealed class EtwTransferKernelTelemetrySource
    : ITransferKernelTelemetrySource
{
    private const string SessionName =
        "SecurityGuard.TransferGuard.Kernel";

    private readonly ITransferPathNormalizer _pathNormalizer;
    private readonly TransferGuardOptions _options;
    private readonly ITransferFileClassifier _fileClassifier;

    public EtwTransferKernelTelemetrySource(
        ITransferPathNormalizer pathNormalizer,
        ITransferFileClassifier fileClassifier,
        TransferGuardOptions options)
    {
        _pathNormalizer =
            pathNormalizer;

        _fileClassifier =
            fileClassifier;

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

        var channel =
            Channel.CreateBounded<TransferKernelActivity>(
                new BoundedChannelOptions(
                    _options.KernelTelemetryChannelCapacity)
                {
                    SingleReader =
                        true,

                    SingleWriter =
                        false,

                    FullMode =
                        BoundedChannelFullMode.DropOldest
                });

        using var session =
            new TraceEventSession(
                SessionName);

        session.StopOnDispose =
            true;

        session.Source.Kernel.FileIoRead +=
            data =>
            {
                if (!ShouldObserveProcess(
                        data.ProcessID))
                {
                    return;
                }

                if (data.IoSize <= 0)
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

                channel.Writer.TryWrite(
                    new FileReadKernelActivity(
                        new FileReadActivity(
                            data.ProcessID,
                            path,
                            data.IoSize,
                            ToUtc(
                                data.TimeStamp),
                            classification)));
            };

        session.Source.Kernel.TcpIpSend +=
            data =>
            {
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
            };

        session.Source.Kernel.TcpIpSendIPV6 +=
            data =>
            {
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
            };

        session.Source.Kernel.UdpIpSend +=
            data =>
            {
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
            };

        session.Source.Kernel.UdpIpSendIPV6 +=
            data =>
            {
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
            };

        session.EnableKernelProvider(
            KernelTraceEventParser.Keywords.FileIOInit |
            KernelTraceEventParser.Keywords.NetworkTCPIP);

        var processingTask =
            Task.Run(
                () =>
                {
                    try
                    {
                        session.Source.Process();

                        channel.Writer.TryComplete();
                    }
                    catch (Exception exception)
                    {
                        channel.Writer.TryComplete(
                            exception);
                    }
                },
                CancellationToken.None);

        using var registration =
            cancellationToken.Register(
                () =>
                {
                    try
                    {
                        session.Stop(
                            true);
                    }
                    catch
                    {
                    }

                    channel.Writer.TryComplete();
                });

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
            try
            {
                session.Stop(
                    true);
            }
            catch
            {
            }

            try
            {
                await processingTask;
            }
            catch
            {
            }
        }
    }

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

        if (remoteAddress.Equals(
                IPAddress.Any) ||
            remoteAddress.Equals(
                IPAddress.IPv6Any))
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
                        timestamp))));
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