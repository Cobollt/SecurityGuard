using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using System.Threading.Channels;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;
using SecurityGuard.TransferGuard.Configuration;
using SecurityGuard.TransferGuard.Contracts;
using SecurityGuard.TransferGuard.Models;

namespace SecurityGuard.TransferGuard.Monitoring;

public sealed class EtwFileReadActivitySource
    : IFileReadActivitySource
{
    private const string SessionName =
        "SecurityGuard.TransferGuard.FileIO";

    private readonly ITransferPathNormalizer _pathNormalizer;
    private readonly TransferGuardOptions _options;

    public EtwFileReadActivitySource(
        ITransferPathNormalizer pathNormalizer,
        TransferGuardOptions options)
    {
        _pathNormalizer =
            pathNormalizer;

        _options =
            options;
    }

    public async IAsyncEnumerable<FileReadActivity> WatchAsync(
        [EnumeratorCancellation]
        CancellationToken cancellationToken = default)
    {
        if (TraceEventSession.IsElevated() !=
            true)
        {
            throw new InvalidOperationException(
                "Kernel ETW File I/O monitoring requires elevated privileges.");
        }

        var channel =
            Channel.CreateBounded<FileReadActivity>(
                new BoundedChannelOptions(
                    _options.FileReadChannelCapacity)
                {
                    SingleReader =
                        true,

                    SingleWriter =
                        false,

                    FullMode =
                        BoundedChannelFullMode.DropOldest
                });

        var fileObjects =
            new ConcurrentDictionary<ulong, string>();

        using var session =
            new TraceEventSession(
                SessionName);

        session.StopOnDispose =
            true;

        session.Source.Kernel.FileIoCreate +=
            data =>
            {
                if (data.ProcessID <= 4 ||
                    data.ProcessID ==
                    Environment.ProcessId)
                {
                    return;
                }

                var path =
                    _pathNormalizer.Normalize(
                        data.OpenPath);

                if (string.IsNullOrWhiteSpace(
                        path))
                {
                    return;
                }

                fileObjects[data.FileObject] =
                    path;
            };

        session.Source.Kernel.FileIoClose +=
            data =>
            {
                fileObjects.TryRemove(
                    data.FileObject,
                    out _);
            };

        session.Source.Kernel.FileIoRead +=
            data =>
            {
                if (data.ProcessID <= 4 ||
                    data.ProcessID ==
                    Environment.ProcessId)
                {
                    return;
                }

                if (data.IoSize <= 0)
                {
                    return;
                }

                if (!fileObjects.TryGetValue(
                        data.FileObject,
                        out var path))
                {
                    return;
                }

                var activity =
                    new FileReadActivity(
                        data.ProcessID,
                        path,
                        data.IoSize,
                        new DateTimeOffset(
                            data.TimeStamp.ToUniversalTime()));

                channel.Writer.TryWrite(
                    activity);
            };

        session.EnableKernelProvider(
            KernelTraceEventParser.Keywords.FileIOInit);

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
                var item in
                channel.Reader.ReadAllAsync(
                    cancellationToken))
            {
                yield return item;
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
}