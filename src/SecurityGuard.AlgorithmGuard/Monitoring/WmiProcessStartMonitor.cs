using System.Management;
using System.Runtime.CompilerServices;
using System.Threading.Channels;
using SecurityGuard.AlgorithmGuard.Contracts;
using SecurityGuard.AlgorithmGuard.Models;

namespace SecurityGuard.AlgorithmGuard.Monitoring;

public sealed class WmiProcessStartMonitor
    : IProcessStartMonitor
{
    public async IAsyncEnumerable<ProcessStartSignal> WatchAsync(
        [EnumeratorCancellation]
        CancellationToken cancellationToken = default)
    {
        var channel =
            Channel.CreateUnbounded<ProcessStartSignal>(
                new UnboundedChannelOptions
                {
                    SingleReader = true,
                    SingleWriter = false
                });

        using var watcher =
            new ManagementEventWatcher(
                new WqlEventQuery(
                    "SELECT * FROM Win32_ProcessStartTrace"));

        watcher.EventArrived +=
            (_, eventArgs) =>
            {
                try
                {
                    var processId =
                        Convert.ToInt32(
                            eventArgs.NewEvent[
                                "ProcessID"]);

                    var parentProcessId =
                        Convert.ToInt32(
                            eventArgs.NewEvent[
                                "ParentProcessID"]);

                    var processName =
                        Convert.ToString(
                            eventArgs.NewEvent[
                                "ProcessName"]) ??
                        string.Empty;

                    channel.Writer.TryWrite(
                        new ProcessStartSignal(
                            processId,
                            parentProcessId,
                            processName,
                            DateTimeOffset.UtcNow));
                }
                catch
                {
                }
            };

        watcher.Start();

        using var registration =
            cancellationToken.Register(
                () =>
                {
                    try
                    {
                        watcher.Stop();
                    }
                    catch
                    {
                    }

                    channel.Writer.TryComplete();
                });

        try
        {
            await foreach (
                var signal in
                channel.Reader.ReadAllAsync(
                    cancellationToken))
            {
                yield return signal;
            }
        }
        finally
        {
            try
            {
                watcher.Stop();
            }
            catch
            {
            }

            channel.Writer.TryComplete();
        }
    }
}