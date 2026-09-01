using System.Collections.Concurrent;
using System.Diagnostics;
using SecurityGuard.TransferGuard.Contracts;
using SecurityGuard.TransferGuard.Models;

namespace SecurityGuard.TransferGuard.Services;

public sealed class WindowsTransferProcessInstanceRegistry
    : ITransferProcessInstanceRegistry
{
    private readonly ConcurrentDictionary<
        int,
        TransferProcessInstanceId> _instances =
        new();

    public void Prime()
    {
        foreach (var process in
                 Process.GetProcesses())
        {
            using (process)
            {
                var instance =
                    TryRead(
                        process);

                if (instance is null)
                {
                    continue;
                }

                _instances[instance.Value.ProcessId] =
                    instance.Value;
            }
        }
    }

    public TransferProcessInstanceId? Resolve(
        int processId)
    {
        if (processId <= 0)
        {
            return null;
        }

        if (_instances.TryGetValue(
                processId,
                out var existing))
        {
            return existing;
        }

        try
        {
            using var process =
                Process.GetProcessById(
                    processId);

            var instance =
                TryRead(
                    process);

            if (instance is null)
            {
                return null;
            }

            _instances[processId] =
                instance.Value;

            return instance;
        }
        catch
        {
            return null;
        }
    }

    public TransferProcessInstanceId RegisterStart(
        int processId,
        DateTimeOffset detectedAtUtc)
    {
        var startedAtUtc =
            TryReadSystemStartTime(
                processId) ??
            detectedAtUtc;

        var instance =
            new TransferProcessInstanceId(
                processId,
                startedAtUtc);

        _instances[processId] =
            instance;

        return instance;
    }

    public TransferProcessInstanceId? RegisterStop(
        int processId)
    {
        if (_instances.TryRemove(
                processId,
                out var instance))
        {
            return instance;
        }

        return null;
    }

    public IReadOnlyList<TransferProcessInstanceId> PruneStale()
    {
        var removed =
            new List<TransferProcessInstanceId>();

        foreach (var item in
                 _instances)
        {
            var currentStart =
                TryReadSystemStartTime(
                    item.Key);

            if (currentStart is not null &&
                IsSameInstance(
                    item.Value.StartedAtUtc,
                    currentStart.Value))
            {
                continue;
            }

            if (_instances.TryRemove(
                    item.Key,
                    out var stale))
            {
                removed.Add(
                    stale);
            }
        }

        return removed;
    }

    private static TransferProcessInstanceId? TryRead(
        Process process)
    {
        try
        {
            return new TransferProcessInstanceId(
                process.Id,
                new DateTimeOffset(
                    process.StartTime.ToUniversalTime()));
        }
        catch
        {
            return null;
        }
    }

    private static DateTimeOffset? TryReadSystemStartTime(
        int processId)
    {
        try
        {
            using var process =
                Process.GetProcessById(
                    processId);

            return new DateTimeOffset(
                process.StartTime.ToUniversalTime());
        }
        catch
        {
            return null;
        }
    }

    private static bool IsSameInstance(
        DateTimeOffset first,
        DateTimeOffset second)
    {
        return (first - second)
                   .Duration() <
               TimeSpan.FromSeconds(1);
    }
}