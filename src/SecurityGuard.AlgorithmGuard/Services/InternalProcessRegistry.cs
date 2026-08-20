using System.Collections.Concurrent;
using SecurityGuard.AlgorithmGuard.Contracts;

namespace SecurityGuard.AlgorithmGuard.Services;

public sealed class InternalProcessRegistry
    : IInternalProcessRegistry
{
    private readonly ConcurrentDictionary<int, DateTimeOffset> _processes =
        new();

    private static readonly TimeSpan Lifetime =
        TimeSpan.FromMinutes(2);

    public void Register(int processId)
    {
        if (processId <= 0)
        {
            return;
        }

        Cleanup();

        _processes[processId] =
            DateTimeOffset.UtcNow;
    }

    public bool TryConsume(int processId)
    {
        Cleanup();

        return _processes.TryRemove(
            processId,
            out _);
    }

    private void Cleanup()
    {
        var threshold =
            DateTimeOffset.UtcNow - Lifetime;

        foreach (var item in _processes)
        {
            if (item.Value >= threshold)
            {
                continue;
            }

            _processes.TryRemove(
                item.Key,
                out _);
        }
    }
}