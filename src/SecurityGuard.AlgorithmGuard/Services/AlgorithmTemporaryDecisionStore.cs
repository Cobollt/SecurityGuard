using System.Collections.Concurrent;
using SecurityGuard.AlgorithmGuard.Contracts;

namespace SecurityGuard.AlgorithmGuard.Services;

public sealed class AlgorithmTemporaryDecisionStore
    : IAlgorithmTemporaryDecisionStore
{
    private readonly ConcurrentDictionary<string, byte> _allowed =
        new(StringComparer.OrdinalIgnoreCase);

    public void AllowOnce(string identity)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(identity);

        _allowed[identity] = 0;
    }

    public bool TryConsumeAllowOnce(string identity)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(identity);

        return _allowed.TryRemove(
            identity,
            out _);
    }
}