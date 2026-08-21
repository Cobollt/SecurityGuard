using System.Collections.Concurrent;
using SecurityGuard.AlgorithmGuard.Contracts;

namespace SecurityGuard.AlgorithmGuard.Services;

public sealed class AlgorithmTemporaryDecisionStore
    : IAlgorithmTemporaryDecisionStore
{
    private readonly ConcurrentDictionary<string, DateTimeOffset> _allowed =
        new(StringComparer.OrdinalIgnoreCase);

    public void AllowOnce(
        string identity,
        DateTimeOffset expiresAtUtc)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(
            identity);

        CleanupExpired();

        if (expiresAtUtc <=
            DateTimeOffset.UtcNow)
        {
            return;
        }

        _allowed[identity] =
            expiresAtUtc;
    }

    public bool TryConsumeAllowOnce(
        string identity)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(
            identity);

        CleanupExpired();

        if (!_allowed.TryRemove(
                identity,
                out var expiresAtUtc))
        {
            return false;
        }

        return expiresAtUtc >
               DateTimeOffset.UtcNow;
    }

    private void CleanupExpired()
    {
        var now =
            DateTimeOffset.UtcNow;

        foreach (var item in _allowed)
        {
            if (item.Value > now)
            {
                continue;
            }

            _allowed.TryRemove(
                item.Key,
                out _);
        }
    }
}