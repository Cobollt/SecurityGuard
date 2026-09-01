using SecurityGuard.ArchiveGuard.Contracts;

namespace SecurityGuard.ArchiveGuard.Services;

public sealed class EmptyKnownThreatHashStore
    : IKnownThreatHashStore
{
    public Task<bool> IsMaliciousAsync(
        string sha256,
        CancellationToken cancellationToken = default)
    {
        return Task.FromResult(
            false);
    }
}