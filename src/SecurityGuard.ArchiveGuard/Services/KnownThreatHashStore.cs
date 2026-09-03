using SecurityGuard.ArchiveGuard.Contracts;
using SecurityGuard.Core.Contracts;

namespace SecurityGuard.ArchiveGuard.Services;

public sealed class KnownThreatHashStore
    : IKnownThreatHashStore
{
    private readonly IThreatHashRepository _repository;

    public KnownThreatHashStore(
        IThreatHashRepository repository)
    {
        _repository =
            repository;
    }

    public async Task<bool> IsMaliciousAsync(
        string sha256,
        CancellationToken cancellationToken = default)
    {
        var entry =
            await _repository.GetBySha256Async(
                sha256,
                cancellationToken);

        return entry?.Enabled ==
               true;
    }
}