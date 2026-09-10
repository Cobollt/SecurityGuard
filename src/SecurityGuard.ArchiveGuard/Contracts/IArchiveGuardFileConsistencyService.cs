using SecurityGuard.ArchiveGuard.Models;

namespace SecurityGuard.ArchiveGuard.Contracts;

public interface IArchiveGuardFileConsistencyService
{
    Task<bool> IsConsistentAsync(
        ArchiveFileMetadata metadata,
        CancellationToken cancellationToken = default);
}