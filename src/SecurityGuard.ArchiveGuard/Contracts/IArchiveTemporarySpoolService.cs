using SecurityGuard.ArchiveGuard.Models;

namespace SecurityGuard.ArchiveGuard.Contracts;

public interface IArchiveTemporarySpoolService
{
    Task<ArchiveTemporarySpool> CreateAsync(
        CancellationToken cancellationToken = default);
}